use futures::future::FutureExt;
use futures::lock::Mutex;
use futures::TryFutureExt;
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::convert::TryFrom;
use std::path::{Component, Path, PathBuf};
use url::Url;
use ya_runtime_sdk::server::ContainerEndpoint;

use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use ya_runtime_vm::demux_socket_comm::MAX_P9_PACKET_SIZE;
use ya_runtime_vm::vm::VMBuilder;

use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};
use ya_runtime_sdk::{
    runtime_api::{
        deploy::{DeployResult, StartMode},
        server,
    },
    serialize,
    server::Server,
    Context, EmptyResponse, EndpointResponse, Error, EventEmitter, OutputResponse, ProcessId,
    ProcessIdResponse, RuntimeMode,
};

use ya_runtime_vm::{
    cpu::CpuInfo,
    deploy::Deployment,
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType, RemoteCommandResult},
};

use ya_runtime_vm::vm::RuntimeData;
use ya_runtime_vm::vm_runner::VMRunner;

const DIR_RUNTIME: &str = "runtime";
const FILE_TEST_IMAGE: &str = "self-test.gvmi";
const FILE_DEPLOYMENT: &str = "deployment.json";
const DEFAULT_CWD: &str = "/";

#[derive(StructOpt, Clone, Default)]
#[structopt(rename_all = "kebab-case")]
pub struct Cli {
    /// GVMI image path
    #[structopt(short, long, required_ifs(
    &[
    ("command", "deploy"),
    ("command", "start"),
    ("command", "run")
    ])
    )]
    task_package: Option<PathBuf>,
    /// Number of logical CPU cores
    #[structopt(long, default_value = "1")]
    cpu_cores: usize,
    /// Amount of RAM [GiB]
    #[structopt(long, default_value = "0.25")]
    mem_gib: f64,
    /// Amount of disk storage [GiB]
    #[allow(unused)]
    #[structopt(long, default_value = "0.25")]
    storage_gib: f64,
    /// VPN endpoint address
    #[structopt(long)]
    vpn_endpoint: Option<Url>,
    /// INET endpoint address
    #[structopt(long)]
    inet_endpoint: Option<Url>,
}

#[derive(ya_runtime_sdk::RuntimeDef, Default)]
#[cli(Cli)]
struct Runtime {
    data: Arc<Mutex<RuntimeData>>,
}

impl ya_runtime_sdk::Runtime for Runtime {
    fn deploy<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        let workdir = ctx.cli.workdir.clone().expect("Workdir not provided");
        let cli = ctx.cli.runtime.clone();

        deploy(workdir, cli).map_err(Into::into).boxed_local()
    }

    fn start<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("ya_runtime_sdk::Runtime - start");

        let emitter = ctx
            .emitter
            .clone()
            .expect("Service is not running in Server mode");
        let workdir = ctx.cli.workdir.clone().expect("Workdir not provided");
        let data = self.data.clone();

        let vpn_endpoint = ctx.cli.runtime.vpn_endpoint.clone();
        let inet_endpoint = ctx.cli.runtime.inet_endpoint.clone();

        log::info!("VPN endpoint: {:?}", vpn_endpoint);
        log::info!("INET endpoint: {:?}", inet_endpoint);

        async move {
            {
                let mut data = data.lock().await;

                if let Some(vpn_endpoint) = vpn_endpoint {
                    let endpoint =
                        ContainerEndpoint::try_from(vpn_endpoint).map_err(Error::from)?;
                    data.vpn.replace(endpoint);
                }
                if let Some(inet_endpoint) = inet_endpoint {
                    let endpoint =
                        ContainerEndpoint::try_from(inet_endpoint).map_err(Error::from)?;
                    data.inet.replace(endpoint);
                }
            }

            let deployment_file = std::fs::File::open(workdir.join(FILE_DEPLOYMENT))
                .expect("Unable to open the deployment file");
            let deployment: Deployment = serialize::json::from_reader(deployment_file)
                .expect("Failed to read the deployment file");
            {
                let mut data = data.lock().await;
                data.deployment.replace(deployment);
            }

            let res = start(workdir, data, emitter).await;
            if let Err(e) = &res {
                log::error!("Starting the runtime failed with error {e}");
            }

            res
        }
        .map_err(Into::into)
        .boxed_local()
    }

    fn stop<'a>(&mut self, _: &mut Context<Self>) -> EmptyResponse<'a> {
        stop(self.data.clone()).map_err(Into::into).boxed_local()
    }

    fn run_command<'a>(
        &mut self,
        command: server::RunProcess,
        mode: RuntimeMode,
        _: &mut Context<Self>,
    ) -> ProcessIdResponse<'a> {
        if let RuntimeMode::Command = mode {
            return async move { Err(anyhow::anyhow!("CLI `run` is not supported")) }
                .map_err(Into::into)
                .boxed_local();
        }

        run_command(self.data.clone(), command)
            .map_err(Into::into)
            .boxed_local()
    }

    fn kill_command<'a>(
        &mut self,
        kill: server::KillProcess,
        _: &mut Context<Self>,
    ) -> EmptyResponse<'a> {
        kill_command(self.data.clone(), kill)
            .map_err(Into::into)
            .boxed_local()
    }

    fn offer<'a>(&mut self, _: &mut Context<Self>) -> OutputResponse<'a> {
        async move { Ok(offer()?) }.boxed_local()
    }

    fn test<'a>(&mut self, _: &mut Context<Self>) -> EmptyResponse<'a> {
        test().map_err(Into::into).boxed_local()
    }

    fn join_network<'a>(
        &mut self,
        join: server::CreateNetwork,
        _: &mut Context<Self>,
    ) -> EndpointResponse<'a> {
        join_network(self.data.clone(), join)
            .map_err(Into::into)
            .boxed_local()
    }
}

async fn deploy(workdir: PathBuf, cli: Cli) -> anyhow::Result<Option<serialize::json::Value>> {
    let workdir = normalize_path(&workdir).await?;
    let package_path = normalize_path(&cli.task_package.unwrap()).await?;
    let package_file = fs::File::open(&package_path).await?;

    let deployment = Deployment::try_from_input(
        package_file,
        cli.cpu_cores,
        (cli.mem_gib * 1024.) as usize,
        package_path,
    )
    .await
    .expect("Error reading package metadata");

    for vol in &deployment.volumes {
        fs::create_dir_all(workdir.join(&vol.name)).await?;
    }
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(workdir.join(FILE_DEPLOYMENT))
        .await?
        .write_all(serde_json::to_string(&deployment)?.as_bytes())
        .await?;

    Ok(Some(serialize::json::to_value(DeployResult {
        valid: Ok(Default::default()),
        vols: deployment.volumes,
        start_mode: StartMode::Blocking,
    })?))
}

async fn start(
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
    emitter: EventEmitter,
) -> anyhow::Result<Option<serialize::json::Value>> {
    let runtime_dir = runtime_dir().expect("Unable to resolve current directory");

    let deployment = runtime_data
        .lock()
        .await
        .deployment()
        .expect("Missing deployment data")
        .clone();

    let vm = VMBuilder::new(
        deployment.cpu_cores,
        deployment.mem_mib,
        &deployment.task_package,
        None,
    )
    .build(runtime_data.clone())
    .await?;

    let mut data = runtime_data.lock().await;

    /* let mut cmd = vm.get_cmd(runtime_dir.join(FILE_RUNTIME));

    cmd.current_dir(&runtime_dir);

    log::debug!(
        "Running VM in runtime directory: {}\nCommand: {} {}\n",
        runtime_dir.to_str().unwrap_or("???"),
        FILE_RUNTIME,
        vm.get_args().join(" ")
    );*/

    let mut vm_runner = VMRunner::new(vm);
    vm_runner.run_vm(runtime_dir).await?;

    vm_runner
        .start_9p_service(&work_dir, &deployment.volumes)
        .await?;

    let ga = GuestAgent::connected(
        vm_runner.get_vm().get_manager_sock(),
        10,
        move |notification, ga| {
            let mut emitter = emitter.clone();
            async move {
                let status = notification_into_status(notification, ga).await;
                emitter.emit(status).await;
            }
            .boxed()
        },
    )
    .await?;

    {
        let mut ga = ga.lock().await;
        for (idx, volume) in deployment.volumes.iter().enumerate() {
            let max_p9_packet_size = u32::try_from(MAX_P9_PACKET_SIZE).unwrap();
            ga.mount(
                format!("mnt{}", idx).as_str(),
                max_p9_packet_size,
                volume.path.as_str(),
            )
            .await?
            .expect("Mount failed");
        }
    }

    data.vm_runner.replace(vm_runner);
    data.ga.replace(ga);

    Ok(None)
}

async fn run_command(
    runtime_data: Arc<Mutex<RuntimeData>>,
    run: server::RunProcess,
) -> Result<ProcessId, server::ErrorResponse> {
    let data = runtime_data.lock().await;
    let deployment = data.deployment().expect("Runtime not started");

    let (uid, gid) = deployment.user;
    let env = deployment.env();
    let cwd = deployment
        .config
        .working_dir
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.as_str())
        .unwrap_or_else(|| DEFAULT_CWD);

    log::debug!("got run process: {:?}", run);
    log::debug!("work dir: {:?}", deployment.config.working_dir);

    let result = data
        .ga()
        .unwrap()
        .lock()
        .await
        .run_process(
            &run.bin,
            run.args
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<&str>>()
                .as_slice(),
            Some(&env[..]),
            uid,
            gid,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeCyclic(0x1000)),
                Some(RedirectFdType::RedirectFdPipeCyclic(0x1000)),
            ],
            Some(cwd),
        )
        .await;

    convert_result(result, "Running process")
}

async fn kill_command(
    runtime_data: Arc<Mutex<RuntimeData>>,
    kill: server::KillProcess,
) -> Result<(), server::ErrorResponse> {
    log::debug!("got kill: {:?}", kill);
    // TODO: send signal
    let data = runtime_data.lock().await;
    let mutex = data.ga().unwrap();
    let result = mutex.lock().await.kill(kill.pid).await;
    convert_result(result, &format!("Killing process {}", kill.pid))?;
    Ok(())
}

async fn stop(runtime_data: Arc<Mutex<RuntimeData>>) -> Result<(), server::ErrorResponse> {
    log::debug!("got shutdown");
    let mut data = runtime_data.lock().await;

    let mut vm_runner = data.vm_runner.take().unwrap();

    vm_runner.stop_p9_service().await;

    {
        let mutex = data.ga().unwrap();
        let mut ga = mutex.lock().await;
        convert_result(ga.quit().await, "Sending quit")?;
    }

    vm_runner
        .stop_vm(&Duration::from_secs(5), false)
        .await
        .expect("Waiting for runtime stop failed");
    Ok(())
}

fn offer() -> anyhow::Result<Option<serde_json::Value>> {
    let cpu = CpuInfo::try_new()?;
    let model = format!(
        "Stepping {} Family {} Model {}",
        cpu.model.stepping, cpu.model.family, cpu.model.model
    );

    Ok(Some(serde_json::json!({
        "properties": {
            "golem.inf.cpu.vendor": cpu.model.vendor,
            "golem.inf.cpu.brand": cpu.model.brand,
            "golem.inf.cpu.model": model,
            "golem.inf.cpu.capabilities": cpu.capabilities,
            "golem.runtime.capabilities": ["vpn"]
        },
        "constraints": ""
    })))
}

async fn test() -> anyhow::Result<()> {
    server::run_async(|e| async {
        let ctx = Context::try_new().expect("Failed to initialize context");
        let task_package = runtime_dir()
            .expect("Runtime directory not found")
            .join(FILE_TEST_IMAGE)
            .canonicalize()
            .expect("Test image not found");

        log::debug!("Task package: {}", task_package.display());
        let runtime_data = RuntimeData {
            deployment: Some(Deployment {
                cpu_cores: 1,
                mem_mib: 128,
                task_package,
                ..Default::default()
            }),
            ..Default::default()
        };
        let runtime = Runtime {
            data: Arc::new(Mutex::new(runtime_data)),
        };

        println!("Starting runtime");
        start(
            std::env::temp_dir(),
            runtime.data.clone(),
            EventEmitter::spawn(e),
        )
        .await
        .expect("Failed to start runtime");

        println!("Stopping runtime");
        stop(runtime.data.clone())
            .await
            .expect("Failed to stop runtime");

        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        Server::new(runtime, ctx)
    })
    .await;
    Ok(())
}

async fn join_network(
    runtime_data: Arc<Mutex<RuntimeData>>,
    join: server::CreateNetwork,
) -> Result<ContainerEndpoint, server::ErrorResponse> {
    let hosts = join.hosts;
    let networks = join.networks;
    let iface = match server::NetworkInterface::from_i32(join.interface) {
        Some(iface) => iface,
        _ => {
            return Err(server::ErrorResponse::msg(format!(
                "invalid network interface type: {:?}",
                join.interface
            )));
        }
    };

    let data = runtime_data.lock().await;
    let endpoint = match iface {
        server::NetworkInterface::Vpn => data.vpn.as_ref(),
        server::NetworkInterface::Inet => data.inet.as_ref(),
    }
    .cloned()
    .expect("No network endpoint");

    let mutex = data.ga().unwrap();
    let mut ga = mutex.lock().await;
    convert_result(ga.add_hosts(hosts.iter()).await, "Updating network hosts")?;

    for net in networks {
        let (net_addr, net_mask) = match iface {
            server::NetworkInterface::Vpn => (net.addr, net.mask.clone()),
            server::NetworkInterface::Inet => Default::default(),
        };

        convert_result(
            ga.add_address(&net.if_addr, &net.mask, iface as u16).await,
            &format!("Adding interface address {} {}", net.if_addr, net.gateway),
        )?;
        convert_result(
            ga.create_network(&net_addr, &net_mask, &net.gateway, iface as u16)
                .await,
            &format!(
                "Creating route via {} for {} ({:?})",
                net.gateway, net_addr, iface
            ),
        )?;
    }

    Ok(endpoint)
}

async fn normalize_path<P: AsRef<Path>>(path: P) -> anyhow::Result<PathBuf> {
    Ok(fs::canonicalize(path)
        .await?
        .components()
        .into_iter()
        .filter(|c| matches!(c, Component::Prefix(_)))
        .collect::<PathBuf>())
}

fn convert_result<T>(
    result: io::Result<RemoteCommandResult<T>>,
    msg: &str,
) -> Result<T, server::ErrorResponse> {
    match result {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(exit_code)) => Err(server::ErrorResponse::msg(format!(
            "{} failed, exit code: {}",
            msg, exit_code
        ))),
        Err(error) => Err(server::ErrorResponse::msg(format!(
            "{} failed: {}",
            msg, error
        ))),
    }
}

async fn notification_into_status(
    notification: Notification,
    ga: Arc<Mutex<GuestAgent>>,
) -> server::ProcessStatus {
    match notification {
        Notification::OutputAvailable { id, fd } => {
            log::debug!("Process {} has output available on fd {}", id, fd);

            let output = {
                let result = {
                    let mut guard = ga.lock().await;
                    guard.query_output(id, fd as u8, 0, u64::MAX).await
                };
                match result {
                    Ok(Ok(vec)) => vec,
                    Ok(Err(e)) => {
                        log::error!("Remote error while querying output: {:?}", e);
                        Vec::new()
                    }
                    Err(e) => {
                        log::error!("Error querying output: {:?}", e);
                        Vec::new()
                    }
                }
            };
            let (stdout, stderr) = match fd {
                1 => (output, Vec::new()),
                _ => (Vec::new(), output),
            };

            server::ProcessStatus {
                pid: id,
                running: true,
                return_code: 0,
                stdout,
                stderr,
            }
        }
        Notification::ProcessDied { id, reason } => {
            log::debug!("Process {} died with {:?}", id, reason);

            // TODO: reason._type ?
            server::ProcessStatus {
                pid: id,
                running: false,
                return_code: reason.status as i32,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
    }
}

fn runtime_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_path_buf()
        .join(DIR_RUNTIME))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} {l} {t} - {m}{n}")))
        .build(r#"logs/ya-runtime-vm.log"#)?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(LevelFilter::Debug),
        )?;

    log4rs::init_config(config)?;
    log::debug!("Runtime VM starting - log level debug message ...");
    log::info!("Runtime VM starting - log level info message ...");
    ya_runtime_sdk::run::<Runtime>().await
}
