use std::convert::TryFrom;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use bollard_stubs::models::ContainerConfig;
use futures::future::FutureExt;
use futures::lock::Mutex;
use futures::TryFutureExt;
use serde::__private::de;
use serde_json::Value;
use structopt::StructOpt;
use tokio::time::sleep;
use tokio::{
    fs,
    io::{self, AsyncWriteExt},
};
use url::Url;

use ya_runtime_sdk::runtime_api::deploy::{ContainerEndpoint, ContainerVolume};
use ya_runtime_sdk::runtime_api::server::proto::output::Type;
use ya_runtime_sdk::runtime_api::server::proto::Output;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{
    runtime_api::{
        deploy::{DeployResult, StartMode},
        server,
    },
    serialize,
    server::Server,
    Context, EmptyResponse, EndpointResponse, Error, ErrorExt, EventEmitter, OutputResponse,
    ProcessId, ProcessIdResponse, RuntimeMode,
};
use ya_runtime_sdk::{ProcessStatus, RuntimeStatus};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification};
use ya_runtime_vm::{
    cpu::CpuInfo,
    deploy::Deployment,
    guest_agent_comm::{RedirectFdType, RemoteCommandResult},
    vmrt::{runtime_dir, start_vmrt, RuntimeData},
};

const FILE_TEST_IMAGE: &'static str = "self-test.gvmi";
const FILE_DEPLOYMENT: &'static str = "deployment.json";
const DEFAULT_CWD: &'static str = "/";

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
        let emitter = ctx
            .emitter
            .clone()
            .expect("Service not running in Server mode");

        let workdir = ctx.cli.workdir.clone().expect("Workdir not provided");

        let deployment_file = std::fs::File::open(workdir.join(FILE_DEPLOYMENT))
            .expect("Unable to open the deployment file");
        let deployment: Deployment = serialize::json::from_reader(deployment_file)
            .expect("Failed to read the deployment file");

        log::debug!("Deployment: {deployment:?}");

        let vpn_endpoint = ctx.cli.runtime.vpn_endpoint.clone();
        let inet_endpoint = ctx.cli.runtime.inet_endpoint.clone();

        log::info!("VPN endpoint: {vpn_endpoint:?}");
        log::info!("INET endpoint: {inet_endpoint:?}");

        let cmd_args = ctx.cli.command.args();
        log::debug!("Start command parameters: {cmd_args:?}");

        let entrypoint = if cmd_args.iter().any(|arg| *arg == "start-entrypoint") {
            match extract_entrypoint(&deployment.config) {
                None => return async {
                            Err(Error::from_string("'start_entrypoint' flag is set but the container does not define an entrypoint!"))
                        }.boxed_local(),
                entrypoint => entrypoint,
            }
        } else {
            None
        };

        let data = self.data.clone();
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

                data.deployment.replace(deployment);
            }

            let start_response = start(workdir, data.clone(), emitter).await?;

            Ok(match entrypoint {
                Some(entrypoint) => Some(run_entrypoint(start_response, entrypoint, data).await?),
                None => start_response,
            })
        }
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

    fn test<'a>(&mut self, ctx: &mut Context<Self>) -> EmptyResponse<'a> {
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
    let work_dir = normalize_path(&workdir).await?;
    let package_path = normalize_path(&cli.task_package.unwrap()).await?;
    let package_file = fs::File::open(&package_path).await?;

    let deployment = Deployment::try_from_input(
        package_file,
        cli.cpu_cores,
        (cli.mem_gib * 1024.) as usize,
        package_path,
    )
    .await
    .or_err("Error reading package metadata")?;

    for vol in &deployment.volumes {
        fs::create_dir_all(work_dir.join(&vol.name)).await?;
    }

    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(work_dir.join(FILE_DEPLOYMENT))
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
    start_vmrt(work_dir, runtime_data, emitter).await
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

    Ok(convert_result(result, "Running process")?)
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
    let mut runtime = data.runtime().unwrap();

    {
        let mutex = data.ga().unwrap();
        let mut ga = mutex.lock().await;
        convert_result(ga.quit().await, "Sending quit")?;
    }

    runtime
        .wait()
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
            "golem.runtime.capabilities": ["inet", "vpn", "manifest-support", "start-entrypoint"]
        },
        "constraints": ""
    })))
}

async fn test() -> anyhow::Result<()> {
    let work_dir = std::env::temp_dir();

    let package_path = runtime_dir()
        .expect("Runtime directory not found")
        .join(FILE_TEST_IMAGE)
        .canonicalize()
        .expect("Test image not found");

    log::info!("Task package: {}", package_path.display());

    let package_file = fs::File::open(package_path.clone())
        .await
        .or_err("Error reading package file")?;
    let deployment = Deployment::try_from_input(package_file, 1, 125, package_path.clone())
        .await
        .or_err("Error reading package metadata")?;

    for vol in &deployment.volumes {
        let vol_dir = work_dir.join(&vol.name);
        log::debug!("Creating volume dir: {vol_dir:?} for path {}", vol.path);
        fs::create_dir_all(vol_dir)
            .await
            .or_err("Failed to create volume dir")?;
    }
    let runtime_data = RuntimeData {
        deployment: Some(deployment),
        ..Default::default()
    };
    let runtime = Runtime {
        data: Arc::new(Mutex::new(runtime_data)),
    };

    let mut status: Option<ProcessStatus> = None;
    server::run_async(|e| async {
        let ctx = Context::try_new().expect("Failed to initialize context");

        log::info!("Starting");
        let (status_sender, mut status_receiver) = mpsc::channel();
        let emitter = EventEmitter::spawn(ProcessOutputHandler {
            handler: Box::new(e),
            status_sender,
        });
        let start_response = start(work_dir.clone(), runtime.data.clone(), emitter.clone())
            .await
            .expect("Failed to start runtime");
        log::info!("Response {:?}", start_response);

        let run: ya_runtime_sdk::RunProcess = server::RunProcess {
            bin: "/bin/ya-self-test".into(),
            args: vec!["ya-self-test".into()],
            work_dir: "/data".into(),
            ..Default::default()
        };

        log::debug!("Starting. Runtime: {:?}", runtime.data);
        log::debug!("Run: {run:?}");

        let pid = run_command(runtime.data.clone(), run)
            .await
            .expect("Can run command");

        let (final_status_sender, final_status_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let status = async {
                listen_process_status(&mut status_receiver, pid).expect("Can listen on process")
            }
            .await;
            final_status_sender.send(status)
        });
        status = Some(final_status_receiver.await.expect("Got status"));
        log::info!("Process finished: {status:?}");

        log::info!("Stopping runtime");
        stop(runtime.data.clone())
            .await
            .expect("Failed to stop runtime");

        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        let status = status.expect("Failed to run self test process");
        if status.return_code == 0 {
            let response: Value = serde_json::from_slice(&status.stdout)
                .expect("Cannot serialize self test stdout to json.");
            println!("{}", response.to_string())
        } else {
            let err_message = std::str::from_utf8(&status.stderr)
                .expect("Can read stderr as string.")
                .to_string();
            eprintln!("self test process failed: {err_message}");
        }

        Server::new(runtime, ctx)
    })
    .await;
    Ok(())
}
struct ProcessOutputHandler {
    status_sender: mpsc::Sender<ProcessStatus>,
    handler: Box<dyn RuntimeHandler + 'static>,
}

impl RuntimeHandler for ProcessOutputHandler {
    fn on_process_status<'a>(&self, status: ProcessStatus) -> futures::future::BoxFuture<'a, ()> {
        if let Err(err) = self.status_sender.send(status.clone()) {
            log::error!("Failed to send process status {err}");
        }
        self.handler.on_process_status(status)
    }

    fn on_runtime_status<'a>(&self, status: RuntimeStatus) -> futures::future::BoxFuture<'a, ()> {
        self.handler.on_runtime_status(status)
    }
}

fn listen_process_status(
    status_receiver: &mut mpsc::Receiver<ProcessStatus>,
    pid: u64,
) -> anyhow::Result<ProcessStatus> {
    log::debug!("Start listening on process: {pid}");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut return_code = 0;
    while let Ok(status) = status_receiver.recv() {
        if status.pid != pid {
            continue;
        }
        stdout.append(&mut status.stdout.clone());
        stderr.append(&mut status.stderr.clone());
        return_code = status.return_code;
        if !status.running {
            break;
        }
    }
    let running = false;
    Ok(ProcessStatus {
        pid,
        running,
        return_code,
        stdout,
        stderr,
    })
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
        .filter(|c| match c {
            Component::Prefix(_) => false,
            _ => true,
        })
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

fn extract_entrypoint(config: &ContainerConfig) -> Option<Vec<String>> {
    let entrypoint = config
        .entrypoint
        .clone()
        .unwrap_or_default()
        .into_iter()
        .chain(config.cmd.clone().unwrap_or_default())
        .collect::<Vec<_>>();
    if entrypoint.is_empty() {
        None
    } else {
        Some(entrypoint)
    }
}

async fn run_entrypoint(
    start_response: Option<serde_json::Value>,
    entrypoint: Vec<String>,
    data: Arc<Mutex<RuntimeData>>,
) -> Result<serde_json::Value, server::ErrorResponse> {
    log::debug!("Starting container entrypoint: {entrypoint:?}");
    let mut args = entrypoint.clone();
    let bin_name = Path::new(&args[0])
        .file_name()
        .ok_or_else(|| Error::from_string("Invalid binary name for container entrypoint"))?
        .to_string_lossy()
        .to_string();
    let bin = std::mem::replace(&mut args[0], bin_name);

    run_command(
        data,
        server::RunProcess {
            bin,
            args,
            ..Default::default()
        },
    )
    .await
    .map(|pid| {
        use serde_json::json;

        json!({
            "start": start_response.unwrap_or(json!(null)),
            "entrypoint": json!({ "pid": json!(pid), "command": json!(entrypoint)}),
        })
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ya_runtime_sdk::run::<Runtime>().await
}
