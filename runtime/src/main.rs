use futures::future::FutureExt;
use futures::lock::Mutex;
use futures::TryFutureExt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt},
    process, spawn,
};

use ya_runtime_sdk::{
    runner::exe_dir,
    runtime_api::{
        deploy::{DeployResult, StartMode},
        server,
    },
    serialize, Context, EmptyResponse, EventEmitter, OutputResponse, ProcessId, ProcessIdResponse,
    RuntimeMode, Server,
};
use ya_runtime_vm::{
    cpu::CpuInfo,
    deploy::Deployment,
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType, RemoteCommandResult},
};

const DIR_RUNTIME: &'static str = "runtime";
const FILE_RUNTIME: &'static str = "vmrt";
const FILE_VMLINUZ: &'static str = "vmlinuz-virt";
const FILE_INITRAMFS: &'static str = "initramfs.cpio.gz";
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
}

#[derive(ya_runtime_sdk::RuntimeDef, Default)]
#[cli(Cli)]
struct Runtime {
    data: Arc<Mutex<RuntimeData>>,
}

#[derive(Default)]
struct RuntimeData {
    runtime: Option<process::Child>,
    deployment: Option<Deployment>,
    ga: Option<Arc<Mutex<GuestAgent>>>,
}

impl RuntimeData {
    fn runtime(&mut self) -> anyhow::Result<process::Child> {
        self.runtime
            .take()
            .ok_or_else(|| anyhow::anyhow!("Runtime process not available"))
    }

    fn deployment(&self) -> anyhow::Result<&Deployment> {
        self.deployment
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Runtime not deployed"))
    }

    fn ga(&self) -> anyhow::Result<Arc<Mutex<GuestAgent>>> {
        self.ga
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Runtime not started"))
    }
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
            .expect("Service is not running in Server mode");
        let workdir = ctx.cli.workdir.clone().expect("Workdir not provided");
        let data = self.data.clone();

        async move {
            let deployment_file = std::fs::File::open(workdir.join(FILE_DEPLOYMENT))
                .expect("Deployment file not found");
            let deployment: Deployment = serialize::json::from_reader(deployment_file)
                .expect("Failed to read the deployment file");

            {
                let mut data = data.lock().await;
                data.deployment.replace(deployment);
            }
            start(workdir, data, emitter).await
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
}

async fn deploy(workdir: PathBuf, cli: Cli) -> anyhow::Result<serialize::json::Value> {
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

    Ok(serialize::json::to_value(DeployResult {
        valid: Ok(Default::default()),
        vols: deployment.volumes,
        start_mode: StartMode::Blocking,
    })?)
}

async fn start(
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
    emitter: EventEmitter,
) -> anyhow::Result<serialize::json::Value> {
    let socket_name = uuid::Uuid::new_v4().to_simple().to_string();
    let socket_path = std::env::temp_dir().join(format!("{}.sock", socket_name));
    let runtime_dir = runtime_dir().expect("Unable to resolve current directory");

    let mut data = runtime_data.lock().await;
    let deployment = data.deployment().unwrap();

    let mut cmd = process::Command::new(runtime_dir.join(FILE_RUNTIME));
    cmd.current_dir(&runtime_dir);
    cmd.args(&[
        "-m",
        format!("{}M", deployment.mem_mib).as_str(),
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        FILE_VMLINUZ,
        "-initrd",
        FILE_INITRAMFS,
        "-net",
        "none",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        deployment.cpu_cores.to_string().as_str(),
        "-append",
        "console=ttyS0 panic=1",
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        format!(
            "socket,path={},server,nowait,id=manager_cdev",
            socket_path.display()
        )
        .as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-drive",
        format!(
            "file={},cache=unsafe,readonly=on,format=raw,if=virtio",
            deployment.task_package.display()
        )
        .as_str(),
        "-no-reboot",
    ]);

    for (idx, volume) in deployment.volumes.iter().enumerate() {
        cmd.arg("-virtfs");
        cmd.arg(format!(
            "local,id={tag},path={path},security_model=none,mount_tag={tag}",
            tag = format!("mnt{}", idx),
            path = work_dir.join(&volume.name).to_string_lossy(),
        ));
    }

    let mut runtime = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = runtime.stdout.take().unwrap();
    spawn(reader_to_log(stdout));

    let ga = GuestAgent::connected(socket_path, 10, move |notification, ga| {
        let emitter = emitter.clone();
        async move {
            let status = notification_into_status(notification, ga).await;
            emitter.emit(status).await;
        }
        .boxed()
    })
    .await?;

    {
        let mut ga = ga.lock().await;
        for (idx, volume) in deployment.volumes.iter().enumerate() {
            ga.mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                .await?
                .expect("Mount failed");
        }
    }

    data.runtime.replace(runtime);
    data.ga.replace(ga);

    Ok(().into())
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
    let runtime = data.runtime().unwrap();

    {
        let mutex = data.ga().unwrap();
        let mut ga = mutex.lock().await;
        convert_result(ga.quit().await, "Sending quit")?;
    }

    runtime.await.expect("Waiting for runtime stop failed");
    Ok(())
}

fn offer() -> anyhow::Result<serde_json::Value> {
    let cpu = CpuInfo::try_new()?;
    let model = format!(
        "Stepping {} Family {} Model {}",
        cpu.model.stepping, cpu.model.family, cpu.model.model
    );

    Ok(serde_json::json!({
        "properties": {
            "golem.inf.cpu.vendor": cpu.model.vendor,
            "golem.inf.cpu.model": model,
            "golem.inf.cpu.capabilities": cpu.capabilities,
        },
        "constraints": ""
    }))
}

async fn test() -> anyhow::Result<()> {
    server::run_async(|e| async {
        let ctx = Context::try_new().expect("Failed to initialize context");
        let task_package = runtime_dir()
            .expect("Runtime directory not found")
            .join(FILE_TEST_IMAGE)
            .canonicalize()
            .expect("Test image not found");

        println!("Task package: {}", task_package.display());
        let runtime_data = RuntimeData {
            runtime: None,
            ga: None,
            deployment: Some(Deployment {
                cpu_cores: 1,
                mem_mib: 128,
                task_package,
                ..Deployment::default()
            }),
        };
        let runtime = Runtime {
            data: Arc::new(Mutex::new(runtime_data)),
        };

        println!("Starting runtime");
        start(
            std::env::temp_dir(),
            runtime.data.clone(),
            EventEmitter::new(Box::new(e)),
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

async fn reader_to_log<T: io::AsyncRead + Unpin>(reader: T) {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                log::debug!("VM: {}", String::from_utf8_lossy(&bytes).trim_end());
                buf.clear();
            }
            Err(e) => log::error!("VM output error: {}", e),
        }
    }
}

fn runtime_dir() -> io::Result<PathBuf> {
    Ok(exe_dir()?.join(DIR_RUNTIME))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    ya_runtime_sdk::run::<Runtime>().await
}
