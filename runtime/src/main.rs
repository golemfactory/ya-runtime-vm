use anyhow::anyhow;
use futures::future::FutureExt;
use futures::lock::Mutex;
use futures::TryFutureExt;
use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt},
    process,
    process::Child,
    spawn,
};
use ya_runtime_sdk::{
    runtime_api::{
        deploy::{DeployResult, StartMode},
        server,
    },
    serialize,
    server::Server,
    Context, EmptyResponse, EndpointResponse, EventEmitter, OutputResponse, ProcessId,
    ProcessIdResponse, RuntimeMode,
};
use ya_runtime_vm::demux_socket_comm::{
    start_demux_communication, stop_demux_communication, DemuxSocketHandle,
};
use ya_runtime_vm::{
    cpu::CpuInfo,
    deploy::Deployment,
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType, RemoteCommandResult},
};

const DIR_RUNTIME: &str = "runtime";
#[cfg(unix)]
const FILE_RUNTIME: &'static str = "vmrt";
#[cfg(windows)]
const FILE_RUNTIME: &str = "qemu-system-x86_64.exe";

#[cfg(windows)]
const FILE_SERVER_RUNTIME: &str = "ya-vm-file-server.exe";

#[cfg(unix)]
const FILE_SERVER_RUNTIME: &str = "ya-vm-file-server";

const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";
//const FILE_TEST_IMAGE: &str = "self-test.gvmi";
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
}

#[derive(ya_runtime_sdk::RuntimeDef, Default)]
#[cli(Cli)]
struct Runtime {
    data: Arc<Mutex<RuntimeData>>,
}

#[derive(Clone)]
#[non_exhaustive]
enum NetworkEndpoint {
    #[cfg(unix)]
    Socket(PathBuf),
    #[cfg(windows)]
    Socket(String),
}

#[derive(Default)]
struct RuntimeData {
    runtime: Option<process::Child>,
    runtime_p9: Vec<process::Child>,
    p9_communication_handle: Option<DemuxSocketHandle>,
    network: Option<NetworkEndpoint>,
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
        log::info!("ya_runtime_sdk::Runtime - start");

        let emitter = ctx
            .emitter
            .clone()
            .expect("Service is not running in Server mode");
        let workdir = ctx.cli.workdir.clone().expect("Workdir not provided");
        let data = self.data.clone();

        async move {
            let deployment_file = std::fs::File::open(workdir.join(FILE_DEPLOYMENT))
                .expect("Unable to open the deployment file");
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

fn spawn_9p_server(mount_point: String, log_path: String, port: i32) -> anyhow::Result<Child> {
    let runtime_dir = runtime_dir().expect("Unable to resolve current directory");

    let exe_path = runtime_dir.join(FILE_SERVER_RUNTIME);
    let mut cmd = process::Command::new(&exe_path);
    cmd.env("RUST_LOG", "error");

    log::debug!(
        "Running {}. Mount point: {}, port: {}",
        exe_path.to_str().unwrap_or(""),
        mount_point,
        port
    );

    let local_address = std::format!("127.0.0.1:{}", port);
    let args = &[
        "--mount-point",
        mount_point.as_str(),
        "--log-path",
        log_path.as_str(),
        "--network-address",
        local_address.as_str(),
        "--network-protocol",
        "tcp",
    ];

    cmd.current_dir(&runtime_dir).args(args);

    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true);

    cmd.spawn().map_err(|err| {
        log::error!("Error when spawning p9 server {}", err);
        anyhow::Error::from(err)
    })
}

async fn start(
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
    emitter: EventEmitter,
) -> anyhow::Result<Option<serialize::json::Value>> {
    let runtime_dir = runtime_dir().expect("Unable to resolve current directory");

    let manager_sock;
    let net_sock;
    let chardev;

    #[cfg(unix)]
    {
        let uid = uuid::Uuid::new_v4().to_simple().to_string();
        manager_sock = std::env::temp_dir().join(format!("{}.sock", uid));
        net_sock = std::env::temp_dir().join(format!("{}_net.sock", uid));

        chardev = |n, p: &PathBuf| format!("socket,path={},server,nowait,id={}", p.display(), n);
    }

    #[cfg(windows)]
    {
        manager_sock = "127.0.0.1:9003";
        net_sock = "127.0.0.1:9004";

        chardev = |n, p: &str| {
            let addr: SocketAddr = p.parse().unwrap();
            format!(
                "socket,host={},port={},server,nowait,id={}",
                addr.ip(),
                addr.port(),
                n
            )
        };
    }

    let p9_sock = "127.0.0.1:9005";

    let mut data = runtime_data.lock().await;
    let deployment = data.deployment().expect("Missing deployment data");

    let chardev_wait = |n, p: &str| {
        let addr: SocketAddr = p.parse().unwrap();
        format!(
            "socket,host={},port={},server,id={}",
            addr.ip(),
            addr.port(),
            n
        )
    };

    let mut cmd = process::Command::new(runtime_dir.join(FILE_RUNTIME));
    cmd.current_dir(&runtime_dir);

    let tmp0 = format!("{}M", deployment.mem_mib);
    let tmp1 = format!(
        "file={},cache=unsafe,readonly=on,format=raw,if=virtio",
        deployment.task_package.display()
    );
    let chardev1 = chardev("manager_cdev", &manager_sock);
    let chardev2 = chardev("net_cdev", &net_sock);
    let chardev3 = chardev_wait("p9_cdev", &p9_sock);

    let cpu_string = deployment.cpu_cores.to_string();

    let acceleration = if cfg!(windows) { "whpx" } else { "kvm" };

    let args = &[
        "-m",
        tmp0.as_str(),
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        FILE_VMLINUZ,
        "-initrd",
        FILE_INITRAMFS,
        "-net",
        "none",
        /*   "-enable-kvm",*/
        /*  "-cpu",
          "host",*/
        "-smp",
        cpu_string.as_str(),
        "-append",
        "\"console=ttyS0 panic=1\"",
        "-device",
        "virtio-serial",
        /* "-device",
        "virtio-rng-pci",*/
        "-chardev",
        chardev1.as_str(),
        "-chardev",
        chardev2.as_str(),
        "-chardev",
        chardev3.as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-device",
        "virtserialport,chardev=net_cdev,name=net_port",
        "-device",
        "virtserialport,chardev=p9_cdev,name=p9_port",
        "-drive",
        tmp1.as_str(),
        "-no-reboot",
        "-accel",
        acceleration,
        "-nodefaults",
        "--serial",
        "stdio",
    ];

    cmd.args(args);
    /*
        for (idx, volume) in deployment.volumes.iter().enumerate() {
            cmd.arg("-virtfs");
            cmd.arg(format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = format!("mnt{}", idx),
                path = work_dir.join(&volume.name).to_string_lossy(),
            ));
        }
    */

    log::debug!(
        "Running VM in runtime directory: {}\nCommand: {} {}\n",
        runtime_dir.to_str().unwrap_or("???"),
        FILE_RUNTIME,
        args.join(" ")
    );

    let mut runtime = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = runtime.stdout.take().unwrap();
    let stderr = runtime.stderr.take().unwrap();
    spawn(reader_to_log(stdout));
    spawn(reader_to_log_error(stderr));

    log::debug!("Spawn p9 servers...");

    let mut runtime_p9s: Vec<process::Child> = vec![];

    {
        for (idx, volume) in deployment.volumes.iter().enumerate() {
            let mount_point_host = work_dir
                .join(&volume.name)
                .to_str()
                .ok_or(anyhow!("cannot resolve 9p mount point"))?
                .to_string();
            let runtime_p9 = spawn_9p_server(
                mount_point_host,
                work_dir
                    .join("logs")
                    .join(std::format!("ya-vm-file-server_{}.log", idx))
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
                9101 + idx as i32,
            )?;
            runtime_p9s.push(runtime_p9);
        }
    }
    sleep(Duration::from_millis(1000)).await;

    log::debug!("Connect to p9 servers...");

    let vmp9stream = TcpStream::connect(std::format!("127.0.0.1:{}", 9005)).await?;

    let mut p9streams: Vec<tokio::net::TcpStream> = vec![];
    {
        for (idx, _volume) in deployment.volumes.iter().enumerate() {
            let stream =
                TcpStream::connect(std::format!("127.0.0.1:{}", 9101 + idx as i32)).await?;
            p9streams.push(stream);
        }
    }

    let demux_socket_handle = start_demux_communication(vmp9stream, p9streams)?;

    #[cfg(unix)]
    let path = manager_sock.to_str().unwrap();
    #[cfg(windows)]
    let path = manager_sock;

    let ga = GuestAgent::connected(
        path,
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
            ga.mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                .await?
                .expect("Mount failed");
        }
    }

    data.runtime_p9 = runtime_p9s; //prevent dropping
    data.p9_communication_handle.replace(demux_socket_handle); //prevent dropping
    data.runtime.replace(runtime);
    data.network
        .replace(NetworkEndpoint::Socket(net_sock.to_owned()));
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
    log::debug!("Finished command");

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

    if let Some(dsh) = data.p9_communication_handle.take() {
        stop_demux_communication(dsh).await;
    }

    let mut runtime = data.runtime().unwrap();

    {
        let mutex = data.ga().unwrap();
        let mut ga = mutex.lock().await;
        convert_result(ga.quit().await, "Sending quit")?;
    }

    runtime.wait().await.expect("Waiting for runtime stop failed");
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
    /*server::run_async(|e| async {
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
    .await;*/
    Ok(())
}

async fn join_network(
    runtime_data: Arc<Mutex<RuntimeData>>,
    join: server::CreateNetwork,
) -> Result<String, server::ErrorResponse> {
    log::error!("join_network");
    let hosts = join.hosts;
    let networks = join.networks;
    let data = runtime_data.lock().await;

    let endpoint = data
        .network
        .as_ref()
        .map(|network| match network {
            #[cfg(windows)]
            NetworkEndpoint::Socket(path) => path.clone(),
            #[cfg(unix)]
            NetworkEndpoint::Socket(path) => path
                .clone()
                .into_os_string()
                .into_string()
                .expect("Invalid endpoint path"),
        })
        .expect("No network endpoint");

    let mutex = data.ga().unwrap();
    let mut ga = mutex.lock().await;
    convert_result(ga.add_hosts(hosts.iter()).await, "Updating network hosts")?;

    for net in networks {
        convert_result(
            ga.add_address(&net.if_addr, &net.mask).await,
            &format!("Adding interface address {} {}", net.if_addr, net.gateway),
        )?;
        convert_result(
            ga.create_network(&net.addr, &net.mask, &net.gateway).await,
            &format!("Creating network {} {}", net.addr, net.gateway),
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
            Ok(0) => {
                log::warn!("VM: reader.read_until returned 0")
            }
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                log::debug!("VM: {}", String::from_utf8_lossy(&bytes).trim_end());
                buf.clear();
            }
            Err(e) => log::error!("VM output error: {}", e),
        }
    }
}

async fn reader_to_log_error<T: io::AsyncRead + Unpin>(reader: T) {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => {
                log::warn!("VM ERROR: reader.read_until returned 0")
            }
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                log::debug!(
                    "VM ERROR STREAM: {}",
                    String::from_utf8_lossy(&bytes).trim_end()
                );
                buf.clear();
            }
            Err(e) => log::error!("VM stderr error: {}", e),
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
