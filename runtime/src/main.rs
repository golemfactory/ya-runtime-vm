mod cpu;

use cpu::CpuInfo;
use futures::future::{FutureExt, TryFutureExt};
use futures::lock::Mutex;
use semver::{Version, VersionReq};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use structopt::{clap, StructOpt};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt},
    process, spawn,
};
use ya_runtime_api::{
    deploy::{DeployResult, StartMode},
    server::{self, RuntimeService},
};
use ya_runtime_vm::{
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

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct CmdArgs {
    #[structopt(short, long, required_ifs(
        &[
            ("command", "deploy"),
            ("command", "start")
        ])
    )]
    workdir: Option<PathBuf>,
    #[structopt(short, long, required_ifs(
        &[
            ("command", "deploy"),
            ("command", "start")
        ])
    )]
    task_package: Option<PathBuf>,
    #[structopt(long, default_value = "1")]
    cpu_cores: usize,
    #[structopt(long, default_value = "0.25")]
    mem_gib: f64,
    #[allow(unused)]
    #[structopt(long, default_value = "0.25")]
    storage_gib: f64,
    #[structopt(subcommand)]
    command: Commands,
}

#[derive(StructOpt)]
#[structopt(setting = clap::AppSettings::DeriveDisplayOrder)]
enum Commands {
    /// Perform a self-test
    Test {},
    /// Print the market offer template (JSON)
    OfferTemplate {},
    /// Deploy an image
    Deploy {},
    /// Start a deployed image
    Start {},
}

struct RuntimeData {
    runtime: Option<process::Child>,
    ga: Arc<Mutex<GuestAgent>>,
}

#[derive(Clone)]
#[non_exhaustive]
enum NetworkEndpoint {
    Socket(PathBuf),
}

struct Runtime {
    data: Mutex<RuntimeData>,
    network: NetworkEndpoint,
    deployment: Deployment,
}

async fn deploy(cmdargs: CmdArgs) -> anyhow::Result<()> {
    let workdir = normalize_path(&cmdargs.workdir.unwrap()).await?;
    let task_package = normalize_path(&cmdargs.task_package.unwrap()).await?;
    let package_file = fs::File::open(&task_package).await?;
    let deployment = Deployment::try_from_input(
        package_file,
        cmdargs.cpu_cores,
        (cmdargs.mem_gib * 1024.) as usize,
        task_package,
    )
    .await
    .expect("Error reading package metadata");

    fs::create_dir_all(&workdir).await?;
    for vol in &deployment.volumes {
        fs::create_dir(workdir.join(&vol.name)).await?;
    }

    write_file(
        workdir.join(FILE_DEPLOYMENT),
        serde_json::to_string(&deployment)?.as_bytes(),
    )
    .await?;

    let result = DeployResult {
        valid: Ok(Default::default()),
        vols: deployment.volumes,
        start_mode: StartMode::Blocking,
    };
    let result_json = format!("{}\n", serde_json::to_string(&result)?);

    let mut stdout = io::stdout();
    stdout.write_all(result_json.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

async fn write_file<P: AsRef<Path>>(path: P, bytes: &[u8]) -> anyhow::Result<()> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path.as_ref())
        .await?
        .write_all(bytes)
        .await?;
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
            log::trace!("Process {} has output available on fd {}", id, fd);
            let output = {
                let result = {
                    let mut guard = ga.lock().await;
                    guard.query_output(id, fd as u8, 0, u64::MAX).await
                };
                match result {
                    Ok(output) => match output {
                        Ok(vec) => vec,
                        Err(e) => {
                            log::error!("Remote error while querying output: {:?}", e);
                            Vec::new()
                        }
                    },
                    Err(e) => {
                        log::error!("Error querying output: {:?}", e);
                        Vec::new()
                    }
                }
            };

            let (stdout, stderr) = if fd == 1 {
                (output, Vec::new())
            } else {
                (Vec::new(), output)
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
            Ok(len) => {
                if len > 0 {
                    log::trace!(
                        "VM: {}",
                        String::from_utf8_lossy(&strip_ansi_escapes::strip(&buf).unwrap())
                            .trim_end()
                    );
                    buf.clear();
                } else {
                    break;
                }
            }
            Err(e) => {
                log::error!("VM output error: {}", e);
            }
        }
    }
}

impl Runtime {
    async fn started<'a, E: server::RuntimeEvent + Send + Sync + 'static, P: AsRef<Path>>(
        work_dir: P,
        deployment: Deployment,
        event_emitter: E,
    ) -> io::Result<Self> {
        let runtime_dir = runtime_dir()?;
        let uid = uuid::Uuid::new_v4().to_simple().to_string();
        let manager_sock = std::env::temp_dir().join(format!("{}.sock", uid));
        let net_sock = std::env::temp_dir().join(format!("{}_net.sock", uid));
        let emitter = Arc::new(event_emitter);

        let chardev = |name, path: &PathBuf| {
            format!("socket,path={},server,nowait,id={}", path.display(), name)
        };

        let mut cmd = process::Command::new(runtime_dir.join(FILE_RUNTIME));
        cmd.current_dir(&runtime_dir).args(&[
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
            chardev("manager_cdev", &manager_sock).as_str(),
            "-chardev",
            chardev("net_cdev", &net_sock).as_str(),
            "-device",
            "virtserialport,chardev=manager_cdev,name=manager_port",
            "-device",
            "virtserialport,chardev=net_cdev,name=net_port",
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
                path = work_dir.as_ref().join(&volume.name).to_string_lossy(),
            ));
        }

        let mut runtime = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        spawn(reader_to_log(runtime.stdout.take().unwrap()));

        let ga = GuestAgent::connected(manager_sock, 10, move |notification, ga| {
            let emitter = emitter.clone();
            async move {
                let status = notification_into_status(notification, ga).await;
                emitter.on_process_status(status);
            }
            .boxed()
        })
        .await?;

        {
            let mut ga_guard = ga.lock().await;
            for (idx, volume) in deployment.volumes.iter().enumerate() {
                ga_guard
                    .mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                    .await?
                    .expect("Mount failed");
            }
        }

        Ok(Runtime {
            data: Mutex::new(RuntimeData {
                runtime: Some(runtime),
                ga,
            }),
            network: NetworkEndpoint::Socket(net_sock),
            deployment,
        })
    }
}

impl server::RuntimeService for Runtime {
    fn hello(&self, version: &str) -> server::AsyncResponse<String> {
        let client_version = version.to_owned();
        let server_version = ya_runtime_api::PROTOCOL_VERSION;
        log::debug!("server version: {}", server_version);

        async move {
            let client = Version::parse(&client_version)?;
            let mut server = Version::parse(server_version)?;
            if server.major > 0 {
                server.minor = 0;
            }
            server.patch = 0;

            let required = VersionReq::parse(&format!("^{}", server))?;
            if !required.matches(&client) {
                return Err(anyhow::anyhow!(
                    "Client version {} is incompatible with {}",
                    client_version,
                    server_version
                ));
            }

            Ok::<_, anyhow::Error>(server_version.to_owned())
        }
        .map_err(|e| ya_runtime_api::server::ErrorResponse {
            message: format!("Version error: {}", e),
            ..Default::default()
        })
        .boxed_local()
    }

    fn run_process(
        &self,
        run: server::RunProcess,
    ) -> server::AsyncResponse<server::RunProcessResp> {
        log::debug!("got run process: {:?}", run);
        log::debug!("work dir: {:?}", self.deployment.config.working_dir);

        let (uid, gid) = self.deployment.user;
        let env = self.deployment.env();
        let cwd = self
            .deployment
            .config
            .working_dir
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.as_str())
            .unwrap_or_else(|| DEFAULT_CWD);

        async move {
            let data = self.data.lock().await;
            let result = data
                .ga
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
            convert_result(result, "Running process").map(|pid| server::RunProcessResp { pid })
        }
        .boxed_local()
    }

    fn kill_process(&self, kill: server::KillProcess) -> server::AsyncResponse<()> {
        log::debug!("got kill: {:?}", kill);
        async move {
            // TODO: send signal
            let data = self.data.lock().await;
            let result = data.ga.lock().await.kill(kill.pid).await;
            convert_result(result, &format!("Killing process {}", kill.pid))
        }
        .boxed_local()
    }

    fn create_network(
        &self,
        msg: server::CreateNetwork,
    ) -> server::AsyncResponse<'_, server::CreateNetworkResp> {
        log::debug!("got create network");
        let hosts = msg.hosts;
        let networks = msg.networks;

        async move {
            let network = self.network.clone();
            let data = self.data.lock().await;
            let mut ga = data.ga.lock().await;

            convert_result(ga.add_hosts(hosts.iter()).await, "Updating network hosts")?;

            for net in networks {
                convert_result(
                    ga.create_network(&net.addr, &net.mask, &net.gateway).await,
                    &format!("Creating network {} {}", net.addr, net.gateway),
                )?;
            }

            Ok(match network {
                NetworkEndpoint::Socket(path) => server::CreateNetworkResp {
                    endpoint: Some(server::proto::response::create_network::Endpoint::Socket(
                        path.display().to_string(),
                    )),
                },
            })
        }
        .boxed_local()
    }

    fn shutdown(&self) -> server::AsyncResponse<'_, ()> {
        log::debug!("got shutdown");
        async move {
            let mut data = self.data.lock().await;
            let runtime = data
                .runtime
                .take()
                .ok_or(server::ErrorResponse::msg("not running"))?;

            let result = {
                let mut ga = data.ga.lock().await;
                convert_result(ga.quit().await, "Sending quit")
            };
            if result.is_err() {
                return result;
            }

            if let Err(e) = runtime.await {
                return Err(server::ErrorResponse::msg(format!(
                    "Waiting for runtime shutdown failed: {}",
                    e
                )));
            }

            Ok(())
        }
        .boxed_local()
    }
}

fn offer_template() -> anyhow::Result<serde_json::Value> {
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

async fn self_test() -> anyhow::Result<()> {
    server::run_async(|e| async {
        let deployment = Deployment {
            cpu_cores: 1,
            mem_mib: 128,
            task_package: runtime_dir()
                .expect("runtime directory not found")
                .join(FILE_TEST_IMAGE)
                .canonicalize()
                .expect("test image not found"),
            ..Deployment::default()
        };

        println!("Starting runtime @ {}", deployment.task_package.display());
        let runtime = Runtime::started(std::env::temp_dir(), deployment, e)
            .await
            .expect("failed to start runtime");

        println!("Stopping runtime");
        runtime.shutdown().await.expect("failed to stop runtime");
        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        runtime
    })
    .await;
    Ok(())
}

fn runtime_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .join(DIR_RUNTIME))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cmdargs = CmdArgs::from_args();
    match &cmdargs.command {
        Commands::OfferTemplate { .. } => println!("{}", offer_template()?.to_string()),
        Commands::Test { .. } => self_test().await?,
        Commands::Deploy { .. } => deploy(cmdargs).await?,
        Commands::Start { .. } => {
            let work_dir = cmdargs.workdir.unwrap();
            server::run_async(|e| async {
                let deployment: Deployment = serde_json::from_reader(
                    std::fs::File::open(work_dir.join(FILE_DEPLOYMENT))
                        .expect("deployment file not found"),
                )
                .expect("failed to read the deployment file");
                Runtime::started(&work_dir, deployment, e)
                    .await
                    .expect("failed to start runtime")
            })
            .await
        }
    }
    Ok(())
}
