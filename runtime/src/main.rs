use futures::future::FutureExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use structopt::StructOpt;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    process, spawn,
    sync::Mutex,
};
use ya_runtime_api::{
    deploy::{ContainerVolume, DeployResult, StartMode},
    server,
};
use ya_runtime_vm::{
    guest_agent_comm::{GuestAgent, Notification, RemoteCommandResult},
    volume::get_volumes,
};

static ASSET_VMLINUZ: &'static [u8] = include_bytes!("../../init-container/vmlinuz-virt");
static ASSET_INITRAMFS: &'static [u8] = include_bytes!("../../init-container/initramfs.cpio.gz");

#[derive(StructOpt)]
enum Commands {
    Deploy {},
    Start {},
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct CmdArgs {
    #[structopt(short, long)]
    workdir: PathBuf,
    #[structopt(short, long)]
    task_package: PathBuf,
    #[structopt(subcommand)]
    command: Commands,
}

struct RuntimeData {
    qemu: Option<process::Child>,
    ga: GuestAgent,
}

struct Runtime(Mutex<RuntimeData>);

#[derive(Debug, Deserialize, Serialize)]
struct Deployment {
    workdir: PathBuf,
    task_package: PathBuf,
    vols: Vec<ContainerVolume>,
}

async fn deploy(cmdargs: &CmdArgs) -> anyhow::Result<()> {
    let workdir = &cmdargs.workdir;
    let package_file = fs::File::open(&cmdargs.task_package).await?;
    let vols = match get_volumes(package_file).await {
        Ok(volumes) => volumes,
        Err(err) => {
            log::warn!("failed to get volumes: {}", err);
            Vec::new()
        }
    };

    fs::create_dir_all(&workdir).await?;
    for vol in &vols {
        fs::create_dir_all(workdir.join(&vol.name)).await?;
    }
    write_file(workdir.join("vmlinuz-virt"), ASSET_VMLINUZ).await?;
    write_file(workdir.join("initramfs.cpio.gz"), ASSET_INITRAMFS).await?;

    let result = DeployResult {
        valid: Ok(Default::default()),
        vols,
        start_mode: StartMode::Blocking,
    };
    let result_json = format!("{}\n", serde_json::to_string(&result)?);

    let deployment = Deployment {
        workdir: cmdargs.workdir.clone(),
        task_package: cmdargs.task_package.clone(),
        vols: result.vols,
    };
    let deployment_json = serde_json::to_string_pretty(&deployment)?;
    write_file(workdir.join("deployment.json"), deployment_json.as_bytes()).await?;

    let mut stdout = io::stdout();
    stdout.write_all(result_json.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

async fn deployment(cmdargs: &CmdArgs) -> anyhow::Result<Deployment> {
    let mut json = String::new();
    fs::OpenOptions::new()
        .read(true)
        .open(cmdargs.workdir.join("deployment.json"))
        .await?
        .read_to_string(&mut json)
        .await?;
    Ok(serde_json::from_str(&json)?)
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

fn notification_into_status(notification: Notification) -> server::ProcessStatus {
    match notification {
        Notification::OutputAvailable { id, fd } => {
            log::debug!("Process {} has output available on fd {}", id, fd);
            server::ProcessStatus {
                pid: id,
                running: true,
                return_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
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
                    log::debug!(
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
    async fn started<'a, E: server::RuntimeEvent + Send + 'static>(
        deployment: Deployment,
        event_emitter: E,
    ) -> io::Result<Self> {
        let mut cmd = process::Command::new("qemu-system-x86_64");
        cmd.args(&[
            "-m",
            "256m",
            "-nographic",
            "-vga",
            "none",
            "-kernel",
            "./vmlinuz-virt",
            "-initrd",
            "./initramfs.cpio.gz",
            "-no-reboot",
            "-net",
            "none",
            "-smp",
            "1",
            "-append",
            "console=ttyS0 panic=1",
            "-device",
            "virtio-serial",
            "-chardev",
            "socket,path=./manager.sock,server,nowait,id=manager_cdev",
            "-device",
            "virtserialport,chardev=manager_cdev,name=manager_port",
            "-drive",
        ]);
        cmd.arg(format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            deployment.task_package.display()
        ));

        for (idx, volume) in deployment.vols.iter().enumerate() {
            cmd.arg("-virtfs");
            cmd.arg(format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = format!("mnt{}", idx),
                path = deployment.workdir.join(&volume.name).to_string_lossy(),
            ));
        }

        let mut qemu = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        spawn(reader_to_log(qemu.stdout.take().unwrap()));

        let mut ga = GuestAgent::connected("./manager.sock", 10, move |notification| {
            event_emitter.on_process_status(notification_into_status(notification));
        })
        .await?;

        for (idx, volume) in deployment.vols.iter().enumerate() {
            ga.mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                .await?
                .expect("Mount failed");
        }

        Ok(Self(Mutex::new(RuntimeData {
            qemu: Some(qemu),
            ga,
        })))
    }
}

impl server::RuntimeService for Runtime {
    fn hello(&self, version: &str) -> server::AsyncResponse<String> {
        log::info!("server version: {}", version);
        async { Ok("0.0.0-demo".to_owned()) }.boxed_local()
    }

    fn run_process(
        &self,
        run: server::RunProcess,
    ) -> server::AsyncResponse<server::RunProcessResp> {
        log::debug!("got run process: {:?}", run);
        async move {
            let result = self
                .0
                .lock()
                .await
                .ga
                .run_process(
                    &run.bin,
                    run.args
                        .iter()
                        .map(|s| s.as_ref())
                        .collect::<Vec<&str>>()
                        .as_slice(),
                    /*maybe_env*/ None, // TODO
                    /*uid*/ 0, // TODO
                    /*gid*/ 0, // TODO
                    /*fds*/ &[None, None, None], // TODO
                    /*maybe_cwd*/ None, // TODO
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
            let result = self.0.lock().await.ga.kill(kill.pid).await;
            convert_result(result, &format!("Killing process {}", kill.pid))
        }
        .boxed_local()
    }

    fn shutdown(&self) -> server::AsyncResponse<'_, ()> {
        log::debug!("got shutdown");
        async move {
            let mut data = self.0.lock().await;
            let qemu = data
                .qemu
                .take()
                .ok_or(server::ErrorResponse::msg("not running"))?;

            {
                let result = data.ga.quit().await;
                let result = convert_result(result, "Sending quit");
                if result.is_err() {
                    return result;
                }
            }

            if let Err(e) = qemu.await {
                return Err(server::ErrorResponse::msg(format!(
                    "Waiting for qemu shutdown failed: {}",
                    e
                )));
            }

            Ok(())
        }
        .boxed_local()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cmdargs = CmdArgs::from_args();
    match &cmdargs.command {
        Commands::Deploy { .. } => deploy(&cmdargs).await?,
        Commands::Start { .. } => {
            server::run_async(|e| async {
                let deployment = deployment(&cmdargs)
                    .await
                    .expect("failed to read the deployment file");
                Runtime::started(deployment, e)
                    .await
                    .expect("failed to start runtime")
            })
            .await
        }
    }
    Ok(())
}
