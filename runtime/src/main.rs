use futures::future::FutureExt;
use std::{io, path::PathBuf, process::Stdio};
use structopt::StructOpt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process, spawn,
    sync::Mutex,
};
use ya_runtime_api::{
    deploy::{DeployResult, StartMode},
    server,
};

use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RemoteCommandResult};

#[derive(StructOpt)]
enum Commands {
    Deploy {},
    Start {},
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct CmdArgs {
    #[structopt(short, long)]
    workdir: PathBuf, // TODO: use it
    #[structopt(short, long)]
    task_package: PathBuf, // TODO: use it
    #[structopt(subcommand)]
    command: Commands,
}

async fn deploy() -> std::io::Result<()> {
    let res = DeployResult {
        valid: Ok(Default::default()),
        vols: Default::default(),
        start_mode: StartMode::Blocking,
    };

    let mut stdout = tokio::io::stdout();
    let json = format!("{}\n", serde_json::to_string(&res)?);
    stdout.write_all(json.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

struct RuntimeData {
    qemu: Option<process::Child>,
    ga: GuestAgent,
}

struct Runtime(Mutex<RuntimeData>);

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

async fn reader_to_log<T: tokio::io::AsyncRead + Unpin>(reader: T) {
    let mut reader = tokio::io::BufReader::new(reader);
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
    async fn started<E: server::RuntimeEvent + Send + 'static>(
        event_emitter: E,
    ) -> std::io::Result<Self> {
        let mut qemu = process::Command::new("qemu-system-x86_64")
            .args(&[
                "-m",
                "256m",
                "-nographic",
                "-vga",
                "none",
                "-kernel",
                "init-container/vmlinuz-virt",
                "-initrd",
                "init-container/initramfs.cpio.gz",
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
                "file=./squashfs_drive,cache=none,readonly=on,format=raw,if=virtio",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        spawn(reader_to_log(qemu.stdout.take().unwrap()));
        let ga = GuestAgent::connected("./manager.sock", 10, move |notification| {
            event_emitter.on_process_status(notification_into_status(notification));
        })
        .await?;
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
            let qemu = data.qemu.take().ok_or(server::ErrorResponse::msg("not running"))?;

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
    match cmdargs.command {
        Commands::Deploy { .. } => deploy().await?,
        Commands::Start { .. } => {
            server::run_async(|e| async {
                Runtime::started(e).await.expect("failed to start runtime")
            })
            .await
        }
    }
    Ok(())
}
