use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    process::Child,
    sync::{self, Mutex},
};
use ya_runtime_vm::{
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType},
    vm::{VMBuilder, VM},
};

pub struct Notifications {
    pub process_died: Mutex<HashMap<u64, Arc<sync::Notify>>>,
    pub output_available: Mutex<HashMap<u64, Arc<sync::Notify>>>,
}

impl Notifications {
    pub fn new() -> Self {
        Notifications {
            process_died: Mutex::new(HashMap::new()),
            output_available: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get_process_died_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.process_died.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    pub async fn get_output_available_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.output_available.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    pub async fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);

                self.get_output_available_notification(id)
                    .await
                    .notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.get_process_died_notification(id).await.notify_one();
            }
        }
    }
}

pub async fn run_process_with_output(
    ga: &mut GuestAgent,
    notifications: &Notifications,
    bin: &str,
    argv: &[&str],
) -> io::Result<()> {
    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
            ],
            None,
        )
        .await?
        .expect("Run process failed");

    log::info!("Spawned process with id: {}", id);
    let died = notifications.get_process_died_notification(id).await;

    let output = notifications.get_output_available_notification(id).await;

    loop {
        tokio::select! {
            _ = died.notified() => {
                log::info!("Process {id} died");
                break;
            },
            _ = output.notified() => {
                match ga.query_output(id, 1, 0, u64::MAX).await? {
                    Ok(out) => {
                        log::info!("STDOUT Output {argv:?}:");
                        io::stdout().write_all(&out)?;
                    }
                    Err(code) => log::info!("{argv:?} no data on STDOUT, reason {code}"),
                }

                match ga.query_output(id, 2, 0, u64::MAX).await? {
                    Ok(out) => {
                        log::error!("STDERR Output {argv:?}:");
                        io::stdout().write_all(&out)?;
                    }
                    Err(code) => log::info!("{argv:?} no data on STDERR, reason {code}"),
                }
             }
        }
    }

    Ok(())
}

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("invalid manifest dir")
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    let joined = path.as_ref().join(file.to_string());

    // Under windows Paths has UNC prefix that is not parsed correctly by qemu
    // Wrap Path with simplified method to remove that prefix
    // It has no effect on Unix
    dunce::simplified(
        joined
            // canonicalize checks existence of the file, it may failed, if does not exist
            .canonicalize()
            .expect(&joined.display().to_string())
            .as_path(),
    )
    .display()
    .to_string()
}

pub fn spawn_vm() -> (Child, VM) {
    #[cfg(windows)]
    let vm_executable = "vmrt.exe";
    #[cfg(unix)]
    let vm_executable = "vmrt";

    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");

    let vm = VMBuilder::new(1, 256, &image_dir.join("ubuntu.gvmi"))
        .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
        .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
        .build();

    let mut cmd = vm.create_cmd(&runtime_dir.join(vm_executable));

    log::info!("CMD: {cmd:?}");

    //cmd.stdin(Stdio::null());

    // cmd.stderr(Stdio::null());
    // cmd.stdout(Stdio::null());

    cmd.current_dir(runtime_dir);
    (cmd.spawn().expect("failed to spawn VM"), vm)
}

fn main() {
    println!("Common module does not contain any example to run, but utilities that makes writing examples easier.");
}
