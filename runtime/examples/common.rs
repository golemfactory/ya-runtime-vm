use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::{self, Mutex};
use ya_runtime_vm::vm_runner::VMRunner;
use ya_runtime_vm::{
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType},
    vm::VMBuilder,
};

pub struct Notifications {
    process_died: Mutex<HashMap<u64, Arc<sync::Notify>>>,
    output_available: Mutex<HashMap<u64, Arc<sync::Notify>>>,
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

pub async fn spawn_vm(
    tmp_path: &Path,
    cpu_cores: usize,
    mem_mib: usize,
) -> anyhow::Result<VMRunner> {
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");
    let source_qcow2_file = project_dir
        .join("poc")
        .join("qcow2")
        .join("empty_10GB.qcow2");
    let qcow2_file = tmp_path.join("rw_drive.qcow2");
    fs::copy(&source_qcow2_file, &qcow2_file)?;
    let qcow2_file = qcow2_file.canonicalize()?;

    let vm = VMBuilder::new(cpu_cores, mem_mib, &image_dir.join("ubuntu.gvmi"), None)
        .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
        .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
        .build();

    let mut vm_runner = VMRunner::new(vm);
    vm_runner.run_vm(runtime_dir).await?;
    Ok(vm_runner)
}
