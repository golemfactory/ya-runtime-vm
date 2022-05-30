use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::{self, Mutex};
use crate::vm_runner::VMRunner;
use crate::{
    guest_agent_comm::{Notification},
    vm::VMBuilder,
};

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
    let _qcow2_file = qcow2_file.canonicalize()?;

    let vm = VMBuilder::new(cpu_cores, mem_mib, &image_dir.join("ubuntu.gvmi"), None)
        .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
        .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
        .build();

    let mut vm_runner = VMRunner::new(vm);
    vm_runner.run_vm(runtime_dir).await?;
    Ok(vm_runner)
}
