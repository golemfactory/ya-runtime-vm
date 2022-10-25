use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::vm::{RuntimeData, VMBuilder};
use crate::vm_runner::VMRunner;
use futures::lock::Mutex;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;

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

pub fn prepare_tmp_path() -> PathBuf {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("invalid manifest dir");
    let temp_path = project_dir.join(Path::new("tmp"));
    if temp_path.exists() {
        fs::remove_dir_all(&temp_path).unwrap();
    }
    fs::create_dir_all(&temp_path).unwrap();
    temp_path
}

pub fn prepare_mount_directories(
    base_path: &PathBuf,
    number_of_drives: u64,
) -> Vec<ContainerVolume> {
    let mut mount_args = vec![];

    for id in 0..number_of_drives {
        let name = format!("inner{id}");

        let inner_path = base_path.join(&name);

        std::fs::create_dir_all(&inner_path).expect(&format!(
            "Failed to create a dir {:?} inside temp dir",
            inner_path.as_os_str()
        ));

        mount_args.push(ContainerVolume {
            name,
            path: format!("/mnt/mnt1/tag{id}"),
        });
    }
    mount_args
}

pub async fn spawn_vm(
    tmp_path: &Path,
    cpu_cores: usize,
    mem_gib: f64,
    use_qcow2_volume: bool,
) -> anyhow::Result<VMRunner> {
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");
    if use_qcow2_volume {
        let source_qcow2_file = project_dir
            .join("poc")
            .join("qcow2")
            .join("empty_10GB.qcow2");
        let qcow2_file = tmp_path.join("rw_drive.qcow2");
        fs::copy(&source_qcow2_file, &qcow2_file)?;
        let _qcow2_file = qcow2_file.canonicalize()?;
    }

    let runtime_data = Arc::new(Mutex::new(RuntimeData::default()));

    let vm = VMBuilder::new(
        cpu_cores,
        (mem_gib * 1024.0) as usize,
        &image_dir.join("ubuntu.gvmi"),
        None,
    )
    .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
    .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
    .build(runtime_data)
    .await?;

    let mut vm_runner = VMRunner::new(vm);
    vm_runner.run_vm(runtime_dir).await?;
    Ok(vm_runner)
}
