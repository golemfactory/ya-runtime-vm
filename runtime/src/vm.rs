use std::{ffi::OsStr, net::SocketAddr, path::PathBuf};
use tokio::process::Command;

use crate::arg_builder::ArgsBuilder;

const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";

#[derive(Default)]
pub struct VMBuilder {
    rw_drive: Option<String>,
    task_package: String,
    cpu_cores: usize,
    mem_mib: usize,
    kernel_path: Option<String>,
    ramfs_path: Option<String>,
}

impl VMBuilder {
    pub fn new(
        cpu_cores: usize,
        mem_mib: usize,
        task_package: &PathBuf,
        rw_drive: Option<&PathBuf>,
    ) -> Self {
        Self {
            rw_drive: rw_drive.map(|rw_drive| rw_drive.as_os_str().to_str().unwrap().into()),
            task_package: task_package.as_os_str().to_str().unwrap().into(),
            cpu_cores,
            mem_mib,
            kernel_path: None,
            ramfs_path: None,
        }
    }

    pub fn with_kernel_path(mut self, path: String) -> Self {
        self.kernel_path = Some(path);
        self
    }

    pub fn with_ramfs_path(mut self, path: String) -> Self {
        self.ramfs_path = Some(path);
        self
    }

    pub fn build(self) -> VM {
        let manager_sock;
        let net_sock;
        // TODO: that doesn't need to be a tcp connection under unix
        let p9_sock = "127.0.0.1:9005";

        let chardev;

        #[cfg(unix)]
        {
            chardev =
                |n, p: &PathBuf| format!("socket,path={},server=on,wait=off,id={}", p.display(), n);

            let uid = uuid::Uuid::new_v4().to_simple().to_string();
            manager_sock = std::env::temp_dir().join(format!("{}.sock", uid));
            net_sock = std::env::temp_dir().join(format!("{}_net.sock", uid));
        }

        #[cfg(windows)]
        {
            chardev = |n, p: &str| {
                let addr: SocketAddr = p.parse().unwrap();
                format!(
                    "socket,host={},port={},server=on,wait=off,id={}",
                    addr.ip(),
                    addr.port(),
                    n
                )
            };

            manager_sock = "127.0.0.1:9003";
            net_sock = "127.0.0.1:9004";
        }

        let chardev_9p = |n, p: &str| {
            let addr: SocketAddr = p.parse().unwrap();
            format!(
                "socket,host={},port={},server,id={}",
                addr.ip(),
                addr.port(),
                n
            )
        };

        let acceleration = if cfg!(windows) { "whpx" } else { "kvm" };

        let kernel_path = self.kernel_path.unwrap_or(FILE_VMLINUZ.to_string());
        let ramfs_path = self.ramfs_path.unwrap_or(FILE_INITRAMFS.to_string());

        #[rustfmt::skip]
        let ab = {
            let mut ab = ArgsBuilder::new();
            ab.add_2("-m", &format!("{}M", self.mem_mib));
            ab.add_1("-nographic");
            ab.add_2("-vga", "none");
            ab.add_2("-kernel", &kernel_path);
            ab.add_2("-initrd", &ramfs_path);
            ab.add_2("-net", "none");
            ab.add_2("-smp", &format!("{}", self.cpu_cores));
            ab.add_2("-append", r#""console=ttyS0 panic=1""#);
            ab.add_2("-device", "virtio-serial");
            ab.add_2("-chardev", &chardev("manager_cdev", &manager_sock));
            ab.add_2("-chardev", &chardev("net_cdev", &net_sock));
            ab.add_2("-chardev", &chardev_9p("p9_cdev", &p9_sock));
            ab.add_2("-device", "virtserialport,chardev=manager_cdev,name=manager_port" );
            ab.add_2("-device", "virtserialport,chardev=net_cdev,name=net_port");
            ab.add_2("-device", "virtserialport,chardev=p9_cdev,name=p9_port");
            ab.add_2("-drive", &format!("file={},cache=unsafe,readonly=on,format=raw,if=virtio", self.task_package));
            if let Some(rw_drive) = self.rw_drive { ab.add_2("-drive", &format!("file={},format=qcow2,if=virtio", rw_drive)) }
            ab.add_1("-no-reboot");
            ab.add_2("-accel", acceleration);
            ab.add_1("-nodefaults");
            ab.add_2("--serial", "stdio");
            ab
        };

        let args = ab.get_args_vector();
        log::debug!("Arguments for VM array: {:?}", args);
        log::info!("VM runtime command line: {}", ab.get_args_string());

        #[cfg(windows)]
        return VM {
            manager_sock: manager_sock.to_string(),
            net_sock: net_sock.to_string(),
            p9_sock: p9_sock.to_string(),
            args,
        };

        #[cfg(unix)]
        return VM {
            manager_sock: manager_sock.display().to_string(),
            net_sock: net_sock.display().to_string(),
            p9_sock: p9_sock.to_string(),
            args,
        };
    }
}

/// Hold VM parameters, can be later used to create Command object and spawn the VM
#[derive(Debug)]
pub struct VM {
    manager_sock: String,
    net_sock: String,
    p9_sock: String,

    args: Vec<String>,
}

impl VM {
    pub fn get_manager_sock(&self) -> &str {
        &self.manager_sock.as_str()
    }

    pub fn get_net_sock(&self) -> &str {
        &self.net_sock
    }

    pub fn get_9p_sock(&self) -> &str {
        &self.p9_sock
    }

    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }

    /// Creates Command object with args from the VM instance
    pub fn get_cmd<S: AsRef<OsStr>>(&self, exe_path: S) -> tokio::process::Command {
        let mut cmd = Command::new(exe_path);
        cmd.args(&self.args);

        cmd
    }
}
