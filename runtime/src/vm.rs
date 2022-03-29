use std::{ffi::OsStr, net::SocketAddr, path::PathBuf};

use tokio::process::Command;

const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";

#[derive(Default)]
pub struct VMBuilder {
    task_package: String,
    cpu_cores: usize,
    mem_mib: usize,
    kernel_path: Option<String>,
    ramfs_path: Option<String>,
}

impl VMBuilder {
    pub fn new(cpu_cores: usize, mem_mib: usize, task_package: &PathBuf) -> Self {
        Self {
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
                |n, p: &PathBuf| format!("socket,path={},server,nowait,id={}", p.display(), n);

            let uid = uuid::Uuid::new_v4().to_simple().to_string();
            manager_sock = std::env::temp_dir().join(format!("{}.sock", uid));
            net_sock = std::env::temp_dir().join(format!("{}_net.sock", uid));
        }

        #[cfg(windows)]
        {
            chardev = |n, p: &str| {
                let addr: SocketAddr = p.parse().unwrap();
                format!(
                    "socket,host={},port={},server,nowait,id={}",
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
                "socket,host={},port={},server,id={},nowait",
                addr.ip(),
                addr.port(),
                n
            )
        };
        let tmp0 = format!("{}M", self.mem_mib);
        let tmp1 = format!(
            "file={},cache=unsafe,readonly=on,format=raw,if=virtio",
            self.task_package
        );
        let chardev1 = chardev("manager_cdev", &manager_sock);
        let chardev2 = chardev("net_cdev", &net_sock);
        let chardev3 = chardev_9p("p9_cdev", &p9_sock);

        let cpu_string = format!("{}", self.cpu_cores);

        let acceleration = if cfg!(windows) { "whpx" } else { "kvm" };

        let kernel_path = self.kernel_path.unwrap_or(FILE_VMLINUZ.to_string());
        let ramfs_path = self.ramfs_path.unwrap_or(FILE_INITRAMFS.to_string());

        let args = vec![
            "-m",
            tmp0.as_str(),
            "-nographic",
            "-vga",
            "none",
            "-kernel",
            kernel_path.as_str(),
            "-initrd",
            ramfs_path.as_str(),
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

        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();

        #[cfg(windows)]
        VM {
            manager_sock: manager_sock.to_string(),
            net_sock: net_sock.to_string(),
            p9_sock: p9_sock.to_string(),
            args,
        }
    }
}

/// Hold VM parameters, can be later used to create Command object and spawn the VM
pub struct VM {
    manager_sock: String,
    net_sock: String,
    p9_sock: String,

    args: Vec<String>,
}

impl VM {
    pub fn get_manager_sock(&self) -> &str {
        #[cfg(unix)]
        return manager_sock.to_str().unwrap();
        #[cfg(windows)]
        return &self.manager_sock;
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
    pub fn create_cmd<S: AsRef<OsStr>>(&self, exe_path: S) -> tokio::process::Command {
        let mut cmd = Command::new(exe_path);
        cmd.args(&self.args);

        cmd
    }
}
