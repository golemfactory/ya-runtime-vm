use anyhow::anyhow;
use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{net::TcpStream, process::Command, time::sleep};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_vm_file_server::InprocServer;

use crate::arg_builder::ArgsBuilder;
use crate::demux_socket_comm::{start_demux_communication, DemuxSocketHandle, MAX_P9_PACKET_SIZE};

const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";

#[derive(Default)]
pub struct VMBuilder {
    rw_drive: String,
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
        rw_drive: &PathBuf,
    ) -> Self {
        Self {
            rw_drive: rw_drive.as_os_str().to_str().unwrap().into(),
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

        let use_rw_drive = true;

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
            if use_rw_drive { ab.add_2("-drive", &format!("file={},format=qcow2,if=virtio", self.rw_drive)) }
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
    pub fn create_cmd<S: AsRef<OsStr>>(&self, exe_path: S) -> tokio::process::Command {
        let mut cmd = Command::new(exe_path);
        cmd.args(&self.args);

        cmd
    }

    async fn connect_to_9p_endpoint(&self, tries: usize) -> anyhow::Result<TcpStream> {
        log::debug!("Connect to the 9P VM endpoint...");

        for _ in 0..tries {
            match TcpStream::connect(self.get_9p_sock()).await {
                Ok(stream) => {
                    log::debug!("Connected to the 9P VM endpoint");
                    return Ok(stream);
                }
                Err(e) => {
                    log::debug!("Failed to connect to 9P VM endpoint: {e}");
                    // The VM is not ready yet, try again
                    sleep(Duration::from_secs(1)).await;
                }
            };
        }

        Err(anyhow!(
            "Failed to connect to the 9P VM endpoint after #{tries} tries"
        ))
    }

    /// Spawns tasks handling 9p communication for given mount points
    pub async fn start_9p_service(
        &self,
        work_dir: &Path,
        volumes: &[ContainerVolume],
    ) -> anyhow::Result<(Vec<InprocServer>, DemuxSocketHandle)> {
        log::debug!("Connecting to the 9P VM endpoint...");

        let vmp9stream = self.connect_to_9p_endpoint(10).await?;

        log::debug!("Spawn 9P inproc servers...");

        let mut runtime_9ps = vec![];

        for volume in volumes.iter() {
            let mount_point_host = work_dir
                .join(&volume.name)
                .to_str()
                .ok_or(anyhow!("cannot resolve 9P mount point"))?
                .to_string();

            log::debug!("Creating inproc 9p server with mount point {mount_point_host}");
            let runtime_9p = InprocServer::new(&mount_point_host);

            runtime_9ps.push(runtime_9p);
        }

        log::debug!("Connect to 9P inproc servers...");

        let mut p9streams = vec![];

        for server in &runtime_9ps {
            let client_stream = server.attach_client(MAX_P9_PACKET_SIZE);
            p9streams.push(client_stream);
        }

        let demux_socket_handle = start_demux_communication(vmp9stream, p9streams)?;

        // start_demux_communication(vm_stream, p9_streams);
        Ok((runtime_9ps, demux_socket_handle))
    }
}
