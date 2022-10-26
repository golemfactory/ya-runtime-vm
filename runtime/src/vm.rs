use futures::lock::Mutex;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::{
    ffi::OsStr,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::atomic::AtomicU32,
};
use tokio::process::Command;
use ya_runtime_sdk::server::ContainerEndpoint;

use crate::arg_builder::ArgsBuilder;
use crate::deploy::Deployment;
use crate::guest_agent_comm::GuestAgent;
use crate::vm_runner::VMRunner;

const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";

#[derive(Default)]
pub struct RuntimeData {
    pub vm_runner: Option<VMRunner>,
    pub vpn: Option<ContainerEndpoint>,
    pub inet: Option<ContainerEndpoint>,
    pub deployment: Option<Deployment>,
    pub ga: Option<Arc<Mutex<GuestAgent>>>,
}

impl RuntimeData {
    //fn vm_runner(&mut self) -> anyhow::Result<VMRunner> {
    //    self.vm_runner
    //        .take()
    //        .ok_or_else(|| anyhow::anyhow!("VM runner process not available"))
    //}

    pub fn deployment(&self) -> anyhow::Result<&Deployment> {
        self.deployment
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Runtime not deployed"))
    }

    pub fn ga(&self) -> anyhow::Result<Arc<Mutex<GuestAgent>>> {
        self.ga
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Runtime not started"))
    }
}

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
        task_package: &Path,
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

    pub async fn build(self, runtime_data: Arc<Mutex<RuntimeData>>) -> anyhow::Result<VM> {
        let mut data = runtime_data.lock().await;
        let manager_sock;
        // TODO: that doesn't need to be a tcp connection under unix
        let p9_sock = "127.0.0.1:9005";

        #[cfg(unix)]
        {
            let uid = uuid::Uuid::new_v4().simple().to_string();
            manager_sock = std::env::temp_dir().join(format!("{}.sock", uid));
        }

        #[cfg(windows)]
        {
            manager_sock = "127.0.0.1:9003";
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

        let kernel_path = self.kernel_path.unwrap_or_else(|| FILE_VMLINUZ.to_string());
        let ramfs_path = self
            .ramfs_path
            .unwrap_or_else(|| FILE_INITRAMFS.to_string());

        let temp_dir = std::env::temp_dir();
        let uid = uuid::Uuid::new_v4().simple().to_string();
        let vpn_remote = data.vpn.clone();
        let inet_remote = data.inet.clone();

        #[rustfmt::skip]
        let (ab, (vpn, inet)) = {
            let mut ab = ArgsBuilder::new();
            ab.add_2("-m", &format!("{}M", self.mem_mib));
            ab.add_1("-nographic");
            ab.add_2("-vga", "none");
            ab.add_2("-kernel", &kernel_path);
            ab.add_2("-initrd", &ramfs_path);
            ab.add_2("-smp", &format!("{}", self.cpu_cores));
            ab.add_2("-append", r#""console=ttyS0 panic=1""#);
            ab.add_2("-device", "virtio-serial");
            ab.add_2("-chardev", &chardev("manager_cdev", &manager_sock));
            ab.add_2("-chardev", &chardev_9p("p9_cdev", p9_sock));
            ab.add_2("-device", "virtserialport,chardev=manager_cdev,name=manager_port" );
            ab.add_2("-device", "virtserialport,chardev=p9_cdev,name=p9_port");
            ab.add_2("-drive", &format!("file={},cache=unsafe,readonly=on,format=raw,if=virtio", self.task_package));
            if let Some(rw_drive) = self.rw_drive { ab.add_2("-drive", &format!("file={},format=qcow2,if=virtio", rw_drive)) }
            ab.add_1("-no-reboot");
            ab.add_2("-accel", acceleration);
            ab.add_1("-nodefaults");
            ab.add_2("--serial", "stdio");

            let (vpn, inet) =
            // backward-compatibility mode
            if vpn_remote.is_none() && inet_remote.is_none() {
                ab.add_2("-net", "none");

                let vpn = configure_chardev_endpoint(&mut ab, ("vpn", 9004), &temp_dir, &uid)?;
                let inet = configure_chardev_endpoint(&mut ab, ("inet", 9006), &temp_dir, &uid)?;
                (vpn, inet)
            // virtio-net (preferred)
            } else {
                let mut pair = SocketPairConf::default();
                pair.probe().await?;

                let vpn = configure_netdev_endpoint(&mut ab, "vpn", &vpn_remote, pair.first)?;
                let inet = configure_netdev_endpoint(&mut ab, "inet", &inet_remote, pair.second)?;
                (vpn, inet)
            };

            (ab, (vpn, inet))
        };

        data.vpn.replace(vpn);
        data.inet.replace(inet);

        let args = ab.get_args_vector();
        log::debug!("Arguments for VM array: {:?}", args);
        log::info!("VM runtime command line: {}", ab.get_args_string());

        Ok(VM {
            #[cfg(windows)]
            manager_sock: manager_sock.to_string(),
            #[cfg(unix)]
            manager_sock: manager_sock.display().to_string(),
            p9_sock: p9_sock.to_string(),
            args,
        })
    }
}

/// Hold VM parameters, can be later used to create Command object and spawn the VM
#[derive(Debug)]
pub struct VM {
    manager_sock: String,
    p9_sock: String,

    args: Vec<String>,
}

impl VM {
    pub fn get_manager_sock(&self) -> &str {
        &self.manager_sock
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

#[derive(Copy, Clone, Debug)]
struct SocketConf {
    ip: Ipv4Addr,
    udp: u16,
    tcp: u16,
}

#[derive(Debug)]
struct SocketPairConf {
    first: SocketConf,
    second: SocketConf,
}

impl Default for SocketPairConf {
    fn default() -> Self {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        Self {
            first: SocketConf { ip, udp: 0, tcp: 0 },
            second: SocketConf { ip, udp: 0, tcp: 0 },
        }
    }
}

impl SocketPairConf {
    // FIXME: TOC/TOU
    async fn probe(&mut self) -> anyhow::Result<()> {
        let first = std::net::UdpSocket::bind(&(self.first.ip, self.first.udp))?;
        let second = std::net::UdpSocket::bind(&(self.second.ip, self.second.udp))?;

        self.first.udp = first.local_addr()?.port();
        self.second.udp = second.local_addr()?.port();

        let first = std::net::TcpListener::bind(&(self.first.ip, self.first.tcp))?;
        let second = std::net::TcpListener::bind(&(self.second.ip, self.second.tcp))?;

        self.first.tcp = first.local_addr()?.port();
        self.second.tcp = second.local_addr()?.port();

        Ok(())
    }
}

struct HexWriter<'a>(&'a [u8]);

impl<'a> std::fmt::LowerHex for HexWriter<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            let sep = if i < self.0.len().saturating_sub(1) {
                ":"
            } else {
                ""
            };
            fmt.write_fmt(format_args!("{:02x}{}", byte, sep))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn chardev(n: &str, p: &Path) -> String {
    format!("socket,path={},server=on,wait=off,id={}", p.display(), n)
}

#[cfg(windows)]
fn chardev(n: &str, p: &str) -> String {
    let addr: SocketAddr = p.parse().unwrap();
    format!(
        "socket,host={},port={},server=on,wait=off,id={}",
        addr.ip(),
        addr.port(),
        n
    )
}

fn configure_netdev_endpoint(
    ab: &mut ArgsBuilder,
    id: &str,
    endpoint: &Option<ContainerEndpoint>,
    conf: SocketConf,
) -> anyhow::Result<ContainerEndpoint> {
    static COUNTER: AtomicU32 = AtomicU32::new(1);

    let ipv4 = conf.ip;
    let endpoint = if let Some(endpoint) = endpoint {
        match endpoint {
            ContainerEndpoint::UdpDatagram(remote_addr) => {
                let port = conf.udp;

                ab.add_2(
                    "-netdev",
                    &format!("socket,id={id},udp={remote_addr},localaddr={ipv4}:{port}"),
                );

                ContainerEndpoint::UdpDatagram(SocketAddrV4::new(ipv4, port).into())
            }
            ContainerEndpoint::TcpStream(remote_addr) => {
                ab.add_2("-netdev", &format!("socket,id={id},connect={remote_addr}"));

                ContainerEndpoint::TcpStream(*remote_addr)
            }
            ContainerEndpoint::TcpListener(_) => {
                let port = conf.tcp;

                ab.add_2("-netdev", &format!("socket,id={id},listen={ipv4}:{port}"));

                ContainerEndpoint::TcpStream(SocketAddrV4::new(ipv4, port).into())
            }
            _ => return Err(anyhow::anyhow!("Unsupported remote VPN VM endpoint")),
        }
    } else {
        let port = conf.tcp;

        ab.add_2("-netdev", &format!("socket,id={id},listen={ipv4}:{port}"));

        ContainerEndpoint::TcpListener(SocketAddrV4::new(ipv4, port).into())
    };

    let counter = COUNTER.fetch_add(1, Relaxed);
    let bytes = counter.to_be_bytes();

    ab.add_2(
        "-device",
        &format!(
            "virtio-net-pci,netdev={id},mac=90:13:{:0x}",
            HexWriter(&bytes),
        ),
    );

    Ok(endpoint)
}

fn configure_chardev_endpoint(
    ab: &mut ArgsBuilder,
    id: (&str, u16),
    temp_dir: impl AsRef<Path>,
    uid: &str,
) -> anyhow::Result<ContainerEndpoint> {
    let sock;

    #[cfg(unix)]
    {
        sock = temp_dir.as_ref().join(format!("{}_{}.sock", uid, id.0));
    }

    #[cfg(windows)]
    {
        sock = format!("127.0.0.1:{}", id.1);
    }

    ab.add_2("-chardev", &chardev(&format!("{}_cdev", id.0), &sock));

    ab.add_2(
        "-device",
        &format!("virtserialport,chardev={0}_cdev,name={0}_port", id.0),
    );

    #[cfg(unix)]
    return Ok(ContainerEndpoint::UnixStream(sock));

    #[cfg(windows)]
    return Ok(ContainerEndpoint::TcpStream(
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), id.1).into(),
    ));
}
