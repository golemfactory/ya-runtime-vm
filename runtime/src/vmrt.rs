use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use futures::lock::Mutex;
use futures::FutureExt;
use tokio::io::AsyncBufReadExt;
use tokio::{io, process, spawn};

use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::runtime_api::server;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::{serialize, ErrorExt, EventEmitter};

use crate::deploy::{Deployment, DeploymentMount};
use crate::guest_agent_comm::{GuestAgent, Notification};

const DIR_RUNTIME: &str = "runtime";
const FILE_RUNTIME: &str = "vmrt";
const FILE_VMLINUZ: &str = "vmlinuz-virt";
const FILE_INITRAMFS: &str = "initramfs.cpio.gz";
const FILE_NVIDIA_FILES: &str = "nvidia-files.squashfs";

#[derive(Default)]
pub struct RuntimeData {
    pub runtime: Option<process::Child>,
    pub vpn: Option<ContainerEndpoint>,
    pub inet: Option<ContainerEndpoint>,
    pub deployment: Option<Deployment>,
    pub ga: Option<Arc<Mutex<GuestAgent>>>,
    pub pci_device_id: Option<Vec<String>>,
}

impl RuntimeData {
    pub fn runtime(&mut self) -> anyhow::Result<process::Child> {
        self.runtime
            .take()
            .ok_or_else(|| anyhow::anyhow!("Runtime process not available"))
    }

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

pub async fn start_vmrt(
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
    emitter: EventEmitter,
) -> anyhow::Result<Option<serialize::json::Value>> {
    let runtime_dir = runtime_dir().or_err("Unable to resolve current directory")?;
    let temp_dir = std::env::temp_dir();
    let uid = uuid::Uuid::new_v4().simple().to_string();

    let mut data = runtime_data.lock().await;
    let deployment = data.deployment.clone().or_err("Missing deployment data")?;
    let volumes = deployment.volumes.clone();

    let manager_sock = temp_dir.join(format!("{}.sock", uid));
    let vpn_remote = data.vpn.clone();
    let inet_remote = data.inet.clone();

    let mut kernel_cmdline = "console=ttyS0 panic=1".to_string();

    let mut cmd = process::Command::new(runtime_dir.join(FILE_RUNTIME));
    cmd.current_dir(&runtime_dir);
    cmd.args([
        "-m",
        format!("{}M", deployment.mem_mib).as_str(),
        "-nographic",
        "-kernel",
        FILE_VMLINUZ,
        "-initrd",
        FILE_INITRAMFS,
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        deployment.cpu_cores.to_string().as_str(),
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        format!(
            "socket,path={},server=on,wait=off,id=manager_cdev",
            manager_sock.display()
        )
        .as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-drive",
        format!(
            "file={},cache=unsafe,readonly=on,format=raw,id=rootfs,if=none",
            deployment.task_package.display()
        )
        .as_str(),
        "-device",
        format!("virtio-blk-pci,drive=rootfs,serial=rootfs").as_str(),
        "-no-reboot",
    ]);

    for (
        vol_idx,
        DeploymentMount {
            name,
            guest_path,
            mount,
        },
    ) in deployment.mounts.iter().enumerate()
    {
        match mount {
            VolumeMount::Storage { errors, .. } => {
                let errors = errors.as_deref().unwrap_or("continue");

                let img_path = work_dir.join(name);
                cmd.args([
                    "-drive",
                    format!(
                        "file={},format=qcow2,media=disk,id=vol-{vol_idx},if=none",
                        img_path.display()
                    )
                    .as_str(),
                    "-device",
                    format!("virtio-blk-pci,drive=vol-{vol_idx},serial=vol-{vol_idx}").as_ref(),
                ]);
                kernel_cmdline.push_str(&format!(" vol-{vol_idx}-path={guest_path}"));
                kernel_cmdline.push_str(&format!(" vol-{vol_idx}-errors={errors}"));
            }
            VolumeMount::Ram { size } => {
                let size = size.as_u64();
                kernel_cmdline.push_str(&format!(" vol-{vol_idx}-path={guest_path}"));
                kernel_cmdline.push_str(&format!(" vol-{vol_idx}-size={size}"));
            }
        }
    }

    if let Some(pci_device_id) = &data.pci_device_id {
        for device_id in pci_device_id.iter() {
            cmd.arg("-device");
            cmd.arg(format!("vfio-pci,host={}", device_id).as_str());
        }
    } else {
        cmd.arg("-vga");
        cmd.arg("none");
    }

    if runtime_dir.join(FILE_NVIDIA_FILES).exists() {
        cmd.args([
            "-drive",
            format!(
                "file={},cache=unsafe,readonly=on,format=raw,id=nvidia-files,if=none",
                runtime_dir.join(FILE_NVIDIA_FILES).display()
            )
            .as_str(),
            "-device",
            format!("virtio-blk-pci,drive=nvidia-files,serial=nvidia-files").as_ref(),
        ]);
    }

    cmd.args(["-append", &kernel_cmdline]);

    let (vpn, inet) =
    // backward-compatibility mode
    if vpn_remote.is_none() && inet_remote.is_none() {
        cmd.args(["-net", "none"]);

        let vpn = configure_chardev_endpoint(&mut cmd, "vpn", &temp_dir, &uid)?;
        let inet = configure_chardev_endpoint(&mut cmd, "inet", &temp_dir, &uid)?;
        (vpn, inet)
    // virtio-net (preferred)
    } else {
        let mut pair = SocketPairConf::default();
        pair.probe().await?;

        let vpn = configure_netdev_endpoint(&mut cmd, "vpn", &vpn_remote, pair.first)?;
        let inet = configure_netdev_endpoint(&mut cmd, "inet", &inet_remote, pair.second)?;
        (vpn, inet)
    };

    data.vpn.replace(vpn);
    data.inet.replace(inet);

    for (idx, volume) in volumes.iter().enumerate() {
        cmd.arg("-virtfs");
        cmd.arg(format!(
            "local,id={tag},path={path},security_model=none,mount_tag={tag}",
            tag = format!("mnt{}", idx),
            path = work_dir.join(&volume.name).to_string_lossy(),
        ));
    }

    log::info!("Executing command: {cmd:?}");

    let mut runtime = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = runtime.stdout.take().unwrap();
    spawn(reader_to_log(stdout));

    let ga = GuestAgent::connected(manager_sock, 10, move |notification, ga| {
        let mut emitter = emitter.clone();
        async move {
            let status = notification_into_status(notification, ga).await;
            emitter.emit(status).await;
        }
        .boxed()
    })
    .await?;

    {
        let mut ga = ga.lock().await;
        for (idx, volume) in deployment.volumes.iter().enumerate() {
            ga.mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                .await?
                .expect("Mount failed");
        }
    }

    data.runtime.replace(runtime);
    data.ga.replace(ga);

    Ok(None)
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
        let first = std::net::UdpSocket::bind((self.first.ip, self.first.udp))?;
        let second = std::net::UdpSocket::bind((self.second.ip, self.second.udp))?;

        self.first.udp = first.local_addr()?.port();
        self.second.udp = second.local_addr()?.port();

        let first = std::net::TcpListener::bind((self.first.ip, self.first.tcp))?;
        let second = std::net::TcpListener::bind((self.second.ip, self.second.tcp))?;

        self.first.tcp = first.local_addr()?.port();
        self.second.tcp = second.local_addr()?.port();

        Ok(())
    }
}

fn configure_chardev_endpoint(
    cmd: &mut process::Command,
    id: &str,
    temp_dir: impl AsRef<Path>,
    uid: &str,
) -> anyhow::Result<ContainerEndpoint> {
    let sock = temp_dir.as_ref().join(format!("{}_{}.sock", uid, id));

    cmd.arg("-chardev");
    cmd.arg(format!(
        "socket,path={},server,wait=off,id={id}_cdev",
        sock.display()
    ));

    cmd.arg("-device");
    cmd.arg(format!("virtserialport,chardev={id}_cdev,name={id}_port"));

    Ok(ContainerEndpoint::UnixStream(sock))
}

fn configure_netdev_endpoint(
    cmd: &mut process::Command,
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

                cmd.arg("-netdev");
                cmd.arg(format!(
                    "socket,id={id},udp={remote_addr},localaddr={ipv4}:{port}"
                ));

                ContainerEndpoint::UdpDatagram(SocketAddrV4::new(ipv4, port).into())
            }
            ContainerEndpoint::TcpStream(remote_addr) => {
                cmd.arg("-netdev");
                cmd.arg(format!("socket,id={id},connect={remote_addr}"));

                ContainerEndpoint::TcpStream(*remote_addr)
            }
            ContainerEndpoint::TcpListener(_) => {
                let port = conf.tcp;

                cmd.arg("-netdev");
                cmd.arg(format!("socket,id={id},listen={ipv4}:{port}"));

                ContainerEndpoint::TcpStream(SocketAddrV4::new(ipv4, port).into())
            }
            _ => return Err(anyhow::anyhow!("Unsupported remote VPN VM endpoint")),
        }
    } else {
        let port = conf.tcp;

        cmd.arg("-netdev");
        cmd.arg(format!("socket,id={id},listen={ipv4}:{port}"));

        ContainerEndpoint::TcpListener(SocketAddrV4::new(ipv4, port).into())
    };

    let counter = COUNTER.fetch_add(1, Relaxed);
    let bytes = counter.to_be_bytes();

    cmd.arg("-device");
    cmd.arg(format!(
        "virtio-net-pci,netdev={id},mac=90:13:{:0x}",
        HexWriter(&bytes),
    ));

    Ok(endpoint)
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

pub fn runtime_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_path_buf()
        .join(DIR_RUNTIME))
}

async fn reader_to_log<T: io::AsyncRead + Unpin>(reader: T) {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                log::debug!("VM: {}", String::from_utf8_lossy(&bytes).trim_end());
                buf.clear();
            }
            Err(e) => log::error!("VM output error: {}", e),
        }
    }
}

async fn notification_into_status(
    notification: Notification,
    ga: Arc<Mutex<GuestAgent>>,
) -> server::ProcessStatus {
    match notification {
        Notification::OutputAvailable { id, fd } => {
            log::debug!("Process {} has output available on fd {}", id, fd);

            let output = {
                let result = {
                    let mut guard = ga.lock().await;
                    guard.query_output(id, fd as u8, 0, u64::MAX).await
                };
                match result {
                    Ok(Ok(vec)) => vec,
                    Ok(Err(e)) => {
                        log::error!("Remote error while querying output: {:?}", e);
                        Vec::new()
                    }
                    Err(e) => {
                        log::error!("Error querying output: {:?}", e);
                        Vec::new()
                    }
                }
            };
            let (stdout, stderr) = match fd {
                1 => (output, Vec::new()),
                _ => (Vec::new(), output),
            };

            server::ProcessStatus {
                pid: id,
                running: true,
                return_code: 0,
                stdout,
                stderr,
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
