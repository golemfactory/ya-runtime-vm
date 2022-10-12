use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use futures::lock::Mutex;
use futures::FutureExt;
use tokio::io::AsyncBufReadExt;
use tokio::{io, process, spawn};

use ya_runtime_sdk::runtime_api::server;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::{serialize, ErrorExt, EventEmitter};

use crate::deploy::Deployment;
use crate::guest_agent_comm::{GuestAgent, Notification};

const DIR_RUNTIME: &'static str = "runtime";
// const FILE_RUNTIME: &'static str = "vmrt";
const FILE_RUNTIME: &'static str = "/usr/bin/qemu-system-x86_64";
const FILE_VMLINUZ: &'static str = "vmlinuz-virt";
const FILE_INITRAMFS: &'static str = "initramfs.cpio.gz";

#[derive(Default)]
pub struct RuntimeData {
    pub runtime: Option<process::Child>,
    pub vpn: Option<ContainerEndpoint>,
    pub inet: Option<ContainerEndpoint>,
    pub deployment: Option<Deployment>,
    pub ga: Option<Arc<Mutex<GuestAgent>>>,
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

    let mut cmd = process::Command::new(runtime_dir.join(FILE_RUNTIME));
    cmd.current_dir(&runtime_dir);
    cmd.args(&[
        "-m",
        format!("{}M", deployment.mem_mib).as_str(),
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        FILE_VMLINUZ,
        "-initrd",
        FILE_INITRAMFS,
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        deployment.cpu_cores.to_string().as_str(),
        "-append",
        "console=ttyS0 panic=1",
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
            "file={},cache=unsafe,readonly=on,format=raw,if=virtio",
            deployment.task_package.display()
        )
        .as_str(),
        "-no-reboot",
    ]);

    let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
    let (vpn_udp, inet_udp) =
        test_udp_port_pair(format!("{ipv4}:0")).or_err("no free UDP ports available")?;
    let (vpn_tcp, inet_tcp) =
        test_tcp_port_pair(format!("{ipv4}:0")).or_err("no free TCP ports available")?;

    set_endpoint_netdev(
        "vpn",
        &mut data.vpn,
        &vpn_remote,
        ipv4,
        vpn_udp,
        vpn_tcp,
        &mut cmd,
    )?;

    set_endpoint_netdev(
        "inet",
        &mut data.inet,
        &inet_remote,
        ipv4,
        inet_udp,
        inet_tcp,
        &mut cmd,
    )?;

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

pub fn runtime_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_path_buf()
        .join(DIR_RUNTIME))
}

// FIXME: TOC/TOU
fn test_udp_port_pair<A: std::net::ToSocketAddrs>(addr: A) -> Option<(u16, u16)> {
    let first = std::net::UdpSocket::bind(&addr).ok()?;
    let second = std::net::UdpSocket::bind(&addr).ok()?;
    Some((
        first.local_addr().ok()?.port(),
        second.local_addr().ok()?.port(),
    ))
}

// FIXME: TOC/TOU
fn test_tcp_port_pair<A: std::net::ToSocketAddrs>(addr: A) -> Option<(u16, u16)> {
    let first = std::net::TcpListener::bind(&addr).ok()?;
    let second = std::net::TcpListener::bind(&addr).ok()?;
    Some((
        first.local_addr().ok()?.port(),
        second.local_addr().ok()?.port(),
    ))
}

fn set_endpoint_netdev(
    id: &str,
    dst: &mut Option<ContainerEndpoint>,
    endpoint: &Option<ContainerEndpoint>,
    ipv4: Ipv4Addr,
    udp_port: u16,
    tcp_port: u16,
    cmd: &mut process::Command,
) -> anyhow::Result<()> {
    const COUNTER: AtomicU32 = AtomicU32::new(1);

    if let Some(endpoint) = endpoint {
        match endpoint {
            ContainerEndpoint::UdpDatagram(remote_addr) => {
                let port = udp_port;

                cmd.arg("-netdev");
                cmd.arg(format!(
                    "socket,id={id},udp={remote_addr},localaddr={ipv4}:{port}"
                ));

                dst.replace(ContainerEndpoint::UdpDatagram(
                    SocketAddrV4::new(ipv4, port).into(),
                ));
            }
            ContainerEndpoint::TcpStream(remote_addr) => {
                cmd.arg("-netdev");
                cmd.arg(format!("socket,id={id},connect={remote_addr}"));

                dst.replace(ContainerEndpoint::TcpStream(*remote_addr));
            }
            ContainerEndpoint::TcpListener(_) => {
                let port = tcp_port;

                cmd.arg("-netdev");
                cmd.arg(format!("socket,id={id},listen={ipv4}:{port}"));

                dst.replace(ContainerEndpoint::TcpStream(
                    SocketAddrV4::new(ipv4, port).into(),
                ));
            }
            _ => return Err(anyhow::anyhow!("Unsupported remote VPN VM endpoint")),
        }
    } else {
        let port = tcp_port;

        cmd.arg("-netdev");
        cmd.arg(format!("socket,id={id},listen={ipv4}:{port}"));

        dst.replace(ContainerEndpoint::TcpListener(
            SocketAddrV4::new(ipv4, port).into(),
        ));
    }

    let counter = COUNTER.fetch_add(1, Relaxed);
    let bytes = counter.to_be_bytes();
    let writer = HexWriter(&bytes);

    cmd.arg("-device");
    cmd.arg(format!(
        "virtio-net-pci,netdev={id},mac=90:13:{:0x}",
        writer,
    ));

    Ok(())
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
