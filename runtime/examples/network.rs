use futures::lock::Mutex;
use futures::FutureExt;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::{atomic::AtomicU16, Arc},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{process::Child, sync};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_runtime_vm::vm::{VMBuilder, VM};

#[cfg(windows)]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(unix)]
type PlatformStream = UnixStream;
#[cfg(windows)]
type PlatformStream = TcpStream;

const IDENTIFICATION: AtomicU16 = AtomicU16::new(42);
const MTU: usize = 65535;
const PREFIX_LEN: usize = 2;

struct Notifications {
    process_died: sync::Notify,
    ga: Option<Arc<Mutex<GuestAgent>>>,
}

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: sync::Notify::new(),
            ga: None,
        }
    }

    fn set_ga(&mut self, ga: Arc<Mutex<GuestAgent>>) {
        self.ga.replace(ga);
    }

    fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                let ga = match self.ga.as_ref() {
                    Some(ga) => ga.clone(),
                    _ => return,
                };

                tokio::spawn(async move {
                    match ga
                        .lock()
                        .await
                        .query_output(id, fd as u8, 0u64, u64::MAX)
                        .await
                    {
                        Ok(res) => match res {
                            Ok(out) => while let Err(_) = io::stdout().write_all(&out[..]) {},
                            Err(code) => eprintln!("Output query failed with: {}", code),
                        },
                        Err(code) => eprintln!("Output query failed with: {}", code),
                    }
                });
            }
            Notification::ProcessDied { id, reason } => {
                eprintln!("Process {} died with {:?}", id, reason);
                self.process_died.notify_one();
            }
        }
    }
}

async fn run_process(ga: &mut GuestAgent, bin: &str, argv: &[&str]) -> io::Result<()> {
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
    eprintln!("Spawned process with id: {}", id);
    Ok(())
}

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .unwrap()
}

fn get_root_dir() -> PathBuf {
    get_project_dir().join("..").canonicalize().unwrap()
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    dunce::simplified(
        path.as_ref()
            .join(file.to_string())
            .canonicalize()
            .unwrap()
            .as_path(),
    )
    .display()
    .to_string()
}

fn spawn_vm() -> (Child, VM) {
    #[cfg(windows)]
    let vm_executable = "vmrt.exe";
    #[cfg(unix)]
    let vm_executable = "vmrt";

    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");

    let vm = VMBuilder::new(1, 256, &image_dir.join("ubuntu.gvmi"))
        .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
        .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
        .build();

    let mut cmd = vm.create_cmd(&runtime_dir.join(vm_executable));

    println!("CMD: {cmd:?}");

    cmd.stdin(Stdio::null());
    cmd.current_dir(runtime_dir);
    (cmd.spawn().expect("failed to spawn VM"), vm)
}

async fn handle_net<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let stream = PlatformStream::connect(path.as_ref().display().to_string()).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    let fut = async move {
        let mut buf: [u8; MTU] = [0u8; MTU];
        loop {
            let count = match read.read(&mut buf).await {
                Err(_) | Ok(0) => break,
                Ok(c) => c,
            };
            eprintln!("-> {:?}", &buf[..count]);
            if let Some(mut res) = handle_ethernet_packet(&buf[PREFIX_LEN..count]) {
                let len_u16 = res.len() as u16;
                res.reserve(PREFIX_LEN);
                res.splice(0..0, u16::to_ne_bytes(len_u16).to_vec());

                eprintln!("<- {:?}", &res);
                if let Err(e) = write.write_all(&res).await {
                    eprintln!("Write error: {:?}", e);
                }
            }
        }
    };

    tokio::spawn(fut);
    Ok(())
}

fn handle_icmp(src: IpAddr, dst: IpAddr, packet: &[u8]) -> Option<Vec<u8>> {
    let icmp_packet = match IcmpPacket::new(packet) {
        Some(icmp_packet) => icmp_packet,
        None => return None,
    };

    match icmp_packet.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let reply = echo_reply::EchoReplyPacket::new(packet).unwrap();
            eprintln!(
                "-> ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                src,
                dst,
                reply.get_sequence_number(),
                reply.get_identifier()
            );
        }
        IcmpTypes::EchoRequest => {
            let request = echo_request::EchoRequestPacket::new(packet).unwrap();
            eprintln!(
                "-> ICMP echo request {} -> {} (seq={:?}, id={:?}, size={})",
                src,
                dst,
                request.get_sequence_number(),
                request.get_identifier(),
                request.packet().len(),
            );

            let mut data: Vec<u8> = vec![0u8; request.packet().len()];
            {
                let mut reply = echo_reply::MutableEchoReplyPacket::new(&mut data[..]).unwrap();
                reply.set_identifier(request.get_identifier());
                reply.set_sequence_number(request.get_sequence_number());
                reply.set_icmp_type(IcmpTypes::EchoReply);
                reply.set_icmp_code(request.get_icmp_code());
                reply.set_payload(request.payload());
            }

            let mut reply =
                MutableIcmpPacket::new(&mut data[..request.payload().len() + 8]).unwrap();
            let checksum = pnet::packet::icmp::checksum(&reply.to_immutable());
            reply.set_checksum(checksum);

            return Some(reply.packet().to_vec());
        }
        _ => eprintln!(
            "-> ICMP packet {} -> {} (type={:?})",
            src,
            dst,
            icmp_packet.get_icmp_type()
        ),
    }

    None
}

fn handle_transport(
    src: IpAddr,
    dst: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) -> Option<Vec<u8>> {
    match protocol {
        IpNextHeaderProtocols::Icmp => handle_icmp(src, dst, packet),
        _ => None,
    }
}

fn handle_ipv4_packet(data: &[u8]) -> Option<Vec<u8>> {
    match Ipv4Packet::new(data) {
        Some(ip) => {
            let reply = handle_transport(
                IpAddr::V4(ip.get_source()),
                IpAddr::V4(ip.get_destination()),
                ip.get_next_level_protocol(),
                ip.payload(),
            );

            reply.map(move |payload| {
                let mut data: Vec<u8> = vec![0u8; MTU];
                let reply_len = 20 + payload.len();

                let mut reply = MutableIpv4Packet::new(&mut data[..reply_len]).unwrap();
                reply.set_version(4);
                reply.set_header_length(5);
                reply.set_total_length(reply_len as u16);
                reply.set_identification(IDENTIFICATION.fetch_add(1, Relaxed));
                reply.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
                reply.set_fragment_offset(0);
                reply.set_ttl(ip.get_ttl() - 1);
                reply.set_payload(&payload[..]);
                reply.set_dscp(ip.get_dscp());
                reply.set_ecn(ip.get_ecn());
                reply.set_next_level_protocol(ip.get_next_level_protocol());
                reply.set_source(ip.get_destination());
                reply.set_destination(ip.get_source());

                reply.set_checksum(pnet::packet::ipv4::checksum(&reply.to_immutable()));
                reply.packet().to_vec()
            })
        }
        _ => {
            eprintln!("Malformed IPv4 Packet");
            None
        }
    }
}

fn handle_arp_packet(data: &[u8]) -> Option<Vec<u8>> {
    match ArpPacket::new(data) {
        Some(arp) => match arp.get_operation() {
            ArpOperations::Request => {
                let mut buffer = [0u8; 28];
                let mut reply = MutableArpPacket::new(&mut buffer).unwrap();

                reply.set_hardware_type(arp.get_hardware_type());
                reply.set_protocol_type(arp.get_protocol_type());
                reply.set_hw_addr_len(arp.get_hw_addr_len());
                reply.set_proto_addr_len(arp.get_proto_addr_len());
                reply.set_operation(ArpOperations::Reply);
                reply.set_sender_hw_addr(MacAddr(1, 2, 3, 4, 5, 6));
                reply.set_sender_proto_addr(arp.get_target_proto_addr());
                reply.set_target_hw_addr(arp.get_sender_hw_addr());
                reply.set_target_proto_addr(arp.get_sender_proto_addr());

                return Some(reply.packet().to_vec());
            }
            _ => (),
        },
        _ => {
            eprintln!("Malformed ARP Packet");
        }
    };
    None
}

fn handle_ethernet_packet(data: &[u8]) -> Option<Vec<u8>> {
    match EthernetPacket::new(data) {
        Some(eth) => match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                eprintln!("-> IPv4 packet");
                handle_ipv4_packet(eth.payload())
            }
            EtherTypes::Arp => {
                eprintln!("-> ARP packet");
                handle_arp_packet(eth.payload())
            }
            eth_type => {
                eprintln!("-> ETH packet: {:?}", eth_type);
                None
            }
        }
        .map(move |payload| {
            let mut data: Vec<u8> = vec![0u8; 14 + payload.len()];
            let mut reply = MutableEthernetPacket::new(&mut data).unwrap();
            reply.set_source(eth.get_destination());
            reply.set_destination(eth.get_source());
            reply.set_ethertype(eth.get_ethertype());
            reply.set_payload(&payload);
            reply.packet().to_vec()
        }),
        _ => {
            eprintln!("Malformed Ethernet Packet");
            None
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let notifications = Arc::new(Mutex::new(Notifications::new()));
    let (mut child, vm) = spawn_vm();

    let temp_dir = tempdir::TempDir::new("ya-vm-network").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let (_p9streams, _muxer_handle) = vm.start_9p_service(&temp_path, &[]).await.unwrap();

    let ns = notifications.clone();

    let ga_mutex = GuestAgent::connected(vm.get_manager_sock(), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().lock().await.handle(n) }.boxed()
    })
    .await?;

    {
        notifications.clone().lock().await.set_ga(ga_mutex.clone());
    };

    handle_net(vm.get_net_sock()).await?;

    {
        let hosts = [("host0", "127.0.0.2"), ("host1", "127.0.0.3")]
            .iter()
            .map(|(h, i)| (h.to_string(), i.to_string()))
            .collect::<Vec<_>>();

        let mut ga = ga_mutex.lock().await;
        match ga.add_address("10.0.0.1", "255.255.255.0").await? {
            Ok(_) | Err(0) => (),
            Err(code) => anyhow::bail!("Unable to set address {}", code),
        }
        match ga
            .create_network("10.0.0.0", "255.255.255.0", "10.0.0.1")
            .await?
        {
            Ok(_) | Err(0) => (),
            Err(code) => anyhow::bail!("Unable to join network {}", code),
        }
        match ga.add_hosts(hosts.into_iter()).await? {
            Ok(_) | Err(0) => (),
            Err(code) => anyhow::bail!("Unable to add hosts {}", code),
        }
    }
    {
        let mut ga = ga_mutex.lock().await;
        run_process(
            &mut ga,
            "/bin/ping",
            &["ping", "-v", "-n", "-c", "3", "10.0.0.2"],
        )
        .await?;
    }

    /* VM should quit now. */
    let e = child.wait().await.expect("failed to wait on child");
    eprintln!("{:?}", e);

    Ok(())
}
