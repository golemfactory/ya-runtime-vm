use futures::lock::Mutex;
use futures::FutureExt;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, PacketSize};
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
use tokio::net::UnixStream;
use tokio::{
    process::{Child, Command},
    sync,
};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};

const IDENTIFICATION: AtomicU16 = AtomicU16::new(42);

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
                            Err(code) => println!("Output query failed with: {}", code),
                        },
                        Err(code) => println!("Output query failed with: {}", code),
                    }
                });
            }
            Notification::ProcessDied { id, reason } => {
                println!("Process {} died with {:?}", id, reason);
                self.process_died.notify();
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
    println!("Spawned process with id: {}", id);
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
    path.as_ref()
        .join(file.to_string())
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn spawn_vm<'a, P: AsRef<Path>>(temp_path: P) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let socket_path = temp_path.as_ref().join(format!("manager.sock"));
    let socket_net_path = temp_path.as_ref().join(format!("net.sock"));

    let chardev =
        |name, path: &PathBuf| format!("socket,path={},server,nowait,id={}", path.display(), name);

    let mut cmd = Command::new("vmrt");
    cmd.current_dir(runtime_dir).args(&[
        "-m",
        "256m",
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        join_as_string(&init_dir, "vmlinuz-virt").as_str(),
        "-initrd",
        join_as_string(&init_dir, "initramfs.cpio.gz").as_str(),
        "-no-reboot",
        "-net",
        "none",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-append",
        "console=ttyS0 panic=1",
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        chardev("manager_cdev", &socket_path).as_str(),
        "-chardev",
        chardev("net_cdev", &socket_net_path).as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-device",
        "virtserialport,chardev=net_cdev,name=net_port",
        "-drive",
        format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            root_dir.join("squashfs_drive").display()
        )
        .as_str(),
    ]);
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn VM")
}

async fn handle_net<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let stream = UnixStream::connect(path.as_ref()).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    let fut = async move {
        let mut buf: [u8; 1500] = [0u8; 1500];
        loop {
            let count = match read.read(&mut buf).await {
                Err(e) => break println!("Read error: {:?}", e),
                Ok(0) => break println!("No more data to read"),
                Ok(c) => c,
            };
            if let Some(res) = handle_ethernet_packet(&buf[..count]) {
                if let Err(e) = write.write_all(&res).await {
                    println!("Write error: {:?}", e);
                }
            }
        }
    };

    tokio::spawn(fut);
    Ok(())
}

fn handle_udp(src: IpAddr, dst: IpAddr, packet: &[u8]) -> Option<Vec<u8>> {
    if let Some(udp) = UdpPacket::new(packet) {
        println!(
            "UDP Packet: {}:{} > {}:{}; length: {}",
            src,
            udp.get_source(),
            dst,
            udp.get_destination(),
            udp.get_length()
        );
    }
    None
}

fn handle_tcp(src: IpAddr, dst: IpAddr, packet: &[u8]) -> Option<Vec<u8>> {
    if let Some(tcp) = TcpPacket::new(packet) {
        println!(
            "TCP Packet: {}:{} > {}:{}; length: {}",
            src,
            tcp.get_source(),
            dst,
            tcp.get_destination(),
            packet.len()
        );
    }
    None
}

fn handle_icmp(src: IpAddr, dst: IpAddr, packet: &[u8]) -> Option<Vec<u8>> {
    let icmp_packet = match IcmpPacket::new(packet) {
        Some(icmp_packet) => icmp_packet,
        None => return None,
    };

    match icmp_packet.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let reply = echo_reply::EchoReplyPacket::new(packet).unwrap();
            println!(
                "ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                src,
                dst,
                reply.get_sequence_number(),
                reply.get_identifier()
            );
        }
        IcmpTypes::EchoRequest => {
            let request = echo_request::EchoRequestPacket::new(packet).unwrap();
            println!(
                "ICMP echo request {} -> {} (seq={:?}, id={:?}, size={})",
                src,
                dst,
                request.get_sequence_number(),
                request.get_identifier(),
                request.packet_size(),
            );

            let mut data: Vec<u8> = vec![0u8; 64];
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
        _ => println!(
            "ICMP packet {} -> {} (type={:?})",
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
        IpNextHeaderProtocols::Udp => handle_udp(src, dst, packet),
        IpNextHeaderProtocols::Tcp => handle_tcp(src, dst, packet),
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
                let mut data: Vec<u8> = vec![0u8; 1500];
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
            println!("Malformed IPv4 Packet");
            None
        }
    }
}

fn handle_arp_packet(data: &[u8]) -> Option<Vec<u8>> {
    match ArpPacket::new(data) {
        Some(arp) => match arp.get_operation() {
            ArpOperations::Request => {
                println!("Arp packet");

                let mut buffer = [0u8; 28];
                let mut reply = MutableArpPacket::new(&mut buffer).unwrap();

                reply.set_hardware_type(arp.get_hardware_type());
                reply.set_protocol_type(arp.get_protocol_type());
                reply.set_hw_addr_len(arp.get_hw_addr_len());
                reply.set_proto_addr_len(arp.get_proto_addr_len());
                reply.set_operation(ArpOperations::Reply);
                reply.set_sender_hw_addr(arp.get_target_hw_addr());
                reply.set_sender_proto_addr(arp.get_target_proto_addr());
                reply.set_target_hw_addr(arp.get_sender_hw_addr());
                reply.set_target_proto_addr(arp.get_sender_proto_addr());

                return Some(reply.packet().to_vec());
            }
            _ => (),
        },
        _ => {
            println!("Malformed ARP Packet");
        }
    };
    None
}

fn handle_ethernet_packet(data: &[u8]) -> Option<Vec<u8>> {
    match EthernetPacket::new(data) {
        Some(eth) => match eth.get_ethertype() {
            EtherTypes::Ipv4 => handle_ipv4_packet(eth.payload()),
            EtherTypes::Arp => {
                println!("Got ARP packet");
                handle_arp_packet(eth.payload())
            }
            eth_type => {
                println!("Got ethernet packet: {:?}", eth_type);
                None
            }
        }
        .map(move |payload| {
            let mut data: Vec<u8> = vec![0u8; 1500];
            let mut reply = MutableEthernetPacket::new(&mut data).unwrap();
            reply.set_source(eth.get_destination());
            reply.set_destination(eth.get_source());
            reply.set_ethertype(eth.get_ethertype());
            reply.set_payload(&payload);
            reply.packet().to_vec()
        }),
        _ => {
            println!("Malformed Ethernet Packet");
            None
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();

    let notifications = Arc::new(Mutex::new(Notifications::new()));
    let child = spawn_vm(&temp_path);

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(temp_path.join("manager.sock"), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().lock().await.handle(n) }.boxed()
    })
    .await?;

    {
        notifications.clone().lock().await.set_ga(ga_mutex.clone());
    };

    handle_net(temp_path.join("net.sock")).await?;

    {
        let hosts = [
            ("host0", "127.0.0.1"),
            ("host1", "127.0.0.1"),
            ("host2", "127.0.0.1"),
            ("host3", "127.0.0.1"),
            ("host4", "127.0.0.1"),
            ("host5", "127.0.0.1"),
        ]
        .iter()
        .map(|(h, i)| (h.to_string(), i.to_string()))
        .collect::<Vec<_>>();

        let mut ga = ga_mutex.lock().await;
        match ga
            .create_network("10.0.0.10", "255.255.255.0", "10.0.0.1")
            .await?
        {
            Ok(_) | Err(0) => (),
            Err(code) => anyhow::bail!("Unable to join network {}", code),
        }
        match ga
            .create_network("10.0.1.10", "255.255.255.0", "10.0.1.1")
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
        run_process(&mut ga, "/bin/cat", &["cat", "/etc/hosts"]).await?;
    }

    {
        let mut ga = ga_mutex.lock().await;
        run_process(&mut ga, "/bin/ip", &["ip", "-d", "a"]).await?;
    }
    {
        let mut ga = ga_mutex.lock().await;
        run_process(&mut ga, "/sbin/route", &["route", "-n"]).await?;
    }
    {
        let mut ga = ga_mutex.lock().await;
        run_process(
            &mut ga,
            "/bin/ip",
            &["ip", "route", "show", "table", "local"],
        )
        .await?;
    }
    {
        let mut ga = ga_mutex.lock().await;
        run_process(
            &mut ga,
            "/bin/ping",
            &["ping", "-v", "-n", "-D", "-c", "3", "10.0.1.4"],
        )
        .await?;
    }

    /* VM should quit now. */
    let e = child.await.expect("failed to wait on child");
    println!("{:?}", e);

    Ok(())
}
