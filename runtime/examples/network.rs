use futures::FutureExt;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::{io::prelude::*, sync::atomic::AtomicU16};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use structopt::StructOpt;

use std::time::Duration;
#[cfg(windows)]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use ya_runtime_vm::local_notification_handler::start_local_agent_communication;
use ya_runtime_vm::local_spawn_vm::{prepare_mount_directories, prepare_tmp_path, spawn_vm};

#[cfg(unix)]
type PlatformStream = UnixStream;
#[cfg(windows)]
type PlatformStream = TcpStream;

const IDENTIFICATION: AtomicU16 = AtomicU16::new(42);
const MTU: usize = 65535;
const PREFIX_LEN: usize = 2;

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

#[derive(Debug, StructOpt)]
#[structopt(name = "options", about = "Options for VM")]
pub struct Opt {
    /// Number of logical CPU cores
    #[structopt(long, default_value = "1")]
    cpu_cores: usize,
    /// Amount of RAM [GiB]
    #[structopt(long, default_value = "0.25")]
    mem_gib: f64,
    /// Amount of disk storage [GiB]
    #[allow(unused)]
    #[structopt(long, default_value = "0.25")]
    storage_gib: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::init();

    log::info!("Running example fs_benchmark...");

    let temp_path = prepare_tmp_path();
    let mount_args = prepare_mount_directories(&temp_path, 2);

    let mut vm_runner = spawn_vm(&temp_path, opt.cpu_cores, opt.mem_gib, false).await?;

    //let VM start before trying to connect p9 service
    tokio::time::sleep(Duration::from_secs_f64(2.5)).await;

    let (_p9streams, _muxer_handle) = vm_runner
        .start_9p_service(&temp_path, &mount_args)
        .await
        .unwrap();

    let comm = start_local_agent_communication(vm_runner.get_vm().get_manager_sock()).await?;

    comm.run_mount(&mount_args).await?;

    handle_net(vm_runner.get_vm().get_net_sock()).await?;

    {
        let hosts = [("host0", "127.0.0.2"), ("host1", "127.0.0.3")]
            .iter()
            .map(|(h, i)| (h.to_string(), i.to_string()))
            .collect::<Vec<_>>();

        let ga_mutex = comm.get_ga();
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
    comm.run_command("/bin/ping", &["ping", "-v", "-n", "-c", "3", "10.0.0.2"])
        .await?;

    /* VM should quit now. */
    //let e = timeout(Duration::from_secs(5), vm_runner..wait()).await;
    vm_runner.stop_vm(&Duration::from_secs(5), true).await?;

    Ok(())
}
