//! Small Ethernet peer for VM tests. It answers ARP/NDP and echoes only the
//! labelled UDP test packets; it never forwards traffic to the host network.
use anyhow::ensure;
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use ya_runtime_sdk::server::ContainerEndpoint;

#[derive(Clone, Copy, Debug)]
pub enum Transport {
    Udp,
    Connect,
    Listen,
}

pub struct Peer {
    role: u16,
    pub endpoint: ContainerEndpoint,
    task: Option<JoinHandle<()>>,
    packets: Arc<[AtomicUsize; 2]>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
fn spawn(future: impl Future<Output = anyhow::Result<()>> + Send + 'static) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = future.await {
            log::error!("VM Ethernet test peer: {error:#}");
        }
    })
}
impl Peer {
    pub async fn new(role: u16, transport: Transport) -> anyhow::Result<Self> {
        let packets = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let (endpoint, task) = match transport {
            Transport::Udp => {
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                let endpoint = ContainerEndpoint::UdpDatagram(socket.local_addr()?);
                let observed = packets.clone();
                let task = spawn(async move {
                    let mut buffer = vec![0; 65535];
                    loop {
                        let (size, peer) = socket.recv_from(&mut buffer).await?;
                        if let Some(reply) = response(&buffer[..size], role, &observed)? {
                            socket.send_to(&reply, peer).await?;
                        }
                    }
                });
                (endpoint, Some(task))
            }
            Transport::Connect => {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let endpoint = ContainerEndpoint::TcpStream(listener.local_addr()?);
                let observed = packets.clone();
                let task = spawn(async move {
                    let (stream, _) = listener.accept().await?;
                    tcp(stream, role, observed).await
                });
                (endpoint, Some(task))
            }
            Transport::Listen => (ContainerEndpoint::TcpListener("127.0.0.1:0".parse()?), None),
        };
        Ok(Self {
            role,
            endpoint,
            task,
            packets,
        })
    }
    pub async fn attach(&mut self, endpoint: ContainerEndpoint) -> anyhow::Result<()> {
        if self.task.is_none() {
            // The runtime listens; its returned endpoint tells this peer to connect.
            let ContainerEndpoint::TcpStream(address) = endpoint else {
                anyhow::bail!(
                    "runtime did not expose a connectable TCP frame endpoint: {endpoint:?}"
                )
            };
            let stream = TcpStream::connect(address).await?;
            self.task = Some(spawn(tcp(stream, self.role, self.packets.clone())));
        }
        Ok(())
    }
    pub fn verify(&self) -> anyhow::Result<()> {
        for (family, count) in self.packets.iter().enumerate() {
            // The VPN MTU of 1220 is below IPv6's minimum of 1280.
            let expected = if self.role == 0 && family == 1 { 0 } else { 3 };
            ensure!(
                count.load(Ordering::Relaxed) == expected,
                "role {} IPv{} did not carry all test datagrams",
                self.role,
                if family == 0 { 4 } else { 6 }
            );
        }
        Ok(())
    }
}
async fn tcp(
    mut stream: TcpStream,
    role: u16,
    packets: Arc<[AtomicUsize; 2]>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        let size = match stream.read_u32().await {
            Ok(size) => size as usize,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            (14..=65535).contains(&size),
            "invalid Ethernet frame size {size}"
        );
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame).await?;
        if let Some(reply) = response(&frame, role, &packets)? {
            let prefix = (reply.len() as u32).to_be_bytes();
            // Exercise partial framing in the runtime, including a split length.
            stream.write_all(&prefix[..1]).await?;
            tokio::task::yield_now().await;
            stream.write_all(&prefix[1..]).await?;
            for part in reply.chunks(511) {
                stream.write_all(part).await?;
            }
        }
    }
}
fn word(bytes: &[u8], offset: usize) -> usize {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize
}
fn checksum(parts: &[&[u8]]) -> [u8; 2] {
    let bytes = parts.concat();
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|part| u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (!(sum as u16)).to_be_bytes()
}
fn swap(frame: &mut [u8], left: usize, right: usize, count: usize) {
    for n in 0..count {
        frame.swap(left + n, right + n);
    }
}
fn response(
    frame: &[u8],
    role: u16,
    packets: &[AtomicUsize; 2],
) -> anyhow::Result<Option<Vec<u8>>> {
    ensure!(frame.len() >= 14, "truncated Ethernet frame");
    let mac = [2, 0, 0, 0, 0, 0x10 + role as u8];
    let ipv4 = [10, 71 + role as u8, 0, 1];
    let ipv6 = format!("fd00:{}::1", 71 + role)
        .parse::<std::net::Ipv6Addr>()?
        .octets();
    match word(frame, 12) {
        0x0806 if frame.len() >= 42 && word(frame, 20) == 1 && frame[38..42] == ipv4 => {
            let mut reply = frame[..42].to_vec();
            reply[..6].copy_from_slice(&frame[6..12]);
            reply[6..12].copy_from_slice(&mac);
            reply[20..22].copy_from_slice(&2u16.to_be_bytes());
            reply[32..42].copy_from_slice(&frame[22..32]);
            reply[22..28].copy_from_slice(&mac);
            reply[28..32].copy_from_slice(&ipv4);
            Ok(Some(reply))
        }
        0x86dd
            if frame.len() >= 78
                && frame[20] == 58
                && frame[54] == 135
                && frame[62..78] == ipv6 =>
        {
            if frame[22..38].iter().all(|byte| *byte == 0) {
                return Ok(None);
            }
            let mut reply = vec![0; 86];
            reply[..6].copy_from_slice(&frame[6..12]);
            reply[6..12].copy_from_slice(&mac);
            reply[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            reply[14] = 0x60;
            reply[18..20].copy_from_slice(&32u16.to_be_bytes());
            reply[20] = 58;
            reply[21] = 255;
            reply[22..38].copy_from_slice(&ipv6);
            reply[38..54].copy_from_slice(&frame[22..38]);
            reply[54] = 136;
            reply[58] = 0xe0;
            reply[62..78].copy_from_slice(&ipv6);
            reply[78..80].copy_from_slice(&[2, 1]);
            reply[80..86].copy_from_slice(&mac);
            let sum = checksum(&[
                &reply[22..54],
                &32u32.to_be_bytes(),
                &[0, 0, 0, 58],
                &reply[54..],
            ]);
            reply[56..58].copy_from_slice(&sum);
            Ok(Some(reply))
        }
        // Large test datagrams must arrive whole, so reject IPv4 fragments.
        0x0800 if frame.len() >= 42 && frame[23] == 17 => {
            ensure!(word(frame, 20) & 0x3fff == 0, "IPv4 packet was fragmented");
            echo(frame, role, &mac, false, packets)
        }
        0x86dd if frame.len() >= 62 && frame[20] == 17 => echo(frame, role, &mac, true, packets),
        _ => Ok(None),
    }
}
fn echo(
    frame: &[u8],
    role: u16,
    mac: &[u8; 6],
    v6: bool,
    packets: &[AtomicUsize; 2],
) -> anyhow::Result<Option<Vec<u8>>> {
    let header = if v6 {
        40
    } else {
        (frame[14] as usize & 15) * 4
    };
    ensure!(
        header >= 20 && frame.len() >= 14 + header + 8,
        "truncated IP/UDP packet"
    );
    let udp = 14 + header;
    let size = word(frame, udp + 4);
    ensure!(size >= 8 && udp + size <= frame.len(), "invalid UDP size");
    let label = if role == 0 { "vpn" } else { "inet" };
    ensure!(
        word(frame, udp + 2) == 18000 + role as usize,
        "packet used the wrong virtual interface"
    );
    ensure!(
        frame[udp + 8..udp + size].starts_with(format!("REQ-{label}-").as_bytes()),
        "packet reached the wrong network peer"
    );
    let mut reply = frame[..udp + size].to_vec();
    reply[..6].copy_from_slice(&frame[6..12]);
    reply[6..12].copy_from_slice(mac);
    swap(&mut reply, udp, udp + 2, 2);
    reply[udp + 8..udp + 11].copy_from_slice(b"ACK");
    reply[udp + 6..udp + 8].fill(0);
    let length = (size as u16).to_be_bytes();
    let sum = if v6 {
        swap(&mut reply, 22, 38, 16);
        checksum(&[
            &reply[22..54],
            &(size as u32).to_be_bytes(),
            &[0, 0, 0, 17],
            &reply[udp..],
        ])
    } else {
        swap(&mut reply, 26, 30, 4);
        reply[24..26].fill(0);
        let ip_sum = checksum(&[&reply[14..udp]]);
        reply[24..26].copy_from_slice(&ip_sum);
        checksum(&[&reply[26..34], &[0, 17], &length, &reply[udp..]])
    };
    reply[udp + 6..udp + 8].copy_from_slice(if sum == [0, 0] { &[255, 255] } else { &sum });
    packets[usize::from(v6)].fetch_add(1, Ordering::Relaxed);
    Ok(Some(reply))
}
