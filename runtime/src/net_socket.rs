// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UDP/TCP Ethernet frame transport for the OpenVMM network backend.

use async_trait::async_trait;
use futures::AsyncRead;
use futures::AsyncWrite;
use inspect::InspectMut;
use mesh::MeshPayload;
use net_backend::linearize;
use net_backend::next_packet;
use net_backend::BufferAccess;
use net_backend::Endpoint;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::TxError;
use net_backend::TxId;
use net_backend::TxSegment;
use pal_async::driver::Driver;
use pal_async::socket::PolledSocket;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::Context;
use std::task::Poll;

#[derive(Clone, Debug, PartialEq, MeshPayload)]
pub enum SocketMode {
    Udp,
    TcpConnect,
    TcpListen,
}

static REGISTERED_ENDPOINTS: OnceLock<Mutex<HashMap<String, SocketEndpoint>>> = OnceLock::new();

fn registered_endpoints() -> &'static Mutex<HashMap<String, SocketEndpoint>> {
    REGISTERED_ENDPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Default)]
pub(crate) struct SocketRegistrationGuard(Vec<String>);

impl SocketRegistrationGuard {
    pub(crate) fn register(&mut self, endpoint: SocketEndpoint) -> (String, SocketAddr) {
        let local = endpoint.local_addr();
        let id = uuid::Uuid::new_v4().to_string();
        registered_endpoints().lock().insert(id.clone(), endpoint);
        self.0.push(id.clone());
        (id, local)
    }
}

impl Drop for SocketRegistrationGuard {
    fn drop(&mut self) {
        let mut endpoints = registered_endpoints().lock();
        for id in &self.0 {
            endpoints.remove(id);
        }
    }
}

pub(crate) fn take_registered_endpoint(id: &str) -> anyhow::Result<SocketEndpoint> {
    registered_endpoints()
        .lock()
        .remove(id)
        .ok_or_else(|| anyhow::anyhow!("socket endpoint {id} was not registered"))
}

pub struct SocketEndpoint {
    mode: SocketMode,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    prepared_socket: Mutex<Option<Socket>>,
}

impl SocketEndpoint {
    pub fn new(
        mode: SocketMode,
        local: SocketAddr,
        remote: Option<SocketAddr>,
    ) -> anyhow::Result<Self> {
        let mut local = local;
        let prepared_socket = match &mode {
            SocketMode::Udp => {
                let socket = Socket::new(domain(local), Type::DGRAM, Some(Protocol::UDP))?;
                socket.bind(&local.into())?;
                socket.connect(
                    &remote
                        .ok_or_else(|| {
                            anyhow::anyhow!("UDP socket endpoint requires a remote address")
                        })?
                        .into(),
                )?;
                local = socket_local_addr(&socket)?;
                Some(socket)
            }
            SocketMode::TcpListen => {
                let socket = Socket::new(domain(local), Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                socket.bind(&local.into())?;
                socket.listen(1)?;
                local = socket_local_addr(&socket)?;
                Some(socket)
            }
            SocketMode::TcpConnect => None,
        };

        Ok(Self {
            mode,
            local,
            remote,
            prepared_socket: Mutex::new(prepared_socket),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn take_prepared_socket(&self) -> anyhow::Result<Socket> {
        if let Some(socket) = self.prepared_socket.lock().take() {
            return Ok(socket);
        }

        match &self.mode {
            SocketMode::Udp => {
                let socket = Socket::new(domain(self.local), Type::DGRAM, Some(Protocol::UDP))?;
                socket.bind(&self.local.into())?;
                socket.connect(
                    &self
                        .remote
                        .ok_or_else(|| {
                            anyhow::anyhow!("UDP socket endpoint requires a remote address")
                        })?
                        .into(),
                )?;
                Ok(socket)
            }
            SocketMode::TcpListen => {
                let socket = Socket::new(domain(self.local), Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                socket.bind(&self.local.into())?;
                socket.listen(1)?;
                Ok(socket)
            }
            SocketMode::TcpConnect => anyhow::bail!("TCP client socket is not pre-bound"),
        }
    }
}

fn socket_local_addr(socket: &Socket) -> io::Result<SocketAddr> {
    socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "expected IP socket"))
}

fn domain(address: SocketAddr) -> Domain {
    if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

impl InspectMut for SocketEndpoint {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond();
    }
}

#[async_trait]
impl Endpoint for SocketEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "ya-socket"
    }

    async fn get_queues(
        &mut self,
        mut config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(config.len() == 1, "socket endpoint supports one queue");
        let config = config.pop().unwrap();
        let driver = config.driver;
        let queue = SocketQueue::new(self, driver).await?;
        queues.push(Box::new(queue));
        Ok(())
    }

    async fn stop(&mut self) {}

    fn is_ordered(&self) -> bool {
        true
    }
}

enum Connection {
    Udp(PolledSocket<Socket>),
    Tcp {
        listener: Option<PolledSocket<Socket>>,
        stream: Option<PolledSocket<Socket>>,
    },
}

struct SocketQueue {
    driver: Box<dyn Driver>,
    connection: Connection,
    rx_free: VecDeque<RxId>,
    rx_ready: VecDeque<RxId>,
    tcp_rx: Vec<u8>,
    tx: VecDeque<Vec<u8>>,
    tx_offset: usize,
    buffer: Box<[u8]>,
}

impl InspectMut for SocketQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond();
    }
}

impl SocketQueue {
    async fn new(endpoint: &SocketEndpoint, driver: Box<dyn Driver>) -> anyhow::Result<Self> {
        let connection = match &endpoint.mode {
            SocketMode::Udp => {
                let socket = endpoint.take_prepared_socket()?;
                Connection::Udp(PolledSocket::new(driver.as_ref(), socket)?)
            }
            SocketMode::TcpConnect => {
                let remote = endpoint.remote.ok_or_else(|| {
                    anyhow::anyhow!("TCP client endpoint requires a remote address")
                })?;
                let socket = Socket::new(domain(remote), Type::STREAM, Some(Protocol::TCP))?;
                let mut socket = PolledSocket::new(driver.as_ref(), socket)?;
                socket.connect(&remote.into()).await?;
                Connection::Tcp {
                    listener: None,
                    stream: Some(socket),
                }
            }
            SocketMode::TcpListen => {
                let socket = endpoint.take_prepared_socket()?;
                Connection::Tcp {
                    listener: Some(PolledSocket::new(driver.as_ref(), socket)?),
                    stream: None,
                }
            }
        };

        Ok(Self {
            driver,
            connection,
            rx_free: VecDeque::new(),
            rx_ready: VecDeque::new(),
            tcp_rx: Vec::new(),
            tx: VecDeque::new(),
            tx_offset: 0,
            buffer: vec![0; 65535].into_boxed_slice(),
        })
    }

    fn enqueue_rx(&mut self, pool: &mut dyn BufferAccess) {
        while let Some(&id) = self.rx_free.front() {
            if self.tcp_rx.len() < 4 {
                return;
            }
            let frame_len = u32::from_be_bytes(self.tcp_rx[..4].try_into().unwrap()) as usize;
            if frame_len > self.buffer.len() {
                self.tcp_rx.clear();
                return;
            }
            if self.tcp_rx.len() < 4 + frame_len {
                return;
            }
            let frame = self.tcp_rx[4..4 + frame_len].to_vec();
            self.tcp_rx.drain(..4 + frame_len);
            pool.write_packet(
                id,
                &RxMetadata {
                    offset: 0,
                    len: frame.len(),
                    ..Default::default()
                },
                &frame,
            );
            self.rx_free.pop_front();
            self.rx_ready.push_back(id);
        }
    }

    fn poll_tcp_accept(&mut self, cx: &mut Context<'_>) {
        let Connection::Tcp {
            listener: Some(listener),
            stream,
        } = &mut self.connection
        else {
            return;
        };
        if stream.is_some() {
            return;
        }
        match listener.poll_accept(cx) {
            Poll::Ready(Ok((socket, _))) => match PolledSocket::new(self.driver.as_ref(), socket) {
                Ok(socket) => *stream = Some(socket),
                Err(error) => log::warn!("failed to poll accepted network socket: {error}"),
            },
            Poll::Ready(Err(error)) => log::warn!("failed to accept network socket: {error}"),
            Poll::Pending => {}
        }
    }

    fn poll_tx(&mut self, cx: &mut Context<'_>) {
        match &mut self.connection {
            Connection::Udp(socket) => {
                while let Some(packet) = self.tx.front() {
                    match Pin::new(&mut *socket).poll_write(cx, packet) {
                        Poll::Ready(Ok(n)) if n == packet.len() => {
                            self.tx.pop_front();
                        }
                        Poll::Ready(Ok(_)) => {
                            self.tx.pop_front();
                        }
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Poll::Ready(Err(error)) => {
                            log::warn!("UDP frame send failed: {error}");
                            self.tx.pop_front();
                        }
                        Poll::Pending => break,
                    }
                }
            }
            Connection::Tcp { stream, .. } => {
                let stream_slot = stream;
                let Some(stream) = stream_slot.as_mut() else {
                    self.tx.clear();
                    self.tx_offset = 0;
                    return;
                };
                while let Some(packet) = self.tx.front() {
                    match Pin::new(&mut *stream).poll_write(cx, &packet[self.tx_offset..]) {
                        Poll::Ready(Ok(0)) => {
                            *stream_slot = None;
                            self.tx.clear();
                            self.tx_offset = 0;
                            break;
                        }
                        Poll::Ready(Ok(n)) => {
                            self.tx_offset += n;
                            if self.tx_offset == packet.len() {
                                self.tx.pop_front();
                                self.tx_offset = 0;
                            }
                        }
                        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Poll::Ready(Err(error)) => {
                            log::warn!("TCP frame send failed: {error}");
                            *stream_slot = None;
                            self.tx.clear();
                            self.tx_offset = 0;
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
            }
        }
    }
}

impl Queue for SocketQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, pool: &mut dyn BufferAccess) -> Poll<()> {
        self.poll_tcp_accept(cx);
        self.poll_tx(cx);
        // A failed send may have closed the active stream; arrange another
        // accept before returning Pending so the listener can wake us.
        self.poll_tcp_accept(cx);
        if !self.rx_ready.is_empty() {
            return Poll::Ready(());
        }

        self.enqueue_rx(pool);
        while !self.rx_free.is_empty() && self.rx_ready.is_empty() {
            let read = match &mut self.connection {
                Connection::Udp(socket) => Pin::new(socket).poll_read(cx, &mut self.buffer),
                Connection::Tcp { stream, .. } => {
                    let stream_slot = stream;
                    let Some(stream) = stream_slot.as_mut() else {
                        break;
                    };
                    match Pin::new(stream).poll_read(cx, &mut self.buffer) {
                        Poll::Ready(Ok(0)) => {
                            *stream_slot = None;
                            self.tcp_rx.clear();
                            break;
                        }
                        result => result,
                    }
                }
            };

            match read {
                Poll::Ready(Ok(0)) => {
                    // The active TCP stream may have ended. Re-arm the listener
                    // for a later peer before yielding to the network device.
                    self.poll_tcp_accept(cx);
                }
                Poll::Ready(Ok(len)) => match &mut self.connection {
                    Connection::Udp(_) => {
                        let id = self.rx_free.pop_front().unwrap();
                        pool.write_packet(
                            id,
                            &RxMetadata {
                                offset: 0,
                                len,
                                ..Default::default()
                            },
                            &self.buffer[..len],
                        );
                        self.rx_ready.push_back(id);
                    }
                    Connection::Tcp { .. } => {
                        self.tcp_rx.extend_from_slice(&self.buffer[..len]);
                        self.enqueue_rx(pool);
                    }
                },
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => break,
                Poll::Ready(Err(error)) => {
                    log::warn!("network frame receive failed: {error}");
                    break;
                }
                Poll::Pending => break,
            }
            if !self.rx_ready.is_empty() {
                break;
            }
        }

        if self.rx_ready.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.rx_free.extend(done);
    }

    fn rx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        let count = packets.len().min(self.rx_ready.len());
        for (out, id) in packets[..count]
            .iter_mut()
            .zip(self.rx_ready.drain(..count))
        {
            *out = id;
        }
        Ok(count)
    }

    fn tx_avail(
        &mut self,
        pool: &mut dyn BufferAccess,
        mut segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        let count = segments.len();
        while !segments.is_empty() {
            let (_metadata, _packet, _rest) = next_packet(segments);
            let packet = linearize(pool, &mut segments)?;
            match &self.connection {
                Connection::Udp(_) => self.tx.push_back(packet),
                Connection::Tcp { .. } => {
                    let len = u32::try_from(packet.len())?;
                    let mut framed = Vec::with_capacity(4 + packet.len());
                    framed.extend_from_slice(&len.to_be_bytes());
                    framed.extend_from_slice(&packet);
                    self.tx.push_back(framed);
                }
            }
        }
        Ok((true, count))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        _done: &mut [TxId],
    ) -> Result<usize, TxError> {
        Ok(0)
    }
}
