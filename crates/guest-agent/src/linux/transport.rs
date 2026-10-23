//! Incremental, bounded framing for a nonblocking manager connection.
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
};
use ya_vm_agent_protocol::{Message, MAX_FRAME};

const MAX_PENDING: usize = 4 * (MAX_FRAME + 4);

#[derive(Default)]
struct Decoder {
    header: [u8; 4],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
}
impl Decoder {
    fn next(&mut self, stream: &mut File) -> io::Result<Option<Message>> {
        loop {
            let target = if self.header_read < 4 {
                &mut self.header[self.header_read..]
            } else {
                &mut self.body[self.body_read..]
            };
            let read = match stream.read(target) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "manager disconnected during frame",
                    ))
                }
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if self.header_read < 4 {
                self.header_read += read;
                if self.header_read == 4 {
                    self.body
                        .resize(ya_vm_agent_protocol::frame_len(self.header)?, 0);
                }
            } else {
                self.body_read += read;
                if self.body_read == self.body.len() {
                    let result = ya_vm_agent_protocol::decode(&self.body).map_err(io::Error::other);
                    self.header_read = 0;
                    self.body_read = 0;
                    self.body.clear();
                    return result.map(Some);
                }
            }
        }
    }
}

pub struct Connection {
    pub stream: File,
    decoder: Decoder,
    pending: VecDeque<Vec<u8>>,
    written: usize,
    pending_bytes: usize,
}
impl Connection {
    pub fn new(stream: File) -> io::Result<Self> {
        nonblocking(&stream)?;
        Ok(Self {
            stream,
            decoder: Decoder::default(),
            pending: VecDeque::new(),
            written: 0,
            pending_bytes: 0,
        })
    }
    pub fn next(&mut self) -> io::Result<Option<Message>> {
        self.decoder.next(&mut self.stream)
    }
    pub fn can_read(&self) -> bool {
        self.pending_bytes <= MAX_FRAME
    }
    pub fn wants_write(&self) -> bool {
        !self.pending.is_empty()
    }
    pub fn queue(&mut self, message: &Message) -> io::Result<()> {
        let frame = ya_vm_agent_protocol::encode(message).map_err(io::Error::other)?;
        if frame.len() > MAX_FRAME || self.pending_bytes + frame.len() + 4 > MAX_PENDING {
            return Err(io::Error::other("manager transmit queue exceeds limit"));
        }
        let mut bytes = Vec::with_capacity(frame.len() + 4);
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&frame);
        self.pending_bytes += bytes.len();
        self.pending.push_back(bytes);
        Ok(())
    }
    pub fn flush(&mut self) -> io::Result<()> {
        while let Some(frame) = self.pending.front() {
            match self.stream.write(&frame[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.written += n;
                    self.pending_bytes -= n;
                    if self.written == frame.len() {
                        self.pending.pop_front();
                        self.written = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
pub fn nonblocking(fd: &impl rustix::fd::AsFd) -> io::Result<()> {
    rustix::fs::fcntl_setfl(
        fd,
        rustix::fs::fcntl_getfl(fd)? | rustix::fs::OFlags::NONBLOCK,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use ya_vm_agent_protocol::{Command, Value};

    fn pair() -> (Connection, File) {
        let (a, b) = UnixStream::pair().unwrap();
        (
            Connection::new(OwnedFd::from(a).into()).unwrap(),
            OwnedFd::from(b).into(),
        )
    }
    #[test]
    fn partial_prefix_and_payload_do_not_block_the_reactor() {
        let (mut connection, mut peer) = pair();
        let message = Message::Request {
            id: 8,
            command: Command::Quit,
        };
        let frame = ya_vm_agent_protocol::encode(&message).unwrap();
        let header = (frame.len() as u32).to_le_bytes();
        peer.write_all(&header[..2]).unwrap();
        assert!(connection.next().unwrap().is_none());
        peer.write_all(&header[2..]).unwrap();
        peer.write_all(&frame[..1]).unwrap();
        assert!(connection.next().unwrap().is_none());
        peer.write_all(&frame[1..]).unwrap();
        assert_eq!(connection.next().unwrap(), Some(message));
        assert!(connection.next().unwrap().is_none());
        peer.write_all(&u32::MAX.to_le_bytes()).unwrap();
        assert!(connection.next().is_err());
    }
    #[test]
    fn queued_frames_survive_partial_writes_and_slow_receivers() {
        let (mut connection, mut peer) = pair();
        nonblocking(&peer).unwrap();
        let message = Message::Response {
            id: 7,
            result: Ok(Value::Bytes(vec![42; 64 * 1024])),
        };
        let payload = ya_vm_agent_protocol::encode(&message).unwrap();
        let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&payload);
        for _ in 0..16 {
            connection.queue(&message).unwrap();
        }
        connection.flush().unwrap();
        assert!(connection.wants_write());
        let expected = frame.repeat(16);
        let mut got = Vec::new();
        let mut scratch = [0; 8192];
        while got.len() < expected.len() {
            loop {
                match peer.read(&mut scratch) {
                    Ok(n) => got.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    other => panic!("unexpected read: {other:?}"),
                }
            }
            connection.flush().unwrap();
        }
        assert!(!connection.wants_write());
        assert_eq!(got, expected);
    }
}
