//! Shared, versioned protocol for the host runtime and Linux guest agent.
#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
use alloc::{string::String, vec::Vec};
pub use postcard::Error as CodecError;
use serde::{Deserialize, Serialize};

// Version 3 adds `Network::mtu`. Postcard fields are positional, so older
// peers cannot decode it; READY rejects the mismatch.
pub const VERSION: u16 = 3;
pub const VSOCK_PORT: u32 = 1024;
pub const MAX_FRAME: usize = 1024 * 1024;
pub const OUTPUT_CHUNK: usize = 64 * 1024;
const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    Ready {
        version: u16,
    },
    Request {
        id: u64,
        command: Command,
    },
    Response {
        id: u64,
        result: Result<Value, AgentError>,
    },
    Event(Event),
    /// Host confirms output and the terminal status have entered the client queue.
    ExitAck {
        id: u64,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    Run(Run),
    Kill {
        id: u64,
    },
    Mount {
        tag: String,
        path: Vec<u8>,
    },
    QueryOutput {
        id: u64,
        fd: u8,
        offset: u64,
        len: u64,
    },
    Network(Network),
    Hosts {
        entries: Vec<(String, String)>,
    },
    Quit,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Run {
    pub bin: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub env: Option<Vec<Vec<u8>>>,
    pub uid: u32,
    pub gid: u32,
    pub fds: [Option<Redirect>; 3],
    pub cwd: Option<Vec<u8>>,
    pub entrypoint: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Redirect {
    File(Vec<u8>),
    Pipe { capacity: u64, cyclic: bool },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Network {
    pub iface: u16,
    pub addr: Option<String>,
    pub mask: Option<String>,
    pub gateway: Option<String>,
    pub if_addr: Option<String>,
    /// Interface MTU chosen by the host; `None` keeps the current value.
    pub mtu: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Value {
    Ok,
    Id(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentError {
    pub errno: u32,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Event {
    OutputAvailable { id: u64, fd: u32 },
    ProcessDied { id: u64, reason: ExitReason },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitReason {
    pub status: u8,
    pub type_: ExitType,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExitType {
    Exited,
    Killed,
    Dumped,
}

pub fn encode(message: &Message) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec_crc32(message, CRC.digest())
}

pub fn decode(bytes: &[u8]) -> Result<Message, postcard::Error> {
    postcard::from_bytes_crc32(bytes, CRC.digest())
}

#[derive(Debug, Clone, Copy)]
pub struct FrameSizeError;
impl core::fmt::Display for FrameSizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("agent frame exceeds size limit")
    }
}
impl core::error::Error for FrameSizeError {}
#[cfg(feature = "std")]
impl From<FrameSizeError> for std::io::Error {
    fn from(error: FrameSizeError) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, error)
    }
}
pub fn frame_len(bytes: [u8; 4]) -> Result<usize, FrameSizeError> {
    let len = u32::from_le_bytes(bytes) as usize;
    if !(4..=MAX_FRAME).contains(&len) {
        return Err(FrameSizeError);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc_rejects_a_corrupted_command() {
        let mut frame = encode(&Message::Request {
            id: 42,
            command: Command::Quit,
        })
        .unwrap();
        assert!(matches!(
            decode(&frame).unwrap(),
            Message::Request { id: 42, .. }
        ));
        frame[1] ^= 1;
        assert!(decode(&frame).is_err());
    }
    #[test]
    fn network_mtu_round_trips_when_present_or_absent() {
        for mtu in [None, Some(1220), Some(65266)] {
            let message = Message::Request {
                id: 7,
                command: Command::Network(Network {
                    iface: 1,
                    addr: None,
                    mask: Some("24".into()),
                    gateway: None,
                    if_addr: Some("10.0.0.2".into()),
                    mtu,
                }),
            };
            assert_eq!(decode(&encode(&message).unwrap()).unwrap(), message);
        }
    }
    #[test]
    fn frame_limit_rejects_length_before_allocation() {
        assert!(frame_len(0u32.to_le_bytes()).is_err());
        assert!(frame_len(u32::MAX.to_le_bytes()).is_err());
        assert_eq!(frame_len(128u32.to_le_bytes()).unwrap(), 128);
    }
}
