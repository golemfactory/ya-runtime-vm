//! Shared, versioned protocol for the host runtime and Linux guest agent.
use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
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

pub fn frame_len(bytes: [u8; 4]) -> std::io::Result<usize> {
    let len = u32::from_le_bytes(bytes) as usize;
    if !(4..=MAX_FRAME).contains(&len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent frame exceeds size limit",
        ));
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
    fn frame_limit_rejects_length_before_allocation() {
        assert!(frame_len(0u32.to_le_bytes()).is_err());
        assert!(frame_len(u32::MAX.to_le_bytes()).is_err());
        assert_eq!(frame_len(128u32.to_le_bytes()).unwrap(), 128);
    }
}
