use std::convert::TryFrom;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub enum Response {
    Ok,
    OkU64(u64),
    OkBytes(Vec<u8>),
    Err(u32),
}

#[derive(Debug)]
pub enum ExitType {
    Exited,
    Killed,
    Dumped,
}

impl TryFrom<u8> for ExitType {
    type Error = io::Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(ExitType::Exited),
            1 => Ok(ExitType::Killed),
            2 => Ok(ExitType::Dumped),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid exit type",
            )),
        }
    }
}

#[derive(Debug)]
pub struct ExitReason {
    pub status: u8,
    pub type_: ExitType,
}

#[derive(Debug)]
pub enum Notification9p {
    OutputAvailable { id: u64, fd: u32 },
    ProcessDied { id: u64, reason: ExitReason },
}

#[derive(Debug)]
pub struct ResponseCustomP9 {
    pub id: u64,
    pub resp: Response,
}

#[derive(Debug)]
pub enum GuestAgentMessage9p {
    Response(ResponseCustomP9),
    Notification(Notification9p),
}

async fn recv_u8<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<u8> {
    let mut buf = [0; 1];
    stream.read_exact(&mut buf).await?;
    Ok(u8::from_le_bytes(buf))
}

async fn recv_u32<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<u32> {
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await?;
    Ok(u32::from_le_bytes(buf))
}

async fn recv_u64<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<u64> {
    let mut buf = [0; 8];
    stream.read_exact(&mut buf).await?;
    Ok(u64::from_le_bytes(buf))
}

async fn recv_bytes<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<Vec<u8>> {
    let len = recv_u64(stream).await?;
    let mut buf = vec![0; len as usize];
    stream.read_exact(buf.as_mut_slice()).await?;
    Ok(buf)
}

pub async fn parse_one_response_9p<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> io::Result<GuestAgentMessage9p> {
    let id = recv_u64(stream).await?;

    let typ = recv_u8(stream).await?;

    Ok(GuestAgentMessage9p::Response(ResponseCustomP9 {
        id: 0,
        resp: Response::Err(0),
    }))

}
