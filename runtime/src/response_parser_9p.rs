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
pub struct Notification9p {
    pub tag: u8,
    pub bytes_to_9p_server: Vec<u8>,
}

#[derive(Debug)]
pub struct ResponseCustomP9 {
    pub tag: u8,
    pub resp: Vec<u8>,
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

async fn recv_bytes_32<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<Vec<u8>> {
    let len = recv_u32(stream).await?;
    let mut buf = vec![0; len as usize];
    stream.read_exact(buf.as_mut_slice()).await?;
    Ok(buf)
}

pub async fn parse_one_response_9p<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> io::Result<GuestAgentMessage9p> {
    log::debug!("parse_one_response_9p...");

    let tag = recv_u8(stream).await?;

    log::debug!("Got response: tag: {}", tag);

    //let bytes_num = recv_u32(stream).await?;

    //log::debug!("Got response: bytes_num: {}", bytes_num);

    let resp = recv_bytes_32(stream).await?;

    let chars: Vec<char> = resp.iter().map(|byte| *byte as char).collect();
    log::debug!("Got response: bytes: {:?}", chars);



    Ok(GuestAgentMessage9p::Notification(Notification9p {
        tag,
        bytes_to_9p_server: resp,
    }))

}
