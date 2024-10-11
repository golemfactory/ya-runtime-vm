use std::io::{Read, Write};

use prost::Message;
use rinit_protos::rinit::api;
use smol::Async;

use crate::{die, enums::Response, process::ExitReason, utils::FdWrapper};

#[derive(Debug)]
pub struct MessageHeader {
    pub msg_id: u64,
    pub msg_type: u8,
}

impl MessageHeader {
    pub fn from_ne_bytes(buf: &[u8]) -> Self {
        Self {
            msg_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            msg_type: buf[8],
        }
    }

    pub fn to_ne_bytes(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0..8].copy_from_slice(&self.msg_id.to_le_bytes());
        buf[8] = self.msg_type;
        buf
    }
}

pub async fn async_read_n(
    async_fd: &mut Async<FdWrapper>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let n = unsafe {
            async_fd.read_with_mut(|fd| {
                let mut inner_buf = &mut buf[total..];
                fd.read(&mut inner_buf)
            })
        }
        .await?;
        if n == 0 {
            log::info!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }
        total += n;
    }

    Ok(total)
}

pub async fn async_write_n(async_fd: &mut Async<FdWrapper>, buf: &[u8]) -> std::io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let result = unsafe { async_fd.write_with_mut(|fd| fd.write(&buf[total..])) }.await?;
        if result == 0 {
            log::info!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        total += result;
    }

    Ok(total)
}

pub async fn async_write_u8(async_fd: &mut Async<FdWrapper>, value: u8) -> std::io::Result<usize> {
    let buf = [value];
    async_write_n(async_fd, &buf).await
}

pub async fn async_write_u32(
    async_fd: &mut Async<FdWrapper>,
    value: u32,
) -> std::io::Result<usize> {
    let buf = value.to_ne_bytes();
    async_write_n(async_fd, &buf).await
}

pub async fn async_write_u64(
    async_fd: &mut Async<FdWrapper>,
    value: u64,
) -> std::io::Result<usize> {
    let buf = value.to_ne_bytes();
    async_write_n(async_fd, &buf).await
}

pub async fn async_recv_bytes(async_fd: &mut Async<FdWrapper>) -> std::io::Result<Vec<u8>> {
    let size = async_recv_u64(async_fd).await?;

    let mut buf = vec![0u8; size as usize];
    async_read_n(async_fd, &mut buf[0..size as usize]).await?;

    Ok(buf)
}

pub async fn async_recv_strings_array(
    async_fd: &mut Async<FdWrapper>,
) -> std::io::Result<Vec<String>> {
    let size = async_recv_u64(async_fd).await?;

    let mut strings = Vec::with_capacity(size as usize);

    for _ in 0..size {
        let string = async_recv_bytes(async_fd).await?;
        let string = String::from_utf8(string).expect("Failed to convert bytes to string");
        strings.push(string);
    }

    Ok(strings)
}

pub async fn async_recv_u8(async_fd: &mut Async<FdWrapper>) -> std::io::Result<u8> {
    let mut buf = [0u8; 1];
    let result = async_read_n(async_fd, &mut buf).await?;

    if result < 1 {
        die!("Failed to read u8");
    }

    Ok(buf[0])
}

pub async fn async_recv_u32(async_fd: &mut Async<FdWrapper>) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    let result = async_read_n(async_fd, &mut buf).await?;

    if result < 4 {
        die!("Failed to read u32");
    }

    Ok(u32::from_ne_bytes(buf))
}

pub async fn async_recv_u64(async_fd: &mut Async<FdWrapper>) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    let result = async_read_n(async_fd, &mut buf).await?;

    if result < 8 {
        die!("Failed to read u64");
    }

    Ok(u64::from_be_bytes(buf))
}

pub async fn async_send_i32(async_fd: &mut Async<FdWrapper>, value: i32) -> std::io::Result<usize> {
    let buf = value.to_ne_bytes();
    let result = async_write_n(async_fd, &buf).await?;

    Ok(result)
}

pub async fn async_send_u64(async_fd: &mut Async<FdWrapper>, value: u64) -> std::io::Result<usize> {
    let buf = value.to_ne_bytes();
    let result = async_write_n(async_fd, &buf).await?;

    Ok(result)
}

async fn send_response_header(
    async_fd: &mut Async<FdWrapper>,
    message_id: u64,
    msg_type: Response,
) -> std::io::Result<()> {
    let header = MessageHeader {
        msg_id: message_id,
        msg_type: msg_type as u8,
    };

    log::trace!(
        " Sending response header: {:?} ({:?})",
        header,
        header.to_ne_bytes(),
    );

    async_write_n(async_fd, &header.to_ne_bytes()).await?;

    Ok(())
}

pub async fn send_response_u64(
    async_fd: &mut Async<FdWrapper>,
    message_id: u64,
    value: u64,
) -> std::io::Result<()> {
    send_response_header(async_fd, message_id, Response::OkU64).await?;

    async_send_u64(async_fd, value).await?;

    Ok(())
}

pub async fn async_send_response_ok(
    async_fd: &mut Async<FdWrapper>,
    message_id: u64,
) -> std::io::Result<()> {
    send_response_header(async_fd, message_id, Response::Ok).await
}

pub async fn send_response_error(
    async_fd: &mut Async<FdWrapper>,
    msg_id: u64,
    err_type: i32,
) -> std::io::Result<()> {
    send_response_header(async_fd, msg_id, Response::Error).await?;

    async_send_i32(async_fd, err_type).await?;

    Ok(())
}

pub async fn send_process_died(
    async_fd: &mut Async<FdWrapper>,
    proc_id: u64,
    exit_reason: ExitReason,
) -> std::io::Result<()> {
    send_response_header(async_fd, 0, Response::NotifyProcessDied).await?;
    async_write_u64(async_fd, proc_id).await?;
    async_write_u8(async_fd, exit_reason.status).await?;
    async_write_u8(async_fd, exit_reason.reason_type).await?;

    Ok(())
}

pub async fn read_request(async_fd: &mut Async<FdWrapper>) -> std::io::Result<api::Request> {
    let size = async_recv_u64(async_fd).await? as usize;

    let mut buf = vec![0; size as usize];
    async_read_n(async_fd, &mut buf).await?;

    let request = api::Request::decode(buf.as_slice())?;

    Ok(request)
}
