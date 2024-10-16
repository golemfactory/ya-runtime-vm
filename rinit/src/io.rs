use std::io::{Read, Write};

use smol::Async;

use crate::{die, utils::FdWrapper};

pub async fn async_read_n(
    async_fd: &mut Async<FdWrapper>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    println!("async_read_n: {}", buf.len());
    let mut total = 0;

    while total < buf.len() {
        let n = unsafe { async_fd.read_with_mut(|fd| fd.read(&mut buf[total..])) }.await?;
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

pub async fn async_write_u64(
    async_fd: &mut Async<FdWrapper>,
    value: u64,
) -> std::io::Result<usize> {
    let buf = value.to_le_bytes();
    async_write_n(async_fd, &buf).await
}

pub async fn async_recv_u64(async_fd: &mut Async<FdWrapper>) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    let result = async_read_n(async_fd, &mut buf).await?;

    if result < 8 {
        die!("Failed to read u64");
    }

    Ok(u64::from_be_bytes(buf))
}
