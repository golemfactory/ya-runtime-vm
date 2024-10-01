use std::{io, os::fd::AsRawFd};

use nix::errno::Errno;

use crate::{die, enums::Response, CMDS_FD};

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

pub fn read_n(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let result = nix::unistd::read(fd, &mut buf[total..])?;
        // let result = fd.read(&mut buf[total..])?;
        if result == 0 {
            println!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        total += result;
    }

    Ok(total)
}

pub fn recv_bytes(fd: i32) -> io::Result<Vec<u8>> {
    let size = recv_u64(fd)?;

    let mut buf = vec![0u8; size as usize];
    read_n(fd, &mut buf)?;

    Ok(buf)
}

pub fn recv_u8(fd: i32) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    let result = read_n(fd, &mut buf)?;

    if result < 1 {
        die!("Failed to read u8");
    }

    Ok(buf[0])
}

pub fn recv_u32(fd: i32) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    let result = read_n(fd, &mut buf)?;

    if result < 4 {
        die!("Failed to read u32");
    }

    Ok(u32::from_ne_bytes(buf))
}

pub fn recv_strings_array(fd: i32) -> io::Result<Vec<String>> {
    let size = recv_u64(fd)?;

    let mut strings = Vec::with_capacity(size as usize);

    for _ in 0..size {
        let string = recv_bytes(fd)?;
        let string = String::from_utf8(string).expect("Failed to convert bytes to string");
        strings.push(string);
    }

    Ok(strings)
}

pub fn recv_u64(fd: i32) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    let result = read_n(fd, &mut buf)?;

    if result < 8 {
        die!("Failed to read u64");
    }

    Ok(u64::from_ne_bytes(buf))
}

pub fn write_fd(fd: i32, buf: &[u8]) -> usize {
    let res = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len() as libc::size_t) };

    res as usize
}

pub fn write_n(fd: i32, buf: &[u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let result = write_fd(fd, &buf[total..]);
        if result == 0 {
            println!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        total += result;
    }

    Ok(total)
}

pub fn send_i32(fd: i32, value: i32) {
    let buf = value.to_ne_bytes();
    let _result = write_fd(fd, &buf);
}

fn send_response_header(message_id: u64, msg_type: Response) {
    let header = MessageHeader {
        msg_id: message_id,
        msg_type: msg_type as u8,
    };

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };

    println!(
        " Sending response header: {:?} ({:?})",
        header,
        header.to_ne_bytes(),
    );

    let result = write_n(cmds_fd.as_raw_fd(), &header.to_ne_bytes());
    println!("result: {:?} errno: {:?}", result, Errno::last());
}

pub fn send_response_ok(message_id: u64) {
    send_response_header(message_id, Response::Ok);
}

pub fn send_response_error(msg_id: u64, err_type: i32) {
    send_response_header(msg_id, Response::Error);

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };

    send_i32(cmds_fd.as_raw_fd(), err_type);
}
