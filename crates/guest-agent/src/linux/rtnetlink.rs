//! Minimal Linux rtnetlink codec for link/address/route updates.
//! Layouts and constants follow include/uapi/linux/{netlink,rtnetlink}.h.
use crate::error::Result;
use alloc::vec::Vec;
use linux_raw_sys::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR};
use rustix::net::{
    self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink::SocketAddrNetlink,
};

pub fn attribute(message: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    let length = bytes.len() + 4;
    message.extend_from_slice(&(length as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(bytes);
    message.resize(message.len().next_multiple_of(4), 0);
}
fn packet(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(16 + payload.len());
    message.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&(flags | (NLM_F_REQUEST | NLM_F_ACK) as u16).to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(payload);
    message
}
fn acknowledgement(bytes: &[u8]) -> Result<()> {
    crate::ensure!(bytes.len() >= 20, "truncated netlink acknowledgement");
    let length = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
    crate::ensure!(
        length >= 20 && length <= bytes.len(),
        "invalid netlink message length"
    );
    crate::ensure!(
        u16::from_ne_bytes(bytes[4..6].try_into()?) == NLMSG_ERROR as u16,
        "unexpected netlink acknowledgement"
    );
    crate::ensure!(
        u32::from_ne_bytes(bytes[8..12].try_into()?) == 1,
        "netlink sequence mismatch"
    );
    let error = i32::from_ne_bytes(bytes[16..20].try_into()?);
    if error < 0 {
        let errno = error.checked_neg().context("invalid netlink error")?;
        return Err(rustix::io::Errno::from_raw_os_error(errno).into());
    }
    crate::ensure!(error == 0, "invalid netlink error");
    Ok(())
}
use crate::error::Context;
pub fn request(kind: u16, flags: u16, payload: &[u8]) -> Result<()> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )?;
    net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
    net::connect(&fd, &SocketAddrNetlink::new(0, 0))?;
    let message = packet(kind, flags, payload);
    let sent = net::send(&fd, &message, SendFlags::empty())?;
    crate::ensure!(sent == message.len(), "short netlink send");
    let mut reply = [0; 8192];
    let (length, total) = net::recv(&fd, &mut reply[..], RecvFlags::TRUNC)?;
    crate::ensure!(length == total, "truncated netlink datagram");
    acknowledgement(&reply[..length])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_ack_length_sequence_and_kernel_error() {
        let mut ack = vec![0; 20];
        ack[..4].copy_from_slice(&20u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&(NLMSG_ERROR as u16).to_ne_bytes());
        ack[8..12].copy_from_slice(&1u32.to_ne_bytes());
        assert!(acknowledgement(&ack).is_ok());
        assert!(acknowledgement(&ack[..19]).is_err());
        ack[8] = 2;
        assert!(acknowledgement(&ack).is_err());
        ack[8] = 1;
        ack[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        let error = acknowledgement(&ack).unwrap_err();
        assert_eq!(error.errno.as_ref(), Some(&rustix::io::Errno::PERM));
    }
    #[test]
    fn attributes_are_padded_but_report_the_unpadded_length() {
        let mut bytes = Vec::new();
        attribute(&mut bytes, 3, b"ab\0");
        assert_eq!(bytes.len(), 8);
        assert_eq!(u16::from_ne_bytes(bytes[..2].try_into().unwrap()), 7);
        assert_eq!(&bytes[4..7], b"ab\0");
    }
}
