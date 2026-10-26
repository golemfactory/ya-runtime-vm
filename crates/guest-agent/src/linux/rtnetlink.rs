//! Minimal Linux rtnetlink codec for link/address/route updates.
//! Layouts and constants follow include/uapi/linux/{netlink,rtnetlink}.h.
use crate::error::Result;
use alloc::vec::Vec;
use linux_raw_sys::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR, RTM_GETLINK, RTM_NEWLINK};
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
    message.extend_from_slice(&(flags | NLM_F_REQUEST as u16).to_ne_bytes());
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
fn exchange(message: &[u8], reply: &mut [u8]) -> Result<usize> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )?;
    net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
    net::connect(&fd, &SocketAddrNetlink::new(0, 0))?;
    let sent = net::send(&fd, message, SendFlags::empty())?;
    crate::ensure!(sent == message.len(), "short netlink send");
    let (length, total) = net::recv(&fd, reply, RecvFlags::TRUNC)?;
    crate::ensure!(length == total, "truncated netlink datagram");
    Ok(length)
}
pub fn request(kind: u16, flags: u16, payload: &[u8]) -> Result<()> {
    let mut reply = [0; 8192];
    let length = exchange(&packet(kind, flags | NLM_F_ACK as u16, payload), &mut reply)?;
    acknowledgement(&reply[..length])
}
/// Reads a u32 attribute of one link with RTM_GETLINK.
pub fn link_u32(index: u32, kind: u16) -> Result<Option<u32>> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    let mut reply = vec![0; 16384];
    let length = exchange(&packet(RTM_GETLINK as u16, 0, &payload), &mut reply)?;
    link_attribute(&reply[..length], kind)
}
fn link_attribute(bytes: &[u8], kind: u16) -> Result<Option<u32>> {
    crate::ensure!(bytes.len() >= 16, "truncated netlink reply");
    let length = u32::from_ne_bytes(bytes[..4].try_into()?) as usize;
    crate::ensure!(
        length >= 16 && length <= bytes.len(),
        "invalid netlink message length"
    );
    if u16::from_ne_bytes(bytes[4..6].try_into()?) == NLMSG_ERROR as u16 {
        acknowledgement(bytes)?;
        crate::bail!("missing netlink link reply");
    }
    crate::ensure!(
        u16::from_ne_bytes(bytes[4..6].try_into()?) == RTM_NEWLINK as u16,
        "unexpected netlink reply"
    );
    crate::ensure!(
        u32::from_ne_bytes(bytes[8..12].try_into()?) == 1,
        "netlink sequence mismatch"
    );
    // nlmsghdr (16 bytes) and ifinfomsg (16 bytes) precede the attributes.
    let mut offset = 32;
    while offset + 4 <= length {
        let size = usize::from(u16::from_ne_bytes(bytes[offset..offset + 2].try_into()?));
        crate::ensure!(
            size >= 4 && offset + size <= length,
            "invalid netlink attribute"
        );
        if u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into()?) == kind {
            crate::ensure!(size == 8, "unexpected netlink attribute size");
            return Ok(Some(u32::from_ne_bytes(
                bytes[offset + 4..offset + 8].try_into()?,
            )));
        }
        offset += size.next_multiple_of(4);
    }
    Ok(None)
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
    fn link_attribute_is_found_after_the_link_header() {
        let mut reply = vec![0; 32];
        reply[4..6].copy_from_slice(&(RTM_NEWLINK as u16).to_ne_bytes());
        reply[8..12].copy_from_slice(&1u32.to_ne_bytes());
        attribute(&mut reply, 3, b"eth1\0");
        attribute(&mut reply, 51, &65266u32.to_ne_bytes());
        let length = reply.len() as u32;
        reply[..4].copy_from_slice(&length.to_ne_bytes());
        assert_eq!(link_attribute(&reply, 51).unwrap(), Some(65266));
        assert_eq!(link_attribute(&reply, 4).unwrap(), None);
        reply[32..34].copy_from_slice(&200u16.to_ne_bytes());
        assert!(link_attribute(&reply, 51).is_err());
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
