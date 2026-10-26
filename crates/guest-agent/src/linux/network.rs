use super::{
    io as fs,
    rtnetlink::{attribute, request},
};
use crate::error::{Context, Result};
use alloc::vec::Vec;
use core::net::IpAddr;
use linux_raw_sys::netlink::{self as nl, NLM_F_CREATE, NLM_F_REPLACE};
use ya_vm_agent_protocol::Network;
const REPLACE: u16 = (NLM_F_CREATE | NLM_F_REPLACE) as u16;
// Values from the C init. Its INET MTU of 65521 is not restored: OpenVMM
// advertises VIRTIO_NET_F_MTU 1500, which is the guest's maximum MTU.
const MTU_VPN: u32 = 1220;
const NET_MEM_DEFAULT: &str = "1048576";
const NET_MEM_MAX: &str = "2097152";
fn index(name: &str) -> Result<u32> {
    Ok(
        fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()?,
    )
}
fn link(index: u32, flags: u32, change: u32) -> Vec<u8> {
    let mut bytes = vec![0; 4];
    bytes.extend_from_slice(&index.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&change.to_ne_bytes());
    bytes
}
fn up(index: u32) -> Result<()> {
    request(nl::RTM_NEWLINK as u16, 0, &link(index, 1, 1))
}
fn mtu(index: u32, mtu: u32) -> Result<()> {
    let mut message = link(index, 0, 0);
    attribute(&mut message, nl::IFLA_MTU as u16, &mtu.to_ne_bytes());
    request(nl::RTM_NEWLINK as u16, 0, &message)
}
fn sysctl(path: &str, value: &str) -> Result<()> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("opening {path}"))?;
    fs::File::from(file).write_all(value.as_bytes())?;
    Ok(())
}
fn rename(index: u32, name: &str) -> Result<()> {
    let mut message = link(index, 0, 0);
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    attribute(&mut message, nl::IFLA_IFNAME as u16, &name);
    request(nl::RTM_NEWLINK as u16, 0, &message)
}
fn octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
fn family(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 2 } else { 10 }
}
fn address(index: u32, addr: IpAddr, prefix: u8) -> Result<()> {
    let mut message = vec![family(addr), prefix, 0, 0];
    message.extend_from_slice(&index.to_ne_bytes());
    let bytes = octets(addr);
    attribute(&mut message, nl::IFA_ADDRESS as u16, &bytes);
    attribute(&mut message, nl::IFA_LOCAL as u16, &bytes);
    request(nl::RTM_NEWADDR as u16, REPLACE, &message)
}
pub fn loopback() -> Result<()> {
    let mut interfaces = Vec::new();
    for name in fs::read_dir("/sys/class/net")? {
        let mac = fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
        let role = match mac.trim() {
            "90:13:00:00:00:01" => 0,
            "90:13:00:00:00:02" => 1,
            _ => continue,
        };
        let i = index(&name)?;
        rename(i, &format!("ya-net{role}"))?;
        interfaces.push((i, role));
    }
    for (i, role) in interfaces {
        rename(i, &format!("eth{role}"))?;
        if role == 0 {
            mtu(i, MTU_VPN)?;
        }
    }
    for kind in ["rmem", "wmem"] {
        sysctl(
            &format!("/proc/sys/net/core/{kind}_default"),
            NET_MEM_DEFAULT,
        )?;
        sysctl(&format!("/proc/sys/net/core/{kind}_max"), NET_MEM_MAX)?;
    }
    let index = index("lo")?;
    up(index)?;
    address(index, "127.0.0.1".parse()?, 8)
}
fn prefix(mask: &str, ipv4: bool) -> Result<u8> {
    if let Ok(value) = mask.trim_start_matches('/').parse::<u8>() {
        crate::ensure!(
            value <= if ipv4 { 32 } else { 128 },
            "invalid prefix length"
        );
        return Ok(value);
    }
    let bits = match mask.parse::<IpAddr>()? {
        IpAddr::V4(value) if ipv4 => (u128::from(u32::from(value)) << 96) | ((1u128 << 96) - 1),
        IpAddr::V6(value) if !ipv4 => u128::from(value),
        _ => crate::bail!("netmask family mismatch"),
    };
    // IPv4 is checked independently so the low 96 padding bits cannot hide gaps.
    let (value, width) = if ipv4 { (bits >> 96, 32) } else { (bits, 128) };
    let ones = value.count_ones();
    let expected = if ones == 0 {
        0
    } else {
        (u128::MAX << (128 - ones)) >> (128 - width)
    };
    crate::ensure!(value == expected, "non-contiguous netmask");
    Ok(ones as u8)
}
// An empty mask means "unset", as NULL did in the C init.
fn mask<'a>(suffix: Option<&'a str>, mask: Option<&'a str>) -> Option<&'a str> {
    suffix.or(mask).filter(|m| !m.is_empty())
}
pub fn configure(config: Network) -> Result<()> {
    let name = match config.iface {
        0 => "eth0",
        1 => "eth1",
        _ => crate::bail!("unknown guest network interface"),
    };
    let index = index(name).with_context(|| format!("looking up {name}"))?;
    up(index)?;
    if let Some(addr) = config.if_addr.filter(|s| !s.is_empty()) {
        let (addr, suffix) = addr
            .split_once('/')
            .map(|(a, p)| (a, Some(p)))
            .unwrap_or((&addr, None));
        let addr: IpAddr = addr.parse()?;
        crate::ensure!(
            config.iface != 0 || addr.is_ipv4(),
            "IPv6 needs an MTU of at least 1280; the VPN interface uses {MTU_VPN}"
        );
        let prefix = match mask(suffix, config.mask.as_deref()) {
            Some(mask) => prefix(mask, addr.is_ipv4())?,
            None => {
                if addr.is_ipv4() {
                    32
                } else {
                    128
                }
            }
        };
        let bytes = octets(addr);
        let tail = &bytes[bytes.len() - 4..];
        let mut mac = vec![0x90, 0x13];
        mac.extend_from_slice(tail);
        let mut message = link(index, 0, 0);
        attribute(&mut message, nl::IFLA_ADDRESS as u16, &mac);
        request(nl::RTM_NEWLINK as u16, 0, &message)?;
        address(index, addr, prefix)?;
    }
    if let Some(gateway) = config.gateway.filter(|s| !s.is_empty()) {
        let gateway: IpAddr = gateway.parse()?;
        crate::ensure!(
            config.iface != 0 || gateway.is_ipv4(),
            "IPv6 needs an MTU of at least 1280; the VPN interface uses {MTU_VPN}"
        );
        let mut message = vec![
            family(gateway),
            0,
            0,
            0,
            254,
            nl::RTPROT_STATIC as u8,
            0,
            nl::RTN_UNICAST as u8,
            0,
            0,
            0,
            0,
        ];
        attribute(
            &mut message,
            nl::rtattr_type_t::RTA_OIF as u16,
            &index.to_ne_bytes(),
        );
        attribute(
            &mut message,
            nl::rtattr_type_t::RTA_GATEWAY as u16,
            &octets(gateway),
        );
        if let Some(destination) = config.addr.filter(|s| !s.is_empty()) {
            let (destination, suffix) = destination
                .split_once('/')
                .map(|(a, p)| (a, Some(p)))
                .unwrap_or((&destination, None));
            let destination: IpAddr = destination.parse()?;
            crate::ensure!(
                destination.is_ipv4() == gateway.is_ipv4(),
                "route family mismatch"
            );
            message[1] = prefix(
                mask(suffix, config.mask.as_deref()).unwrap_or(if gateway.is_ipv4() {
                    "32"
                } else {
                    "128"
                }),
                gateway.is_ipv4(),
            )?;
            attribute(
                &mut message,
                nl::rtattr_type_t::RTA_DST as u16,
                &octets(destination),
            );
            attribute(
                &mut message,
                nl::rtattr_type_t::RTA_PRIORITY as u16,
                &101u32.to_ne_bytes(),
            );
        }
        request(nl::RTM_NEWROUTE as u16, REPLACE, &message)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_prefixes_for_both_families() {
        assert_eq!(prefix("255.255.255.0", true).unwrap(), 24);
        assert!(prefix("255.0.255.0", true).is_err());
        assert_eq!(prefix("ffff:ffff:ffff:ffff::", false).unwrap(), 64);
        assert!(prefix("129", false).is_err());
    }
    #[test]
    fn empty_masks_are_unset() {
        assert_eq!(mask(None, Some("")), None);
        assert_eq!(mask(Some(""), Some("24")), None);
        assert_eq!(mask(None, Some("24")), Some("24"));
        assert_eq!(mask(Some("16"), Some("24")), Some("16"));
    }
}
