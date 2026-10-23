use anyhow::{Context, Result};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlag, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{fs, net::IpAddr};
use ya_vm_agent_protocol::Network;

fn request(payload: RouteNetlinkMessage, flags: u16) -> Result<()> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    let mut message = NetlinkMessage::from(payload);
    message.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    message.header.sequence_number = 1;
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    socket.send(&bytes, 0)?;
    let (bytes, _) = socket.recv_from_full()?;
    let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes)?;
    match reply.payload {
        NetlinkPayload::Error(error) if error.code.is_some() => Err(error.to_io().into()),
        NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => Ok(()),
        _ => anyhow::bail!("unexpected netlink acknowledgement"),
    }
}
fn index(name: &str) -> Result<u32> {
    Ok(
        fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()?,
    )
}
fn up(index: u32) -> Result<()> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.header.flags = vec![LinkFlag::Up];
    link.header.change_mask = vec![LinkFlag::Up];
    request(RouteNetlinkMessage::NewLink(link), 0)
}
fn address(index: u32, addr: IpAddr, prefix: u8) -> Result<()> {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.family = if addr.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    message.header.prefix_len = prefix;
    message.attributes = vec![
        AddressAttribute::Address(addr),
        AddressAttribute::Local(addr),
    ];
    request(
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_CREATE | NLM_F_REPLACE,
    )
}
fn rename(index: u32, name: &str) -> Result<()> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.attributes.push(LinkAttribute::IfName(name.into()));
    request(RouteNetlinkMessage::NewLink(link), 0)
}
pub fn loopback() -> Result<()> {
    // Keep VPN/INET numbering stable even when only INET exists or the kernel
    // probes virtio-MMIO devices in a different order.
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let mac = fs::read_to_string(entry.path().join("address"))?;
        let role = match mac.trim() {
            "90:13:00:00:00:01" => 0,
            "90:13:00:00:00:02" => 1,
            _ => continue,
        };
        let i = index(&entry.file_name().to_string_lossy())?;
        rename(i, &format!("ya-net{role}"))?;
        interfaces.push((i, role));
    }
    for (i, role) in interfaces {
        rename(i, &format!("eth{role}"))?;
    }

    let index = index("lo")?;
    up(index)?;
    address(index, "127.0.0.1".parse()?, 8)
}
fn prefix(mask: &str, ipv4: bool) -> Result<u8> {
    if let Ok(value) = mask.trim_start_matches('/').parse::<u8>() {
        anyhow::ensure!(
            value <= if ipv4 { 32 } else { 128 },
            "invalid prefix length"
        );
        return Ok(value);
    }
    let bits = match mask.parse::<IpAddr>()? {
        IpAddr::V4(value) if ipv4 => (u128::from(u32::from(value)) << 96) | ((1u128 << 96) - 1),
        IpAddr::V6(value) if !ipv4 => u128::from(value),
        _ => anyhow::bail!("netmask family mismatch"),
    };
    // IPv4 is checked independently so the low 96 padding bits cannot hide gaps.
    let (value, width) = if ipv4 { (bits >> 96, 32) } else { (bits, 128) };
    let ones = value.count_ones();
    let expected = if ones == 0 {
        0
    } else {
        (u128::MAX << (128 - ones)) >> (128 - width)
    };
    anyhow::ensure!(value == expected, "non-contiguous netmask");
    Ok(ones as u8)
}
pub fn configure(config: Network) -> Result<()> {
    let name = match config.iface {
        0 => "eth0",
        1 => "eth1",
        _ => anyhow::bail!("unknown guest network interface"),
    };
    let index = index(name).with_context(|| format!("looking up {name}"))?;
    up(index)?;
    if let Some(addr) = config.if_addr.filter(|s| !s.is_empty()) {
        let (addr, suffix) = addr
            .split_once('/')
            .map(|(a, p)| (a, Some(p)))
            .unwrap_or((&addr, None));
        let addr: IpAddr = addr.parse()?;
        let prefix = match suffix.or(config.mask.as_deref()).filter(|m| !m.is_empty()) {
            Some(mask) => prefix(mask, addr.is_ipv4())?,
            None => {
                if addr.is_ipv4() {
                    32
                } else {
                    128
                }
            }
        };
        let octets = match addr {
            IpAddr::V4(addr) => addr.octets(),
            IpAddr::V6(addr) => addr.octets()[12..].try_into().unwrap(),
        };
        let mut link = LinkMessage::default();
        link.header.index = index;
        link.attributes.push(LinkAttribute::Address(vec![
            0x90, 0x13, octets[0], octets[1], octets[2], octets[3],
        ]));
        request(RouteNetlinkMessage::NewLink(link), 0)?;
        address(index, addr, prefix)?;
    }
    if let Some(gateway) = config.gateway.filter(|s| !s.is_empty()) {
        let gateway: IpAddr = gateway.parse()?;
        let mut route = RouteMessage::default();
        route.header.address_family = if gateway.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        route.header.table = 254;
        route.header.protocol = RouteProtocol::Static;
        route.header.scope = RouteScope::Universe;
        route.header.kind = RouteType::Unicast;
        route.attributes = vec![
            RouteAttribute::Oif(index),
            RouteAttribute::Gateway(match gateway {
                IpAddr::V4(v) => RouteAddress::Inet(v),
                IpAddr::V6(v) => RouteAddress::Inet6(v),
            }),
        ];
        if let Some(destination) = config.addr.filter(|s| !s.is_empty()) {
            let (destination, suffix) = destination
                .split_once('/')
                .map(|(a, p)| (a, Some(p)))
                .unwrap_or((&destination, None));
            let destination: IpAddr = destination.parse()?;
            anyhow::ensure!(
                destination.is_ipv4() == gateway.is_ipv4(),
                "route family mismatch"
            );
            route.header.destination_prefix_length = prefix(
                suffix
                    .or(config.mask.as_deref())
                    .unwrap_or(if gateway.is_ipv4() { "32" } else { "128" }),
                gateway.is_ipv4(),
            )?;
            route
                .attributes
                .push(RouteAttribute::Destination(match destination {
                    IpAddr::V4(v) => RouteAddress::Inet(v),
                    IpAddr::V6(v) => RouteAddress::Inet6(v),
                }));
            route.attributes.push(RouteAttribute::Priority(101));
        }
        request(
            RouteNetlinkMessage::NewRoute(route),
            NLM_F_CREATE | NLM_F_REPLACE,
        )?;
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
}
