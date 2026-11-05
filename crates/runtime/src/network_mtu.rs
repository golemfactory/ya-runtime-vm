//! Interface MTUs chosen by the host.
//!
//! The runtime API's `CreateNetwork` carries no MTU, so the runtime picks one
//! per interface here. A future runtime-API field should override
//! [`guest_mtu`] at this point, limited by [`device_mtu`], which is fixed when
//! the VM starts.

use ya_runtime_sdk::runtime_api::server::NetworkInterface;

/// Guest-to-guest traffic over the yagna VPN (ya-relay) keeps the C init's
/// small MTU.
pub const VPN_MTU: u16 = 1220;

/// Ethernet frame limit of the exe-unit's INET stack: `DEFAULT_MAX_PACKET_SIZE`
/// (0xff00) in yagna's `exe-unit/src/network/inet.rs`, passed to smoltcp as
/// `max_transmission_unit`. For Ethernet, smoltcp includes the 14-byte header.
const INET_MAX_FRAME: u16 = 0xff00;
const ETHERNET_HEADER: u16 = 14;

/// Host-to-guest traffic that the exe-unit forwards to the internet. Use the
/// largest IP MTU whose frames its INET stack accepts: 65266. The C init's
/// 65521 would exceed it.
pub const INET_MTU: u16 = INET_MAX_FRAME - ETHERNET_HEADER;

/// Linux sizes virtio-net receive buffers for 1500 bytes unless the device
/// advertises more.
const ETHERNET_MTU: u16 = 1500;

/// MTU that the guest agent applies to the interface.
pub fn guest_mtu(iface: NetworkInterface) -> u16 {
    match iface {
        NetworkInterface::Vpn => VPN_MTU,
        NetworkInterface::Inet => INET_MTU,
    }
}

/// MTU advertised by the virtio-net device, which is also the interface's
/// maximum. Smaller guest MTUs keep the default device and receive buffers.
pub fn device_mtu(iface: NetworkInterface) -> u16 {
    guest_mtu(iface).max(ETHERNET_MTU)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_allow_the_guest_mtu() {
        assert_eq!(guest_mtu(NetworkInterface::Vpn), 1220);
        assert_eq!(device_mtu(NetworkInterface::Vpn), 1500);
        assert_eq!(guest_mtu(NetworkInterface::Inet), 65266);
        assert_eq!(device_mtu(NetworkInterface::Inet), 65266);
        // An INET frame must fit one UDP datagram of the exe-unit endpoint.
        assert!(usize::from(INET_MTU + ETHERNET_HEADER) <= 65507);
    }
}
