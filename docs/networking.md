# Networking

The VM has two virtio-net interfaces: VPN, carrying Yagna VPN traffic between
guests, and INET, whose frames the exe-unit decodes on the host.

The host chooses each interface's MTU in
[`network_mtu.rs`](../crates/runtime/src/network_mtu.rs) and sends it with the
network configuration; the runtime API has no MTU field. The VPN interface keeps
the C init's 1220 bytes, below IPv6's minimum, so it carries IPv4 only. INET uses
65266 bytes: the exe-unit's INET stack accepts Ethernet frames of up to 65280
(0xff00) bytes including the 14-byte header, so the C init's 65521 would exceed
it.

Upstream OpenVMM advertises a fixed 1500-byte virtio-net MTU, which Linux
treats as the interface maximum, so the runtime uses a
[vendored virtio-net](../third_party/virtio_net/README.md) with a per-device MTU.
The INET device advertises 65266, and Linux then posts receive buffers large
enough for a whole frame; the VPN device keeps 1500. The guest agent rejects an
MTU above the device maximum or below 68, and an IPv6 address or route on an
interface below 1280.

Frame sockets request 2 MiB buffers, as the exe-unit does. Linux caps this at
`net.core.rmem_max`/`wmem_max` (about 208 KiB by default), which holds only a few
64 KiB INET frames; raise those limits on hosts with heavy INET traffic.
