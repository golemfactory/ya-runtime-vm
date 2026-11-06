# OpenVMM virtio-net patch

Source: Microsoft OpenVMM, commit
`8a150698f4b8e39344f4c7099b53e20b5d54f72e`, directory
`vm/devices/virtio/virtio_net`. The MIT license and source copyright notices are
preserved. This copy includes the upstream Rust sources and unit tests.

The root Cargo patch applies this crate to all OpenVMM consumers. Other OpenVMM
crates remain pinned git dependencies. Cargo metadata was made standalone; the
upstream workspace's `clippy::type_complexity = "allow"` is kept for the tests.

Upstream always advertises `VIRTIO_NET_F_MTU` with a fixed 1500-byte MTU, which
the Linux driver uses as the interface's maximum MTU. Local changes, marked
`ya-runtime-vm:` in `src/lib.rs`:

- `NicBuilder::mtu` sets the advertised MTU per device; the default stays 1500.
- `NicBuilder::build` rejects an MTU below 68, which Linux would ignore.
- `Worker::try_queue_tx_packet` rejects TX packets larger than `MAX_TX_PACKET_SIZE`
  (`65553` bytes) before queuing segments so a guest cannot trigger unbounded
  host allocations when a backend linearizes packets.

The upstream resolver for `VirtioNetHandle` is unchanged and keeps 1500. The
runtime builds its devices through its own resource handle to pass the MTU, so
`virtio_resources` does not need a patch. `tests.rs` adds a check that the MTU
reaches the device configuration space.

When updating OpenVMM, compare this copy against the pinned upstream crate and
retain these changes until an equivalent option is available upstream.
