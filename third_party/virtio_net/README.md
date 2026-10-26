# OpenVMM virtio-net patch

Source: Microsoft OpenVMM, commit
`88e78be49228ead4f324bf3e9252769f453059ad`, directory
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

The upstream resolver for `VirtioNetHandle` is unchanged and keeps 1500. The
runtime builds its devices through its own resource handle to pass the MTU, so
`virtio_resources` does not need a patch. `tests.rs` adds a check that the MTU
reaches the device configuration space.

When updating OpenVMM, compare this copy against the pinned upstream crate and
retain these changes until an equivalent option is available upstream.
