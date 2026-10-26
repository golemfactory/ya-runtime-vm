# OpenVMM FUSE decoder patch

Source: Microsoft OpenVMM, commit
`88e78be49228ead4f324bf3e9252769f453059ad`, directory
`vm/devices/support/fs/fuse`. The MIT license and source copyright notices are
preserved. This copy includes the upstream Rust sources and integration test;
`fuse.h` is not used by the Rust crate and is omitted.

The root Cargo patch applies this crate to all OpenVMM consumers. Other OpenVMM
crates remain pinned git dependencies. Cargo metadata was made standalone and
Rust formatting follows this repository.

Local changes in `src/request.rs`:

- Limit each incoming frame, including transport bytes, to 1 MiB + 4 KiB.
- Require the declared frame length to match the available bytes before parsing.
- Copy the bounded payload once, then decode through a slice. This avoids the
  transport string reader's descriptor-sized allocation and position rewinding.
- Reject payload counts exceeding the remaining bytes before allocating.
- Preserve the request header for an error reply when a payload is malformed.

`src/reply.rs` also includes the data payload in the length of a reply carrying
both an argument and data. A regression checks the complete serialized frame,
including the reply header, argument and nonempty IOCTL data.

Tests cover excessive WRITE, SETXATTR and IOCTL sizes, invalid frame lengths,
oversized transport descriptors, string parsing and valid maximum writes. The
upstream parser/session tests run with workspace tests. A real `/dev/fuse` mount
integration test remains ignored; the runtime uses in-process virtio-fs.

When updating OpenVMM, compare this copy against the pinned upstream crate and
retain these checks until equivalent protections are available upstream.
