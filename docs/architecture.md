# Architecture

```text
Yagna / exe-unit
       |
       | Yagna runtime API
       v
ya-runtime-vm                         Host: Linux / KVM or Windows / WHP
  +-- Rust runtime and embedded OpenVMM
  |     +-- virtio-blk  --> task images and storage disks
  |     +-- virtio-fs   --> dedicated host data directories
  |     +-- virtio-net  --> VPN / INET endpoints
  |     +-- UART       --> guest boot logs
  |
  +----- virtio-vsock -------------------------------+
                                                    |
                                           Rust guest agent (PID 1)
                                                    |
                                           Linux task processes
```

## Guest agent

The guest agent uses Origin for startup, rustix for Linux syscalls and Talc for
heap allocation backed by `mmap`. Its single epoll loop handles the control
channel, process output and child exits. Nonblocking pipes apply backpressure
independently; `signalfd` delivers SIGCHLD so the agent can reap children,
including orphaned processes.

## Process exit and entrypoint shutdown

Process exit notifications follow EOF and drained buffers on both stdout and
stderr. Before reporting the exit, the host drains both streams once more, then
queues the terminal status for the client and acknowledges the exit. The SDK
delivers queued statuses in order. With `start --start-entrypoint`, the image
entrypoint runs as the guest's entrypoint process: once its exit is
acknowledged, after all of its output and its exit code have been queued, the
guest powers off. The runtime records the halt. `stop()` then succeeds without
contacting the guest, and later run, kill and network commands return an error
naming the halt. The runtime API offers runtime state events, but the current
exe-unit ignores them, so the end is reported only through the entrypoint's
exit status.

## External components

The Rust implementation still uses external system components: a Linux kernel
and modules, plus a static BusyBox `mkfs.ext2` utility in the guest image. Build
and packaging scripts use Python. The upstream OpenVMM dependency graph also
includes OpenSSL, built from source and linked statically through Cargo's
`vendored` feature. No system OpenSSL installation is required; see
[OpenSSL dependency](building.md#openssl-dependency).

## Repository layout

```text
crates/
  runtime/         # Host runtime, OpenVMM integration and virtio-fs backend
  guest-agent/     # Freestanding Linux PID 1 agent
  agent-protocol/  # Shared messages, framing and protocol validation
guest/mkfs/        # Static BusyBox filesystem formatter build inputs
packaging/         # Yagna plugin descriptor
scripts/           # Guest image, self-test download and packaging tools
docs/              # Detailed documentation
.github/workflows/ # Build and release automation
```
