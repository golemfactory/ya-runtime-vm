# ya-runtime-vm

A Rust virtual machine runtime for running Linux task images on the
[Golem Network](https://www.golem.network/). It implements the Yagna runtime API
and embeds [OpenVMM](https://github.com/microsoft/openvmm) in the host executable.

The host runtime, Linux guest agent and shared communication protocol are all
written in Rust. The guest agent runs as PID 1: a freestanding `no_std` binary
with no libc or dynamic linker. The runtime boots the Linux kernel directly,
without BIOS or UEFI firmware or a separate VMM executable.

## What it provides

- **Linux and Windows hosts:** KVM on Linux and Windows Hypervisor Platform
  (WHP) on Windows, running x86_64 Linux guests.
- **Golem task execution:** GVMI task images, layered root filesystems,
  process execution, stdout/stderr streaming and exit notifications.
- **Storage:** host directory shares over virtio-fs, sparse raw storage disks
  formatted as ext2, and RAM volumes backed by tmpfs.
- **Networking:** virtio-net devices connected to Yagna VPN and INET endpoints.
- **Guest control:** a versioned Rust protocol over virtio-vsock, with bounded
  length-prefixed postcard frames and CRC32C checksums.
- **Device assignment:** Linux PCI passthrough through VFIO. GPU workloads
  require additional device and guest userspace setup.

## Architecture

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

The guest agent uses Origin for startup, rustix for Linux syscalls and Talc for
heap allocation backed by `mmap`. Its single epoll loop handles the control
channel, process output and child exits. Nonblocking pipes apply backpressure
independently; `signalfd` delivers SIGCHLD so the agent can reap children,
including orphaned processes.

Process exit notifications follow EOF and drained buffers on both stdout and
stderr. The host acknowledges an exit after queueing the output and terminal
status for the client. An entrypoint exit waits for this acknowledgement before
shutting down the VM.

The Rust implementation still uses external system components: a Linux kernel
and modules, plus a static BusyBox `mkfs.ext2` utility in the guest image. Build
and packaging scripts use Python. The upstream OpenVMM dependency graph also
includes OpenSSL, built from source and linked statically through Cargo's
`vendored` feature. No system OpenSSL installation is required; see
[Known issues](#known-issues).

## Requirements

The repository pins its tools in [mise.toml](mise.toml): Rust 1.99.1 with rustfmt,
Clippy and the Linux GNU/musl targets, plus protoc, Python, CMake and GitHub CLI.
Install [mise](https://mise.jdx.dev/) to use the commands below.

| Host | Native build requirements | VM execution requirements |
| --- | --- | --- |
| Linux x86_64 | C/C++ compiler, Make, Perl and a musl C toolchain | Hardware virtualization and read/write access to `/dev/kvm` |
| Windows x86_64 | MSVC developer environment and Perl | Windows Hypervisor Platform enabled |

Building the Linux guest image requires a Linux host and Docker, unless you
supply an existing static Linux `mkfs.ext2` binary through `YA_VM_MKFS`. The image
builder executes the x86_64 guest agent's startup self-check on the build host.
Kernel and self-test image downloads require network access.

## Build and package on Linux

On Ubuntu, install the native build tools:

```sh
sudo apt install build-essential perl musl-tools
```

From the repository root, install the pinned tools and build a complete package:

```sh
mise trust
mise install
mise run build-release
mise run guest-image
mise run fetch-self-test
mise run package
```

`guest-image` builds the agent with the Cargo `guest` profile, verifies that it
is a static non-PIE ELF with no dynamic loader or dynamic segment, and runs its
`--self-check` to exercise startup and heap allocation. It then combines the
agent, a checksum-pinned Alpine kernel's modules and the filesystem formatter
into an initramfs. The kernel itself is downloaded rather than compiled locally.

The generated files are:

| Path | Contents |
| --- | --- |
| `target/x86_64-unknown-linux-musl/release/ya-runtime-vm` | Static Linux host executable |
| `build/guest/vmlinuz-virt` | Linux guest kernel |
| `build/guest/initramfs.cpio.gz` | Rust `/init`, kernel modules and `mkfs.ext2` |
| `build/guest/self-test.gvmi` | Pinned task image for the runtime self-test |
| `releases/` | Linux `.tar.gz` archive and `.sha256` checksum |

Linux release builds explicitly target `x86_64-unknown-linux-musl`; packaging and
VM tests reject host executables with an ELF interpreter or shared-library dependencies.
Cargo output respects `CARGO_TARGET_DIR`. Shared guest assets always go to
`build/guest/`. The packaging task consumes existing build outputs; rerun the
build tasks after changing the runtime or guest agent.

For a Debian package, run the following after building the runtime and guest
assets and fetching the self-test image:

```sh
mise run package-deb
```

The `.deb` is written under the Cargo target directory's
`x86_64-unknown-linux-musl/debian/` directory and
installs the runtime and plugin descriptor under `/usr/lib/yagna/plugins/`.
Mise installs `cargo-deb` with its default features disabled, so the packaging
tool uses Rust gzip compression without the optional system LZMA dependency.

## Build and package on Windows

Use the [native Windows/WHP test procedure](docs/windows-whp-test.md) to record
execution results; cross-compilation alone does not verify WHP.

Use an MSVC developer shell with Perl available on `PATH`. The Windows tasks
explicitly target `x86_64-pc-windows-msvc` with a static CRT, and packaging checks
DLL imports with `dumpbin /DEPENDENTS`. Cargo builds the
vendored OpenSSL sources; a separate OpenSSL installation is unnecessary.

```powershell
mise trust
mise install
mise run build-release
```

Build the shared guest assets on Linux using `guest-image` and `fetch-self-test`,
then copy `vmlinuz-virt`, `initramfs.cpio.gz` and `self-test.gvmi` into
`build/guest/` in the Windows checkout. Package them with the native executable:

```powershell
mise run package
```

The Windows package is a `.zip` archive with a `.sha256` checksum in `releases/`.
CI follows the same model: one Linux guest build supplies assets to both native
platform builds. PCI device assignment is currently Linux only.

## Run the self-test

Extract the package and enter its `ya-runtime-vm` directory, which contains the
executable and the adjacent `runtime/` asset directory. On Linux:

```sh
RUST_LOG=debug ./ya-runtime-vm test
```

On Windows:

```powershell
$env:RUST_LOG = "debug"
.\ya-runtime-vm.exe test
```

The self-test boots a VM, runs the bundled test task, reads its JSON result from
a shared directory and stops the VM. It requires working KVM or WHP access;
workspace unit tests do not exercise this boot path.

The executable resolves guest assets from `runtime/` beside itself. Keep that
directory with the binary when installing or moving it. Use `ya-runtime-vm --help`
for CLI options. Task process execution is exposed through the runtime server
API; standalone CLI `run` is unsupported.

### Linux guest stops unexpectedly

OpenVMM can report a fatal hypervisor error as `SingleStep` even when no debugger
is attached. The runtime forwards the underlying OpenVMM error to its logger;
check those preceding messages and the host kernel journal:

```sh
journalctl -k --since "10 minutes ago" | rg 'kvm|vmread|vmwrite'
RUST_LOG=info ./ya-runtime-vm test
```

If the journal reports `vmread failed` or `vmwrite failed` while VirtualBox VMs
are running, safely shut down those VMs and retry. Do not force-kill VMs or unload
their active kernel modules. Loaded `vboxdrv` modules alone do not prove a
conflict. If the same build still fails after the other VMs stop, retain the
runtime and kernel logs for diagnosis rather than assuming the same cause.
The runtime does not stop other hypervisors or automatically restart a failed
guest, which could repeat a task's external side effects. Startup and self-test
failures are returned as errors rather than a self-test panic.

## Volumes and host directories

The agent mounts task image layers as read-only SquashFS filesystems and adds a
writable OverlayFS layer. The default writable root overlay uses a 128 MiB
tmpfs; an explicit root storage or RAM volume supplies the overlay instead.
Storage volumes use raw files in the task work directory, exposed as virtio-blk
devices and formatted as ext2 by the guest agent. These task disks are separate
from VMGS, the VMM's internal guest-state store, which is configured as ephemeral.

Directories declared with Docker `VOLUME` become host directory shares. Their
image contents are hidden by the mounted virtio-fs share; place static assets
outside these mountpoints.

### Host directory policy

Docker `VOLUME` shares are simple data directories. The runtime exports regular
files and directories with synthetic UID/GID `0:0` and permissions `0777`.
Guest `chmod` and `chown` succeed without changing host ownership or modes.
New host files use `0600` and directories use `0700` on Linux; Windows uses the
host account's inherited ACLs. Host access checks still apply to the runtime.

Symlink creation and traversal are blocked. Existing symlinks, Windows reparse
points, special files and files with multiple hard links are not exported.
Hard-link creation and extended attributes (including host ACLs) are unsupported.
Names must be single components; Windows device names, alternate streams,
trailing dots/spaces and path separators are rejected on both hosts.

The backend pins directory and file handles, so replacing a cached name with a
symlink cannot redirect file I/O. Open handles continue to refer to the original
objects after host-side moves; do not move an active share's contents into a
sensitive host directory. Export dedicated task directories, not host home or
system directories. This policy reduces the filesystem surface; it is not a
security audit of the hypervisor or the FUSE transport.

The runtime applies a local [FUSE decoder patch](third_party/fuse/README.md) to
all OpenVMM FUSE consumers. Frames are capped at 1 MiB + 4 KiB; declared lengths
must match the supplied bytes, and variable payload counts are checked before
allocation. Decoding uses a bounded copy rather than the transport's string
reader. This fixes the reproduced excessive-allocation request without changing
the remaining OpenVMM crates. The parser/session and malformed-request tests run
in both native CI jobs. These protections do not constitute a full VMM audit.

Per share, cached nodes, open handles and directory snapshots are bounded.
The backend supports ordinary reads, writes, rename, truncate, timestamps and
fsync; it does not provide full POSIX metadata semantics or writeback caching.

## Known issues

[OpenVMM pulls in OpenSSL for unused VM features (#205)](https://github.com/golemfactory/ya-runtime-vm/issues/205).
The pinned upstream resource registry includes UEFI and guest emulation devices,
and its core enables VMGS encryption support. These dependencies bring OpenSSL
into the Linux host build even though this runtime uses direct Linux boot and
ephemeral VMGS. OpenSSL is built from source and linked statically using its
Cargo `vendored` feature; its source version is recorded in `Cargo.lock`. We retain
upstream OpenVMM rather than maintain a fork or copied core solely to remove
OpenSSL. Revisit this dependency
when upstream provides the necessary configuration options. The embedded runtime
explicitly selects OpenSSL on Linux (including musl) and the native backend on
Windows; the upstream musl fallback to shared SymCrypt is not used. Task storage disks
are separate from VMGS and are unaffected by this decision.

## Development

Run the native workspace checks:

```sh
mise run fmt
mise run ci
```

`ci` checks formatting, runs Clippy and workspace tests, and builds the native
release executable. On Linux, also check the actual freestanding guest binary
and rebuild its image:

```sh
mise run guest-lint
mise run guest-image
```

The guest's native test harness uses `std`; `guest-lint` separately checks the
`no_std` executable. The `guest` profile enables fat LTO, strips symbols and
aborts on panic. CI builds and tests the native workspace on Linux and Windows,
and builds the shared guest image on Linux.

### VM integration checks

After building the guest image and fetching the self-test image, run:

```sh
mise run vm-test
```

This builds a static Linux test workload and the native test harness. It runs
the runtime's standard self-test, then boots three VMs to check virtio-fs
reads/writes as root and UID 1000, link rejection, host permissions, rename,
truncate, process kill, rapid exits, exit while a background child holds the
output pipes, cyclic output backpressure, and complete
stdout/stderr before both normal and entrypoint termination. Explicit RAM/storage
mounts under `/tmp` and `/dev/shm` must remain visible, with the configured `/tmp`
size limit enforced. Network cases cover both interfaces over UDP,
INET-only over TCP connect, and VPN-only over TCP listen. A local Ethernet peer
answers ARP/NDP and exchanges labelled UDP payloads over IPv4 and IPv6, including
routing through the configured gateways and partial TCP framing. No external
network, TAP interface or network administrator privileges are required. IPv6
startup waits only for an address confirmed tentative by the guest kernel, with
a finite 10-second DAD deadline; missing or duplicate addresses fail immediately.
The final marker for each VM is
`OPENVMM_INTEGRATION_OK`. The command has finite execution timeouts and requires
access to KVM on Linux or enabled WHP on Windows; unavailable virtualization is
a failure, not a skipped passing test.
Boot/runtime stderr is saved under `target/vm-test/*.stderr.log` (or under
`CARGO_TARGET_DIR`). On failure the command prints the final 60 log lines; CI
also uploads these logs even when the VM test fails.

On Windows, copy the Linux-generated `build/guest/` files, including
`vm-test-probe`, before running the same command. Build this additional workload
on Linux with `mise run vm-probe-build`. It is a test fixture, separate from the
freestanding PID 1 agent, and is not included in release packages.

The Linux native CI job grants its runner account access to `/dev/kvm` and runs
`vm-test` as a required step. The Windows job builds and tests native code;
executing the VM test there requires a WHP-capable host.

### Repository layout

```text
crates/
  runtime/         # Host runtime, OpenVMM integration and virtio-fs backend
  guest-agent/     # Freestanding Linux PID 1 agent
  agent-protocol/  # Shared messages, framing and protocol validation
guest/mkfs/        # Static BusyBox filesystem formatter build inputs
packaging/         # Yagna plugin descriptor
scripts/           # Guest image, self-test download and packaging tools
.github/workflows/ # Build and release automation
```
