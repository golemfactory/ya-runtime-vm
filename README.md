# ya-runtime-vm

A runtime for Linux task images, with OpenVMM embedded in the host executable.
Linux hosts use KVM; Windows hosts use Windows Hypervisor Platform (WHP).
The Linux kernel starts directly, without BIOS or UEFI firmware.

The guest PID 1 agent is written in Rust with rustix. Host and agent share a
versioned postcard protocol with CRC32C and bounded, length-prefixed frames over
virtio-vsock. OpenVMM provides the userspace vsock backend inside the runtime;
no separate host vsock driver or service is needed. UART carries boot logs.
Host directories use virtio-fs; temporary storage uses sparse raw disk images.
The agent handles vsock, stdout/stderr and child exits in one epoll loop.
Nonblocking pipes apply backpressure independently; SIGCHLD arrives through
signalfd, followed by a nonblocking wait for all children, including orphans.

## Build

Install [mise](https://mise.jdx.dev/) and run:

```sh
mise trust
mise install
mise run build-release
```

`mise.toml` pins Rust 1.95.0, rustfmt, Clippy, protoc, CMake, Python and GitHub CLI.
On Ubuntu, native dependencies are:

```sh
sudo apt install pkg-config libssl-dev liblzma-dev
```

Windows builds use the MSVC developer environment and static OpenSSL from vcpkg
(`openssl:x64-windows-static-md`). Set `OPENSSL_DIR` to its installation prefix
and `OPENSSL_STATIC=1`. CI includes native Linux and Windows builds and tests.
Windows execution requires WHP enabled; GPU assignment is currently Linux only.

Build the shared Linux guest assets on Linux:

```sh
mise run guest-image
mise run fetch-self-test
mise run package
```

The guest task builds a static musl Rust agent using the `guest` profile
(`lto = "fat"`, `strip = "symbols"`) and downloads a checksum-pinned Alpine
kernel. Docker builds the small BusyBox `mkfs.ext2` formatter used for empty
storage disks. Alternatively, set `YA_VM_MKFS` to an existing static Linux
`mkfs.ext2` binary. The guest agent itself has no C sources or C submodules.
Windows packages consume the same kernel and initramfs built on Linux.

Archives and checksums appear in `releases/`. Extract an archive and run the
self-test from its `ya-runtime-vm` directory:

```sh
RUST_LOG=debug ./ya-runtime-vm test
```

On Windows use `ya-runtime-vm.exe test`. Linux execution requires access to
`/dev/kvm`. OpenHCL and software CPU emulation are not part of this runtime.

For a Debian package, build the runtime and guest assets, fetch the self-test
image, then run `mise run package-deb`. The package installs under
`/usr/lib/yagna/plugins/`.

## Development

```sh
mise run fmt
mise run ci
```

Repository layout:

```text
crates/
  runtime/         # Native host executable and OpenVMM integration
  guest-agent/     # Linux PID 1 agent
  agent-protocol/  # Shared postcard messages and framing
guest/
  mkfs/            # Static filesystem formatter build inputs
packaging/         # Yagna plugin descriptor
scripts/           # Local and CI build/packaging scripts
.github/workflows/ # CI orchestration
build/guest/       # Generated kernel, initramfs and self-test image (ignored)
releases/          # Generated packages (ignored)
```

Cargo artifacts use `target/` (or `CARGO_TARGET_DIR`). Guest images always use
`build/guest/`, shared by archive packaging, Debian packaging and CI artifacts.
Use `ya-runtime-vm --help` for runtime commands.

Directories declared with Docker `VOLUME` become host directory shares. Their
image contents are hidden by the mounted virtio-fs share; place static assets
outside these mountpoints.
