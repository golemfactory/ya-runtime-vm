# Building and packaging

The repository pins its tools in [mise.toml](../mise.toml): Rust 1.99.1 with rustfmt,
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

## Linux

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
| `build/guest/THIRD-PARTY-NOTICES.txt` | Third-party licenses and source links, shipped in every package |
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

## Windows

Use the [native Windows/WHP test procedure](windows-whp-test.md) to record
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
then copy `vmlinuz-virt`, `initramfs.cpio.gz`, `self-test.gvmi` and
`THIRD-PARTY-NOTICES.txt` into `build/guest/` in the Windows checkout. Package
them with the native executable:

```powershell
mise run package
```

The Windows package is a `.zip` archive with a `.sha256` checksum in `releases/`.
CI follows the same model: one Linux guest build supplies assets to both native
platform builds. PCI device assignment is currently Linux only.

## OpenSSL dependency

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
