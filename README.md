# ya-runtime-vm

`ya-runtime-vm` is an implementation of a Docker-like runtime environment for Linux systems. 

This repository consists of 2 crates:

- `ya-runtime-vm`

   An application for running Virtual Machine images pre-built for yagna.

- `gvmkit`

   A tool for converting Docker images into yagna Virtual Machine images and uploading them to a public repository.
   Requires for [Docker](https://docs.docker.com/engine/install/ubuntu/) to be installed on your system.

## Building

The runtime embeds OpenVMM's `VmWorker` in the `ya-runtime-vm` process. It uses
the pinned OpenVMM `openvmm-v0.3.0` source revision, Rust 1.95, Protocol
Buffers' `protoc`, and the host OpenSSL development libraries.

On Ubuntu, install the native build dependencies:

```bash
sudo apt install autoconf automake cmake cpio curl docker.io gperf liblzma-dev libssl-dev libtool musl-tools pkg-config protobuf-compiler
```

Docker must be running and accessible to the current user; the init-container
build uses it to produce the static `mkfs.ext2` utility.

Initialize the init container's C-library submodules:

```bash
git submodule update --init --recursive
```

Build the Rust runtime and init image:

```bash
cargo build --release
make -C runtime/init-container
```

OpenVMM uses KVM, so running the VM requires access to `/dev/kvm`. See the
[OpenVMM source release guide](https://openvmm.dev/guide/dev_guide/contrib/openvmm_source_release.html)
for details about its pinned source and build inputs.

## Installing

Prerequisites:

- `cargo-deb`

    Cargo helper command which automatically creates binary Debian packages. With Rust already installed, execute in terminal:

    ```bash
    cargo install cargo-deb
    ```

When building a Debian package locally, fetch the self-test image bundled by
the release workflow:

```bash
mkdir -p runtime/image
curl --fail --location --output runtime/image/self-test.gvmi https://github.com/golemfactory/ya-self-test-img/releases/download/v0.1.4/self-test.gvmi
```

Installation:

In terminal, change the working directory to `runtime` and install a freshly minted Debian package.

```bash
cd runtime
sudo dpkg -i $(cargo deb | tail -n1)
```

This installs the runtime at `/usr/lib/yagna/plugins/ya-runtime-vm/ya-runtime-vm`.
The package also installs the guest kernel and initramfs under the runtime
directory; OpenVMM itself is linked into the runtime executable.


## Command line

Follow the installation section before executing.

```
ya-runtime-vm 0.5.4

USAGE:
    ya-runtime-vm [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --workdir <workdir>              
    -t, --task-package <task-package>    
        --cpu-cores <cpu-cores>           [default: 1]
        --mem-gib <mem-gib>               [default: 0.25]
        --storage-gib <storage-gib>       [default: 0.25]

SUBCOMMANDS:
    test              Perform a self-test
    offer-template    Print the market offer template (JSON)
    deploy            Deploy an image
    start             Start a deployed image
    help              Prints this message or the help of the given subcommand(s)
```

## Caveats

- Docker `VOLUME` command

    Directories specified in the `VOLUME` command are a mountpoint for directories on the host filesystem. Contents
    of those directories are passed into the guest through OpenVMM's virtio-fs device.
    
    If you need to place static assets inside the image, try not to use the `VOLUME` command for that directory.
