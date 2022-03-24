# ya-runtime-vm

`ya-runtime-vm` is an implementation of a Docker-like runtime environment for Linux systems.

This repository consists of 2 crates:

- `ya-runtime-vm`

   An application for running Virtual Machine images pre-built for yagna.

- `gvmkit`

   A tool for converting Docker images into yagna Virtual Machine images and uploading them to a public repository.
   Requires for [Docker](https://docs.docker.com/engine/install/ubuntu/) to be installed on your system.

## Building

Prerequisites:

- `rustc`

    Recommendation: use the Rust toolchain installer from [https://rustup.rs/](https://rustup.rs/)

- `musl-gcc`

    On a Ubuntu system, execute in terminal:

    ```bash
       sudo apt install musl musl-tools
    ```

Building:

```bash
cd runtime
cargo build
```

## Installing

Prerequisites:

- `cargo-deb`

    Cargo helper command which automatically creates binary Debian packages. With Rust already installed, execute in terminal:

    ```bash
    cargo install cargo-deb
    ```

Installation:

In terminal, change the working directory to `runtime` and install a freshly minted Debian package.

```bash
cd runtime
sudo dpkg -i $(cargo deb | tail -n1)
```

This will install the binary at `/usr/lib/yagna/plugins/ya-runtime-vm/ya-runtime-vm`.


## Command line

Follow the installation section before executing.

```
ya-runtime-vm 0.2.5

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
    of those directories will appear as empty during execution.

    If you need to place static assets inside the image, try not to use the `VOLUME` command for that directory.

## Running examples
* Some of the examples require ya-runtime-vm installed, so follow [Installing](#installing) paragraph first.
* Create a .gvmi image used by examples with following steps:
  * Build docker image
    ```
    cd runtime/examples
    docker build -t ya-runtime-vm-examples .
    ```
  * Convert to gvmi
    ```
    gvmkit ya-runtime-vm-examples --output /path/to/ya-runtime-vm/squashfs_drive
    ```
* Then run:
    ```
    cargo run --example EXAMPLE_NAME
    ```
