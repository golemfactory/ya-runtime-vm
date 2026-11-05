# Testing and troubleshooting

## Workspace checks

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

Check `Cargo.lock` against the current RustSec advisory database separately:

```sh
mise run audit
```

The task installs pinned `cargo-audit` through mise and fetches the current
advisory database, so it requires network access. A separate Linux CI job runs
the same check for pull requests, branch builds, and releases; reported
vulnerabilities fail the job and block release publication. Advisory matching
does not replace source review of local or vendored code.

## VM integration checks

After building the guest image and fetching the self-test image, run:

```sh
mise run vm-test
```

This builds a static Linux test workload and the native test harness. It runs
the runtime's standard self-test, then boots three VMs to check virtio-fs
reads/writes as root and UID 1000, link rejection, host permissions, rename,
truncate, process kill, rapid exits, exit while a background child holds the
output pipes, cyclic output backpressure, and complete stdout/stderr before
termination.

Each VM starts like `start --start-entrypoint`, with the probe as
the image entrypoint. When signalled, it writes 2.4 MB of numbered stdout lines
(about 600 times the 4 KiB cyclic buffer) and 150 KB of stderr, then exits with
42. Every byte must arrive in order with the exit code before the guest powers
off. After that, `stop()` must succeed, and run, kill and network commands must
fail, all within finite timeouts. Explicit RAM/storage
mounts under `/tmp` and `/dev/shm` must remain visible, with the configured `/tmp`
size limit enforced.

Network cases cover both interfaces over UDP,
INET-only over TCP connect, and VPN-only over TCP listen. A local Ethernet peer
answers ARP/NDP and exchanges labelled UDP payloads over IPv4 and, on INET, IPv6,
including routing through the configured gateways and partial TCP framing.
Networks are configured through the runtime's `join_network`; the probe checks
that each interface has the MTU sent by the host, that IPv6 is refused on the
VPN, and that patterned datagrams filling one MTU-sized frame (about 64 KiB on
INET) return intact and unfragmented. No external
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

## Linux guest stops unexpectedly

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
