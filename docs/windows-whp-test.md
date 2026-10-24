# Verify the runtime on Windows with WHP

Run the same Linux workloads on a native Windows x86_64 host using Windows
Hypervisor Platform (WHP). This procedure covers direct Linux boot, the guest
agent, virtio-fs, VPN/INET frame transport and process lifecycle. GPU assignment
is outside this test.

**Status:** the Linux KVM scenarios pass. Windows cross-compilation is a separate
check and does not prove WHP execution. Record a native Windows run using the
acceptance criteria below before claiming that verification.

## Prepare the Linux guest files

Use the same source revision as the Windows checkout. On Linux, from the repo
root, run:

```sh
mise trust
mise install
mise run guest-image
mise run fetch-self-test
mise run vm-probe-build
sha256sum build/guest/vmlinuz-virt build/guest/initramfs.cpio.gz \
  build/guest/self-test.gvmi build/guest/vm-test-probe
```

Copy those four files into `build/guest/` in the Windows checkout. They can also
be obtained from the `linux-guest` artifact of the corresponding CI run. The
Windows test consumes these files; it does not rebuild the Linux agent or test
workload. Docker is required only for building the Linux filesystem formatter
when no `YA_VM_MKFS` override is provided.

## Prepare the Windows host

Use a local NTFS directory for the checkout and test files. The Windows export
backend uses native POSIX disposition and rename operations so cached/open
handles do not prevent unlink, name reuse or replacing an open destination.

Use a Windows 11 x86_64 machine with hardware virtualization enabled in its
firmware. A nested VM is not a substitute for this first physical-host check.
Install mise, Git and the Visual Studio C++ build tools with an x64 MSVC compiler
and Windows SDK. Perl must be available on `PATH` for the vendored OpenSSL build.
The native tasks target `x86_64-pc-windows-msvc` with a static CRT. Packaging and
VM checks use `dumpbin /DEPENDENTS` in the developer environment to reject
external Visual C++/OpenSSL runtime DLLs. The runtime itself does not need a
separate OpenSSL installation or a vsock service.

Microsoft documents the [C++ build tools workload](https://learn.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-build-tools?view=vs-2022)
and the [WHP API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform).

In an **administrator PowerShell** window, inspect the feature:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
```

If its state is disabled, enable it and complete the requested reboot:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
```

These commands and the reboot requirement follow Microsoft's
[WHP feature troubleshooting instructions](https://learn.microsoft.com/en-gb/dotnet/maui/android/emulator/troubleshooting?view=net-maui-10.0).
WHP is an operating-system feature; configuring Rust or mise does not enable it.
After reboot, repeat the state query. `Enabled` is a prerequisite, not proof that
this runtime can create and execute a partition.

## Build and execute natively

Open an **x64 Native Tools Command Prompt** for Visual Studio and start
`powershell` from it to inherit the MSVC environment. Change to the Windows
checkout. These build/test steps do not require an administrator shell:

```powershell
git rev-parse HEAD
mise trust
mise install
mise run ci
if ($LASTEXITCODE -ne 0) { throw 'Native checks failed' }

Get-FileHash build/guest/vmlinuz-virt, build/guest/initramfs.cpio.gz, build/guest/self-test.gvmi, build/guest/vm-test-probe -Algorithm SHA256

$env:RUST_LOG = 'info'
mise run vm-test
if ($LASTEXITCODE -ne 0) { throw 'WHP VM checks failed; inspect target/vm-test/*.stderr.log' }
```

Compare the four guest-file hashes against Linux or the matching CI artifact.
Keep `RUST_LOG=debug` as an optional diagnostic retry after a failure.

The test creates local UDP/TCP peers inside its host process. It does not need
an external network, a TAP adapter, an administrator network setup, QEMU or
firmware files. TCP listener tests create local sockets; allow the test program
through host security software if it blocks those connections.

## Acceptance criteria

A successful `mise run vm-test` exits with code zero and reports all three cases:

| Case | Frame transport | Required network result |
| --- | --- | --- |
| `both` | UDP | `NETWORK_OK both` |
| `inet-only` | Runtime connects to the TCP peer | `NETWORK_OK inet-only` |
| `vpn-only` | Peer connects to the runtime's TCP listener | `NETWORK_OK vpn-only` |

Each case must also report `FILES_OK root`, `FILES_OK user`, `KILL_OK`,
`RAPID_EXITS_OK`, `CYCLIC_OUTPUT_OK`, both `OUTPUT_OK` results, `ENTRYPOINT_SHUTDOWN_OK` and
`OPENVMM_INTEGRATION_OK`. Expected output lengths are 262147 stdout bytes and
196608 stderr bytes. The file checks exercise a 3 MiB transfer, rename, truncate,
link rejection and synthetic guest permissions. Linux host mode-bit checks are
conditional on Unix; Windows instead exercises its own filesystem and junction
handling. This test does not assert that Windows ACLs are POSIX mode bits.

Keep the native command output and `target/vm-test/*.stderr.log`. If
`CARGO_TARGET_DIR` is set, use its `vm-test/` directory instead. Record:

- Source commit, Windows version and CPU architecture.
- WHP feature state after reboot.
- Guest-file hashes and native `mise run ci` result.
- VM test exit code, all three case results and both stderr logs.

## Diagnose a failure

| Symptom | Next check |
| --- | --- |
| MSVC compiler/linker missing | Reopen the x64 Visual Studio tools shell; check `where.exe cl` and `where.exe link`. |
| OpenSSL build cannot find Perl | Check `where.exe perl` in that same shell. |
| WHP initialization fails | Check the feature state, completed reboot and firmware virtualization setting; retain the full host error. |
| Agent connection times out | Inspect the boot log in `target/vm-test/`; ensure guest files match the source revision. |
| Address readiness fails | Read the reported IPv6 address flags; the test retries only tentative addresses and has a finite DAD deadline. |
| TCP/UDP exchange fails | Inspect the affected case, local socket errors and host security policy. |
| Junction test fails | Retain the `mklink /J` error and check that the temporary directory's filesystem supports junctions. |

Do not classify a compiler-only check, an enabled-feature flag or a partial
`NETWORK_OK` result as a passing WHP integration run.
