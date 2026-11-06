# OpenVMM KVM CPUID override

The runtime uses OpenVMM **0.4.0**, pinned to commit
`8a150698f4b8e39344f4c7099b53e20b5d54f72e`. The `virt_kvm` backend, its `kvm`
ioctl wrapper, and the virtio device crates (`virtio`, `virtio_blk`,
`virtio_vsock`, and `virtiofs`) are overridden from a generated checkout; their
Rust sources are not copied into this repository.
The existing FUSE and virtio-net overrides remain under `third_party/`.

## Preparation

```sh
mise run openvmm-prepare
```

This task fetches the tag from the repository in [config.toml](config.toml),
verifies its exact commit, and applies
[hypervisor-cpuid.patch](hypervisor-cpuid.patch). The resulting checkout lives
under the ignored `build/openvmm/` directory.

The task generates standalone manifests for both crates from the upstream
manifests and workspace settings. Their OpenVMM dependencies point to the same
Git revision as the runtime. This avoids compiling separate path and Git copies
of libraries such as `virt` and `guestmem`, whose Rust types would be incompatible.
The generated crates join the runtime workspace so their tests use our lockfile.
Build, formatting, lint, test, and packaging tasks prepare the checkout automatically.
Run preparation explicitly before invoking Cargo directly on a fresh checkout.
Git and network access are required for initial preparation.

Repeated preparation verifies and reuses the checkout without network access.
Changes to the configuration, patch, or preparation script trigger a fresh checkout.
A failed download or patch leaves the previous checkout intact. The task refuses
to overwrite unrecorded local changes: save those changes as a patch or move the
checkout aside before running it again. Do not commit generated checkout files.
If an interrupted process leaves `build/openvmm.prepare-lock`, remove that empty
directory only after confirming that no preparation process is running.

## CPUID behavior and tests

The patch sets `CPUID.1:ECX[31]` (hypervisor present) in the KVM backend even when
Hyper-V enlightenments are disabled. It preserves the CPU vendor, family/model,
other feature bits, and indexed leaves. Linux uses the hypervisor flag to skip
some bare-metal CPU initialization and uncore discovery paths.

For ordinary, non-isolated guests without Hyper-V enlightenments, the patch also
exposes the KVM signature and a bounded set of host-supported paravirtual features:
the legacy/new KVM clock, stable-clock flag, no I/O delay, steal time, PV EOI,
PV spinlocks, PV TLB flush, PV IPI, polling control, and scheduler yield. These
MSRs and hypercalls are handled by the host KVM kernel; the patch does not add
userspace MSR emulation. Features absent from `KVM_GET_SUPPORTED_CPUID` stay absent.

The KVM feature mask excludes async page faults, migration controls, extended MSI
destinations, and unknown future features. It clears the realtime scheduling
hint because runtime vCPUs can be preempted. Hyper-V and confidential-guest
configurations retain their previous CPUID policy. This override targets the
runtime's fresh-VM lifecycle; it does not add save/restore support for KVM PV MSRs.
See the kernel documentation for [KVM CPUID](https://docs.kernel.org/virt/kvm/x86/cpuid.html),
[MSRs](https://docs.kernel.org/virt/kvm/x86/msr.html), and
[hypercalls](https://docs.kernel.org/virt/kvm/x86/hypercalls.html).

## Enforced PV policy

For ordinary KVM guests, every vCPU enables
`KVM_CAP_ENFORCE_PV_FEATURE_CPUID` with `args[0] = 1` after setting its CPUID and
before its first run. This makes KVM enforce the CPUID restrictions on its
feature-gated PV interfaces; hiding CPUID bits alone does not do that. The small
ioctl wrapper checks host support and propagates enable failures. A host without
this capability fails VM startup with an error naming the capability. There is
no silent fallback to unenforced operation. Hyper-V and SNP configurations retain
their previous behavior.

This is KVM's PV feature enforcement, not a general MSR or hypercall firewall.
Interfaces without a corresponding CPUID feature gate are not covered by this
capability. The patch neither adds host-memory access nor changes VMX/SVM policy.
The host kernel remains responsible for validating guest addresses and requests.
See the [KVM capability contract](https://docs.kernel.org/virt/kvm/api.html#kvm-cap-enforce-pv-feature-cpuid).

`mise run vm-test` includes a Linux-only regression that boots two independent
VMs concurrently, each with four vCPUs. The guest probe:

- Issues actual guest RDMSR/WRMSR through the Linux MSR driver on every vCPU.
- Requires reads and writes of the excluded async-PF MSRs to fault (`EIO` from
  the guest driver), rather than merely checking CPUID.
- Tests PV EOI with misalignment, an unmapped GPA and a high invalid GPA, restores
  the previous EOI registration, and checks reserved poll-control bits.
- Exercises permitted poll-control reads/writes as a positive control, then runs
  the existing file, network, process-output and shutdown tests.

The test module comes from the same checksum-pinned APK as the guest kernel. It
is exported as `build/guest/test-msr.ko` for CI, copied only into the test share,
and loaded only inside disposable guests. It is not included in the production
initramfs or package. The host never loads this module or opens an MSR device.
These bounded regressions are not an exhaustive hypervisor security audit, a
long-running denial-of-service test, or verification of migration/snapshot state.

```sh
mise run test-build-tools
mise run openvmm-test
```

The preparation tests use local Git fixtures and verify commit pinning,
dependency isolation, offline reuse, patch updates, failed patches, and protection
of local edits. The Rust tests check preservation of CPU identity, the KVM
signature and leaf limit, each allowed/rejected feature bit, and suppression of
KVM leaves when disabled. They run without `/dev/kvm` and are also included
in `mise run test` on Linux. A guest boot on an AMD KVM host is still required to
confirm that the reported MSR probes disappear in that environment.

## Virtio bounds and hardening

In addition to the KVM CPUID policy, `hypervisor-cpuid.patch` applies defensive
bounds to the OpenVMM virtio crates:

- `virtio`: rejects indirect descriptor tables whose entry count would overflow
  `u16` (`QueueError::TooLong`) and rejects `VIRTIO_DESC_F_INDIRECT` on entry `0`
  of an indirect descriptor table (`QueueError::DoubleIndirect`).
- `virtio_blk`: bounds request `data_len` to `16 MiB` and bounce-buffer slow-path
  allocations to `DEFAULT_SEG_MAX * PAGE_SIZE` (`254 * 4096` bytes).
- `virtio_vsock`: bounds host-to-guest bounce buffer allocations in
  `handle_host_data` to `min(peer_free, TX_BUF_SIZE)` and adds
  `VirtioVsockDevice::new_in_memory` / `RelaySocket::pair` (`MemoryStream`) so
  in-process guest-agent communication runs entirely in memory without host Unix
  domain sockets or temporary directories.
- `virtiofs`: checks `offset + 4 <= config.len()` in `read_registers_u32` so
  unaligned config reads near the end of `virtio_fs_config` return `0` instead
  of panicking.

When upgrading, update all OpenVMM Git revisions in the Cargo manifests together
with `config.toml`, rebase the patch, regenerate `Cargo.lock`, and run the build
and test tasks. Retain the MIT notices in the upstream checkout and patch.
