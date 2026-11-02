# OpenVMM KVM CPUID override

The runtime uses OpenVMM **0.4.0**, pinned to commit
`8a150698f4b8e39344f4c7099b53e20b5d54f72e`. Only `virt_kvm` is overridden
from a generated checkout; its Rust sources are not copied into this repository.
The existing FUSE and virtio-net overrides remain under `third_party/`.

## Preparation

```sh
mise run openvmm-prepare
```

This task fetches the tag from the repository in [config.toml](config.toml),
verifies its exact commit, and applies
[hypervisor-cpuid.patch](hypervisor-cpuid.patch). The resulting checkout lives
under the ignored `build/openvmm/` directory.

The task generates a standalone manifest for `virt_kvm` from the upstream
manifest and workspace settings. Its OpenVMM dependencies point to the same
Git revision as the runtime. This avoids compiling separate path and Git copies
of libraries such as `virt` and `guestmem`, whose Rust types would be incompatible.
The generated crate joins the runtime workspace so its tests use our lockfile.
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
other feature bits, and indexed leaves. It does not expose KVM paravirtualization
leaves or add MSR emulation. Linux uses the hypervisor flag to skip some
bare-metal CPU initialization and uncore discovery paths.

```sh
mise run test-build-tools
mise run openvmm-test
```

The preparation tests use local Git fixtures and verify commit pinning,
dependency isolation, offline reuse, patch updates, failed patches, and protection
of local edits. The Rust CPUID tests run without `/dev/kvm` and are also included
in `mise run test` on Linux. A guest boot on an AMD KVM host is still required to
confirm that the reported MSR probes disappear in that environment.

When upgrading, update all OpenVMM Git revisions in the Cargo manifests together
with `config.toml`, rebase the patch, regenerate `Cargo.lock`, and run the build
and test tasks. Retain the MIT notices in the upstream checkout and patch.
