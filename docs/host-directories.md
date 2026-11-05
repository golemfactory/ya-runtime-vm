# Volumes and host directories

The agent mounts task image layers as read-only SquashFS filesystems and adds a
writable OverlayFS layer. The default writable root overlay uses a 128 MiB
tmpfs; an explicit root storage or RAM volume supplies the overlay instead.
Storage volumes use raw files in the task work directory, exposed as virtio-blk
devices and formatted as ext2 by the guest agent. These task disks are separate
from VMGS, the VMM's internal guest-state store, which is configured as ephemeral.

Directories declared with Docker `VOLUME` become host directory shares. Their
image contents are hidden by the mounted virtio-fs share; place static assets
outside these mountpoints.

## Host directory policy

Docker `VOLUME` shares are simple data directories. The runtime exports regular
files and directories with synthetic UID/GID `0:0` and permissions `0777`.
Guest `chmod` and `chown` succeed without changing host ownership or modes.
New host files use `0600` and directories use `0700` on Linux; Windows uses the
host account's inherited ACLs. Host access checks still apply to the runtime.

Symlink creation and traversal are blocked. Existing symlinks, Windows reparse
points, special files and files with multiple hard links are not exported.
Hard-link creation and extended attributes (including host ACLs) are unsupported.
Names must be single components; Windows device names, alternate streams,
trailing dots/spaces, control characters and Windows-reserved punctuation are
rejected on both hosts. Names must be valid UTF-8. Console aliases and the
superscript-digit COM/LPT aliases are rejected before host filesystem operations.

The backend pins directory and file handles, so replacing a cached name with a
symlink cannot redirect file I/O. Open handles continue to refer to the original
objects after host-side moves; do not move an active share's contents into a
sensitive host directory. Export dedicated task directories, not host home or
system directories. This policy reduces the filesystem surface; it is not a
security audit of the hypervisor or the FUSE transport.

The runtime applies a local [FUSE decoder patch](../third_party/fuse/README.md) to
all OpenVMM FUSE consumers. Frames are capped at 1 MiB + 4 KiB; declared lengths
must match the supplied bytes, and variable payload counts are checked before
allocation. Decoding uses a bounded copy rather than the transport's string
reader. This fixes the reproduced excessive-allocation request without changing
the remaining OpenVMM crates. The parser/session and malformed-request tests run
in both native CI jobs. These protections do not constitute a full VMM audit.

Per share, cached nodes, open handles and directory snapshots are bounded.
The backend supports ordinary reads, writes, rename, truncate, timestamps and
fsync; it does not provide full POSIX metadata semantics or writeback caching.

## Share limits

Each share defaults to a 10 GiB sum of logical file lengths and 100,000
exported filesystem objects, including the root directory. Configure these
host-side limits before starting the runtime:

```bash
export YA_RUNTIME_VM_SHARE_MAX_BYTES=10737418240
export YA_RUNTIME_VM_SHARE_MAX_ENTRIES=100000
```

The same settings apply independently to every share in that runtime. The byte
limit accepts 1 through `i64::MAX`; the entry limit accepts 1 through 1,000,000.
Exceeding a limit returns `ENOSPC`. Startup counts existing exportable contents
and fails if they exceed either limit; traversal depth is limited to 128
directories. Sparse lengths count in full. Unlink and rename replacement retain
the old object's charge until its cached inode and open handles are released;
`FORGET` alone does not refund a still-linked file. Guest `statfs` reports this
budget with 4096-byte blocks instead of the host filesystem's statistics.

These limits account for guest mutations, not direct writes by host processes.
Avoid concurrent host mutations of an active export; restart the VM after
external changes to rebuild accounting. Logical sizes exclude filesystem
metadata and allocation rounding. Provision enough host capacity for the sum of
all share budgets, entry overhead, and other host workloads: runtime quotas do
not reserve physical disk space or limit IOPS. Strong resource isolation also
requires host filesystem quotas/reservations and process CPU/memory limits.
See the [virtio-fs security review](virtiofs-security-review.md) for the
review scope, assumptions, tests, and remaining risks.
