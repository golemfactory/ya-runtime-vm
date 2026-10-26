# Virtio-fs security review

This review covers the host directory backend, pinned-handle helpers, local
FUSE decoder/session/reply code, and the relevant pinned OpenVMM virtio-fs
transport. It does not establish that a malicious guest cannot harm the host.
The remaining resource and process-isolation limits below are material.

## Threat model

Treat every guest FUSE frame, inode ID, file handle, length, offset, flag, and
filename as untrusted, including requests a normal Linux guest would not send.
The guest may read, change, and delete ordinary files inside its writable share.
That is intended authority. Access to host files outside that share, host
permission changes, and unbounded host resource consumption are not intended.

The provider selects dedicated share roots and trusted limits. Direct concurrent
host mutations are outside the quota-accounting model. Do not move an active
export or its pinned contents into a sensitive directory. Host processes that
interpret guest-created files must treat those contents as untrusted.

## Findings and changes

| Finding | Resolution |
| --- | --- |
| Previous name filtering omitted reserved punctuation, control bytes, console aliases, superscript COM/LPT aliases, and allowed invalid UTF-8 on Linux. | Apply the expanded filter on both hosts before filesystem operations. This is defensive policy hardening; no host escape through these names was reproduced. |
| Writable shares had no total file-size or filesystem-object budget. Cached-node and request limits alone did not prevent disk/inode exhaustion. | Add configurable per-share byte and entry limits, count existing exportable contents, reject excessive growth before host writes, and retain charges for unlinked/replaced pinned objects. |
| `statfs` returned actual host capacity/inode statistics. | Return only share-budget statistics with a fixed block size. This removes that disclosure; it does not make all filesystem behavior indistinguishable across hosts. |

Filename restrictions follow Microsoft's
[file naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
and [console handle documentation](https://learn.microsoft.com/en-us/windows/console/console-handles).

## Reviewed confinement mechanisms

- A share starts from a host-selected, validated directory handle. Guest paths
  are single components; operations are anchored to pinned directory/file
  handles rather than cached paths.
- Linux pins objects with `O_PATH | O_NOFOLLOW`, avoiding device opens and FIFO
  blocking during classification. Windows rejects reparse points and uses
  short-lived directory locks for cap-std operations and relative native
  rename/disposition calls.
- Symlink/hardlink creation, special-node creation, xattrs, and unsupported
  IOCTL/DAX operations are denied. Existing symlinks, reparse points, special
  files, and multiply linked regular files are excluded.
- Read/write/truncate paths validate the inode/handle relationship and access
  mode. File metadata is rechecked, including for already-open handles after
  host-side hardlink insertion. Guest ownership/mode changes remain synthetic.
- FUSE payloads are copied through the bounded decoder. Declared frame sizes
  must match transport bytes; variable payload counts are checked before
  allocation. Backend I/O sizes, nodes, handles, and directory snapshots have
  independent bounds. Shared memory/DAX is disabled for these shares.
- Quota accounting uses host file identities, independently of guest lookup
  counts. Requests cannot obtain refunds by forging a handle or forgetting a
  still-linked inode. Guest operations are serialized by the share mutex.

No direct path from the reviewed guest operations to a file outside the
export was identified. This is a source-review conclusion, not proof of
absence of vulnerabilities in OpenVMM, cap-std, OS filesystem APIs, or kernels.

## Regression coverage

Tests exercise host symlink replacement and cached handles, hardlink insertion
after open, rejected names across namespace operations, wrong inode/handle
pairs, truncated FUSE payloads, oversized lengths/offsets, and unsupported
IOCTL/DAX operations. Sentinel files inside and outside the share must remain
unchanged after hostile wire requests.

Quota tests cover existing nested contents, aggregate lengths, append, sparse
writes, truncate, empty-file/directory limits, forged handles, `FORGET`, open
unlink, and rename over an open destination. `statfs` must retain charges for
unlinked pins and refund them only after release/forget.

The Windows junction regression is conditional on a native Windows runner.
Local Linux tests and cross-compilation cannot substitute for Windows execution
or actual KVM/WHP testing. Deterministic malformed-frame regressions are not a
coverage-guided fuzzing campaign.

Validation on 2026-10-26 used an isolated checkout containing this change,
excluding unrelated uncommitted networking experiments. Formatting and runtime
Clippy with `-D warnings` pass for Linux musl; workspace tests report 112 passed
and two ignored integration tests. The shared-directory suite contains 23
passing tests on Linux. Windows GNU Clippy with all targets/features and
`-D warnings` also passes. Native Windows/MSVC execution and real KVM/WHP tests
were not run for this change.

## Remaining limits

- Logical byte and object quotas do not reserve physical space. Providers must
  provision capacity for all shares, allocation rounding, metadata, and other
  workloads. Direct host writes bypass enforcement; restart after external
  changes to rebuild the initial accounting.
- Per-request and per-share bounds are not CPU/IOPS rate limits. Repeated reads,
  directory scans, and fsync can consume host time or storage bandwidth.
- Pinned objects remain accessible after trusted host-side moves. Moving them
  outside the share does not revoke existing capabilities.
- The backend runs inside the runtime/VMM process. A memory-safety bug in that
  process can have the authority of the runtime's host account. Run it with
  minimal host privileges and resource limits; there is no separate filesystem
  worker sandbox in this implementation. Set process file-descriptor limits
  as well as CPU and memory limits.
- Windows filesystem behavior, case sensitivity, errors, and timing can still
  differ from Linux. Uniform name rules and synthetic metadata are not a
  general host-fingerprinting defense.

For a hard multi-tenant boundary, complement these checks with host-enforced
storage quotas/reservations and OS process isolation. The implementation alone
does not justify an unconditional claim that a guest cannot harm the host.
