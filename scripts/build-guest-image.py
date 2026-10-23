#!/usr/bin/env python3
"""Build the pinned Linux kernel/initramfs with the static Rust PID 1 agent."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
DEST = ROOT / "build/guest"
KERNEL_URL = "https://ya-runtime.s3-eu-west-1.amazonaws.com/vm/kernel/linux-virt-5.10.29-r0.apk"
KERNEL_SHA256 = "f3f7ca3421c5232e260b2a8a741bbf72c21881006afcf790aa3bc938e2262719"
MODULES = [
    "net/core/failover", "drivers/virtio/virtio", "drivers/virtio/virtio_ring",
    "drivers/virtio/virtio_mmio", "drivers/virtio/virtio_pci", "drivers/net/net_failover",
    "drivers/net/virtio_net", "drivers/char/hw_random/rng-core", "drivers/char/hw_random/virtio-rng",
    "drivers/block/virtio_blk", "net/vmw_vsock/vsock", "net/vmw_vsock/vmw_vsock_virtio_transport_common",
    "net/vmw_vsock/vmw_vsock_virtio_transport", "fs/mbcache", "fs/ext2/ext2", "fs/squashfs/squashfs",
    "fs/overlayfs/overlay", "net/packet/af_packet", "net/ipv6/ipv6", "drivers/net/tun", "fs/fuse/fuse",
    "fs/fuse/virtiofs",
]

def add_entry(output, name, data, mode, inode):
    name = name.encode() + b"\0"
    values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
    output.write(header + name)
    output.write(b"\0" * (-(len(header) + len(name)) % 4))
    output.write(data)
    output.write(b"\0" * (-len(data) % 4))

def formatter(cache):
    override = os.environ.get("YA_VM_MKFS")
    if override:
        return Path(override).read_bytes()
    binary = cache / "mkfs.ext2"
    if not binary.exists():
        subprocess.run(["docker", "build", "-t", "ya-vm-mkfs", str(ROOT / "guest/mkfs")], check=True)
        container = subprocess.check_output(["docker", "create", "ya-vm-mkfs"], text=True).strip()
        try:
            subprocess.run(["docker", "cp", f"{container}:/busybox/busybox_MKFS_EXT2", str(binary)], check=True)
        finally:
            subprocess.run(["docker", "rm", "-f", container], check=True)
    return binary.read_bytes()

def main():
    DEST.mkdir(parents=True, exist_ok=True)
    cache = TARGET / "guest-image"
    cache.mkdir(parents=True, exist_ok=True)
    apk = cache / "kernel.apk"
    if not apk.exists():
        with urllib.request.urlopen(KERNEL_URL, timeout=60) as response:
            apk.write_bytes(response.read())
    if hashlib.sha256(apk.read_bytes()).hexdigest() != KERNEL_SHA256:
        apk.unlink()
        raise SystemExit("Kernel APK checksum verification failed")
    entries = [("init", (TARGET / "x86_64-unknown-linux-musl/guest/ya-vm-guest-agent").read_bytes(), stat.S_IFREG | 0o755),
               ("mkfs.ext2", formatter(cache), stat.S_IFREG | 0o755)]
    with tarfile.open(apk, "r:gz") as package:
        members = {member.name.removeprefix("./"): member for member in package.getmembers()}
        (DEST / "vmlinuz-virt").write_bytes(package.extractfile(members["boot/vmlinuz-virt"]).read())
        prefix = "lib/modules/5.10.29-0-virt/kernel/"
        for module in MODULES:
            name = module + ".ko"
            entries.append((Path(name).name, package.extractfile(members[prefix + name]).read(), stat.S_IFREG | 0o644))
        for optional in ("virtio_pci_modern_dev", "virtio_pci_legacy_dev"):
            key = prefix + f"drivers/virtio/{optional}.ko"
            if key in members:
                entries.append((optional + ".ko", package.extractfile(members[key]).read(), stat.S_IFREG | 0o644))
    archive = io.BytesIO()
    for inode, (name, data, mode) in enumerate(entries, 1):
        add_entry(archive, name, data, mode, inode)
    add_entry(archive, "TRAILER!!!", b"", 0, len(entries) + 1)
    (DEST / "initramfs.cpio.gz").write_bytes(gzip.compress(archive.getvalue(), mtime=0))
    print(f"Guest image: {DEST / 'initramfs.cpio.gz'} ({len(entries)} files, Rust /init)")

if __name__ == "__main__":
    main()
