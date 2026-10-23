use super::ROOT;
use anyhow::{Context, Result};
use rustix::mount::MountFlags as Flags;
use std::{
    collections::BTreeMap, ffi::CString, fs, io::Write, os::fd::AsRawFd, path::Path,
    process::Command,
};

pub fn mount(source: &str, target: &Path, kind: &str, flags: Flags, data: &str) -> Result<()> {
    // Resolve guest mountpoints from a directory FD, rejecting symlinks into
    // PID 1's initramfs. Workload images control their directory contents.
    let directory = target
        .strip_prefix(ROOT)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|relative| super::service::directory_in_root(&Path::new("/").join(relative)))
        .transpose()?;
    let fd_path = directory
        .as_ref()
        .map(|fd| format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let target = fd_path.as_deref().map(Path::new).unwrap_or(target);
    fs::create_dir_all(target)?;
    let data = CString::new(data)?;
    rustix::mount::mount(source, target, kind, flags, Some(data.as_c_str()))
        .with_context(|| format!("mounting {source} at {} ({kind})", target.display()))?;
    eprintln!("Mounted {source} at {} ({kind})", target.display());
    Ok(())
}

const MODULES: &[&str] = &[
    "failover",
    "virtio",
    "virtio_ring",
    "virtio_mmio",
    "virtio_pci_modern_dev",
    "virtio_pci_legacy_dev",
    "virtio_pci",
    "net_failover",
    "virtio_net",
    "rng-core",
    "virtio-rng",
    "virtio_blk",
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
    "mbcache",
    "ext2",
    "squashfs",
    "overlay",
    "af_packet",
    "ipv6",
    "tun",
    "fuse",
    "virtiofs",
];

pub fn prepare() -> Result<()> {
    mount(
        "devtmpfs",
        Path::new("/dev"),
        "devtmpfs",
        Flags::NOSUID,
        "mode=0755",
    )?;
    mount(
        "sysfs",
        Path::new("/sys"),
        "sysfs",
        Flags::NOSUID | Flags::NOEXEC | Flags::NODEV,
        "",
    )?;
    mount(
        "proc",
        Path::new("/proc"),
        "proc",
        Flags::NOSUID | Flags::NOEXEC | Flags::NODEV,
        "",
    )?;
    for module in MODULES {
        let path = format!("/{module}.ko");
        if !Path::new(&path).exists() {
            continue;
        }
        let file = fs::File::open(&path)?;
        rustix::system::finit_module(&file, c"", 0).with_context(|| format!("loading {module}"))?;
        fs::remove_file(path)?;
    }
    let env: BTreeMap<_, _> = std::env::vars().collect();
    let mut roots = BTreeMap::new();
    let mut volumes = Vec::new();
    for entry in fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let Ok(serial) = fs::read_to_string(entry.path().join("serial")) else {
            continue;
        };
        let serial = serial.trim();
        let device = format!("/dev/{}", entry.file_name().to_string_lossy());
        if let Some(index) = serial.strip_prefix("rootfs-") {
            roots.insert(index.parse::<usize>()?, device);
        } else if let Some(index) = serial.strip_prefix("vol-") {
            let path = env
                .get(&format!("vol-{index}-path"))
                .context("missing storage mount path")?;
            let errors = env
                .get(&format!("vol-{index}-errors"))
                .map(String::as_str)
                .unwrap_or("continue");
            anyhow::ensure!(
                ["continue", "remount-ro", "panic"].contains(&errors),
                "invalid ext2 error policy"
            );
            let status = Command::new("/mkfs.ext2").arg(&device).status()?;
            anyhow::ensure!(status.success(), "formatting {device} failed: {status}");
            volumes.push((device, path.clone(), "ext2", format!("errors={errors}")));
        }
    }
    anyhow::ensure!(!roots.is_empty(), "no task package block devices found");
    for (key, size) in &env {
        if let Some(index) = key
            .strip_prefix("vol-")
            .and_then(|s| s.strip_suffix("-size"))
        {
            let size = size.parse::<u64>()?;
            let path = env
                .get(&format!("vol-{index}-path"))
                .context("missing RAM volume path")?;
            volumes.push((
                "tmpfs".into(),
                path.clone(),
                "tmpfs",
                format!("mode=0700,size={size}"),
            ));
        }
    }
    let overlay = Path::new("/mnt/overlay");
    if let Some((device, _, kind, options)) = volumes.iter().find(|v| v.1 == "/") {
        mount(device, overlay, kind, Flags::NODEV, options)?;
    } else {
        mount(
            "tmpfs",
            overlay,
            "tmpfs",
            Flags::NOSUID | Flags::NODEV,
            "mode=0700,size=128M",
        )?;
    }
    let mut lowerdirs = Vec::new();
    for (expected, (index, device)) in roots.into_iter().enumerate() {
        anyhow::ensure!(
            index == expected,
            "task package layer sequence contains a gap"
        );
        let path = format!("/mnt/image-{index}");
        mount(
            &device,
            Path::new(&path),
            "squashfs",
            Flags::RDONLY | Flags::NODEV,
            "",
        )?;
        lowerdirs.push(path);
    }
    fs::create_dir_all(overlay.join("upper"))?;
    fs::create_dir_all(overlay.join("work"))?;
    mount(
        "overlay",
        Path::new(ROOT),
        "overlay",
        Flags::NODEV,
        &format!(
            "lowerdir={},upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work",
            lowerdirs.join(":")
        ),
    )?;
    for (device, path, kind, options) in volumes {
        if path == "/" {
            continue;
        }
        let target = guest_path(&path)?;
        mount(&device, &target, kind, Flags::NODEV, &options)?;
    }
    let root = Path::new(ROOT);
    for (name, source, kind, options, flags) in [
        (
            "proc",
            "proc",
            "proc",
            "",
            Flags::NODEV | Flags::NOSUID | Flags::NOEXEC,
        ),
        (
            "sys",
            "sysfs",
            "sysfs",
            "",
            Flags::NODEV | Flags::NOSUID | Flags::NOEXEC,
        ),
        ("dev", "devtmpfs", "devtmpfs", "mode=0755", Flags::NOSUID),
        ("tmp", "tmpfs", "tmpfs", "mode=1777", Flags::NOSUID),
        (
            "dev/pts",
            "devpts",
            "devpts",
            "gid=5,mode=0620",
            Flags::NOSUID | Flags::NOEXEC,
        ),
        (
            "dev/shm",
            "tmpfs",
            "tmpfs",
            "mode=1777",
            Flags::NOSUID | Flags::NODEV,
        ),
    ] {
        mount(source, &root.join(name), kind, flags, options)?;
    }
    if !root.join("dev/fd").exists() {
        std::os::unix::fs::symlink("/proc/self/fd", root.join("dev/fd"))?;
    }
    let _etc = super::service::directory_in_root(Path::new("/etc"))?;
    super::service::root_file(
        Path::new("/etc/hosts"),
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC,
    )?
    .write_all(b"127.0.0.1 localhost\n::1 localhost ip6-localhost\n")?;
    super::service::root_file(
        Path::new("/etc/resolv.conf"),
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC,
    )?
    .write_all(b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n")?;
    if let Some(hostname) = env.get("hostname") {
        rustix::system::sethostname(hostname.as_bytes())?;
    }
    super::network::loopback()?;
    Ok(())
}

pub fn guest_path(path: &str) -> Result<std::path::PathBuf> {
    use std::path::Component;
    let path = Path::new(path);
    anyhow::ensure!(
        path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
        "invalid guest path"
    );
    Ok(Path::new(ROOT).join(path.strip_prefix("/")?))
}
