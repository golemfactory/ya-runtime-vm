use super::{ROOT, io as fs};
use crate::error::{Context, Result};
use alloc::{collections::BTreeMap, ffi::CString, string::String, vec::Vec};
use rustix::{fd::AsRawFd, mount::MountFlags as Flags};

pub fn mount(source: &str, target: &str, kind: &str, flags: Flags, data: &str) -> Result<()> {
    let directory = target
        .strip_prefix("/mnt/newroot/")
        .map(|relative| super::service::directory_in_root(format!("/{relative}").as_bytes()))
        .transpose()?;
    let fd_path = directory
        .as_ref()
        .map(|fd| format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let target = fd_path.as_deref().unwrap_or(target);
    fs::create_dir_all(target)?;
    let data = CString::new(data)?;
    rustix::mount::mount(source, target, kind, flags, Some(data.as_c_str()))
        .with_context(|| format!("mounting {source} at {target} ({kind})"))?;
    eprintln!("Mounted {source} at {target} ({kind})");
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
pub fn prepare(environment: &[CString]) -> Result<()> {
    mount("devtmpfs", "/dev", "devtmpfs", Flags::NOSUID, "mode=0755")?;
    mount(
        "sysfs",
        "/sys",
        "sysfs",
        Flags::NOSUID | Flags::NOEXEC | Flags::NODEV,
        "",
    )?;
    mount(
        "proc",
        "/proc",
        "proc",
        Flags::NOSUID | Flags::NOEXEC | Flags::NODEV,
        "",
    )?;
    for module in MODULES {
        let path = format!("/{module}.ko");
        if !fs::exists(&path) {
            continue;
        }
        let file = fs::File::open(&path)?;
        rustix::system::finit_module(&file, c"", 0).with_context(|| format!("loading {module}"))?;
        rustix::fs::unlink(&path)?;
    }
    let mut env = BTreeMap::new();
    for value in environment {
        if let Ok(value) = value.to_str()
            && let Some((key, value)) = value.split_once('=')
        {
            env.insert(String::from(key), String::from(value));
        }
    }
    let mut roots = BTreeMap::new();
    let mut volumes = Vec::new();
    for name in fs::read_dir("/sys/class/block")? {
        let Ok(serial) = fs::read_to_string(format!("/sys/class/block/{name}/serial")) else {
            continue;
        };
        let serial = serial.trim();
        let device = format!("/dev/{name}");
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
            crate::ensure!(
                ["continue", "remount-ro", "panic"].contains(&errors),
                "invalid ext2 error policy"
            );
            super::process::format(&device, environment)?;
            volumes.push((device, path.clone(), "ext2", format!("errors={errors}")));
        }
    }
    crate::ensure!(!roots.is_empty(), "no task package block devices found");
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
                String::from("tmpfs"),
                path.clone(),
                "tmpfs",
                format!("mode=0700,size={size}"),
            ));
        }
    }
    if let Some((device, _, kind, options)) = volumes.iter().find(|v| v.1 == "/") {
        mount(device, "/mnt/overlay", kind, Flags::NODEV, options)?;
    } else {
        mount(
            "tmpfs",
            "/mnt/overlay",
            "tmpfs",
            Flags::NOSUID | Flags::NODEV,
            "mode=0700,size=128M",
        )?;
    }
    let mut lowerdirs = Vec::new();
    for (expected, (index, device)) in roots.into_iter().enumerate() {
        crate::ensure!(
            index == expected,
            "task package layer sequence contains a gap"
        );
        let path = format!("/mnt/image-{index}");
        mount(&device, &path, "squashfs", Flags::RDONLY | Flags::NODEV, "")?;
        lowerdirs.push(path);
    }
    fs::create_dir_all("/mnt/overlay/upper")?;
    fs::create_dir_all("/mnt/overlay/work")?;
    mount(
        "overlay",
        ROOT,
        "overlay",
        Flags::NODEV,
        &format!(
            "lowerdir={},upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work",
            lowerdirs.join(":")
        ),
    )?;
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
        mount(source, &format!("{ROOT}/{name}"), kind, flags, options)?;
    }
    // Built-in /tmp, /dev and /dev/shm mounts must not hide explicit volumes.
    // Mount configured parents before children, independent of device order.
    volumes.sort_by_key(|(_, path, _, _)| path.split('/').filter(|p| !p.is_empty()).count());
    for (device, path, kind, options) in volumes {
        if path != "/" {
            mount(&device, &guest_path(&path)?, kind, Flags::NODEV, &options)?;
        }
    }
    let dev_fd = format!("{ROOT}/dev/fd");
    if !fs::exists(&dev_fd) {
        rustix::fs::symlink("/proc/self/fd", &dev_fd)?;
    }
    let _etc = super::service::directory_in_root(b"/etc")?;
    let flags = rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC;
    super::service::root_file(b"/etc/hosts", flags)?
        .write_all(b"127.0.0.1 localhost\n::1 localhost ip6-localhost\n")?;
    super::service::root_file(b"/etc/resolv.conf", flags)?
        .write_all(b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n")?;
    if let Some(hostname) = env.get("hostname") {
        rustix::system::sethostname(hostname.as_bytes())?;
    }
    super::network::loopback()?;
    Ok(())
}
pub fn guest_path(path: &str) -> Result<String> {
    crate::ensure!(
        path.starts_with('/') && !path.split('/').any(|p| p == ".."),
        "invalid guest path"
    );
    Ok(format!(
        "{ROOT}/{path}",
        path = path.trim_start_matches('/')
    ))
}
