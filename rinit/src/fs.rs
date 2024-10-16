use std::{
    fs::File,
    io::{BufRead, BufReader},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use nix::{
    mount::{mount, MsFlags},
    sys::stat::{Mode, SFlag},
};

use crate::{storage::Storage, DEFAULT_DIR_PERMS, IRWXU_PERMS, NEW_ROOT, NONE, SYSROOT};

pub fn write_sys(path: &str, value: usize) {
    let _ = std::fs::write(path, format!("{}", value));
}

pub fn mount_core_filesystems() -> std::io::Result<()> {
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755,size=2M"),
    )?;

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )?;

    Ok(())
}

pub fn chroot_to_new_root() -> std::io::Result<()> {
    nix::unistd::chdir(&Path::new("/").join(NEW_ROOT))?;
    mount(Some("."), "/", NONE, MsFlags::MS_MOVE, NONE)?;
    nix::unistd::chroot(".")?;
    mount(NONE, ".", NONE, MsFlags::MS_SHARED, NONE)?;

    Ok(())
}

pub fn create_dirs<P: AsRef<Path>>(path: P, perms: std::fs::Permissions) -> std::io::Result<()> {
    let path = path.as_ref();

    let mut current_path: PathBuf = Path::new("/").to_path_buf();

    for p in path {
        // let p = Path::new(&p);
        let new_path = current_path.join(p);

        if p == Path::new("/") {
            continue;
        }

        if new_path.exists() {
            current_path = new_path;
            continue;
        }

        std::fs::create_dir(new_path.clone())?;
        std::fs::set_permissions(new_path.clone(), perms.clone())?;

        current_path = new_path;
    }

    Ok(())
}

pub fn create_directories() -> std::io::Result<()> {
    for dir in ["/dev", "/sys", SYSROOT] {
        create_dirs(
            dir,
            std::fs::Permissions::from_mode(crate::DEFAULT_DIR_PERMS),
        )?;
    }

    for dir in ["/mnt", "/proc", "/mnt/overlay"] {
        create_dirs(dir, std::fs::Permissions::from_mode(crate::IRWXU_PERMS))?;
    }

    Ok(())
}

pub fn do_mkfs(dev_path: &str) -> std::io::Result<()> {
    let status = std::process::Command::new("/mkfs.ext2")
        .arg(dev_path)
        .status()?;

    log::info!("  mkfs.ext2 status: {:?}", status);

    Ok(())
}

pub fn mount_volume(tag: String, path: String) -> std::io::Result<()> {
    let stripped_path = Path::new(&path[1..]);
    let sysroot_path = Path::new(SYSROOT);
    let final_path = sysroot_path.join(stripped_path);
    log::trace!(
        "mount_volume: Mounting volume '{}' to '{}' ('{}')",
        tag,
        final_path.display(),
        path,
    );

    create_dirs(
        &final_path,
        std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS),
    )?;

    log::info!(
        "Mounting '{}' to '{}' fstype: '{}' data: '{:?}' flags: '{:?}'",
        tag,
        final_path.display(),
        "9p",
        "trans=virtio,version=9p2000.L,msize=104857600",
        MsFlags::empty(),
    );

    mount(
        Some(tag.as_str()),
        final_path.as_path(),
        Some("9p"),
        MsFlags::empty(),
        Some("trans=virtio,version=9p2000.L,msize=104857600"),
    )?;

    Ok(())
}

pub fn mount_overlay(storage: &[Storage]) -> std::io::Result<()> {
    if let Some(s) = storage.iter().find(|s| s.path == "/") {
        log::info!(
            "Mounting tmpfs to /mnt/overlay fstype: '{}' flags: '{:?}' data: {:?}",
            s.fs_type,
            s.flags,
            s.data
        );

        mount(
            Some(s.dev.as_str()),
            "/mnt/overlay",
            Some(s.fs_type.as_str()),
            s.flags,
            s.data.as_deref(),
        )?;
    }

    for s in storage.iter() {
        if !s.path.starts_with("/mnt/image-") {
            continue;
        }

        log::info!(
            "Mounting rootfs '{}' to '{}' fstype: '{}' flags: '{:?}' data: '{:?}'",
            s.dev,
            s.path,
            s.fs_type,
            s.flags,
            s.data
        );

        create_dirs(s.path.clone(), std::fs::Permissions::from_mode(IRWXU_PERMS))?;

        mount(
            Some(s.dev.as_str()),
            s.path.as_str(),
            Some(s.fs_type.as_str()),
            s.flags,
            s.data.as_deref(),
        )?;
    }

    for dir in ["/mnt/overlay/upper", "/mnt/overlay/work"] {
        create_dirs(dir, std::fs::Permissions::from_mode(IRWXU_PERMS))?;
    }

    let rootfs_layers: Vec<String> = storage
        .iter()
        .filter(|s| s.path.starts_with("/mnt/image-"))
        .map(|s| s.path.clone())
        .collect();

    let rootfs_layers = rootfs_layers.join(":");
    let overlay_data = format!(
        "lowerdir={},upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work",
        rootfs_layers
    );

    log::info!(
        "Mounting overlay to '/mnt/newroot' data: '{:?}' fstype: 'overlay' flags: '{:?}'",
        overlay_data,
        MsFlags::MS_NODEV,
    );

    mount(
        Some("overlay"),
        SYSROOT,
        Some("overlay"),
        MsFlags::MS_NODEV,
        Some(overlay_data.as_str()),
    )?;

    let upper_stat = std::fs::metadata("/mnt/overlay/upper")?;

    for s in storage {
        if s.path.starts_with("/mnt/image-") || s.path == "/" {
            continue;
        }

        let storage_path = Path::new(SYSROOT).join(&s.path[1..]);
        create_dirs(
            storage_path.clone(),
            std::fs::Permissions::from_mode(upper_stat.mode()),
        )?;

        log::info!(
            "Mounting '{}' to '{}' fstype: '{}' data: '{:?}' flags: '{:?}'",
            s.dev,
            storage_path.display(),
            s.fs_type,
            s.data,
            s.flags,
        );

        create_dirs(s.path.clone(), std::fs::Permissions::from_mode(IRWXU_PERMS))?;

        mount(
            Some(s.dev.as_str()),
            s.path.as_str(),
            Some(s.fs_type.as_str()),
            s.flags,
            s.data.as_deref(),
        )?;
    }

    Ok(())
}

pub fn mount_sysroot() -> std::io::Result<()> {
    let sysroot = Path::new(SYSROOT);
    for dir in [sysroot.join("dev").as_path(), sysroot.join("tmp").as_path()] {
        create_dirs(dir, std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;
    }

    let default_mount_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;

    mount(
        Some("proc"),
        Path::new("/proc"),
        Some("proc"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("proc"),
        sysroot.join("proc").as_path(),
        Some("proc"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("sysfs"),
        sysroot.join("sys").as_path(),
        Some("sysfs"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("devtmpfs"),
        sysroot.join("dev").as_path(),
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755,size=2M"),
    )?;

    let a = sysroot.join("dev/fd");
    println!("DEV/FD: {:?}", a.display());

    nix::unistd::symlinkat("/proc/self/fd", None, sysroot.join("dev/fd").as_path())?;

    mount(
        Some("tmpfs"),
        sysroot.join("tmp").as_path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )?;

    let dev_pts = sysroot.join("dev/pts");
    let dev_shm = sysroot.join("dev/shm");
    for dir in [dev_pts.as_path(), dev_shm.as_path()] {
        create_dirs(dir, std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;
    }

    mount(
        Some("devpts"),
        dev_pts.as_path(),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("gid=5,mode=0620"),
    )?;

    mount(
        Some("tmpfs"),
        dev_shm.as_path(),
        Some("tmpfs"),
        default_mount_flags,
        NONE,
    )?;

    let mode_rw_ugo = Mode::S_IRUSR
        | Mode::S_IWUSR
        | Mode::S_IRGRP
        | Mode::S_IWGRP
        | Mode::S_IROTH
        | Mode::S_IWOTH;

    let dev_null = sysroot.join("dev/null");
    if !dev_null.exists() {
        nix::sys::stat::mknod(
            dev_null.as_path(),
            SFlag::S_IFCHR,
            mode_rw_ugo,
            libc::makedev(1, 3),
        )?;
    }

    let dev_ptmx = sysroot.join("dev/ptmx");
    if !dev_ptmx.exists() {
        nix::sys::stat::mknod(
            dev_ptmx.as_path(),
            SFlag::S_IFCHR,
            mode_rw_ugo,
            libc::makedev(5, 2),
        )?;
    }

    Ok(())
}

pub fn find_device_major(name: &str) -> std::io::Result<i32> {
    let file = File::open("/proc/devices")?;
    let reader = BufReader::new(file);

    let mut major = -1;
    let mut in_character_devices = false;

    for line in reader.lines() {
        let line = line?;
        if line == "Character devices:" {
            in_character_devices = true;
        } else if line.is_empty() || line == "Block devices:" {
            if in_character_devices {
                break;
            }
        } else if in_character_devices {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if let (Ok(entry_major), entry_name) = (parts[0].parse::<i32>(), parts[1]) {
                    if entry_name == name {
                        major = entry_major;
                        break;
                    }
                }
            }
        }
    }

    Ok(major)
}

pub fn nvidia_gpu_count() -> i32 {
    let mut counter = 0;

    for i in 0..256 {
        let path = format!("/sys/class/drm/card{}", i);
        let path = Path::new(&path);

        if !path.exists() {
            break;
        }

        counter = i + 1;
    }

    counter
}
