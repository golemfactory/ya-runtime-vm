use std::path::Path;

use nix::mount::MsFlags;

use crate::fs::do_mkfs;

#[derive(Debug)]
pub struct Storage {
    pub path: String,
    pub dev: String,
    pub fs_type: String,
    pub data: Option<String>,
    pub flags: MsFlags,
}

fn process_rootfs(serial: &str, dev_path: &str) -> std::io::Result<Option<Storage>> {
    if let Some(layer) = serial.strip_prefix("rootfs-") {
        let rootfs_layer = layer.parse::<u32>().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid rootfs layer")
        })?;
        let rootfs_path = format!("/mnt/image-{}", rootfs_layer);

        log::info!(
            "Storage volume {} [{}] to be mounted at {} with data=''.",
            serial,
            dev_path,
            rootfs_path
        );

        Ok(Some(Storage {
            path: rootfs_path,
            dev: dev_path.to_string(),
            fs_type: "squashfs".to_string(),
            data: None,
            flags: MsFlags::MS_RDONLY | MsFlags::MS_NODEV,
        }))
    } else {
        Ok(None)
    }
}

fn process_volume(serial: &str, dev_path: &str) -> std::io::Result<Option<Storage>> {
    if let Some(vol_id) = serial.strip_prefix("vol-") {
        log::info!(
            "Found virtio-blk: '{}', with serial '{}', format as ext2",
            dev_path,
            serial
        );

        do_mkfs(dev_path)?;

        let vol_path = format!("{}-path", serial);
        let mount_point = std::env::var(&vol_path).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", vol_path),
            )
        })?;

        let vol_errors = format!("{}-errors", serial);
        let errors = std::env::var(&vol_errors).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", vol_errors),
            )
        })?;
        let data = format!("errors={}", errors);

        log::info!(
            "Storage volume {} [{}] to be mounted at {} with data='{}'.",
            serial,
            dev_path,
            mount_point,
            data
        );

        Ok(Some(Storage {
            path: mount_point,
            dev: dev_path.to_string(),
            fs_type: "ext2".to_string(),
            data: Some(data),
            flags: MsFlags::MS_NODEV,
        }))
    } else {
        Ok(None)
    }
}

fn process_block_device(path: &Path) -> std::io::Result<Option<Storage>> {
    let filename = path.file_name().unwrap().to_str().unwrap();
    let serial_path = path.join("serial");

    if !serial_path.exists() {
        log::error!("Path '{}' does not exist", serial_path.display());
        return Ok(None);
    }

    let serial = std::fs::read_to_string(serial_path)?;
    let dev_path = format!("/dev/{}", filename);

    if let Some(storage) = process_rootfs(&serial, &dev_path)? {
        return Ok(Some(storage));
    }

    if let Some(storage) = process_volume(&serial, &dev_path)? {
        return Ok(Some(storage));
    }

    log::info!(
        "Unknown virtio-blk: '{}', with serial '{}'",
        path.display(),
        serial
    );

    Ok(None)
}

fn process_tmpfs_volume(var: &str, value: &str) -> Option<Storage> {
    let volume_id = var.split('-').nth(1)?.parse::<u32>().ok()?;
    let volume_path = format!("vol-{}-path", volume_id);
    let mount_point = std::env::var(volume_path).ok()?;
    let volume_size = value.parse::<u64>().ok()?;

    log::info!(
        "Found tmpfs volume '{}': '{}', size: {}",
        volume_id,
        mount_point,
        volume_size
    );

    Some(Storage {
        path: mount_point,
        dev: "tmpfs".to_string(),
        fs_type: "tmpfs".to_string(),
        data: Some(format!("mode=0700,size={}", volume_size)),
        flags: MsFlags::MS_NODEV,
    })
}

pub fn scan_storage() -> std::io::Result<Vec<Storage>> {
    let block_dir = Path::new("/sys/class/block");

    let mut storage = block_dir
        .read_dir()?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map_or(false, |name| name.starts_with("vd"))
        })
        .filter_map(|entry| process_block_device(&entry.path()).transpose())
        .collect::<Result<Vec<_>, _>>()?;

    let tmpfs_volumes: Vec<Storage> = std::env::vars()
        .filter(|(var, _)| var.starts_with("vol-") && var.ends_with("-size"))
        .filter_map(|(var, value)| process_tmpfs_volume(&var, &value))
        .collect();

    storage.extend(tmpfs_volumes);

    log::info!("Found storage:");
    for s in &storage {
        log::info!(
            " path = '{:8}' @ '{}' fstype = '{}' data = {:?} flags = {:?}",
            s.dev,
            s.path,
            s.fs_type,
            s.data,
            s.flags
        );
    }

    Ok(storage)
}
