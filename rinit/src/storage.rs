use std::{
    io::{Error, ErrorKind},
    path::Path,
};

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

pub fn scan_storage() -> std::io::Result<Vec<Storage>> {
    let block_dir = Path::new("/sys/class/block");

    let mut storage = Vec::new();

    for entry in std::fs::read_dir(block_dir)? {
        let entry = entry?;
        let path = entry.path();

        let filename = path.file_name().unwrap().to_str().unwrap();

        if !filename.starts_with("vd") {
            continue;
        }

        let serial_path = path.join("serial");

        if !serial_path.exists() {
            log::error!("Path '{}' does not exist", serial_path.display());
            continue;
        }

        let serial = std::fs::read_to_string(serial_path)?;

        let dev_path = format!("/dev/{}", filename);

        if serial.starts_with("rootfs-") {
            let rootfs_layer = if let Some((_, layer)) = serial.split_once("rootfs-") {
                layer.parse::<u32>().unwrap()
            } else {
                log::error!("Failed to parse rootfs layer from '{}'", serial);
                continue;
            };

            let rootfs_path = format!("/mnt/image-{}", rootfs_layer);

            log::info!(
                "Storage volume {} [{}] to be mounted at {} with data=''.",
                serial,
                dev_path,
                rootfs_path
            );

            storage.push(Storage {
                path: rootfs_path,
                dev: dev_path,
                fs_type: "squashfs".to_string(),
                data: None,
                flags: MsFlags::MS_RDONLY | MsFlags::MS_NODEV,
            });

            continue;
        }

        if !serial.starts_with("vol-") {
            log::info!(
                "Unknown virtio-blk: '{}', with serial '{}'",
                path.display(),
                serial
            );
            continue;
        }

        log::info!(
            "Found virtio-blk: '{}', with serial '{}', format as ext2",
            path.display(),
            serial
        );

        do_mkfs(&dev_path)?;

        let vol_path = format!("{}-path", serial);
        let mount_point = std::env::var(vol_path.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", vol_path),
            )
        })?;

        let vol_errors = format!("{}-errors", serial);
        let errors = std::env::var(vol_errors.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
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

        storage.push(Storage {
            path: mount_point,
            dev: dev_path,
            fs_type: "ext2".to_string(),
            data: Some(data),
            flags: MsFlags::MS_NODEV,
        });
    }

    for (var, value) in std::env::vars() {
        if !(var.starts_with("vol-") && var.ends_with("-size")) {
            continue;
        }

        let parts: Vec<&str> = var.split('-').collect();
        let volume_id = parts[1].parse::<u32>().map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to parse volume id from '{}'", var),
            )
        })?;

        let volume_path = format!("vol-{}-path", volume_id);
        let mount_point = std::env::var(volume_path.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", volume_path),
            )
        })?;

        let volume_size = value.parse::<u64>().unwrap();

        log::info!(
            "Found tmpfs volume '{}': '{}', size: {}",
            volume_id,
            mount_point,
            volume_size
        );

        let data = format!("mode=0700,size={}", volume_size);

        storage.push(Storage {
            path: mount_point,
            dev: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            data: Some(data),
            flags: MsFlags::MS_NODEV,
        });
    }

    log::info!("Found storage:");
    for s in storage.iter() {
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
