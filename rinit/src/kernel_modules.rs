use std::{ffi::CString, fs::File, os::fd::AsRawFd, path::Path};

use crate::check_bool;

fn load_module(module: &str) -> std::io::Result<()> {
    let path = format!("/{}", module);
    println!("Loading kernel module '{}'", path);

    let path = Path::new(&path);
    check_bool!(path.exists());

    let file = File::open(path)?;

    let params = c"";

    unsafe {
        let result = libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0);

        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn load_nvidia_modules() -> std::io::Result<()> {
    let nvidia_modules = [
        "i2c-core.ko",
        "drm_panel_orientation_quirks.ko",
        "firmware_class.ko",
        "drm.ko",
        "nvidia.ko",
        "nvidia-uvm.ko",
        "fbdev.ko",
        "fb.ko",
        "fb_sys_fops.ko",
        "cfbcopyarea.ko",
        "cfbfillrect.ko",
        "cfbimgblt.ko",
        "syscopyarea.ko",
        "sysfillrect.ko",
        "sysimgblt.ko",
        "drm_kms_helper.ko",
        "nvidia-modeset.ko",
        "nvidia-drm.ko",
    ];

    for module in nvidia_modules {
        load_module(module)?;
    }

    Ok(())
}

pub fn load_modules() -> std::io::Result<()> {
    let modules = [
        (false, "failover.ko"),
        (false, "virtio.ko"),
        (false, "virtio_ring.ko"),
        (true, "virtio_pci_modern_dev.ko"),
        (true, "virtio_pci_legacy_dev.ko"),
        (false, "virtio_pci.ko"),
        (false, "net_failover.ko"),
        (false, "virtio_net.ko"),
        (false, "virtio_console.ko"),
        (false, "rng-core.ko"),
        (false, "virtio-rng.ko"),
        (false, "virtio_blk.ko"),
        (false, "mbcache.ko"),
        (false, "ext2.ko"),
        (false, "squashfs.ko"),
        (false, "overlay.ko"),
        (true, "netfs.ko"),
        (false, "fscache.ko"),
        (false, "af_packet.ko"),
        (false, "ipv6.ko"),
        (false, "tun.ko"),
        (false, "9pnet.ko"),
        (false, "9pnet_virtio.ko"),
        (false, "9p.ko"),
    ];

    let root =  Path::new("/");

    for (check, module) in modules {
        if check {
            let path = root.join(module);
            println!("Checking if kernel module '{}' exists", path.display());
            if path.exists() {
                load_module(module)?;
            }
        } else {
            load_module(module)?;
        }
    }

    if Path::new("/nvidia.ko").exists() {
        load_nvidia_modules()?;
    }

    Ok(())
}
