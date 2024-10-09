use std::{
    fs::{copy, create_dir_all, read_dir, read_link},
    io::Result,
    os::unix::fs::symlink,
    path::Path,
};

use nix::{
    fcntl::{open, OFlag},
    mount::{mount, MsFlags},
    sys::stat::{fstat, mknod, Mode, SFlag},
};

use crate::{check_bool, NEW_ROOT, NONE};


fn copy_recursive_impl(src: &Path, dst: &Path, dst_orig: &Path) -> Result<()> {
    create_dir_all(dst)?;
    for entry in read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let src_path = &entry.path();
        let dst_path = &dst.join(entry.file_name());

        if src_path.starts_with(dst_orig) {
            continue;
        }

        if ft.is_dir() {
            copy_recursive_impl(src_path, dst_path, dst_orig)?;
        } else if ft.is_symlink() {
            let path = read_link(src_path)?;
            symlink(path, dst_path)?;
        } else if ft.is_file() {
            copy(src_path, dst_path)?;
        } else {
            let fd = open(src_path, OFlag::O_PATH, Mode::all())?;
            let stat = fstat(fd)?;
            let kind = SFlag::from_bits_truncate(stat.st_mode);
            let perm = Mode::from_bits_truncate(stat.st_mode);
            mknod(dst_path, kind, perm, stat.st_dev)?;
        }
    }

    Ok(())
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    copy_recursive_impl(src, dst, dst)
}

pub fn copy_initramfs() -> Result<()> {
    let root = Path::new("/");
    let new_root = &root.join(NEW_ROOT);

    println!("Copying initramfs from '{}' to '{}'", root.display(), new_root.display());
    check_bool!(root.exists());
    check_bool!(new_root.exists());
    mount(NONE, new_root, Some("tmpfs"), MsFlags::empty(), NONE)?;
    copy_recursive(root, new_root)?;
    println!("Initramfs copied successfully");

    Ok(())
}
