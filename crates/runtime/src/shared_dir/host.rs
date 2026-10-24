//! Host handle operations and portable name restrictions for directory exports.
use super::Object;
use cap_fs_ext::{DirExt, MetadataExt};
#[cfg(windows)]
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
#[cfg(windows)]
use cap_std::fs::OpenOptions;
use cap_std::fs::{Dir, Metadata};
use fuse::protocol::fuse_kstatfs;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn open_root(work_dir: &Path, name: &str) -> io::Result<File> {
    let name = component(name.as_bytes()).map_err(io::Error::other)?;
    // Only this trusted host-supplied work directory uses ambient authority.
    let parent = Dir::open_ambient_dir(work_dir, cap_std::ambient_authority())?;
    let dir = parent.open_dir_nofollow(name)?;
    check_metadata(&dir.dir_metadata()?).map_err(io::Error::other)?;
    Ok(dir.into_std_file())
}

// Reject path syntax on both hosts, including Windows alternate streams and DOS aliases.
pub(super) fn component(bytes: &[u8]) -> lx::Result<OsString> {
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| matches!(b, 0 | b'/' | b'\\' | b':'))
        || matches!(bytes.last(), Some(b'.' | b' '))
    {
        return Err(lx::Error::EINVAL);
    }
    let base = bytes
        .split(|b| *b == b'.')
        .next()
        .unwrap()
        .to_ascii_uppercase();
    if matches!(base.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || (base.len() == 4
            && matches!(&base[..3], b"COM" | b"LPT")
            && matches!(base[3], b'1'..=b'9'))
    {
        return Err(lx::Error::EINVAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(bytes).to_os_string())
    }
    #[cfg(windows)]
    {
        Ok(OsString::from(
            std::str::from_utf8(bytes).map_err(|_| lx::Error::EINVAL)?,
        ))
    }
}
pub(super) fn name_bytes(name: &OsStr) -> Option<&[u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(name.as_bytes())
    }
    #[cfg(windows)]
    {
        name.to_str().map(str::as_bytes)
    }
}
pub(super) fn check_metadata(metadata: &Metadata) -> lx::Result<()> {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        // Reject all reparse points, not just symbolic-link and junction tags.
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(lx::Error::ELOOP);
        }
    }
    if metadata.is_symlink() {
        return Err(lx::Error::ELOOP);
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(lx::Error::EPERM);
    }
    // A hard link can alias a file outside the exported tree. Directories have
    // multiple links naturally, and are pinned independently instead.
    if metadata.is_file() && metadata.nlink() > 1 {
        return Err(lx::Error::EPERM);
    }
    Ok(())
}
pub(super) fn pin(parent: &Dir, name: &OsStr) -> lx::Result<Object> {
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| lx::Error::EINVAL)?;
        // O_PATH pins the object without opening devices or blocking on FIFOs.
        // The parent is pinned, and name is exactly one validated component.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new owned descriptor.
        unsafe { File::from_raw_fd(fd) }
    };
    #[cfg(windows)]
    let file = {
        use cap_fs_ext::OpenOptionsMaybeDirExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .maybe_dir(true)
            .follow(FollowSymlinks::No);
        // Directories and host read-only files need only a read handle.
        parent
            .open_with(name, &options)
            .or_else(|_| {
                options.write(false);
                parent.open_with(name, &options)
            })?
            .into_std()
    };
    let metadata = Metadata::from_file(&file)?;
    check_metadata(&metadata)?;
    Ok(if metadata.is_dir() {
        Object::Directory(Arc::new(Dir::from_std_file(file)))
    } else {
        Object::File(Arc::new(file))
    })
}
pub(super) fn reopen(file: &File, read: bool, write: bool) -> lx::Result<File> {
    check_metadata(&Metadata::from_file(file)?)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // Deliberately follow only our own pinned, validated regular-file fd.
        // No guest path is involved. O_TRUNC is applied only after validation.
        Ok(std::fs::OpenOptions::new()
            .read(read)
            .write(write)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?)
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::Reopen;
        Ok(file.reopen(OpenOptions::new().read(read).write(write))?)
    }
}
pub(super) fn filesystem_stats(root: &Dir) -> lx::Result<fuse_kstatfs> {
    #[cfg(target_os = "linux")]
    let (blocks, bfree, bavail, files, ffree, bsize) = {
        use std::os::fd::AsRawFd;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: root is a valid descriptor and stats points to writable storage.
        if unsafe { libc::fstatvfs(root.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: fstatvfs initialized stats on success.
        let stats = unsafe { stats.assume_init() };
        (
            stats.f_blocks,
            stats.f_bfree,
            stats.f_bavail,
            stats.f_files,
            stats.f_ffree,
            stats.f_frsize as u32,
        )
    };
    #[cfg(windows)]
    let (blocks, bfree, bavail, files, ffree, bsize) = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Wdk::Storage::FileSystem::{
            FileFsFullSizeInformation, NtQueryVolumeInformationFile,
        };
        use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
        let mut stats = std::mem::MaybeUninit::<FILE_FS_FULL_SIZE_INFORMATION>::uninit();
        let mut iosb = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
        // SAFETY: valid synchronous directory handle and correctly sized output buffers.
        let status = unsafe {
            NtQueryVolumeInformationFile(
                root.as_raw_handle(),
                iosb.as_mut_ptr(),
                stats.as_mut_ptr().cast(),
                size_of::<FILE_FS_FULL_SIZE_INFORMATION>() as u32,
                FileFsFullSizeInformation,
            )
        };
        if status != 0 {
            return Err(lx::Error::EIO);
        }
        // SAFETY: successful query filled the requested structure.
        let stats = unsafe { stats.assume_init() };
        (
            stats.TotalAllocationUnits as u64,
            stats.ActualAvailableAllocationUnits as u64,
            stats.CallerAvailableAllocationUnits as u64,
            0,
            0,
            stats
                .SectorsPerAllocationUnit
                .saturating_mul(stats.BytesPerSector),
        )
    };
    Ok(fuse_kstatfs {
        blocks,
        bfree,
        bavail,
        files,
        ffree,
        bsize,
        namelen: 255,
        frsize: bsize,
        padding: 0,
        spare: [0; 6],
    })
}
