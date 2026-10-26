//! Host handle operations and portable name restrictions for directory exports.
use super::Object;
#[cfg(target_os = "linux")]
use cap_fs_ext::DirExt;
use cap_fs_ext::MetadataExt;
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
    #[cfg(target_os = "linux")]
    let file = parent.open_dir_nofollow(name)?.into_std_file();
    #[cfg(windows)]
    let file = {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        parent
            .open_with(
                name,
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .follow(FollowSymlinks::No),
            )?
            .into_std()
    };
    let metadata = Metadata::from_file(&file)?;
    check_metadata(&metadata).map_err(io::Error::other)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "share root must be a directory",
        ));
    }
    Ok(file)
}

/// Open a short-lived directory capability from its pinned object, never its
/// cached name. On Windows cap-std needs a no-delete-share handle while it
/// performs operations that use the directory's current host path. Keep that
/// lock for the whole operation, rather than preventing rename/rmdir for the
/// lifetime of a cached FUSE inode.
pub(super) fn lock_directory(file: &File) -> lx::Result<Dir> {
    #[cfg(target_os = "linux")]
    let file = file.try_clone()?;
    #[cfg(windows)]
    let file = reopen_directory(
        file,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
        false,
    )?;
    check_metadata(&Metadata::from_file(&file)?)?;
    Ok(Dir::from_std_file(file))
}

#[cfg(windows)]
fn reopen_directory(file: &File, access: u32, share_delete: bool) -> io::Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
            NtCreateFile,
        },
    };
    use windows_sys::Win32::{
        Foundation::{RtlNtStatusToDosError, UNICODE_STRING},
        Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE},
        System::IO::IO_STATUS_BLOCK,
    };
    let empty = [0u16];
    let name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 2,
        Buffer: empty.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file.as_raw_handle(),
        ObjectName: &name,
        ..Default::default()
    };
    let mut handle = std::ptr::null_mut();
    let mut iosb = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    // SAFETY: an empty name relative to the live pinned handle reopens that
    // exact object. DIRECTORY_FILE prevents treating a regular file as a
    // directory; REPARSE_POINT prevents traversal. All buffers live until this
    // synchronous operation completes. ReOpenFile rejects directory handles.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            iosb.as_mut_ptr(),
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: scalar status conversion; no pointers are passed.
        let error = io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
        log::debug!("reopening pinned directory failed (NTSTATUS={status:#x}): {error}");
        return Err(error);
    }
    // SAFETY: successful NtCreateFile returned a new owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn sync_directory(file: &File) -> lx::Result<()> {
    #[cfg(target_os = "linux")]
    let handle = reopen(file, true, false)?;
    #[cfg(windows)]
    let handle = {
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
        reopen_directory(file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, true)?
    };
    handle.sync_all()?;
    Ok(())
}

// Reject path syntax. On Windows also reject alternate streams, names the
// Win32 layer would trim and DOS device aliases; these are legal Linux names.
pub(super) fn component(bytes: &[u8]) -> lx::Result<OsString> {
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| matches!(b, 0 | b'/'))
    {
        return Err(lx::Error::EINVAL);
    }
    #[cfg(windows)]
    {
        if bytes.iter().any(|b| matches!(b, b'\\' | b':'))
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
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            // Unlike maybe_dir(), this preserves FILE_SHARE_DELETE on the
            // persistent pin. lock_directory adds the per-operation lock.
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
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
        Object::Directory(Arc::new(file))
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
        file.reopen(OpenOptions::new().read(read).write(write))
            .map_err(|error| {
                log::debug!("reopening file for read={read} write={write} failed: {error}");
                error.into()
            })
    }
}

pub(super) fn reopen_for_times(file: &File) -> lx::Result<File> {
    #[cfg(target_os = "linux")]
    {
        reopen(file, true, false)
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::Reopen;
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_WRITE_ATTRIBUTES,
        };
        check_metadata(&Metadata::from_file(file)?)?;
        if Metadata::from_file(file)?.is_dir() {
            return Ok(reopen_directory(
                file,
                FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES,
                true,
            )?);
        }
        Ok(file.reopen(
            OpenOptions::new()
                .access_mode(FILE_WRITE_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT),
        )?)
    }
}

pub(super) fn remove_entry(parent: &Dir, name: &OsStr, directory: bool) -> lx::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if directory {
            parent.remove_dir(name)?;
        } else {
            parent.remove_file_or_symlink(name)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_DISPOSITION_DELETE, FILE_DISPOSITION_INFORMATION_EX,
            FILE_DISPOSITION_POSIX_SEMANTICS, FileDispositionInformationEx,
        };
        let file = open_for_namespace_change(parent, name)?;
        let metadata = Metadata::from_file(&file)?;
        if metadata.is_dir() != directory {
            return Err(if directory {
                lx::Error::ENOTDIR
            } else {
                lx::Error::EISDIR
            });
        }
        let disposition = FILE_DISPOSITION_INFORMATION_EX {
            Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
        };
        // Unlink the name now while cached/open handles retain their object.
        // Legacy RemoveDirectoryW would leave the name delete-pending until
        // the final cached inode handle closes, preventing immediate reuse.
        set_information(
            &file,
            &disposition as *const _ as *const _,
            size_of_val(&disposition) as u32,
            FileDispositionInformationEx,
        )
    }
}

pub(super) fn rename_entry(
    parent: &Dir,
    name: &OsStr,
    target: &Dir,
    new_name: &OsStr,
) -> lx::Result<()> {
    #[cfg(target_os = "linux")]
    {
        parent.rename(name, target, new_name)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
            FileRenameInformationEx,
        };
        let file = open_for_namespace_change(parent, name)?;
        let name = new_name.encode_wide().collect::<Vec<_>>();
        let size = (core::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) + name.len() * 2)
            .max(size_of::<FILE_RENAME_INFORMATION>());
        // usize storage gives the variable-length NT record proper alignment.
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: the allocation is aligned for this record and has enough
        // initialized space for the header and the entire UTF-16 name. Both
        // directory capabilities remain locked during this relative rename.
        unsafe {
            core::ptr::addr_of_mut!((*info).Anonymous.Flags)
                .write(FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS);
            core::ptr::addr_of_mut!((*info).RootDirectory).write(target.as_raw_handle());
            core::ptr::addr_of_mut!((*info).FileNameLength).write((name.len() * 2) as u32);
            core::ptr::copy_nonoverlapping(
                name.as_ptr(),
                core::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
        }
        set_information(&file, info.cast(), size as u32, FileRenameInformationEx)
    }
}

#[cfg(windows)]
fn open_for_namespace_change(parent: &Dir, name: &OsStr) -> lx::Result<File> {
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
    };
    let file = parent
        .open_with(
            name,
            OpenOptions::new()
                .access_mode(DELETE | FILE_GENERIC_READ)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .follow(FollowSymlinks::No),
        )?
        .into_std();
    check_metadata(&Metadata::from_file(&file)?)?;
    Ok(file)
}

#[cfg(windows)]
fn set_information(
    file: &File,
    info: *const core::ffi::c_void,
    size: u32,
    class: windows_sys::Wdk::Storage::FileSystem::FILE_INFORMATION_CLASS,
) -> lx::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
    use windows_sys::Win32::{Foundation::RtlNtStatusToDosError, System::IO::IO_STATUS_BLOCK};
    let mut iosb = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    // SAFETY: all callers supply a correctly sized, initialized NT record;
    // file is a synchronous handle, so the kernel finishes using it and the
    // output buffer before returning. We never read an uninitialized iosb.
    let status =
        unsafe { NtSetInformationFile(file.as_raw_handle(), iosb.as_mut_ptr(), info, size, class) };
    if status < 0 {
        // SAFETY: this pure status-code conversion has no pointer arguments.
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    Ok(())
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
