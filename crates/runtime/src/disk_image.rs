use std::io;
use std::path::Path;

/// Creates a sparse raw disk image and reserves the requested initial range.
pub async fn create_sparse_raw_image(
    path: impl AsRef<Path>,
    size: u64,
    preallocate: u64,
) -> io::Result<()> {
    let path = path.as_ref().to_owned();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let file = std::fs::File::create(path)?;
        let preallocate = preallocate.min(size);
        #[cfg(windows)]
        {
            // Reserve the prefix while the file is non-sparse, then expose
            // the full virtual size as holes. Writing zeroes into a sparse
            // file is not a reliable allocation primitive on Windows.
            if preallocate != 0 {
                mark_sparse(&file, false)?;
                file.set_len(preallocate)?;
                // Initialize the prefix while non-sparse so conversion cannot
                // discard uninitialized zero extents as holes.
                write_zeroes(file.try_clone()?, preallocate)?;
                file.sync_all()?;
            }
            mark_sparse(&file, true)?;
        }
        file.set_len(size)?;
        #[cfg(unix)]
        if preallocate != 0 {
            reserve_range(file, preallocate)?;
        }
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(windows)]
fn mark_sparse(file: &std::fs::File, sparse: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::{
        IO::DeviceIoControl,
        Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE},
    };
    let mut returned = 0;
    let input = FILE_SET_SPARSE_BUFFER { SetSparse: sparse };
    // SAFETY: file is synchronous and writable; input is a correctly sized
    // sparse-control buffer. This control has no output buffer.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            &input as *const _ as *const _,
            size_of_val(&input) as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn reserve_range(file: std::fs::File, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let len = libc::off_t::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "preallocation is too large"))?;
    let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, len) };
    if result == 0 {
        return Ok(());
    }

    if !matches!(result, libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL) {
        return Err(io::Error::from_raw_os_error(result));
    }

    write_zeroes(file, len as u64)
}

fn write_zeroes(mut file: std::fs::File, len: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(0))?;
    let zeroes = [0; 1024 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let chunk_len = remaining.min(zeroes.len() as u64) as usize;
        file.write_all(&zeroes[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    const MIB: u64 = 1024 * 1024;

    fn allocated(file: &std::fs::File, _path: &Path) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            file.metadata().unwrap().blocks() * 512
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
            let path = _path
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let mut high = 0;
            // SAFETY: a terminated test path and valid writable output DWORD.
            let low = unsafe { GetCompressedFileSizeW(path.as_ptr(), &mut high) };
            // The test's 64 MiB image cannot have a valid 0xffffffff low size.
            assert_ne!(low, u32::MAX, "{}", io::Error::last_os_error());
            let _ = file;
            ((high as u64) << 32) | low as u64
        }
    }

    #[tokio::test]
    async fn sparse_image_allocates_only_the_requested_initial_range() {
        let temp = tempdir::TempDir::new("sparse-image-test").unwrap();
        let path = temp.path().join("disk.img");
        for reserve in [0, MIB] {
            create_sparse_raw_image(&path, 64 * MIB, reserve)
                .await
                .unwrap();
            let file = std::fs::File::open(&path).unwrap();
            assert_eq!(file.metadata().unwrap().len(), 64 * MIB);
            let used = allocated(&file, &path);
            assert!(
                used >= reserve && used < 2 * MIB,
                "reserve={reserve}, allocated={used}"
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE;
                assert_ne!(
                    file.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE,
                    0
                );
            }
        }
        create_sparse_raw_image(&path, MIB, 2 * MIB).await.unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), MIB);
        assert!(allocated(&file, &path) >= MIB);
    }
}
