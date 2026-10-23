use std::io;
use std::path::Path;
use tokio::fs::File;

/// Creates a sparse raw disk image and reserves the requested initial range.
pub async fn create_sparse_raw_image(
    path: impl AsRef<Path>,
    size: u64,
    preallocate: u64,
) -> io::Result<()> {
    let file = File::create(path).await?;
    file.set_len(size).await?;

    let preallocate = preallocate.min(size);
    if preallocate == 0 {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let file = file.into_std().await;
        tokio::task::spawn_blocking(move || reserve_range(file, preallocate))
            .await
            .map_err(io::Error::other)??;
    }

    #[cfg(not(unix))]
    {
        let _ = (file, preallocate);
    }

    Ok(())
}

#[cfg(unix)]
fn reserve_range(mut file: std::fs::File, len: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
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

    file.seek(SeekFrom::Start(0))?;
    let zeroes = [0; 1024 * 1024];
    let mut remaining = len as u64;
    while remaining > 0 {
        let chunk_len = remaining.min(zeroes.len() as u64) as usize;
        file.write_all(&zeroes[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    file.flush()
}
