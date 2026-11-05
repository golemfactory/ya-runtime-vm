//! Small owned-FD and filesystem helpers; no libc, std I/O or global state.
use alloc::{string::String, vec::Vec};
use core::fmt;
use rustix::{
    fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    fs::{Mode, OFlags},
    io::{self, Errno},
    path::Arg,
};

pub struct File(OwnedFd);
impl From<OwnedFd> for File {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}
impl AsFd for File {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl AsRawFd for File {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
impl File {
    pub fn open(path: impl Arg) -> io::Result<Self> {
        Ok(rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?.into())
    }
    pub fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        rustix::io::read(&self.0, bytes)
    }
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        rustix::io::write(&self.0, bytes)
    }
    pub fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.write(bytes) {
                Ok(0) => return Err(Errno::IO),
                Ok(n) => bytes = &bytes[n..],
                Err(Errno::INTR) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> io::Result<()> {
        struct Adapter<'a>(&'a mut File, Option<Errno>);
        impl fmt::Write for Adapter<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.write_all(s.as_bytes()).map_err(|e| {
                    self.1 = Some(e);
                    fmt::Error
                })
            }
        }
        let mut adapter = Adapter(self, None);
        fmt::write(&mut adapter, args).map_err(|_| adapter.1.unwrap_or(Errno::IO))
    }
}

pub fn log(args: fmt::Arguments<'_>) {
    struct Stderr;
    impl fmt::Write for Stderr {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            // SAFETY: borrow fd 2 without taking ownership or closing it.
            let fd = unsafe { BorrowedFd::borrow_raw(2) };
            let mut bytes = text.as_bytes();
            while !bytes.is_empty() {
                match rustix::io::write(fd, bytes) {
                    Ok(0) => return Err(fmt::Error),
                    Ok(n) => bytes = &bytes[n..],
                    Err(Errno::INTR) => {}
                    Err(_) => return Err(fmt::Error),
                }
            }
            Ok(())
        }
    }
    let _ = fmt::write(&mut Stderr, args);
    let _ = fmt::Write::write_str(&mut Stderr, "\n");
}

pub fn read_to_string(path: impl Arg) -> crate::error::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                crate::ensure!(
                    bytes.len() + n <= 1024 * 1024,
                    "metadata file exceeds size limit"
                );
                bytes.extend_from_slice(&chunk[..n]);
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(String::from_utf8(bytes)?)
}
pub fn read_dir(path: &str) -> crate::error::Result<Vec<String>> {
    let file = File::open(path)?;
    let mut directory = rustix::fs::Dir::read_from(&file)?;
    let mut names = Vec::new();
    while let Some(entry) = directory.read() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(String::from_utf8(name.to_vec())?);
    }
    Ok(names)
}
pub fn create_dir_all(path: &str) -> io::Result<()> {
    let mut partial = String::new();
    for component in path.split('/') {
        if component.is_empty() {
            if partial.is_empty() {
                partial.push('/');
            }
            continue;
        }
        if !partial.ends_with('/') && !partial.is_empty() {
            partial.push('/');
        }
        partial.push_str(component);
        match rustix::fs::mkdir(&partial, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub fn exists(path: &str) -> bool {
    rustix::fs::stat(path).is_ok()
}
