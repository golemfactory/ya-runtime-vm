use std::{
    fmt::Formatter,
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
};

#[macro_export]
macro_rules! die {
    ($expr:expr) => {
        unsafe {
            libc::sync();

            loop {
                log::error!("Error: {:?}", $expr);
                libc::reboot(libc::RB_POWER_OFF);
                std::arch::asm!("hlt");
                unreachable!();
            }
        }
    };
}

#[macro_export]
macro_rules! check {
    ($expr:expr) => {
        if $expr == -1 {
            panic!("Error: {:?}", $expr);
        }
    };
}

#[macro_export]
macro_rules! check_result {
    ($expr:expr) => {
        if $expr.is_err() {
            die!($expr);
        }
    };
}

#[macro_export]
macro_rules! check_bool {
    ($expr:expr) => {
        if !$expr {
            crate::die!($expr);
        }
    };
}

#[derive(Clone)]
pub struct CyclicBuffer {
    buf: Vec<u8>,
    begin: usize,
    end: usize,
}

pub struct FdWrapper {
    pub fd: RawFd,
}

#[derive(Debug)]
pub struct FdPipe {
    pub cyclic_buffer: CyclicBuffer,
    pub fds: [Option<OwnedFd>; 2],
}

impl std::fmt::Debug for CyclicBuffer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CyclicBuffer")
            .field("buf", &self.buf.len())
            .field("begin", &self.begin)
            .field("end", &self.end)
            .finish()
    }
}

impl CyclicBuffer {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        Self {
            buf: vec![0; size],
            begin: 0,
            end: 0,
        }
    }

    pub fn data_size(&self) -> usize {
        (self.end - self.begin + self.buf.len()) % self.buf.len()
    }

    pub fn free_size(&self) -> usize {
        (self.buf.len() - (self.end - self.begin + self.buf.len())) % self.buf.len()
    }
}

impl AsFd for FdWrapper {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // Safety: We ensure that self.fd is a valid file descriptor
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Read for FdWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Write for FdWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
