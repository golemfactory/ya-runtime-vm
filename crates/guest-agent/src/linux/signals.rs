//! SIGCHLD as an epoll source. No handler, helper thread or polling timer.
//!
//! rustix 1.1 does not expose signalfd. This small x86-64 Linux ABI bridge
//! complements its epoll/waitpid APIs and does not depend on libc.
use linux_raw_sys::general::{
    __NR_rt_sigprocmask, __NR_signalfd4, SIGCHLD, SIG_BLOCK, SIG_SETMASK,
};
use rustix::{
    fd::{FromRawFd, OwnedFd},
    io,
};

pub struct ChildSignals {
    pub fd: OwnedFd,
    old_mask: u64,
}

// SAFETY: callers must provide valid arguments for the selected Linux syscall.
#[cfg(target_arch = "x86_64")]
unsafe fn syscall4(number: u32, args: [usize; 4]) -> io::Result<usize> {
    let result: isize;
    // SAFETY: the x86-64 syscall ABI preserves the stack and clobbers rcx/r11.
    // Memory effects are deliberately not marked nomem: the kernel reads and
    // writes the caller's buffers before returning.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as usize => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3],
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
    }
    if (-4095..0).contains(&result) {
        Err(io::Errno::from_raw_os_error(-result as i32))
    } else {
        Ok(result as usize)
    }
}

fn mask(how: u32, new: &u64) -> io::Result<u64> {
    let mut old = 0u64;
    // SAFETY: both pointers refer to initialized, correctly sized kernel
    // sigsets. Only SIGCHLD is blocked, never libc's reserved thread signals.
    unsafe {
        syscall4(
            __NR_rt_sigprocmask,
            [
                how as usize,
                new as *const u64 as usize,
                &mut old as *mut u64 as usize,
                8,
            ],
        )?;
    }
    Ok(old)
}

impl ChildSignals {
    pub fn new() -> io::Result<Self> {
        let child = 1u64 << (SIGCHLD - 1);
        let old_mask = mask(SIG_BLOCK, &child)?;
        // signalfd flags use the same O_NONBLOCK/O_CLOEXEC values as open.
        let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
        // SAFETY: -1 asks Linux to create an FD; child is a valid 8-byte sigset.
        let result = unsafe {
            syscall4(
                __NR_signalfd4,
                [
                    usize::MAX,
                    &child as *const u64 as usize,
                    8,
                    flags.bits() as usize,
                ],
            )
        };
        match result {
            Ok(fd) => Ok(Self {
                // SAFETY: signalfd4 returned a new owned file descriptor.
                fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
                old_mask,
            }),
            Err(error) => {
                let _ = mask(SIG_SETMASK, &old_mask);
                Err(error)
            }
        }
    }
    pub fn drain(&self) -> io::Result<()> {
        // Linux signalfd_siginfo records are exactly 128 bytes; their content
        // is unnecessary because waitpid drains every available child status.
        let mut records = [0u8; 128 * 16];
        loop {
            match rustix::io::read(&self.fd, &mut records) {
                Ok(0) | Err(io::Errno::AGAIN) => return Ok(()),
                Ok(_) | Err(io::Errno::INTR) => {}
                Err(error) => return Err(error),
            }
        }
    }
    pub fn child_mask(&self) -> u64 {
        self.old_mask
    }
    pub fn restore_for_child(old_mask: u64) -> io::Result<()> {
        mask(SIG_SETMASK, &old_mask).map(|_| ())
    }
}
impl Drop for ChildSignals {
    fn drop(&mut self) {
        let _ = mask(SIG_SETMASK, &self.old_mask);
    }
}
