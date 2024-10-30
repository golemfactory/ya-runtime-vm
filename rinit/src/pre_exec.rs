use async_process::Command;
use libc::{c_int, pid_t};
use nix::errno::Errno;
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::unistd::{close, setresgid, setresuid, Gid, Uid};
use std::os::fd::{BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::process::sandbox_apply;
use crate::SecurityContext;

fn nix_to_io(e: nix::Error) -> io::Error {
    Into::<io::Error>::into(e)
}

#[derive(Default, Clone)]
pub struct PreExecOptions {
    procfs: bool,
    chroot: bool,
    chdir: bool,
    unshare: bool,
    cwd: PathBuf,
    gid: Option<Gid>,
    uid: Option<Uid>,
    status_pipe: (RawFd, RawFd),
    security_context: SecurityContext,
}

impl PreExecOptions {
    pub fn new() -> Self {
        PreExecOptions::default()
    }

    pub fn procfs(mut self) -> Self {
        self.procfs = true;
        self
    }

    pub fn chroot(mut self) -> Self {
        self.chroot = true;
        self
    }

    pub fn chdir(mut self, cwd: PathBuf) -> Self {
        self.chdir = true;
        self.cwd = cwd;
        self
    }

    pub fn unshare(mut self) -> Self {
        self.unshare = true;
        self
    }

    pub fn with_gid(mut self, gid: Option<Gid>) -> Self {
        self.gid = gid;
        self
    }

    pub fn with_uid(mut self, uid: Option<Uid>) -> Self {
        self.uid = uid;
        self
    }

    pub fn with_status_pipe(mut self, status_pipe: (RawFd, RawFd)) -> Self {
        self.status_pipe = status_pipe;
        self
    }

    pub fn with_security_context(mut self, security_context: SecurityContext) -> Self {
        self.security_context = security_context;
        self
    }
}

pub trait PreExec {
    fn with_pre_exec(&mut self, options: PreExecOptions) -> &mut Self;
}

impl PreExec for Command {
    fn with_pre_exec(&mut self, options: PreExecOptions) -> &mut Self {
        unsafe { self.pre_exec(move || pre_exec(options.clone())) }
    }
}

fn get_namespace_fd() -> SecurityContext {
    #[link(name = "seccomp")]
    extern "C" {
        fn get_namespace_fd(
            global_pidfd: *mut pid_t,
            global_zombie_pid: *mut pid_t,
            global_userns_fd: *mut c_int,
            global_mountns_fd: *mut c_int,
        );
    }

    let mut security_context = SecurityContext::default();

    unsafe {
        get_namespace_fd(
            &mut security_context.global_pidfd as *mut pid_t,
            &mut security_context.global_zombie_pid as *mut pid_t,
            &mut security_context.global_userns_fd as *mut i32 as *mut c_int,
            &mut security_context.global_mountns_fd as *mut i32 as *mut c_int,
        );
    }

    security_context
}

fn try_pre_exec(options: PreExecOptions) -> io::Result<()> {
    let child_pipe = options.status_pipe.1;

    close(options.status_pipe.0)?;

    if options.unshare {
        let uid = Uid::current();
        let gid = Gid::current();
        let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID;
        if options.procfs {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        unshare(flags).map_err(nix_to_io)?;
        fs::write("/proc/self/setgroups", "deny")?;
        fs::write("/proc/self/uid_map", format!("{} {} 1", uid, uid))?;
        fs::write("/proc/self/gid_map", format!("{} {} 1", gid, gid))?;
    }

    let set = SigSet::empty();
    sigprocmask(signal::SigmaskHow::SIG_SETMASK, Some(&set), None)?;

    if options.security_context.global_pidfd != -1 {
        let global_userns_fd = options.security_context.global_userns_fd;
        let global_mountns_fd = options.security_context.global_mountns_fd;

        let low_fd = if global_userns_fd > global_mountns_fd {
            global_mountns_fd
        } else {
            global_userns_fd
        };

        let high_fd = if global_userns_fd > global_mountns_fd {
            global_userns_fd
        } else {
            global_mountns_fd
        };

        unsafe {
            if low_fd < 3 {
                libc::abort();
            }

            if low_fd > 3 && libc::syscall(libc::SYS_close_range, 3, low_fd - 1, 0) != 0 {
                return Err(nix_to_io(nix::Error::last()));
            }
            if high_fd - low_fd > 1
                && libc::syscall(libc::SYS_close_range, low_fd + 1, high_fd - 1, 0) != 0
            {
                return Err(nix_to_io(nix::Error::last()));
            }

            if libc::setns(global_mountns_fd, libc::CLONE_NEWNS) != 0
                || libc::close(global_mountns_fd) != 0
            {
                return Err(nix_to_io(nix::Error::last()));
            }

            if libc::setns(global_userns_fd, libc::CLONE_NEWUSER) != 0 {
                return Err(nix_to_io(nix::Error::last()));
            }
        }

        nix::unistd::close(global_userns_fd)?;
        nix::unistd::chdir("/")?;
        nix::unistd::chroot(".")?;
    } else {
        unsafe {
            if libc::syscall(libc::SYS_close_range, 3, !0u32, 0) != 0 {
                libc::abort();
            }
        }
        nix::unistd::chroot("/mnt/newroot")?;
        nix::unistd::chdir("/")?;
    }

    if options.chdir {
        nix::unistd::chdir(options.cwd.as_path())?;
    }

    if let Some(gid) = options.gid {
        setresgid(gid, gid, gid)?;
    }

    if let Some(uid) = options.uid {
        setresuid(uid, uid, uid)?;
    }

    if options.security_context.global_pidfd != -1 {
        sandbox_apply(child_pipe);
    }

    Ok(())
}

pub fn pre_exec(options: PreExecOptions) -> io::Result<()> {
    let child_pipe = options.status_pipe.1;
    match try_pre_exec(options) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("Error in pre_exec: {}", e);
            unsafe {
                let _ = nix::unistd::write(BorrowedFd::borrow_raw(child_pipe), &[0u8]);
                libc::_exit(Errno::last_raw());
            }
        }
    }
}
