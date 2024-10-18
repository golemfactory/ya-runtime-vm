use async_process::Command;
use nix::errno::Errno;
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use std::path::{Path, PathBuf};
use std::{fs, io};

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
}

pub trait PreExec {
    fn with_pre_exec(&mut self, options: PreExecOptions) -> &mut Self;
}

impl PreExec for Command {
    fn with_pre_exec(&mut self, options: PreExecOptions) -> &mut Self {
        unsafe { self.pre_exec(move || pre_exec(options.clone())) }
    }
}

fn try_pre_exec(options: PreExecOptions) -> io::Result<()> {
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

    if let Some(gid) = options.gid {
        setresgid(gid, gid, gid)?;
    }

    if let Some(uid) = options.uid {
        setresuid(uid, uid, uid)?;
    }

    if options.chroot {
        nix::unistd::chroot("/mnt/newroot")?;
    }

    if options.chdir {
        nix::unistd::chdir(options.cwd.as_path())?;
    }

    Ok(())
}

pub fn pre_exec(options: PreExecOptions) -> io::Result<()> {
    match try_pre_exec(options) {
        Ok(_) => Ok(()),
        Err(e) => {
            log::error!("Error in pre_exec: {}", e);
            unsafe { libc::_exit(Errno::last_raw()) };
        }
    }
}
