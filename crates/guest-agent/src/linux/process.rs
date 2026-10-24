//! Single-threaded fork/exec with a close-on-exec error pipe.
//! All allocation and path/env validation happens before fork.
use super::{io::File, service::root_file, signals::ChildSignals};
use crate::error::{Context, Result};
use alloc::{ffi::CString, vec::Vec};
use rustix::{
    fd::AsRawFd,
    fs::OFlags,
    io::Errno,
    process::{Pid, Signal, WaitOptions},
    runtime::{self, Fork},
};
use ya_vm_agent_protocol::{Redirect, Run};

pub struct Child {
    pub pid: Pid,
    pub output: [Option<File>; 2],
}
struct Prepared {
    executables: Vec<CString>,
    argv: Vec<CString>,
    environment: Vec<CString>,
    cwd: CString,
    credentials: Option<(u32, u32)>,
    chroot: bool,
    stdio: [Option<File>; 3],
}
fn pipe() -> rustix::io::Result<(File, File)> {
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    Ok((read.into(), write.into()))
}
fn candidates(bin: &[u8], environment: &[CString]) -> Result<Vec<CString>> {
    crate::ensure!(!bin.is_empty(), "empty executable path");
    if bin.contains(&b'/') {
        return Ok(vec![CString::new(bin)?]);
    }
    let path = environment
        .iter()
        .find_map(|s| s.as_bytes().strip_prefix(b"PATH="))
        .unwrap_or(b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    path.split(|&b| b == b':')
        .map(|part| {
            let mut name = part.to_vec();
            if !name.is_empty() {
                name.push(b'/');
            }
            name.extend_from_slice(bin);
            Ok(CString::new(name)?)
        })
        .collect()
}
fn duplicate(source: &File, target: usize) -> rustix::io::Result<()> {
    if source.as_raw_fd() == target as i32 {
        return rustix::io::fcntl_setfd(source, rustix::io::FdFlags::empty());
    }
    match target {
        0 => rustix::stdio::dup2_stdin(source),
        1 => rustix::stdio::dup2_stdout(source),
        2 => rustix::stdio::dup2_stderr(source),
        _ => Err(Errno::INVAL),
    }
}
impl Prepared {
    fn execute(self, output: [Option<File>; 2], signal_mask: u64) -> Result<Child> {
        let argv: Vec<*const u8> = self
            .argv
            .iter()
            .map(|s| s.as_ptr().cast())
            .chain(core::iter::once(core::ptr::null()))
            .collect();
        let env: Vec<*const u8> = self
            .environment
            .iter()
            .map(|s| s.as_ptr().cast())
            .chain(core::iter::once(core::ptr::null()))
            .collect();
        let (mut error_read, mut error_write) = pipe()?;
        // SAFETY: the production agent has one thread and no allocating signal
        // handlers. Child setup below performs only direct syscalls on values
        // prepared before fork, never allocations or user callbacks.
        match unsafe { runtime::kernel_fork()? } {
            Fork::Child(_) => {
                let setup = || -> rustix::io::Result<()> {
                    rustix::process::setpgid(None, None)?;
                    ChildSignals::restore_for_child(signal_mask)?;
                    for (fd, source) in self.stdio.iter().enumerate() {
                        if let Some(source) = source {
                            duplicate(source, fd)?;
                        }
                    }
                    if self.chroot {
                        rustix::process::chroot(c"/mnt/newroot")?;
                    }
                    rustix::process::chdir(self.cwd.as_c_str())?;
                    if let Some((uid, gid)) = self.credentials {
                        let uid = rustix::process::Uid::from_raw(uid);
                        let gid = rustix::process::Gid::from_raw(gid);
                        rustix::thread::set_thread_groups(&[])?;
                        rustix::thread::set_thread_res_gid(gid, gid, gid)?;
                        rustix::thread::set_thread_res_uid(uid, uid, uid)?;
                    }
                    Ok(())
                };
                let error = match setup() {
                    Err(e) => e,
                    Ok(()) => {
                        let mut last = Errno::NOENT;
                        for executable in &self.executables {
                            // SAFETY: all strings and pointer arrays are alive,
                            // NUL-terminated, with a final NULL array sentinel.
                            let error = unsafe {
                                runtime::execve(executable.as_c_str(), argv.as_ptr(), env.as_ptr())
                            };
                            if error == Errno::ACCESS {
                                last = error;
                            } else if error != Errno::NOENT && error != Errno::NOTDIR {
                                last = error;
                                break;
                            }
                        }
                        last
                    }
                };
                let _ = error_write.write_all(&error.raw_os_error().to_le_bytes());
                runtime::exit_group(127);
            }
            Fork::ParentOf(pid) => {
                drop(error_write);
                let mut handshake = || -> rustix::io::Result<()> {
                    let mut errno = [0; 4];
                    let mut filled = 0;
                    loop {
                        match error_read.read(&mut errno[filled..]) {
                            Ok(0) if filled == 0 => return Ok(()),
                            Ok(0) => return Err(Errno::IO),
                            Ok(n) => {
                                filled += n;
                                if filled == 4 {
                                    return Err(Errno::from_raw_os_error(i32::from_le_bytes(
                                        errno,
                                    )));
                                }
                            }
                            Err(Errno::INTR) => {}
                            Err(e) => return Err(e),
                        }
                    }
                };
                if let Err(error) = handshake() {
                    let _ = rustix::process::kill_process_group(pid, Signal::KILL);
                    wait_for(pid)?;
                    return Err(error.into());
                }
                Ok(Child { pid, output })
            }
        }
    }
}
pub fn wait_for(pid: Pid) -> rustix::io::Result<rustix::process::WaitStatus> {
    loop {
        match rustix::process::waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => return Ok(status),
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
            Ok(None) => {}
        }
    }
}
pub fn spawn(run: &Run, inherited: &[CString], signal_mask: u64) -> Result<Child> {
    crate::ensure!(
        run.uid != u32::MAX && run.gid != u32::MAX,
        "invalid uid/gid"
    );
    let environment = match &run.env {
        None => inherited.to_vec(),
        Some(vars) => vars
            .iter()
            .map(|var| {
                crate::ensure!(
                    var.iter().position(|&b| b == b'=').is_some_and(|p| p != 0),
                    "invalid process environment"
                );
                Ok(CString::new(var.as_slice())?)
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let argv = if run.argv.is_empty() {
        vec![CString::new(run.bin.as_slice())?]
    } else {
        run.argv
            .iter()
            .map(|a| CString::new(a.as_slice()).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?
    };
    let mut stdio = [None, None, None];
    let mut output = [None, None];
    for fd in 0..3 {
        stdio[fd] = Some(match &run.fds[fd] {
            Some(Redirect::File(path)) => root_file(
                path,
                if fd == 0 {
                    OFlags::RDONLY
                } else {
                    OFlags::WRONLY | OFlags::CREATE
                },
            )?,
            Some(Redirect::Pipe { .. }) if fd == 0 => {
                crate::bail!("stdin streaming is unsupported")
            }
            Some(Redirect::Pipe { .. }) => {
                let (read, write) = pipe()?;
                super::transport::nonblocking(&read)?;
                output[fd - 1] = Some(read);
                write
            }
            None => rustix::fs::open(
                c"/dev/null",
                OFlags::RDWR | OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?
            .into(),
        });
    }
    Prepared {
        executables: candidates(&run.bin, &environment)?,
        argv,
        environment,
        cwd: CString::new(run.cwd.as_deref().unwrap_or(b"/"))?,
        credentials: Some((run.uid, run.gid)),
        chroot: true,
        stdio,
    }
    .execute(output, signal_mask)
    .context("spawning guest process")
}
pub fn format(device: &str, environment: &[CString]) -> Result<()> {
    let child = Prepared {
        executables: vec![CString::from(c"/mkfs.ext2")],
        argv: vec![CString::from(c"mkfs.ext2"), CString::new(device)?],
        environment: environment.to_vec(),
        cwd: CString::from(c"/"),
        credentials: None,
        chroot: false,
        stdio: [None, None, None],
    }
    .execute([None, None], 0)?;
    crate::ensure!(
        wait_for(child.pid)?.exit_status() == Some(0),
        "formatting {device} failed"
    );
    Ok(())
}
