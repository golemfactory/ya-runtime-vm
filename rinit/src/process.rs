use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        atomic::{AtomicI32, AtomicU64},
        Arc,
    },
};

use async_process::Child;
use async_process::Command;
use libc::SYS_close_range;
use nix::{
    errno::Errno,
    fcntl::OFlag,
    sys::signal::{self, sigprocmask, SigSet},
    unistd::{pipe2, Gid, Pid, Uid},
};
use smol::lock::Mutex;

use crate::{
    enums::RedirectFdDesc,
    fs::create_dirs,
    pre_exec::{PreExec, PreExecOptions},
    utils::FdPipe,
    DEFAULT_DIR_PERMS, OUTPUT_PATH_PREFIX, SYSROOT,
};

static PROC_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static GLOBAL_PIDFD: AtomicI32 = AtomicI32::new(-1);
static GLOBAL_USERNS_FD: AtomicI32 = AtomicI32::new(-1);
static GLOBAL_MOUNTNS_FD: AtomicI32 = AtomicI32::new(-1);

#[derive(Debug, Default)]
pub struct NewProcessArgs {
    pub bin: String,
    pub args: Vec<String>,
    pub envp: Vec<String>,
    pub uid: Option<Uid>,
    pub gid: Option<Gid>,
    pub cwd: String,
    pub is_entrypoint: bool,
}

#[derive(Debug)]
pub struct ProcessDesc {
    pub child: Child,
    pub id: u64,
    pub pid: Pid,
    pub is_alive: bool,
    pub redirs: [RedirectFdDesc; 3],
}

#[derive(Debug)]
pub struct ExitReason {
    pub status: u8,
    pub reason_type: u8,
}

fn get_next_proc_id() -> u64 {
    PROC_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn create_process_fds_dir(id: u64) -> std::io::Result<()> {
    let sysroot = Path::new(SYSROOT);
    let dir = sysroot.join(&OUTPUT_PATH_PREFIX[1..]);
    let dir = dir.join(id.to_string());
    println!("Creating process '{}' fds directory: '{:?}'", id, dir);

    create_dirs(dir, std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;

    Ok(())
}

pub async fn spawn_new_process(
    args: NewProcessArgs,
    fd_desc: [RedirectFdDesc; 3],
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<u64> {
    // TODO(aljen): Handle g_entrypoint_desc/handle_sigchld

    log::info!("Spawning new process: {:?}, fd_desc: {:?}", args, fd_desc);

    let proc_id = get_next_proc_id();
    create_process_fds_dir(proc_id)?;

    let mut redirs = [
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
    ];

    for fd in 0..3 {
        match &fd_desc[fd] {
            RedirectFdDesc::Invalid => redirs[fd] = RedirectFdDesc::Invalid,
            RedirectFdDesc::File(_path) => {
                todo!();
            }
            RedirectFdDesc::PipeBlocking(pipe) => {
                let cyclic_buffer = pipe.cyclic_buffer.clone();
                let status_pipe = pipe2(OFlag::O_CLOEXEC)?;
                redirs[fd] = RedirectFdDesc::PipeBlocking(FdPipe {
                    cyclic_buffer,
                    fds: [Some(status_pipe.0), Some(status_pipe.1)],
                });
                println!("Redirecting fd {} to blocking pipe: {:?}", fd, redirs[fd]);
            }
            RedirectFdDesc::PipeCyclic(pipe) => {
                let cyclic_buffer = pipe.cyclic_buffer.clone();
                let status_pipe = pipe2(OFlag::O_CLOEXEC)?;
                redirs[fd] = RedirectFdDesc::PipeBlocking(FdPipe {
                    cyclic_buffer,
                    fds: [Some(status_pipe.0), Some(status_pipe.1)],
                });
                println!("Redirecting fd {} to cyclic pipe: {:?}", fd, redirs[fd]);
            }
        }
    }

    let status_pipe = pipe2(OFlag::O_CLOEXEC | OFlag::O_DIRECT)?;

    println!("Status pipe: {:?}", status_pipe);

    let envp = args
        .envp
        .iter()
        .map(|s| {
            let (key, value) = s.split_once('=').unwrap();
            (key.to_string(), value.to_string())
        })
        .collect::<Vec<(String, String)>>();

    let child = Command::new(&args.bin)
        .args(&args.args[1..])
        .envs(envp)
        .with_pre_exec(
            PreExecOptions::new()
                .chroot()
                .chdir(args.cwd)
                .with_uid(args.uid)
                .with_gid(args.gid),
        )
        .spawn()?;

    let child_id = child.id() as i32;

    log::info!("Spawned new process: {:?}", child);

    processes.lock().await.push(ProcessDesc {
        child,
        id: proc_id,
        pid: Pid::from_raw(child_id),
        is_alive: true,
        redirs,
    });

    // TODO(aljen): Handle process fds dir

    // TODO(aljen): Handle pipe2

    // TODO(aljen): Handle fd redirs

    // TODO(aljen): Handle close status_pipe[1]

    // TODO(aljen): Handle read from status_pipe[0]/waitpid

    // TODO(aljen): Handle close status_pipe[0]

    // TODO(aljen): Handle cleanup of fd redirs

    // TODO(aljen): Fill proc_desc

    // TODO(aljen): Handle add_process(proc_desc)

    // TODO(aljen): Handle args->is_entrypoint

    Ok(proc_id)
}

fn sandbox_apply() {
    #[link(name = "seccomp")]
    extern "C" {
        fn sandbox_apply();
    }
    unsafe { sandbox_apply() }
}

fn child_wrapper(parent_pipe: (i32, i32), args: NewProcessArgs) -> std::io::Result<()> {
    if unsafe { libc::close(parent_pipe.0) } < 0 {
        unsafe { libc::_exit(Errno::last_raw()) };
    }

    let set = SigSet::empty();
    match sigprocmask(signal::SigmaskHow::SIG_SETMASK, Some(&set), None) {
        Ok(_) => (),
        Err(_) => {
            unsafe { libc::_exit(Errno::last_raw()) };
        }
    }

    // TODO(aljen): Handle fd redirs

    if GLOBAL_PIDFD.load(std::sync::atomic::Ordering::SeqCst) == -1 {
        let global_userns_fd = GLOBAL_USERNS_FD.load(std::sync::atomic::Ordering::SeqCst);
        let global_mountns_fd = GLOBAL_MOUNTNS_FD.load(std::sync::atomic::Ordering::SeqCst);

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

        if low_fd < 3 {
            unsafe { libc::abort() };
        }

        if low_fd > 3 && unsafe { libc::syscall(SYS_close_range, 3, low_fd - 1, 0) } < 0 {
            unsafe { libc::_exit(Errno::last_raw()) };
        }

        // TODO(aljen): Handle SYS_close_range

        // TODO(aljen): Handle setns

        // TODO(aljen): Handle close global_userns_fd

        // TODO(aljen): Handle chdir

        // TODO(aljen): Handle chroot
    } else {
        // TODO(aljen): Handle SYS_close_range

        // TODO(aljen): Handle chroot

        // TODO(aljen): Handle chdir
    }

    if !args.cwd.is_empty() {
        // TODO(aljen): Handle chdir
    }

    // TODO(aljen): Handle gid/uid

    // TODO(aljen): Handle sandbox/caps
    if GLOBAL_PIDFD.load(std::sync::atomic::Ordering::SeqCst) != -1 {
        sandbox_apply();
        // ...
    }

    // TODO(aljen): Handle execve

    Ok(())
}
