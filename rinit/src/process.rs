use std::sync::atomic::{AtomicI32, AtomicU64};

use libc::SYS_close_range;
use nix::{
    errno::Errno,
    sys::signal::{self, sigprocmask, SigSet},
};

static PROC_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
static GLOBAL_PIDFD: AtomicI32 = AtomicI32::new(-1);
static GLOBAL_USERNS_FD: AtomicI32 = AtomicI32::new(-1);
static GLOBAL_MOUNTNS_FD: AtomicI32 = AtomicI32::new(-1);

#[derive(Debug, Default)]
pub struct NewProcessArgs {
    pub bin: String,
    pub args: Vec<String>,
    pub envp: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub cwd: String,
    pub is_entrypoint: bool,
}

fn get_next_proc_id() -> u64 {
    PROC_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

pub fn spawn_new_process(args: NewProcessArgs) -> std::io::Result<u64> {
    // TODO(aljen): Handle g_entrypoint_desc/handle_sigchld

    let proc_id = get_next_proc_id();

    // TODO(aljen): Handle process fds dir

    // TODO(aljen): Handle pipe2

    // TODO(aljen): Handle fd redirs

    let pid = unsafe { libc::fork() };

    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let pipe_status = (-1, -1);

    if pid == 0 {
        child_wrapper(pipe_status, args)?;
    }

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
