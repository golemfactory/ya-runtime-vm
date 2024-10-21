use std::{
    borrow::Cow,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::PermissionsExt,
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI32, AtomicU64},
        Arc,
    },
};

use async_process::Child;
use async_process::Command;
use libc::{c_int, SYS_close_range};
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
    SecurityContext, DEFAULT_DIR_PERMS, OUTPUT_PATH_PREFIX, SYSROOT,
};

static PROC_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
pub struct NewProcessArgs<'a> {
    pub bin: Cow<'a, str>,
    pub args: Vec<Cow<'a, str>>,
    pub envp: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub uid: Option<Uid>,
    pub gid: Option<Gid>,
    pub cwd: PathBuf,
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

fn prepare_redirects(fd_desc: &[RedirectFdDesc; 3]) -> std::io::Result<[RedirectFdDesc; 3]> {
    fd_desc
        .iter()
        .map(|desc| match desc {
            RedirectFdDesc::Invalid => Ok(RedirectFdDesc::Invalid),
            RedirectFdDesc::File(_) => todo!(),
            RedirectFdDesc::PipeBlocking(pipe) | RedirectFdDesc::PipeCyclic(pipe) => {
                let cyclic_buffer = pipe.cyclic_buffer.clone();
                let status_pipe = pipe2(OFlag::O_CLOEXEC)?;
                Ok(RedirectFdDesc::PipeBlocking(FdPipe {
                    cyclic_buffer,
                    fds: [Some(status_pipe.0), Some(status_pipe.1)],
                }))
            }
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Invalid redirect count"))
}

fn spawn_child(
    args: &NewProcessArgs,
    status_pipe: (RawFd, RawFd),
    redirs: &[RedirectFdDesc; 3],
    security_context: SecurityContext,
) -> std::io::Result<Child> {
    Command::new(args.bin.as_ref())
        .args(args.args[1..].iter().map(AsRef::as_ref))
        .envs(args.envp.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
        .with_pre_exec(
            PreExecOptions::new()
                .chroot()
                .chdir(args.cwd.clone())
                .with_uid(args.uid)
                .with_gid(args.gid)
                .with_status_pipe(status_pipe)
                .with_security_context(security_context),
        )
        .spawn()
}

pub async fn spawn_new_process<'a>(
    args: NewProcessArgs<'a>,
    fd_desc: [RedirectFdDesc; 3],
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
    security_context: SecurityContext,
) -> std::io::Result<u64> {
    // TODO(aljen): Handle g_entrypoint_desc/handle_sigchld

    log::info!("Spawning new process: {:?}, fd_desc: {:?}", args, fd_desc);

    let proc_id = get_next_proc_id();
    create_process_fds_dir(proc_id)?;

    let redirs = prepare_redirects(&fd_desc)?;

    let status_pipe = pipe2(OFlag::O_CLOEXEC | OFlag::O_DIRECT)?;

    let child = spawn_child(
        &args,
        (status_pipe.0.as_raw_fd(), status_pipe.1.as_raw_fd()),
        &redirs,
        security_context,
    )?;

    println!("Status pipe: {:?}", status_pipe);

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

pub fn sandbox_apply(child_pipe: i32) {
    #[link(name = "seccomp")]
    extern "C" {
        fn sandbox_apply(child_pipe: c_int);
    }

    unsafe {
        sandbox_apply(child_pipe as c_int);
    }
}
