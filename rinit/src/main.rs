use std::env;
use std::fs::File;
use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
use std::path::Path;
use std::sync::{atomic::AtomicU32, Arc};

use async_io::Async;
use futures::{future::FutureExt, pin_mut, select};
use io::{async_write_n, async_write_u64};
use libc::{mode_t, prctl, PR_SET_DUMPABLE};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::stat::{mknod, Mode, SFlag};
use process::ProcessDesc;
use prost::Message;
use rinit_protos::rinit::api;

use fs::{
    chroot_to_new_root, create_directories, create_dirs, find_device_major, mount_core_filesystems,
    mount_overlay, mount_sysroot, nvidia_gpu_count, write_sys,
};
use handlers::{handle_message, handle_sigchld};
use initramfs::copy_initramfs;
use kernel_modules::load_modules;
use network::{setup_network, stop_network};
use smol::lock::Mutex;
use storage::scan_storage;
use utils::FdWrapper;

mod enums;
mod fs;
mod handlers;
mod initramfs;
mod io;
mod kernel_modules;
mod network;
mod pre_exec;
mod process;
mod storage;
mod utils;

const DEV_VPN: &str = "eth0";
const DEV_INET: &str = "eth1";

const IRWXU_PERMS: mode_t = 0o700;
const DEFAULT_DIR_PERMS: mode_t = 0o755;
const NEW_ROOT: &str = "newroot";
const SYSROOT: &str = "/mnt/newroot";
const OUTPUT_PATH_PREFIX: &str = "/var/tmp/guest_agent_private/fds";
const NONE: Option<&'static [u8]> = None;

const VPORT_CMD: &str = "/dev/vport0p1";

const NET_MEM_DEFAULT: usize = 1048576;
const NET_MEM_MAX: usize = 2097152;
const MTU_VPN: usize = 1220;
const MTU_INET: usize = 65521;

static ALIAS_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub struct RequestError {
    request_id: u64,
    error: std::io::Error,
}

impl RequestError {
    pub fn new(request_id: u64, error: std::io::Error) -> Self {
        Self { request_id, error }
    }

    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Request {} failed: {}", self.request_id, self.error)
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

async fn try_main() -> std::io::Result<()> {
    unsafe {
        let result = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        if !(result == 0 || result == -1) {
            return Err(std::io::Error::last_os_error());
        }
    }

    log::info!("Program args count: {}, args:", env::args().len());
    for arg in env::args() {
        log::info!("  {}", arg);
    }

    log::info!("Environment vars:");
    for (env, val) in env::vars() {
        log::info!("  {} = {}", env, val);
    }

    copy_initramfs()?;
    chroot_to_new_root()?;
    create_directories()?;
    mount_core_filesystems()?;
    let nvidia_loaded = load_modules()?;
    let storage = scan_storage()?;

    mount_overlay(&storage)?;
    mount_sysroot()?;

    let do_sandbox = if env::args().any(|arg| arg == "sandbox=yes") {
        true
    } else if env::args().any(|arg| arg == "sandbox=no") {
        false
    } else {
        nvidia_loaded
    };

    if nvidia_loaded {
        setup_nvidia(do_sandbox)?;
    }

    setup_sandbox();
    setup_network()?;
    setup_agent_directories()?;
    block_signals()?;

    if do_sandbox {
        write_sys("/proc/sys/net/ipv4/ip_unprivileged_port_start", 0);
        write_sys("/proc/sys/user/max_user_namespaces", 1);
        get_namespace_fd();
    }

    let cmds_fd = File::options().read(true).append(true).open(VPORT_CMD)?;
    let sig_fd = setup_sigfd()?;

    set_nonblocking(cmds_fd.as_raw_fd())?;
    set_nonblocking(sig_fd.as_raw_fd())?;

    let async_cmds_fd = Arc::new(Mutex::new(Async::new(FdWrapper {
        fd: cmds_fd.as_raw_fd(),
    })?));
    let async_sig_fd = Arc::new(Mutex::new(Async::new(FdWrapper {
        fd: sig_fd.as_raw_fd(),
    })?));

    let processes = Arc::new(Mutex::new(Vec::new()));

    main_loop(async_cmds_fd, async_sig_fd, processes).await?;
    stop_network()?;

    die!("Finished");
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}
async fn read_request(
    async_cmds_fd: Arc<Mutex<Async<FdWrapper>>>,
    async_sig_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> Result<(Option<api::response::Command>, u64), RequestError> {
    let cmd_future = async {
        let cmd_fd = async_cmds_fd.lock().await;
        cmd_fd.readable().await
    }
    .fuse();
    let sig_future = async {
        let sig_fd = async_sig_fd.lock().await;
        sig_fd.readable().await
    }
    .fuse();

    pin_mut!(cmd_future, sig_future);

    select! {
        _ = cmd_future => {
            handle_message(async_cmds_fd.clone(), processes.clone()).await
        }
        _ = sig_future => {
            handle_sigchld(async_sig_fd.clone(), processes.clone()).await
        }
    }
}

async fn send_response(
    async_cmds_fd: Arc<Mutex<Async<FdWrapper>>>,
    request_id: u64,
    result: Result<api::response::Command, api::response::Command>,
) -> std::io::Result<()> {
    let response = api::Response {
        request_id,
        command: Some(match result {
            Ok(command) => command,
            Err(error) => error,
        }),
    };

    let mut buf = Vec::new();
    response.encode(&mut buf)?;

    let mut async_fd = async_cmds_fd.lock().await;

    async_write_u64(&mut async_fd, buf.len() as u64).await?;
    async_write_n(&mut async_fd, &buf).await?;

    Ok(())
}

async fn main_loop(
    async_cmds_fd: Arc<Mutex<Async<FdWrapper>>>,
    async_sig_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<()> {
    loop {
        let result = read_request(
            async_cmds_fd.clone(),
            async_sig_fd.clone(),
            processes.clone(),
        )
        .await;

        match result {
            Ok((response, request_id)) => {
                if let Some(command) = response {
                    let quit = matches!(command, api::response::Command::Quit(_));
                    send_response(async_cmds_fd.clone(), request_id, Ok(command)).await?;

                    if quit {
                        break;
                    }
                }
            }
            Err(e) => {
                let request_id = e.request_id();
                let error_response = api::response::Command::Error(api::Error {
                    code: e.error.raw_os_error().unwrap_or(libc::EIO) as u32,
                    message: e.error.to_string(),
                });
                send_response(async_cmds_fd.clone(), request_id, Err(error_response)).await?;
            }
        }
    }

    println!("Exiting main loop");

    Ok(())
}

fn setup_sigfd() -> std::io::Result<SignalFd> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);

    let sig_fd = SignalFd::with_flags(&set, SfdFlags::SFD_CLOEXEC)?;

    Ok(sig_fd)
}

fn block_signals() -> std::io::Result<()> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);
    set.add(signal::SIGPIPE);
    sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&set), None)?;

    Ok(())
}

fn get_namespace_fd() {
    // TODO(aljen): Use C version of this function
}

fn setup_agent_directories() -> std::io::Result<()> {
    let sysroot = Path::new(SYSROOT);
    let dir = sysroot.join(&OUTPUT_PATH_PREFIX[1..]);
    println!("Creating agent directory: {:?}", dir);

    create_dirs(dir, std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;

    Ok(())
}

fn setup_nvidia(do_sandbox: bool) -> std::io::Result<()> {
    if !do_sandbox {
        log::error!("Sandboxing is disabled, refusing to enable Nvidia GPU passthrough.");
        log::error!(
            "Please re-run the container with sandboxing enabled or disable GPU passthrough.\n"
        );

        die!("Nvidia GPU passthrough requires sandboxing to be enabled.");
    }

    let nvidia_major = find_device_major("nvidia-frontend")?;
    let nvidia_count = nvidia_gpu_count();

    for i in 0..nvidia_count {
        let path = format!("/mnt/newroot/dev/nvidia{}", i);

        mknod(
            Path::new(&path),
            SFlag::S_IFCHR,
            Mode::from_bits(0o666 & 0o777).unwrap(),
            (nvidia_major << 8 | i) as u64,
        )?;
    }

    mknod(
        Path::new("/mnt/newroot/dev/nvidiactl"),
        SFlag::S_IFCHR,
        Mode::from_bits(0o666 & 0o777).unwrap(),
        (nvidia_major << 8 | 255) as u64,
    )?;

    let nvidia_major = find_device_major("nvidia-uvm")?;
    mknod(
        Path::new("/mnt/newroot/dev/nvidia-uvm"),
        SFlag::S_IFCHR,
        Mode::from_bits(0o666 & 0o777).unwrap(),
        (nvidia_major << 8) as u64,
    )?;

    Ok(())
}

fn setup_sandbox() {
    #[link(name = "seccomp")]
    extern "C" {
        fn setup_sandbox();
    }
    unsafe { setup_sandbox() }
}

fn main() {
    stderrlog::new()
        .module(module_path!())
        .verbosity(log::Level::Trace)
        .timestamp(stderrlog::Timestamp::Off)
        .show_level(false)
        .init()
        .unwrap();

    smol::block_on(async {
        match try_main().await {
            Ok(_) => (),
            Err(e) => {
                die!(e);
            }
        }
    });
}
