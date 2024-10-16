use std::env;
use std::fs::File;
use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
use std::path::Path;
use std::sync::{atomic::AtomicU32, Arc};

use async_io::Async;
use futures::{future::FutureExt, pin_mut, select};
use io::{async_read_n, async_recv_u64, async_write_n, async_write_u64};
use libc::{mode_t, prctl, PR_SET_DUMPABLE};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::stat::{mknod, Mode, SFlag};
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

    main_loop().await?;
    stop_network()?;

    die!("Finished");
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}

async fn main_loop() -> std::io::Result<()> {
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

    loop {
        let (response, request_id) = {
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

            let mut request_id = 0;

            let result = select! {
                _ = cmd_future => {
                    handle_message(async_cmds_fd.clone(), processes.clone(), &mut request_id).await
                }
                _ = sig_future => {
                    handle_sigchld(async_sig_fd.clone(), processes.clone(), &mut request_id).await
                }
            };

            (result, request_id)
        };

        let quit = match response {
            Ok(Some(command)) => {
                println!("Handling response command: {:?}", command);

                let quit = matches!(command, api::response::Command::Quit(_));

                let response = api::Response {
                    request_id,
                    command: Some(command),
                };

                let mut buf = Vec::new();
                response.encode(&mut buf)?;

                log::info!("locking async_fd");
                let mut async_fd = async_cmds_fd.lock().await;

                log::info!("sending response message");
                async_write_u64(&mut async_fd, buf.len() as u64).await?;
                async_write_n(&mut async_fd, &buf).await?;

                quit
            }
            Err(e) => {
                log::error!("Error handling command message: {}", e);

                let response = api::Response {
                    request_id,
                    command: Some(api::response::Command::Error(api::Error {
                        code: e.raw_os_error().unwrap_or(libc::EIO) as u32,
                        message: e.to_string(),
                    })),
                };

                let mut buf = Vec::new();
                response.encode(&mut buf)?;

                log::info!("locking async_fd");
                let mut async_fd = async_cmds_fd.lock().await;

                log::info!("sending error response message");
                async_write_u64(&mut async_fd, buf.len() as u64).await?;
                async_write_n(&mut async_fd, &buf).await?;

                false
            }
            _ => false,
        };

        if quit {
            break;
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
