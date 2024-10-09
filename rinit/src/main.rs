use std::fs::File;
use std::sync::atomic::AtomicU32;
use std::{env, os::unix::fs::PermissionsExt, path::Path};

use libc::{mode_t, prctl, PR_SET_DUMPABLE};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::sys::signalfd::SfdFlags;
use nix::sys::signalfd::SignalFd;

use fs::{
    chroot_to_new_root, create_directories, create_dirs, mount_core_filesystems, mount_overlay,
    mount_sysroot,
};
use handlers::handle_messages;
use initramfs::copy_initramfs;
use kernel_modules::load_modules;
use network::{setup_network, stop_network};
use storage::scan_storage;

mod enums;
mod fs;
mod handlers;
mod initramfs;
mod io;
mod kernel_modules;
mod network;
mod process;
mod storage;
mod utils;

use crate::enums::EpollFdType;

const DEV_VPN: &str = "eth0";
const DEV_INET: &str = "eth1";

const IRWXU_PERMS: mode_t = 0o700;
const DEFAULT_DIR_PERMS: mode_t = 0o755;
const NEW_ROOT: &str = "newroot";
const SYSROOT: &str = "/mnt/newroot";
const OUTPUT_PATH_PREFIX: &str = "/var/tmp/guest_agent_private/fds";
const NONE: Option<&'static [u8]> = None;

const VPORT_CMD: &str = "/dev/vport0p1";
const VPORT_NET: &str = "/dev/vport0p2";
const VPORT_INET: &str = "/dev/vport0p3";

const NET_MEM_DEFAULT: usize = 1048576;
const NET_MEM_MAX: usize = 2097152;
const MTU_VPN: usize = 1220;
const MTU_INET: usize = 65521;

static ALIAS_COUNTER: AtomicU32 = AtomicU32::new(0);
static mut SIG_FD: Option<SignalFd> = None;
static mut CMDS_FD: Option<File> = None;
// static mut CMDS_FD: Option<i32> = None;

fn try_main() -> std::io::Result<()> {
    unsafe {
        let result = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        if result != 0 || result != -1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    println!("Program args count: {}, args:", env::args().len());
    for arg in env::args() {
        println!("  {}", arg);
    }

    println!("Environment vars:");
    for (env, val) in env::vars() {
        println!("  {} = {}", env, val);
    }

    copy_initramfs()?;
    chroot_to_new_root()?;
    create_directories()?;
    mount_core_filesystems()?;
    load_modules()?;

    let storage = scan_storage()?;

    mount_overlay(&storage)?;
    mount_sysroot()?;

    // TODO(aljen): Handle 'sandbox' environment variable
    // TODO(aljen): Handle 'nvidia_loaded'

    setup_sandbox();
    setup_network()?;
    setup_agent_directories()?;
    block_signals()?;
    setup_sigfd()?;
    main_loop()?;
    stop_network()?;

    die!("Finished");
}

fn main_loop() -> std::io::Result<()> {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;

    unsafe {
        CMDS_FD = Some(
            File::options()
                .read(true)
                .write(true)
                .append(true)
                .open(VPORT_CMD)?,
        );
        // let cmds_fd = nix::fcntl::open(
        //     VPORT_CMD,
        //     nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CLOEXEC,
        //     nix::sys::stat::Mode::empty(),
        // )?;
        // CMDS_FD = Some(cmds_fd);

        epoll.add(
            CMDS_FD.as_ref().unwrap(),
            // cmds_fd,
            EpollEvent::new(EpollFlags::EPOLLIN, EpollFdType::Cmds.into()),
        )?;

        epoll.add(
            SIG_FD.as_ref().unwrap(),
            EpollEvent::new(EpollFlags::EPOLLIN, EpollFdType::Sig.into()),
        )?;
    }

    loop {
        match handle_messages(&epoll) {
            Ok(_) => (),
            Err(e) => {
                println!("Error: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

fn setup_sigfd() -> std::io::Result<()> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);

    unsafe {
        SIG_FD = Some(SignalFd::with_flags(&set, SfdFlags::SFD_CLOEXEC)?);
    }

    Ok(())
}

fn block_signals() -> std::io::Result<()> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);
    set.add(signal::SIGPIPE);
    sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&set), None)?;

    Ok(())
}

fn setup_agent_directories() -> std::io::Result<()> {
    let dir = Path::new(OUTPUT_PATH_PREFIX);

    create_dirs(dir, std::fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;

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
    smol::block_on(async {
        match try_main() {
            Ok(_) => (),
            Err(e) => {
                die!(e);
            }
        }
    });
}
