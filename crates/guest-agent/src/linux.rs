mod boot;
pub mod io;
mod network;
mod process;
mod rtnetlink;
mod service;
mod signals;
mod transport;

use crate::error::Context;
use alloc::{ffi::CString, vec::Vec};
use core::ffi::CStr;
use io::File;
use rustix::net::{AddressFamily, SocketAddrAny, SocketFlags, SocketType};

pub const ROOT: &str = "/mnt/newroot";

/// # Safety
/// envp must be the NULL-terminated environment vector supplied by Origin.
pub unsafe fn run(envp: *mut *mut u8) -> crate::error::Result<()> {
    crate::ensure!(
        rustix::process::getpid() == rustix::process::Pid::INIT,
        "guest agent must run as PID 1"
    );
    eprintln!(
        "Rust guest init: protocol {}",
        ya_vm_agent_protocol::VERSION
    );
    let mut environment = Vec::new();
    let mut current = envp;
    // SAFETY: guaranteed by this function's contract; copy before boot work.
    unsafe {
        while !(*current).is_null() {
            environment.push(CString::from(CStr::from_ptr((*current).cast())));
            current = current.add(1);
        }
    }
    boot::prepare(&environment)?;
    let fd = rustix::net::socket_with(
        AddressFamily::VSOCK,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    set_vsock_buffer_size(&fd, VSOCK_BUFFER)
        .context("limiting the manager vsock receive buffer")?;
    // rustix exposes AF_VSOCK but does not yet provide a typed sockaddr_vm.
    // Linux's 16-byte layout below has no padding and is fully initialized.
    #[repr(C)]
    struct VmAddress {
        family: u16,
        reserved: u16,
        port: u32,
        cid: u32,
        zero: [u8; 4],
    }
    let address = VmAddress {
        family: 40,
        reserved: 0,
        port: ya_vm_agent_protocol::VSOCK_PORT,
        cid: 2,
        zero: [0; 4],
    };
    // SAFETY: sockaddr_vm is valid for AF_VSOCK and all 16 bytes are initialized.
    let address = unsafe {
        SocketAddrAny::read(
            (&address as *const VmAddress).cast(),
            core::mem::size_of::<VmAddress>() as _,
        )
    };
    rustix::net::connect(&fd, &address).context("connecting to embedded OpenVMM vsock relay")?;
    eprintln!(
        "Guest agent connected through virtio-vsock port {}",
        ya_vm_agent_protocol::VSOCK_PORT
    );
    service::serve(File::from(fd), environment)
}

// Linux 5.10 never answers OpenVMM's CREDIT_REQUEST, and OpenVMM reads the
// guest's credit only from CREDIT_UPDATE packets, not from RW headers. Below
// 64 KiB the guest sends CREDIT_UPDATE after every read; at the default
// 256 KiB it sends none, so host-to-guest traffic stalled after 256 KiB.
const VSOCK_BUFFER: u64 = 32 * 1024;

fn set_vsock_buffer_size(fd: &impl rustix::fd::AsRawFd, size: u64) -> rustix::io::Result<()> {
    // AF_VSOCK level, SO_VM_SOCKETS_BUFFER_SIZE; rustix has no typed setter.
    const AF_VSOCK: usize = 40;
    const SO_VM_SOCKETS_BUFFER_SIZE: usize = 0;
    // SAFETY: fd is an open socket and size is a live, initialized u64.
    unsafe {
        signals::syscall5(
            linux_raw_sys::general::__NR_setsockopt,
            [
                fd.as_raw_fd() as usize,
                AF_VSOCK,
                SO_VM_SOCKETS_BUFFER_SIZE,
                &size as *const u64 as usize,
                core::mem::size_of::<u64>(),
            ],
        )
    }
    .map(|_| ())
}

pub fn shutdown() -> ! {
    rustix::fs::sync();
    let _ = rustix::system::reboot(rustix::system::RebootCommand::PowerOff);
    loop {
        rustix::event::pause();
    }
}
