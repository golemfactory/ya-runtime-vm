mod boot;
mod network;
mod service;
mod signals;
mod transport;

use anyhow::Context;
use rustix::net::{AddressFamily, SocketAddrAny, SocketFlags, SocketType};
use std::fs::File;

pub const ROOT: &str = "/mnt/newroot";

pub fn run() -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::process::getpid() == rustix::process::Pid::INIT,
        "guest agent must run as PID 1"
    );
    eprintln!(
        "Rust guest init: protocol {}",
        ya_vm_agent_protocol::VERSION
    );
    boot::prepare()?;
    let fd = rustix::net::socket_with(
        AddressFamily::VSOCK,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
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
            std::mem::size_of::<VmAddress>() as _,
        )
    };
    rustix::net::connect(&fd, &address).context("connecting to embedded OpenVMM vsock relay")?;
    eprintln!(
        "Guest agent connected through virtio-vsock port {}",
        ya_vm_agent_protocol::VSOCK_PORT
    );
    service::serve(File::from(fd))
}

pub fn shutdown() -> ! {
    rustix::fs::sync();
    let _ = rustix::system::reboot(rustix::system::RebootCommand::PowerOff);
    loop {
        rustix::event::pause();
    }
}
