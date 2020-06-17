use std::io;
use std::process::{Command, Stdio};

mod guest_agent_comm;
use crate::guest_agent_comm::{GuestAgent, RedirectFdType};

fn main() -> io::Result<()> {
    let mut child = Command::new("qemu-system-x86_64")
        .args(&[
            "-m", "256m",
            "-nographic",
            "-vga", "none",
            "-kernel", "init-container/vmlinuz-virt",
            "-initrd", "init-container/initramfs.cpio.gz",
            "-no-reboot",
            "-net", "none",
            "-smp", "1",
            "-append", "console=ttyS0 panic=1",
            "-device", "virtio-serial",
            "-chardev", "socket,path=./manager.sock,server,nowait,id=manager_cdev",
            "-device", "virtserialport,chardev=manager_cdev,name=manager_port",
            "-drive", "file=./squashfs_drive,cache=none,readonly=on,format=raw,if=virtio"])
        .stdin(Stdio::null())
        .spawn()
        .expect("failed to spawn VM");

    let mut ga = GuestAgent::connected("./manager.sock", 10)?;

    let no_redir = [None, None, None];
    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile("/a".as_bytes())),
        Some(RedirectFdType::RedirectFdFile("/b".as_bytes())),
    ];

    ga.run_process("/bin/ls", &["ls", "-al", "/"], None, 0, 0, &no_redir)?;

    ga.run_process("/bin/echo", &["echo", "TEST TEST TEST"], None, 0, 0, &fds)?;

    ga.run_process("/bin/ls", &["ls", "-al", "/"], None, 0, 0, &no_redir)?;

    ga.run_process(
        "/bin/echo",
        &["echo", "Contents of \"/a\":"],
        None,
        0,
        0,
        &no_redir,
    )?;
    ga.run_process("/bin/cat", &["cat", "/a"], None, 0, 0, &no_redir)?;

    ga.quit()?;

    let e = child.wait().expect("failed to wait on child");
    println!("{:?}", e);

    Ok(())
}
