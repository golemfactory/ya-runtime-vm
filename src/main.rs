use std::process::{Command, Stdio};

mod guest_agent_comm;
use crate::guest_agent_comm::GuestAgent;

fn main() {
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

    let mut ga = GuestAgent::connected("./manager.sock", 10).unwrap();

    let argv = ["a0", "a1", "a2"];
    ga.run_process("binary_name", &argv, None, 0).unwrap();
    println!("");

    ga.quit().unwrap();

    let e = child.wait().expect("failed to wait on child");
    println!("{:?}", e);
}
