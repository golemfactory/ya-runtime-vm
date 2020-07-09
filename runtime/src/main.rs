mod guest_agent_comm;
mod response_parser;

use std::{
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::{process::Command, sync};

use crate::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};

struct Notifications {
    process_died: sync::Notify,
}

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: sync::Notify::new(),
        }
    }

    fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                println!("Process {} has output available on fd {}", id, fd);
            }
            Notification::ProcessDied { id, reason } => {
                println!("Process {} died with {:?}", id, reason);
                self.process_died.notify();
            }
        }
    }
}

async fn run_process_with_output(
    ga: &mut GuestAgent,
    notifications: &Notifications,
    bin: &str,
    argv: &[&str],
) -> io::Result<()> {
    let id = ga
        .run_process(bin, argv, None, 0, 0, &[None, None, None], None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    let out = ga
        .query_output(id, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!("Output:");
    io::stdout().write_all(&out)?;
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let notifications = Arc::new(Notifications::new());

    let child = Command::new("qemu-system-x86_64")
        .args(&[
            "-m",
            "256m",
            "-nographic",
            "-vga",
            "none",
            "-kernel",
            "init-container/vmlinuz-virt",
            "-initrd",
            "init-container/initramfs.cpio.gz",
            "-no-reboot",
            "-net",
            "none",
            "-smp",
            "1",
            "-append",
            "console=ttyS0 panic=1",
            "-device",
            "virtio-serial",
            "-chardev",
            "socket,path=./manager.sock,server,nowait,id=manager_cdev",
            "-device",
            "virtserialport,chardev=manager_cdev,name=manager_port",
            "-drive",
            "file=./squashfs_drive,cache=none,readonly=on,format=raw,if=virtio",
        ])
        .stdin(Stdio::null())
        .spawn()
        .expect("failed to spawn VM");

    let mut ga = GuestAgent::connected("./manager.sock", 10, {
        let notifications = notifications.clone();
        move |n| {
            notifications.handle(n);
        }
    })
    .await?;

    let no_redir = [None, None, None];

    let id = ga
        .run_process(
            "/bin/ls",
            &["ls", "-al", "."],
            None,
            0,
            0,
            &no_redir,
            Some("/etc"),
        )
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    let out = ga
        .query_output(id, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!("Output:");
    io::stdout().write_all(&out)?;

    run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-al", "/"]).await?;

    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile("/a".as_bytes())),
        None,
    ];
    let id = ga
        .run_process(
            "/bin/echo",
            &["echo", "TEST TEST TEST"],
            None,
            0,
            0,
            &fds,
            None,
        )
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    let out = ga
        .query_output(id, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!("Output:");
    io::stdout().write_all(&out)?;

    run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-al", "/"]).await?;

    run_process_with_output(&mut ga, &notifications, "/bin/cat", &["cat", "/a"]).await?;

    let id = ga
        .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &no_redir, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);

    ga.kill(id).await?.expect("Kill failed");
    notifications.process_died.notified().await;

    // ga.quit().await?.expect("Quit failed");

    let id = ga
        .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &no_redir, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    /* VM should quit now. */
    let e = child.await.expect("failed to wait on child");
    println!("{:?}", e);

    Ok(())
}
