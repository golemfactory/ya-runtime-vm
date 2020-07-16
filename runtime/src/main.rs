mod guest_agent_comm;
mod response_parser;

use std::{
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    process::{Child, Command},
    sync,
};

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
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
            ],
            None,
        )
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    match ga.query_output(id, 0, u64::MAX).await? {
        Ok(out) => {
            println!("Output:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => println!("Output query failed with: {}", code),
    }
    Ok(())
}

fn spawn_vm<'a>(mount_args: &'a [(&'a str, &'a str)]) -> Child {
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(&[
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
    ]);
    for (tag, path) in mount_args.iter() {
        cmd.args(&[
            "-virtfs",
            &format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = tag,
                path = path
            ),
        ]);
    }
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn VM")
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let notifications = Arc::new(Notifications::new());

    let mount_args = [("tag0", "init-container"), ("tag1", "runtime")];
    let child = spawn_vm(&mount_args);

    let mut ga = GuestAgent::connected("./manager.sock", 10, {
        let notifications = notifications.clone();
        move |n| {
            notifications.handle(n);
        }
    })
    .await?;

    let no_redir = [None, None, None];

    for (i, (tag, dir)) in mount_args.iter().enumerate() {
        ga.mount(tag, &format!("/mnt/mnt{}/{}", i, dir))
            .await?
            .expect("Mount failed");
    }

    let id = ga
        .run_process(
            "/bin/ls",
            &["ls", "-al", "."],
            None,
            0,
            0,
            &no_redir,
            Some("/mnt"),
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

    run_process_with_output(
        &mut ga,
        &notifications,
        "/bin/ls",
        &["ls", "-al", "/mnt/mnt1/runtime"],
    )
    .await?;

    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile(
            "/mnt/mnt1/runtime/write_test".as_bytes(),
        )),
        None,
    ];
    let id = ga
        .run_process("/bin/echo", &["echo", "WRITE TEST"], None, 0, 0, &fds, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    run_process_with_output(
        &mut ga,
        &notifications,
        "/bin/cat",
        &["cat", "/mnt/mnt1/runtime/write_test"],
    )
    .await?;

    let id = ga
        .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &no_redir, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);

    ga.kill(id).await?.expect("Kill failed");
    notifications.process_died.notified().await;

    let id = ga
        .run_process(
            "/bin/bash",
            &[
                "bash",
                "-c",
                "for i in {1..8000}; do echo -ne a >> /big; done; cat /big",
            ],
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                None,
            ],
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
    println!(
        "Big output 1: {} {}",
        out.len(),
        out.iter().filter(|x| **x != 0x61).count()
    );
    let out = ga
        .query_output(id, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!(
        "Big output 2: {} {}",
        out.len(),
        out.iter().filter(|x| **x != 0x61).count()
    );

    let id = ga
        .run_process(
            "/bin/bash",
            &[
                "bash",
                "-c",
                "echo > /big; for i in {1..4000}; do echo -ne a >> /big; done; for i in {1..4096}; do echo -ne b >> /big; done; cat /big",
            ],
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeCyclic(0x1000)),
                None,
            ],
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
    println!(
        "Big output 1: {} {}",
        out.len(),
        out.iter().filter(|x| **x != 0x62).count()
    );
    let out = ga
        .query_output(id, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!("Big output 2: {}, expected 0", out.len());

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
