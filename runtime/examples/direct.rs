use futures::FutureExt;
use std::path::{Path, PathBuf};
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    process::{Child, Command},
    sync,
};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};

struct Notifications {
    process_died: sync::Notify,
    output_available: sync::Notify,
}

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: sync::Notify::new(),
            output_available: sync::Notify::new(),
        }
    }

    fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                println!("Process {} has output available on fd {}", id, fd);
                self.output_available.notify();
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
    notifications.output_available.notified().await;
    match ga.query_output(id, 1, 0, u64::MAX).await? {
        Ok(out) => {
            println!("Output:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => println!("Output query failed with: {}", code),
    }
    Ok(())
}

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .unwrap()
}

fn get_root_dir() -> PathBuf {
    get_project_dir().join("..").canonicalize().unwrap()
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    path.as_ref()
        .join(file.to_string())
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn spawn_vm<'a, P: AsRef<Path>>(temp_path: P, mount_args: &'a [(&'a str, impl ToString)]) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let mut cmd = Command::new("vmrt");
    cmd.current_dir(runtime_dir).args(&[
        "-m",
        "256m",
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        join_as_string(&init_dir, "vmlinuz-virt").as_str(),
        "-initrd",
        join_as_string(&init_dir, "initramfs.cpio.gz").as_str(),
        "-no-reboot",
        "-net",
        "none",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-append",
        "console=ttyS0 panic=1",
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        format!(
            "socket,path={},server,nowait,id=manager_cdev",
            temp_path.as_ref().join("manager.sock").display()
        )
        .as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-drive",
        format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            root_dir.join("squashfs_drive").display()
        )
        .as_str(),
    ]);
    for (tag, path) in mount_args.iter() {
        cmd.args(&[
            "-virtfs",
            &format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = tag,
                path = path.to_string()
            ),
        ]);
    }
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn VM")
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let inner_path = temp_path.join("inner");

    std::fs::create_dir_all(&inner_path).expect("Failed to create a dir inside temp dir");

    let notifications = Arc::new(Notifications::new());
    let mount_args = [
        ("tag0", temp_path.display()),
        ("tag1", inner_path.display()),
    ];
    let child = spawn_vm(&temp_path, &mount_args);

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(temp_path.join("manager.sock"), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n) }.boxed()
    })
    .await?;
    let mut ga = ga_mutex.lock().await;

    let no_redir = [None, None, None];

    for (i, (tag, _)) in mount_args.iter().enumerate() {
        ga.mount(tag, &format!("/mnt/mnt{}/{}", i, tag))
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
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!("Output:");
    io::stdout().write_all(&out)?;

    run_process_with_output(
        &mut ga,
        &notifications,
        "/bin/ls",
        &["ls", "-al", "/mnt/mnt1/tag1"],
    )
    .await?;

    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile(
            "/mnt/mnt1/tag1/write_test".as_bytes(),
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
        &["cat", "/mnt/mnt1/tag1/write_test"],
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
    notifications.output_available.notified().await;
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!(
        "Big output 1: {} {}",
        out.len(),
        out.iter().filter(|x| **x != 0x61).count()
    );
    notifications.output_available.notified().await;
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
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
    notifications.output_available.notified().await;
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    println!(
        "Big output 1: {} {}",
        out.len(),
        out.iter().filter(|x| **x != 0x62).count()
    );
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
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
