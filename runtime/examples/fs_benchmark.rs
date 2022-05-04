
use ::futures::{future, FutureExt, lock::Mutex};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::{process::Child, sync};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_runtime_vm::vm::{VMBuilder, VM};

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
                log::debug!("Process {} has output available on fd {}", id, fd);
                self.output_available.notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.process_died.notify_one();
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
        .expect("invalid manifest dir")
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    let joined = path.as_ref().join(file.to_string());

    // Under windows Paths has UNC prefix that is not parsed correctly by qemu
    // Wrap Path with simplified method to remove that prefix
    // It has no effect on Unix
    dunce::simplified(
        joined
            // canonicalize checks existence of the file, it may failed, if does not exist
            .canonicalize()
            .expect(&joined.display().to_string())
            .as_path(),
    )
    .display()
    .to_string()
}

fn spawn_vm() -> (Child, VM) {
    #[cfg(windows)]
    let vm_executable = "vmrt.exe";
    #[cfg(unix)]
    let vm_executable = "vmrt";

    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");

    let vm = VMBuilder::new(1, 256, &image_dir.join("ubuntu.gvmi"))
        .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
        .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
        .build();

    let mut cmd = vm.create_cmd(&runtime_dir.join(vm_executable));

    println!("CMD: {cmd:?}");

    cmd.stdin(Stdio::null());

    cmd.current_dir(runtime_dir);
    (cmd.spawn().expect("failed to spawn VM"), vm)
}

async fn test_multiple_fs_calls(bytes_to_write: usize, vm_manager_sock: &str) {}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (mut child, vm) = spawn_vm();

    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let notifications = Arc::new(Notifications::new());

    const MOUNTS: usize = 5;

    let mut mount_args = vec![];

    for id in 0..MOUNTS {
        let name = format!("inner{id}");

        let inner_path = temp_path.join(&name);

        std::fs::create_dir_all(&inner_path).expect(&format!(
            "Failed to create a dir {:?} inside temp dir",
            inner_path.as_os_str()
        ));

        mount_args.push(ContainerVolume {
            name,
            path: format!("mnt/mnt1/tag{id}"),
        });
    }

    let (_p9streams, _muxer_handle) = vm.start_9p_service(&temp_path, &mount_args).await.unwrap();

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(vm.get_manager_sock(), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n) }.boxed()
    })
    .await?;

    {
        let mut ga = ga_mutex.lock().await;

        for ContainerVolume { name, path } in mount_args.iter() {
            ga.mount(name, path).await?.expect("Mount failed");
        }

        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/ls",
            &["ls", "-al", "/mnt/mnt1/"],
        )
        .await?;
    }

    let mut tasks = vec![];
    for ContainerVolume { name, path } in mount_args {
        let manager_sock = vm.get_manager_sock().to_owned();

        let ga_mutex = ga_mutex.clone();
        let notifications = notifications.clone();

        let join = tokio::spawn(async move {
            println!("Spawning task for {name}");
            // let notifications = Arc::new(Notifications::new());

            // let ns = notifications.clone();

            // let ga_mutex = GuestAgent::connected(&manager_sock, 10, move |n, _g| {
            //     let notifications = ns.clone();
            //     async move { notifications.clone().handle(n) }.boxed()
            // })
            // .await
            // .expect("Cannot connect to guest agent");

            // let mut ga = ga_mutex.lock().await;


            test_big_write(ga_mutex, &notifications, &path)
                .await
                .unwrap();
        });

        tasks.push(join);
    }

    println!("Joining...");
    future::join_all(tasks).await;

    {
        let mut ga = ga_mutex.lock().await;
        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &NO_REDIR, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;
    }

    /* VM should quit now. */
    let e = child.wait().await.expect("failed to wait on child");
    println!("{:?}", e);

    // tokio::time::sleep(Duration::from_secs(30)).await;

    Ok(())
}

const NO_REDIR: [Option<RedirectFdType>; 3] = [None, None, None];

async fn test_big_write(
    ga: Arc<Mutex<GuestAgent>>,
    notifications: &Notifications,
    path: &str,
) -> io::Result<()> {
    println!("***** test_big_write *****");

    let mut ga = ga.lock().await;

    let id = ga
        .run_process(
            "/bin/bash",
            &[
                "bash",
                "-c",
                &format!("for i in {{1..100}}; do echo -ne a >> {path}/big; done; cat {path}/big"),
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
        .await
        .expect("Run process failed")
        .expect("Remote command failed");

    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    notifications.output_available.notified().await;

    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");

    println!("Big Output:");
    println!(
        "Big output 1: len: {} unexpected characters: {}",
        out.len(),
        out.iter().filter(|x| **x != 'a' as u8).count()
    );

    // List files
    run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-la", path]).await?;

    Ok(())
}
