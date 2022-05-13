use ::futures::{future, lock::Mutex, FutureExt};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::time::timeout;
use tokio::{process::Child, sync};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_runtime_vm::vm::{VMBuilder, VM};

struct Notifications {
    process_died: Mutex<HashMap<u64, Arc<sync::Notify>>>,
    output_available: Mutex<HashMap<u64, Arc<sync::Notify>>>,
}

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: Mutex::new(HashMap::new()),
            output_available: Mutex::new(HashMap::new()),
        }
    }

    async fn get_process_died_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.process_died.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    async fn get_output_available_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.output_available.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    async fn handle(&self, notification: Notification) {
        log::info!("GOT NOTIFICATION {notification:?}");

        match notification {
            Notification::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);

                self.get_output_available_notification(id)
                    .await
                    .notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.get_process_died_notification(id).await.notify_one();
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

    log::info!("Spawned process with id: {}", id);
    notifications
        .get_process_died_notification(id)
        .await
        .notified()
        .await;
    notifications
        .get_output_available_notification(id)
        .await
        .notified()
        .await;

    match ga.query_output(id, 1, 0, u64::MAX).await? {
        Ok(out) => {
            log::info!("STDOUT Output {argv:?}:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => log::info!("{argv:?} no data on STDOUT, reason {code}"),
    }

    match ga.query_output(id, 2, 0, u64::MAX).await? {
        Ok(out) => {
            log::error!("STDERR Output {argv:?}:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => log::info!("{argv:?} no data on STDERR, reason {code}"),
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

    log::info!("CMD: {cmd:?}");

    cmd.stdin(Stdio::null());

    // cmd.stderr(Stdio::null());
    // cmd.stdout(Stdio::null());

    cmd.current_dir(runtime_dir);
    (cmd.spawn().expect("failed to spawn VM"), vm)
}

/// Write for one byte to the file, create as many tasks as there are mount points
async fn test_parallel_write_small_chunks(
    mount_args: Arc<Vec<ContainerVolume>>,
    ga_mutex: Arc<Mutex<GuestAgent>>,
    notifications: Arc<Notifications>,
) {
    let mut tasks = vec![];

    for ContainerVolume { name, path } in mount_args.as_ref() {
        let ga_mutex = ga_mutex.clone();
        let notifications = notifications.clone();

        let cmd = format!("for i in {{1..100}}; do echo -ne a >> {path}/small_chunks; done; cat {path}/small_chunks");

        let name = name.clone();
        let path = path.clone();
        let join = tokio::spawn(async move {
            log::info!("Spawning task for {name}");
            let ga = ga_mutex.clone();
            test_write(ga_mutex, &notifications, &cmd).await.unwrap();

            {
                let mut ga = ga.lock().await;
                // List files
                run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-la", &path])
                    .await
                    .unwrap();
            }
        });

        tasks.push(join);
    }

    log::info!("Joining...");
    future::join_all(tasks).await;
}

async fn test_parallel_write_big_chunk(
    mount_args: Arc<Vec<ContainerVolume>>,
    ga_mutex: Arc<Mutex<GuestAgent>>,
    notifications: Arc<Notifications>,
) {
    // prepare chunk
    {
        let mut ga = ga_mutex.lock().await;
        // List files
        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/dd",
            &[
                "dd",
                // TODO: /dev/random causes problems?
                "if=/dev/zero",
                "of=/mnt/mnt1/tag0/big_file",
                "bs=1048576",
                "count=10",
            ],
        )
        .await
        .unwrap();

        run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-lh", &"/mnt/mnt1/tag0/"])
            .await
            .unwrap();
        // run_process_with_output(&mut ga, &notifications, "/bin/df", &["df","-h"])
        //     .await
        //     .unwrap();
    }

    let mut tasks = vec![];

    for ContainerVolume { name, path } in mount_args.as_ref() {
        let ga_mutex = ga_mutex.clone();
        let notifications = notifications.clone();

        // let cmd = format!("A=\"A\"; for i in {{1..24}}; do A=\"${{A}}${{A}}\"; done; echo -ne $A >> {path}/big_chunk");
        let cmd = format!("cp /mnt/mnt1/tag0/big_file  {path}/big_chunk;");
        // let cmd = format!("cp /mnt/mnt1/tag0/big_file  /{path}/big_chunk");

        let name = name.clone();
        let path = path.clone();
        let join = tokio::spawn(async move {
            log::info!("Spawning task for {name}");
            let ga = ga_mutex.clone();
            test_write(ga_mutex, &notifications, &cmd).await.unwrap();

            {
                let mut ga = ga.lock().await;
                // List files
                run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-l", &path])
                    .await
                    .unwrap();
            }
        });

        tasks.push(join);
    }

    log::info!("Joining...");
    future::join_all(tasks).await;
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    log::info!("hai!");
    let (mut child, vm) = spawn_vm();

    log::info!("hai!");
    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let notifications = Arc::new(Notifications::new());

    const MOUNTS: usize = 1;

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
            path: format!("/mnt/mnt1/tag{id}"),
        });
    }

    let mount_args = Arc::new(mount_args);

    let (_p9streams, _muxer_handle) = vm.start_9p_service(&temp_path, &mount_args).await.unwrap();

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(vm.get_manager_sock(), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n).await }.boxed()
    })
    .await?;

    {
        let mut ga = ga_mutex.lock().await;

        for ContainerVolume { name, path } in mount_args.iter() {
            if let Err(e) = ga.mount(name, path).await? {
                log::error!("Mount failed at {name}, {path}, {e}")
            }
        }

        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/ls",
            &["ls", "-al", "/mnt/mnt1/"],
        )
        .await?;
    }

    // test_parallel_write_small_chunks(mount_args.clone(), ga_mutex.clone(), notifications.clone())
    //     .await;

    test_parallel_write_big_chunk(mount_args.clone(), ga_mutex.clone(), notifications.clone())
        .await;

    let e = timeout(Duration::from_secs(5), child.wait()).await;
    {
        let mut ga = ga_mutex.lock().await;

        run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "auxjf"]).await?;

        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "60"], None, 0, 0, &NO_REDIR, None)
            .await?
            .expect("Run process failed");
        log::info!("Spawned process with id: {}", id);
        notifications
            .get_process_died_notification(id)
            .await
            .notified()
            .await;
    }

    /* VM should quit now. */
    let e = timeout(Duration::from_secs(5), child.wait()).await;
    log::info!("{:?}", e);

    Ok(())
}

const NO_REDIR: [Option<RedirectFdType>; 3] = [None, None, None];

async fn test_write(
    ga: Arc<Mutex<GuestAgent>>,
    notifications: &Notifications,
    cmd: &str,
) -> io::Result<()> {
    log::info!("***** test_big_write *****");

    let fds = &[
        None,
        Some(RedirectFdType::RedirectFdPipeBlocking(0x10000)),
        None,
    ];
    let argv = ["bash", "-c", &cmd];

    let id = {
        let mut ga = ga.lock().await;
        ga.run_process("/bin/bash", &argv, None, 0, 0, fds, None)
            .await
            .expect("Run process failed")
            .expect("Remote command failed")
    };

    log::info!("Spawned process with id: {}, for {}", id, cmd);

    log::info!("waiting on died for {id}");
    let notif = notifications.get_process_died_notification(id).await;
    let fut = notif.notified();

    // if let Err(_) = timeout(Duration::from_secs(60), fut).await {
    //     log::error!("Got timeout on died notification for process {id}");
    // }

    fut.await;

    // log::info!("waiting on output for {id}");
    // notifications
    //     .get_output_available_notification(id)
    //     .await
    //     .notified()
    //     .await;

    // log::info!("waiting on query for {id}");
    // let out = {
    //     let mut ga = ga.lock().await;
    //     ga.query_output(id, 1, 0, u64::MAX)
    //         .await?
    //         .expect("Output query failed")
    // };

    // log::info!("Cmd output: {cmd}");
    // log::info!("Output len: {}", out.len());

    Ok(())
}
