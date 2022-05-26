use ::futures::{future, lock::Mutex, FutureExt};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{
    env, fs,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use structopt::StructOpt;
use tokio::time::timeout;
use tokio::{process::Child, sync};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::demux_socket_comm::MAX_P9_PACKET_SIZE;
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
                Some(RedirectFdType::RedirectFdPipeBlocking(0x10000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x10000)),
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
    timeout(Duration::from_secs(1), notifications
        .get_output_available_notification(id)
        .await
        .notified()).await;


    log::error!("dupa4");

    match ga.query_output(id, 1, 0, u64::MAX).await? {
        Ok(out) => {
            log::info!("STDOUT Output {argv:?}:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => log::info!("{argv:?} no data on STDOUT, reason {code}"),
    }
    log::error!("dupa6");

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

fn spawn_vm(tmp_path: &Path, cpu_cores: usize, mem_mib: usize) -> (Child, VM) {
    #[cfg(windows)]
    let vm_executable = "vmrt.exe";
    #[cfg(unix)]
    let vm_executable = "vmrt";

    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let image_dir = project_dir.join("poc").join("squashfs");
    let init_dir = project_dir.join("init-container");
    let source_qcow2_file = project_dir
        .join("poc")
        .join("qcow2")
        .join("empty_10GB.qcow2");
    let qcow2_file = tmp_path.join("rw_drive.qcow2");
    fs::copy(&source_qcow2_file, &qcow2_file).unwrap();
    let qcow2_file = qcow2_file.canonicalize().unwrap();

    let vm = VMBuilder::new(
        cpu_cores,
        mem_mib,
        &image_dir.join("ubuntu.gvmi"),
        &qcow2_file,
    )
    .with_kernel_path(join_as_string(&init_dir, "vmlinuz-virt"))
    .with_ramfs_path(join_as_string(&init_dir, "initramfs.cpio.gz"))
    .build();

    let mut cmd = vm.create_cmd(&runtime_dir.join(vm_executable));
//    let mut cmd = vm.create_cmd(r#"C:\Program Files\qemu\qemu-system-x86_64.exe"#);

    log::info!("CMD: {cmd:?}");

    cmd.stdin(Stdio::piped());

    cmd.current_dir(runtime_dir);
    (cmd.spawn().expect("failed to spawn VM"), vm)
}

/// Write for one byte to the file, create as many tasks as there are mount points
#[allow(dead_code)]
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
    test_file_size: u64,
    mount_args: Arc<Vec<ContainerVolume>>,
    ga_mutex: Arc<Mutex<GuestAgent>>,
    notifications: Arc<Notifications>,
) {
    // prepare chunk

    {
        let mut ga = ga_mutex.lock().await;
        let start = Instant::now();
        // List files
        let block_size = 1000000;
        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/dd",
            &[
                "dd",
                // TODO: /dev/random causes problems?
                "if=/dev/zero",
                "of=/mnt/mnt1/tag0/big_file",
                std::format!("bs={}", block_size).as_str(),
                std::format!("count={}", test_file_size / block_size).as_str(),
            ],
        )
        .await
        .unwrap();

        let test_file_size = test_file_size / block_size * block_size;

        let duration = start.elapsed();
        let time_in_secs = duration.as_secs_f64();
        let speed_mbs = test_file_size as f64 / time_in_secs / 1000.0 / 1000.0;
        log::info!(
            "File generated in {:.3}s. {:.3}MB/s",
            time_in_secs,
            speed_mbs
        );


    }

    let mut tasks = vec![];

    for ContainerVolume { name, path } in mount_args.as_ref() {
        let ga_mutex = ga_mutex.clone();
        let notifications = notifications.clone();

        // let cmd = format!("A=\"A\"; for i in {{1..24}}; do A=\"${{A}}${{A}}\"; done; echo -ne $A >> {path}/big_chunk");
        let cmd = format!("cat /mnt/mnt1/tag0/big_file > {path}/big_chunk;");
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
                run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-lh", &path])
                    .await
                    .unwrap();
            }
        });

        tasks.push(join);
    }

    log::info!("Joining...");
    future::join_all(tasks).await;
}

#[derive(Debug, StructOpt)]
#[structopt(name = "options", about = "Options for performance benchmark")]
pub struct Opt {
    /// Number of logical CPU cores
    #[structopt(long, default_value = "1")]
    cpu_cores: usize,
    /// Amount of RAM [GiB]
    #[structopt(long, default_value = "0.25")]
    mem_gib: f64,
    /// Amount of disk storage [GiB]
    #[allow(unused)]
    #[structopt(long, default_value = "0.25")]
    storage_gib: f64,
    /// Number of mounts
    #[allow(unused)]
    #[structopt(long, default_value = "3")]
    mount_count: u32,
    /// File size to test in bytes [bytes]
    #[allow(unused)]
    #[structopt(long, default_value = "10000000")]
    file_test_size: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::init();

    log::info!("hai!");
    let temp_path = get_project_dir().join(Path::new("tmp"));
    if temp_path.exists() {
        fs::remove_dir_all(&temp_path)?;
    }
    fs::create_dir_all(&temp_path)?;
    let (mut child, vm) = spawn_vm(&temp_path, opt.cpu_cores, (opt.mem_gib * 1024.0) as usize);

    let notifications = Arc::new(Notifications::new());

    const MOUNTS: usize = 2;

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
            let max_p9_packet_size = u32::try_from(MAX_P9_PACKET_SIZE).unwrap();

            if let Err(e) = ga.mount(name, max_p9_packet_size, path).await? {
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
    {
        let mut ga = ga_mutex.lock().await;

        tokio::time::sleep(Duration::from_secs(5)).await;
        log::error!("dupa_start");
        run_process_with_output(&mut ga, &notifications, "/bin/mkdir", &["mkdir", "/mnt/here"])
            .await?;
        //log::error!("dupa_koniec");

        run_process_with_output(&mut ga, &notifications,"/bin/ls",&["ls", "-al", "/dev2"])
            .await?;
        run_process_with_output(&mut ga, &notifications, "/bin/mount", &["mount", "-t", "ext4", "/dev/vdb", "/mnt/here"])
            .await?;
         run_process_with_output(&mut ga, &notifications,"/bin/ls",&["ls", "-al", "/mnt"])
             .await?;
        run_process_with_output(&mut ga, &notifications,"/bin/ls",&["ls", "-al", "/mnt/here"])
            .await?;
    }

    // test_parallel_write_small_chunks(mount_args.clone(), ga_mutex.clone(), notifications.clone())
    //     .await;

    test_parallel_write_big_chunk(
        opt.file_test_size,
        mount_args.clone(),
        ga_mutex.clone(),
        notifications.clone(),
    )
    .await;

    log::info!("test_parallel_write_big_chunk finished");


    {
        let mut ga = ga_mutex.lock().await;

        //run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "aux"]).await?;
        run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-la", "/dev"]).await?;

    }

    {
        let mut ga = ga_mutex.lock().await;

        //run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "aux"]).await?;
        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/busybox",
            &["top", "-b", "-n", "1"],
        )
        .await?;

        /*
        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "60"], None, 0, 0, &NO_REDIR, None)
            .await?
            .expect("Run process failed");
        log::info!("Spawned process with id: {}", id);
        notifications
            .get_process_died_notification(id)
            .await
            .notified()
            .await;*/
    }

    /* VM should quit now. */
    let e = timeout(Duration::from_secs(5), child.wait()).await;
    log::info!("{:?}", e);
    child.kill().await.unwrap();

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

    if let Err(_) = timeout(Duration::from_secs(60), fut).await {
        log::error!("Got timeout on died notification for process {id}");
    }

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
