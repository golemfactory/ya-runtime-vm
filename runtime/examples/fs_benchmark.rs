use ::futures::{future, lock::Mutex, FutureExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::time::timeout;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::guest_agent_comm::{GuestAgent, RedirectFdType};

mod common;
use common::run_process_with_output;
use common::spawn_vm;
use common::Notifications;

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

        let start = Instant::now();

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
                "count=2000",
            ],
        )
        .await
        .unwrap();

        log::info!("Creating big file took: {}s", start.elapsed().as_secs());

        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/ls",
            &["ls", "-lh", &"/mnt/mnt1/tag0/"],
        )
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
        let cmd = format!("cat /mnt/mnt1/tag0/big_file >  {path}/big_chunk;");
        // let cmd = format!("cp /mnt/mnt1/tag0/big_file  /{path}/big_chunk");

        let name = name.clone();
        let path = path.clone();
        let join = tokio::spawn(async move {
            log::info!("Spawning task for {name}");
            let ga = ga_mutex.clone();

            let start = Instant::now();
            test_write(ga_mutex, &notifications, &cmd).await.unwrap();

            log::info!(
                "Copy big chunk for {name} took {}s",
                start.elapsed().as_secs()
            );
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

async fn test_fio(
    mount_args: Arc<Vec<ContainerVolume>>,
    ga_mutex: Arc<Mutex<GuestAgent>>,
    notifications: Arc<Notifications>,
) {
    for ContainerVolume { name : _, path } in mount_args.iter() {
        let mut ga = ga_mutex.lock().await;

        // TODO: this is serialized
        run_process_with_output(
            &mut ga,
            &notifications,
            "/usr/bin/fio",
            &[
                "fio",
                "--randrepeat=1",
                "--ioengine=libaio",
                "--direct=1",
                "--gtod_reduce=1",
                "--name=test",
                "--bs=4k",
                "--iodepth=64",
                "--readwrite=randrw",
                "--rwmixread=75",
                "--size=100M",
                "--max-jobs=4",
                "--numjobs=4",
                &format!("--filename={path}/test_fio"),
            ],
        )
        .await
        .unwrap();
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let (mut child, vm) = spawn_vm();
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

    // test_parallel_write_big_chunk(mount_args.clone(), ga_mutex.clone(), notifications.clone())
    //     .await;

    {
        let mut ga = ga_mutex.lock().await;

        run_process_with_output(&mut ga, &notifications, "/bin/mkdir", &["mkdir", "/tmp/testo"]).await?;

    }

    test_fio(mount_args.clone(), ga_mutex.clone(), notifications.clone()).await;

    {
        let mut ga = ga_mutex.lock().await;

        run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "aux"]).await?;

        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "5"], None, 0, 0, &NO_REDIR, None)
            .await?
            .expect("Run process failed");
        log::info!("Spawned process with id: {}", id);
        notifications
            .get_process_died_notification(id)
            .await
            .notified()
            .await;
    }

    // /* VM should quit now. */
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

    log::debug!("waiting on died for {id}");
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
