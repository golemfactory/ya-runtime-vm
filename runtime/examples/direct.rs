use futures::FutureExt;
use std::{
    io::{self},
    sync::Arc,
};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::guest_agent_comm::{GuestAgent, RedirectFdType};

mod common;

use common::{spawn_vm, Notifications, run_process_with_output};

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let inner_path = temp_path.join("inner");

    std::fs::create_dir_all(&inner_path).expect("Failed to create a dir inside temp dir");

    let notifications = Arc::new(Notifications::new());
    let mount_args = [
        ContainerVolume {
            name: "".to_string(),
            path: "/mnt/mnt0/tag0".to_string(),
        },
        ContainerVolume {
            name: "inner".to_string(),
            path: "/mnt/mnt1/tag1".to_string(),
        },
    ];

    let (mut child, vm) = spawn_vm();

    let (_p9streams, _muxer_handle) = vm.start_9p_service(&temp_path, &mount_args).await.unwrap();

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(vm.get_manager_sock(), 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n).await }.boxed()
    })
    .await?;
    let mut ga = ga_mutex.lock().await;

    for ContainerVolume { name, path } in mount_args.iter() {
        ga.mount(name, path).await?.expect("Mount failed");
    }

    run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-al", "/mnt"]).await?;

    run_process_with_output(
        &mut ga,
        &notifications,
        "/bin/ls",
        &["ls", "-al", "/mnt/mnt1/tag1"],
    )
    .await?;

    test_write(&mut ga, &notifications).await?;

    // test_indirect(&mut ga, &notifications).await?;

    test_start_and_kill(&mut ga, &notifications).await?;

    test_big_write(&mut ga, &notifications).await?;

    // ga.quit().await?.expect("Quit failed");

    let id = ga
        .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &NO_REDIR, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.get_process_died_notification(id).await.notified().await;

    /* VM should quit now. */
    let e = child.wait().await.expect("failed to wait on child");
    println!("{:?}", e);

    println!("inner path: {}", inner_path.as_os_str().to_string_lossy());

    // tokio::time::sleep(Duration::from_secs(30)).await;

    Ok(())
}

const NO_REDIR: [Option<RedirectFdType>; 3] = [None, None, None];

async fn test_big_write(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_big_write *****");
    let id = ga
        .run_process(
            "/bin/bash",
            &[
                "bash",
                "-c",
                "for i in {1..3311}; do echo -ne a >> /big; done; cat /big",
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
    notifications.get_process_died_notification(id).await.notified().await;

    notifications.get_output_available_notification(id).await.notified().await;

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

    Ok(())
}

async fn test_start_and_kill(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_start_and_kill *****");

    let id = ga
        .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &NO_REDIR, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);

    ga.kill(id).await?.expect("Kill failed");

    // TODO: timeout
    notifications.get_process_died_notification(id).await.notified().await;

    Ok(())
}

async fn test_write(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_write *****");

    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile(
            "/mnt/mnt1/tag1/write_test".as_bytes(),
        )),
        None,
    ];
    // Write something to the file
    let id = ga
        .run_process("/bin/echo", &["echo", "WRITE TEST"], None, 0, 0, &fds, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.get_process_died_notification(id).await.notified().await;

    // Check it's there
    run_process_with_output(
        ga,
        &notifications,
        "/bin/cat",
        &["cat", "/mnt/mnt1/tag1/write_test"],
    )
    .await?;

    // Check timestamp
    run_process_with_output(
        ga,
        &notifications,
        "/bin/ls",
        &["ls", "-la", "/mnt/mnt1/tag1/"],
    )
    .await?;

    Ok(())
}
