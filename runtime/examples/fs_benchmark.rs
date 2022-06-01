use futures::future;
use std::time::{Duration, Instant};

use structopt::StructOpt;

use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;

use ya_runtime_vm::local_spawn_vm::{prepare_mount_directories, prepare_tmp_path, spawn_vm};

use std::sync::Arc;
use tokio::io;
use ya_runtime_vm::local_notification_handler::{
    start_local_agent_communication, LocalAgentCommunication,
};

/// Write for one byte to the file, create as many tasks as there are mount points
#[allow(dead_code)]
async fn test_parallel_write_small_chunks(
    mount_args: Arc<Vec<ContainerVolume>>,
    comm: Arc<LocalAgentCommunication>,
) {
    let mut tasks = vec![];

    for ContainerVolume { name, path } in mount_args.as_ref() {
        let cmd = format!("for i in {{1..100}}; do echo -ne a >> {path}/small_chunks; done; cat {path}/small_chunks");

        let name = name.clone();
        let path = path.clone();
        let comm = comm.clone();
        let join = tokio::spawn(async move {
            log::info!("Spawning task for {name}");
            test_write(comm.clone(), &cmd).await.unwrap();

            {
                comm.run_command("/bin/ls", &["ls", "-la", &path])
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
    mount_args: &[ContainerVolume],
    comm: Arc<LocalAgentCommunication>,
) {
    // prepare chunk

    {
        let start = Instant::now();
        // List files
        let block_size = 1000000;
        //comm.run_bash_command("touch /mnt/mnt1/tag0/big_file").await.unwrap();
        comm.run_command(
            "/bin/dd",
            &[
                "dd",
                // TODO: /dev/random causes problems?
                "if=/dev/urandom",
                "of=/mnt/mnt1/tag0/big_file",
                std::format!("bs={}", block_size).as_str(),
                std::format!("count={}", test_file_size / block_size).as_str(),
            ],
        )
        .await
        .unwrap();

        //comm.run_bash_command(&format!("head -c {} </dev/urandom > /mnt/mnt1/tag0/big_file", test_file_size)).await.unwrap();
        /*comm.run_command(
                    "/bin/busybox",
                    &[
                        "shred",
                        // TODO: /dev/random causes problems?
                        "-n",
                        "1",
                        "-s",
                        std::format!("{}", test_file_size).as_str(),
                        "/mnt/mnt1/tag0/big_file"
                    ],
                )
                .await
                .unwrap();
        */
        let test_file_size = test_file_size / block_size * block_size;

        let duration = start.elapsed();
        let time_in_secs = duration.as_secs_f64();
        let speed_mbs = test_file_size as f64 / time_in_secs / 1000.0 / 1000.0;
        println!(
            "File generated in {:.3}s. {:.3}MB/s",
            time_in_secs,
            speed_mbs
        );
    }

    let mut tasks = vec![];
    let start = Instant::now();

    for ContainerVolume { name, path } in mount_args.as_ref() {
        // let cmd = format!("A=\"A\"; for i in {{1..24}}; do A=\"${{A}}${{A}}\"; done; echo -ne $A >> {path}/big_chunk");
        let cmd = format!("cat /mnt/mnt1/tag0/big_file >  {path}/big_chunk;");
        // let cmd = format!("cp /mnt/mnt1/tag0/big_file  /{path}/big_chunk");

        let name = name.clone();
        let path = path.clone();
        let comm = comm.clone();
        let join = tokio::spawn(async move {
            log::info!("Spawning task for {name}");
            let start = Instant::now();
            test_write(comm.clone(), &cmd).await.unwrap();

            log::info!(
                "Copy big chunk for {name} took {:.2}s",
                start.elapsed().as_secs_f64()
            );
            {
                // List files
                comm.run_command("/bin/ls", &["ls", "-l", &path])
                    .await
                    .unwrap();
            }
        });

        tasks.push(join);
    }

    log::info!("Joining...");
    future::join_all(tasks).await;
    let duration = start.elapsed();
    let time_in_secs = duration.as_secs_f64();
    let speed_mbs = mount_args.len() as f64 * test_file_size as f64 / time_in_secs / 1000.0 / 1000.0;
    println!(
        "Files ({}) copied in {:.3}s. {:.3}MB/s",
        mount_args.len(),
        time_in_secs,
        speed_mbs
    );
}

async fn test_fio(mount_args: Arc<Vec<ContainerVolume>>, comm: LocalAgentCommunication) {
    for ContainerVolume { name: _, path } in mount_args.iter() {
        // TODO: this is serialized
        comm.run_command(
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
async fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::init();

    log::info!("Running example fs_benchmark...");

    let temp_path = prepare_tmp_path();
    let mount_args = prepare_mount_directories(&temp_path, 2);

    let mut vm_runner = spawn_vm(&temp_path, opt.cpu_cores, opt.mem_gib, false).await?;

    //let VM start before trying to connect p9 service
    tokio::time::sleep(Duration::from_secs_f64(2.5)).await;

    let (_p9streams, _muxer_handle) = vm_runner
        .start_9p_service(&temp_path, &mount_args)
        .await
        .unwrap();

    let comm = start_local_agent_communication(vm_runner.get_vm().get_manager_sock()).await?;

    comm.run_mount(&mount_args).await?;

    comm.run_bash_command("ls -la /mnt/mnt1").await?;
    // test_parallel_write_small_chunks(mount_args.clone(), ga_mutex.clone(), notifications.clone())
    //     .await;

    test_parallel_write_big_chunk(opt.file_test_size, &mount_args, comm.clone()).await;

    log::info!("test_parallel_write_big_chunk finished");

    {
        //run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "aux"]).await?;
        //comm.run_command("/bin/ls", &["ls", "-la", "/dev"]).await?;
        comm.run_bash_command("ls -la /dev;sleep 0.5").await?;
    }

    {
        //run_process_with_output(&mut ga, &notifications, "/bin/ps", &["ps", "aux"]).await?;
        comm.run_bash_command("top -b -n 1").await?;
    }

    /* VM should quit now. */
    //let e = timeout(Duration::from_secs(5), vm_runner..wait()).await;
    vm_runner.stop_vm(&Duration::from_secs(5), true).await?;
    //log::info!("{:?}", e);
    //child.kill().await.unwrap();

    Ok(())
}

async fn test_write(comm: Arc<LocalAgentCommunication>, cmd: &str) -> io::Result<()> {
    log::info!("***** test_big_write *****");

    let argv = ["bash", "-c", &cmd];

    comm.run_command("/bin/bash", &argv).await?;

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
