use ::futures::{future, FutureExt};

use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{
    env, fs,
    io::{self},
    sync::Arc,
};

use structopt::StructOpt;

use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_vm::demux_socket_comm::MAX_P9_PACKET_SIZE;

use ya_runtime_vm::local_spawn_vm::spawn_vm;

use ya_runtime_vm::local_notification_handler::{
    start_local_agent_communication, LocalAgentCommunication,
};

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("invalid manifest dir")
}

#[derive(Debug, StructOpt)]
#[structopt(name = "options", about = "Options for VM")]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    env_logger::init();

    log::info!("Running example fs_benchmark...");
    let temp_path = get_project_dir().join(Path::new("tmp"));
    if temp_path.exists() {
        fs::remove_dir_all(&temp_path)?;
    }
    fs::create_dir_all(&temp_path)?;
    let mut vm_runner =
        spawn_vm(&temp_path, opt.cpu_cores, (opt.mem_gib * 1024.0) as usize).await?;

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

    let (_p9streams, _muxer_handle) = vm_runner
        .start_9p_service(&temp_path, &mount_args)
        .await
        .unwrap();

    let comm = start_local_agent_communication(vm_runner.get_vm().get_manager_sock()).await?;

    {
        let ga = comm.get_ga();
        let mut guest_agent = ga.lock().await;

        for ContainerVolume { name, path } in mount_args.iter() {
            let max_p9_packet_size = u32::try_from(MAX_P9_PACKET_SIZE).unwrap();

            if let Err(e) = guest_agent.mount(name, max_p9_packet_size, path).await? {
                log::error!("Mount failed at {name}, {path}, {e}")
            }
        }
    }

    /* VM should quit now. */
    //let e = timeout(Duration::from_secs(5), vm_runner..wait()).await;
    vm_runner.stop_vm(&Duration::from_secs(5), true).await?;

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
