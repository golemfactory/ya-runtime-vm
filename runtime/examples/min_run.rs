use std::time::Duration;
use structopt::StructOpt;
use ya_runtime_vm::local_notification_handler::start_local_agent_communication;
use ya_runtime_vm::local_spawn_vm::{prepare_mount_directories, prepare_tmp_path, spawn_vm};

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

    /* VM should quit now. */
    //let e = timeout(Duration::from_secs(5), vm_runner..wait()).await;
    vm_runner.stop_vm(&Duration::from_secs(5), true).await?;

    Ok(())
}
