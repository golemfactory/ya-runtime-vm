use anyhow::bail;
use futures::lock::Mutex;
use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Notify;
use uuid::Uuid;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{runtime_api::server, server::Server, Context, Error, ErrorExt, EventEmitter};
use ya_runtime_sdk::{ProcessStatus, RunProcess, RuntimeStatus};

use crate::deploy::Deployment;
use crate::vmrt::{runtime_dir, RuntimeData};
use crate::Runtime;

const FILE_TEST_IMAGE: &str = "self-test.gvmi";
const FILE_TEST_EXECUTABLE: &str = "ya-self-test";

pub(crate) async fn test(
    pci_device_id: Option<String>,
    timeout: Duration,
    cpu_cores: usize,
    mem_gib: f64,
) -> Result<(), Error> {
    run_self_test(verify_status, pci_device_id, timeout, cpu_cores, mem_gib).await;
    // Dead code. ya_runtime_api::server::run_async requires killing a process to stop
    Ok(())
}

pub(crate) fn verify_status(status: anyhow::Result<Value>) -> anyhow::Result<String> {
    let status = status?;
    Ok(serde_json::to_string(&status)?)
}

pub(crate) async fn run_self_test<HANDLER>(
    handle_result: HANDLER,
    pci_device_id: Option<String>,
    timeout: Duration,
    cpu_cores: usize,
    mem_gib: f64,
) where
    HANDLER: Fn(anyhow::Result<Value>) -> anyhow::Result<String>,
{
    let work_dir = std::env::temp_dir();

    let deployment = self_test_deployment(&work_dir, cpu_cores, mem_gib)
        .await
        .expect("Prepares self test img deployment");

    let output_volume =
        get_self_test_only_volume(&deployment).expect("Self test image has an output volume");
    let output_file_name = format!("out_{}.json", Uuid::new_v4());
    let output_file_vm = PathBuf::from_str(&output_volume.path)
        .expect("Can create self test volume path")
        .join(&output_file_name);
    let output_dir = work_dir.join(output_volume.name);
    let output_file = output_dir.join(&output_file_name);

    let runtime = self_test_runtime(deployment, pci_device_id);

    server::run_async(|emitter| async {
        let ctx = Context::try_new().expect("Creates runtime context");

        log::info!("Starting runtime");
        let start_response = start_runtime(emitter, work_dir.clone(), runtime.data.clone())
            .await
            .expect("Starts runtime");
        log::info!("Runtime start response {:?}", start_response);

        log::info!("Runtime: {:?}", runtime.data);
        log::info!("Running self test command");
        run_self_test_command(
            runtime.data.clone(),
            &output_dir,
            &output_file,
            &output_file_vm,
            timeout,
        )
        .await
        .expect("Can run self-test command");

        log::info!("Stopping runtime");
        crate::stop(runtime.data.clone())
            .await
            .expect("Stops runtime");

        log::info!("Handling result");
        let out_result = read_json(&output_file);
        let result = handle_result(out_result).expect("Handles test result");
        if !result.is_empty() {
            // the server refuses to stop by itself; print output to stdout
            println!("{result}");
        }

        log::debug!("Deleting output files");
        std::fs::remove_dir_all(output_dir).expect("Removes self-test output dir");

        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        Server::new(runtime, ctx)
    })
    .await;
}

fn self_test_runtime(deployment: Deployment, pci_device_id: Option<String>) -> Runtime {
    let runtime_data = RuntimeData {
        deployment: Some(deployment),
        pci_device_id,
        ..Default::default()
    };
    Runtime {
        data: Arc::new(Mutex::new(runtime_data)),
    }
}

/// Builds self test deployment based on `FILE_TEST_IMAGE` from path returned by `runtime_dir()`
async fn self_test_deployment(
    work_dir: &Path,
    cpu_cores: usize,
    mem_gib: f64,
) -> anyhow::Result<Deployment> {
    let package_path = runtime_dir()
        .expect("Runtime directory not found")
        .join(FILE_TEST_IMAGE)
        .canonicalize()
        .expect("Test image not found");

    log::info!("Task package: {}", package_path.display());
    let mem_mib = (mem_gib * 1024.) as usize;
    let package_file = fs::File::open(package_path.clone())
        .await
        .or_err("Error reading package file")?;
    let deployment =
        Deployment::try_from_input(package_file, cpu_cores, mem_mib, package_path.clone())
            .await
            .or_err("Error reading package metadata")?;
    for vol in &deployment.volumes {
        let vol_dir = work_dir.join(&vol.name);
        log::debug!("Creating volume dir: {vol_dir:?} for path {}", vol.path);
        fs::create_dir_all(vol_dir)
            .await
            .or_err("Failed to create volume dir")?;
    }
    Ok(deployment)
}

/// Returns path to self test image only volume.
/// Fails if `self_test_deployment` has no volumes or more than one.
fn get_self_test_only_volume(self_test_deployment: &Deployment) -> anyhow::Result<ContainerVolume> {
    if self_test_deployment.volumes.len() != 1 {
        bail!("Self test image has to have one volume");
    }
    Ok(self_test_deployment.volumes.first().unwrap().clone())
}

/// Starts runtime with runtime handler wrapped to log process stdout and stdderr
async fn start_runtime<HANDLER: RuntimeHandler + 'static>(
    handler: HANDLER,
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
) -> anyhow::Result<Option<Value>> {
    let emitter = ProcessOutputLogger::new(handler);
    let emitter = EventEmitter::spawn(emitter);
    crate::start(work_dir.clone(), runtime_data, emitter.clone()).await
}

/// Runs command, monitors `output_dir` looking for `output_file`.
/// Fails if `output_file` not created before `timeout`.
async fn run_self_test_command(
    runtime_data: Arc<Mutex<RuntimeData>>,
    output_dir: &Path,
    output_file: &Path,
    output_file_vm: &Path,
    timeout: Duration,
) -> anyhow::Result<()> {
    let run_process: RunProcess = server::RunProcess {
        bin: format!("/{FILE_TEST_EXECUTABLE}"),
        args: vec![
            FILE_TEST_EXECUTABLE.into(),
            output_file_vm.to_string_lossy().into(),
        ],
        ..Default::default()
    };
    log::info!("Self test process: {run_process:?}");

    let output_notification = Arc::new(Notify::new());
    // Keep `_watcher` . Watcher shutdowns when dropped.
    let _watcher = spawn_output_watcher(output_notification.clone(), output_dir, output_file)?;

    if let Err(err) = crate::run_command(runtime_data, run_process).await {
        bail!("Code: {}, msg: {}", err.code, err.message);
    };

    if let Err(err) = tokio::time::timeout(timeout, output_notification.notified()).await {
        log::error!("File {output_file:?} not created before timeout of {timeout:?}s. Err: {err}.");
    };
    Ok(())
}

fn spawn_output_watcher(
    output_notification: Arc<Notify>,
    output_dir: &Path,
    output_file: &Path,
) -> anyhow::Result<RecommendedWatcher> {
    let output_file = output_file.into();
    let mut watcher = notify::recommended_watcher(move |res| match res {
        Ok(Event {
            kind: EventKind::Access(AccessKind::Close(AccessMode::Write)),
            paths,
            ..
        }) if paths.contains(&output_file) => output_notification.notify_waiters(),
        Ok(event) => {
            log::trace!("Output file watch event: {:?}", event);
        }
        Err(error) => {
            log::error!("Output file watch error: {:?}", error);
        }
    })?;

    watcher.watch(output_dir, RecursiveMode::Recursive)?;
    Ok(watcher)
}

fn read_json(output_file: &Path) -> anyhow::Result<Value> {
    let output_file = std::fs::File::open(output_file)?;
    Ok(serde_json::from_reader(&output_file)?)
}
struct ProcessOutputLogger {
    handler: Box<dyn RuntimeHandler + 'static>,
}

impl ProcessOutputLogger {
    fn new<HANDLER: RuntimeHandler + 'static>(handler: HANDLER) -> Self {
        let handler = Box::new(handler);
        Self { handler }
    }
}

impl RuntimeHandler for ProcessOutputLogger {
    fn on_process_status<'a>(&self, status: ProcessStatus) -> futures::future::BoxFuture<'a, ()> {
        if !status.stdout.is_empty() {
            log::debug!(
                "PID: {}, stdout: {}",
                status.pid,
                String::from_utf8_lossy(&status.stdout)
            );
        } else if !status.stderr.is_empty() {
            log::debug!(
                "PID: {}, stderr: {}",
                status.pid,
                String::from_utf8_lossy(&status.stderr)
            );
        }
        self.handler.on_process_status(status)
    }
    fn on_runtime_status<'a>(&self, status: RuntimeStatus) -> futures::future::BoxFuture<'a, ()> {
        self.handler.on_runtime_status(status)
    }
}
