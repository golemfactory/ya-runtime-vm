use anyhow::bail;
use futures::future::BoxFuture;
use futures::lock::Mutex;
use futures::FutureExt;
use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::collections::HashMap;
use std::future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Notify;
use uuid::Uuid;
use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{runtime_api::server, Error, ErrorExt, EventEmitter};
use ya_runtime_sdk::{ProcessStatus, RunProcess, RuntimeStatus};

use crate::deploy::{Deployment, DeploymentMount};
use crate::vmrt::{runtime_dir, RuntimeData};
use crate::{qcow2_min, Runtime, TestConfig};

const FILE_TEST_IMAGE: &str = "self-test.gvmi";
const FILE_TEST_EXECUTABLE: &str = "ya-self-test";

struct RaiiDir(PathBuf);

impl RaiiDir {
    pub fn create(path: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RaiiDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0)
            .unwrap_or_else(|_| panic!("Couldn't remove {}", self.0.display()));
    }
}

pub(crate) async fn test(
    pci_device_id: Option<Vec<String>>,
    test_config: TestConfig,
) -> Result<(), Error> {
    run_self_test(verify_status, pci_device_id, test_config).await;
    Ok(())
}

pub(crate) fn verify_status(status: anyhow::Result<Value>) -> anyhow::Result<String> {
    let status = status?;
    Ok(serde_json::to_string(&status)?)
}

pub(crate) async fn run_self_test<HANDLER>(
    handle_result: HANDLER,
    pci_device_id: Option<Vec<String>>,
    test_config: TestConfig,
) where
    HANDLER: Fn(anyhow::Result<Value>) -> anyhow::Result<String>,
{
    struct Emitter;

    impl RuntimeHandler for Emitter {
        fn on_process_status<'a>(&self, _: ProcessStatus) -> BoxFuture<'a, ()> {
            future::ready(()).boxed()
        }

        fn on_runtime_status<'a>(&self, _: RuntimeStatus) -> BoxFuture<'a, ()> {
            future::ready(()).boxed()
        }
    }

    let emitter = Emitter;

    let tmp = std::env::temp_dir();
    let work_dir = tmp.join(format!("ya-runtime-vm-self-test-{}", Uuid::new_v4()));
    let work_dir_handle =
        RaiiDir::create(work_dir.clone()).expect("Failed to create workdir for self-test");

    let deployment = self_test_deployment(&work_dir, &test_config)
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

    let work_dir = &work_dir;

    log::info!("Starting runtime");
    let start_response = start_runtime(emitter, work_dir.clone(), runtime.data.clone())
        .await
        .expect("Starts runtime");
    log::info!("Runtime start response {:?}", start_response);

    log::info!("Runtime: {:?}", runtime.data);
    log::info!("Running self test command");
    let timeout = test_config.test_timeout();
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
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(result.as_bytes()).unwrap();
        stdout.write_all(b"\n").unwrap();
        stdout.flush().unwrap();
    }

    log::debug!("Deleting output files");
    std::fs::remove_dir_all(output_dir).expect("Removes self-test output dir");

    drop(work_dir_handle);
}

fn self_test_runtime(deployment: Deployment, pci_device_id: Option<Vec<String>>) -> Runtime {
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
    test_config: &TestConfig,
) -> anyhow::Result<Deployment> {
    let package_path = runtime_dir()
        .expect("Runtime directory not found")
        .join(FILE_TEST_IMAGE)
        .canonicalize()
        .expect("Test image not found");

    let package_paths = [package_path];

    let cpu_cores = test_config.test_cpu_cores;
    let mem_gib = test_config.test_mem_gib;
    log::info!("Task packages:");
    for path in package_paths.iter() {
        log::info!("{}", path.display());
    }
    let mem_mib = (mem_gib * 1024.) as usize;
    let package_file = fs::File::open(package_paths[0].clone())
        .await
        .or_err("Error reading package file")?;
    let deployment = Deployment::try_from_input(
        package_file,
        cpu_cores,
        mem_mib,
        &package_paths,
        HashMap::from_iter([
            (
                "/golem/storage".to_string(),
                VolumeMount::Storage {
                    size: "1mi".parse().unwrap(),
                    preallocate: None,
                    errors: Some("remount-ro".to_string()),
                },
            ),
            (
                "/golem/storage2".to_string(),
                VolumeMount::Ram {
                    size: "1gi".parse().unwrap(),
                },
            ),
        ]),
    )
    .await
    .or_err("Error reading package metadata")?;

    for vol in &deployment.volumes {
        let vol_dir = work_dir.join(&vol.name);
        log::debug!("Creating volume dir: {vol_dir:?} for path {}", vol.path);
        fs::create_dir_all(vol_dir)
            .await
            .or_err("Failed to create volume dir")?;
    }

    for DeploymentMount {
        name,
        mount,
        guest_path,
    } in &deployment.mounts
    {
        let VolumeMount::Storage {
            size, preallocate, ..
        } = mount
        else {
            continue;
        };

        let qcow2_dir = work_dir.join(name);
        log::debug!(
            "Creating qcow2 image: {qcow2_dir:?} for path {guest_path} with parameters {mount:?}"
        );
        let file = fs::File::create(qcow2_dir).await?;
        let qcow2 =
            qcow2_min::Qcow2Image::new(size.as_u64(), preallocate.unwrap_or_default().as_u64());
        qcow2.write(file).await?;
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
