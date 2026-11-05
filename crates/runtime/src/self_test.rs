use anyhow::{Context, bail};
use futures::FutureExt;
use futures::future::BoxFuture;
use futures::lock::Mutex;
use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::Value;
use std::collections::HashMap;
use std::future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Notify;
use uuid::Uuid;
use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{Error, ErrorExt, EventEmitter, runtime_api::server};
use ya_runtime_sdk::{ProcessStatus, RunProcess, RuntimeStatus};

use crate::deploy::{Deployment, DeploymentMount};
use crate::vmrt::{RuntimeData, runtime_dir};
use crate::{Runtime, TestConfig, disk_image};

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
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            log::warn!("Couldn't remove {}: {error}", self.0.display());
        }
    }
}

pub(crate) async fn test(
    pci_device_id: Option<Vec<String>>,
    test_config: TestConfig,
) -> Result<(), Error> {
    run_self_test(verify_status, pci_device_id, test_config)
        .await
        .map_err(|error| Error::from(format!("{error:#}")))
}

pub(crate) fn verify_status(status: anyhow::Result<Value>) -> anyhow::Result<String> {
    let status = status?;
    Ok(serde_json::to_string(&status)?)
}

pub(crate) async fn run_self_test<HANDLER>(
    handle_result: HANDLER,
    pci_device_id: Option<Vec<String>>,
    test_config: TestConfig,
) -> anyhow::Result<()>
where
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
        RaiiDir::create(work_dir.clone()).context("creating self-test workdir")?;

    let deployment = self_test_deployment(&work_dir, &test_config)
        .await
        .context("preparing self-test deployment")?;

    let output_volume =
        get_self_test_only_volume(&deployment).context("self-test image has no output volume")?;
    let output_file_name = format!("out_{}.json", Uuid::new_v4());
    // This path is consumed by Linux even when the host is Windows.
    let output_file_vm = format!(
        "{}/{}",
        output_volume.path.trim_end_matches('/'),
        output_file_name
    );
    let output_dir = work_dir.join(output_volume.name);
    let output_file = output_dir.join(&output_file_name);

    let runtime = self_test_runtime(deployment, pci_device_id);

    let work_dir = &work_dir;

    log::info!("Starting runtime");
    let start_response = start_runtime(emitter, work_dir.clone(), runtime.data.clone())
        .await
        .context("starting self-test runtime")?;
    log::info!("Runtime start response {:?}", start_response);

    log::info!("Runtime: {:?}", runtime.data);
    log::info!("Running self test command");
    let timeout = test_config.test_timeout();
    let command_result = run_self_test_command(
        runtime.data.clone(),
        &output_dir,
        &output_file,
        &output_file_vm,
        timeout,
    )
    .await
    .context("running self-test command");

    log::info!("Stopping runtime");
    let stop_result = crate::stop(runtime.data.clone())
        .await
        .map_err(|error| anyhow::anyhow!("stopping self-test runtime: {error:?}"));
    command_result?;
    stop_result?;

    log::info!("Handling result");
    let out_result = read_json(&output_file);
    let result = handle_result(out_result).context("handling self-test result")?;
    if !result.is_empty() {
        // the server refuses to stop by itself; print output to stdout
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(result.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }

    log::debug!("Deleting output files");
    std::fs::remove_dir_all(output_dir).context("removing self-test output directory")?;

    drop(work_dir_handle);
    Ok(())
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
        .context("finding runtime directory")?
        .join(FILE_TEST_IMAGE)
        .canonicalize()
        .context("finding self-test image")?;

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
        "golem".to_string(),
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

        let image_path = work_dir.join(name);
        log::debug!(
            "Creating raw disk image: {image_path:?} for path {guest_path} with parameters {mount:?}"
        );
        disk_image::create_sparse_raw_image(
            image_path,
            size.as_u64(),
            preallocate.unwrap_or_default().as_u64(),
        )
        .await?;
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
    output_file_vm: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let run_process: RunProcess = server::RunProcess {
        bin: format!("/{FILE_TEST_EXECUTABLE}"),
        args: vec![FILE_TEST_EXECUTABLE.into(), output_file_vm.into()],
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
        bail!("File {output_file:?} not created before timeout of {timeout:?}: {err}");
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
            kind:
                EventKind::Access(AccessKind::Close(AccessMode::Write))
                | EventKind::Modify(_)
                | EventKind::Create(_),
            paths,
            ..
        }) if paths.contains(&output_file) && read_json(&output_file).is_ok() => {
            output_notification.notify_one()
        }
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
