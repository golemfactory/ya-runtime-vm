use anyhow::bail;
use futures::lock::Mutex;
use serde_json::Value;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tokio::fs;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{runtime_api::server, server::Server, Context, ErrorExt, EventEmitter};
use ya_runtime_sdk::{Error, ProcessStatus, RuntimeStatus};

use crate::deploy::Deployment;
use crate::vmrt::{runtime_dir, RuntimeData};
use crate::Runtime;

const FILE_TEST_IMAGE: &str = "self-test.gvmi";

pub(crate) async fn test(pci_device_id: Option<String>, timeout: Duration) -> Result<(), Error> {
    run_self_test(verify_status, pci_device_id, timeout).await;
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
) where
    HANDLER: Fn(anyhow::Result<Value>) -> anyhow::Result<String>,
{
    let work_dir = std::env::temp_dir();

    let deployment = self_test_deployment(&work_dir)
        .await
        .expect("Prepares self test img deployment");

    let runtime_data = RuntimeData {
        deployment: Some(deployment),
        pci_device_id,
        ..Default::default()
    };
    let runtime = Runtime {
        data: Arc::new(Mutex::new(runtime_data)),
    };

    server::run_async(|e| async {
        let ctx = Context::try_new().expect("Creates runtime context");

        log::info!("Starting runtime");
        let (status_sender, mut status_receiver) = mpsc::channel();
        let emitter = EventEmitter::spawn(ProcessOutputHandler {
            handler: Box::new(e),
            status_sender,
        });
        let start_response = crate::start(work_dir.clone(), runtime.data.clone(), emitter.clone())
            .await
            .expect("Starts runtime");
        log::info!("Runtime start response {:?}", start_response);

        let run_process: ya_runtime_sdk::RunProcess = server::RunProcess {
            bin: "/ya-self-test".into(),
            args: vec!["ya-self-test".into()],
            work_dir: "/".into(),
            ..Default::default()
        };

        log::info!("Runtime: {:?}", runtime.data);
        log::info!("Self test process: {run_process:?}");

        let pid: u64 = crate::run_command(runtime.data.clone(), run_process)
            .await
            .expect("Runs command");

        let (final_status_sender, final_status_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let status = collect_process_response(&mut status_receiver, pid, timeout).await;
            final_status_sender.send(status)
        });
        let process_result = final_status_receiver
            .await
            .expect("Receives process status");

        log::info!("Process finished");
        let result = handle_result(process_result).expect("Handles test result");
        if !result.is_empty() {
            println!("{result}");
        }

        log::info!("Stopping runtime");
        crate::stop(runtime.data.clone())
            .await
            .expect("Stops runtime");

        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        Server::new(runtime, ctx)
    })
    .await;
}

async fn self_test_deployment(work_dir: &Path) -> anyhow::Result<Deployment> {
    let package_path = runtime_dir()
        .expect("Runtime directory not found")
        .join(FILE_TEST_IMAGE)
        .canonicalize()
        .expect("Test image not found");

    log::info!("Task package: {}", package_path.display());
    let package_file = fs::File::open(package_path.clone())
        .await
        .or_err("Error reading package file")?;
    let deployment = Deployment::try_from_input(package_file, 1, 125, package_path.clone())
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

struct ProcessOutputHandler {
    status_sender: mpsc::Sender<ProcessStatus>,
    handler: Box<dyn RuntimeHandler + 'static>,
}

impl RuntimeHandler for ProcessOutputHandler {
    fn on_process_status<'a>(&self, status: ProcessStatus) -> futures::future::BoxFuture<'a, ()> {
        if let Err(err) = self.status_sender.send(status.clone()) {
            log::warn!("Failed to send process status {err}");
        }
        self.handler.on_process_status(status)
    }

    fn on_runtime_status<'a>(&self, status: RuntimeStatus) -> futures::future::BoxFuture<'a, ()> {
        self.handler.on_runtime_status(status)
    }
}

/// Collects process `stdout` and tries to parse it into `serde_json::Value`.
///  # Arguments
/// * `status_receiver` of `ProcessStatus`
/// * `pid`
/// * `timeout` used to wait for `ProcessStatus`
async fn collect_process_response(
    status_receiver: &mut mpsc::Receiver<ProcessStatus>,
    pid: u64,
    timeout: Duration,
) -> anyhow::Result<Value> {
    log::debug!("Start listening on process: {pid}");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut return_code = 0;
    while let Ok(status) = status_receiver.recv_timeout(timeout) {
        if status.pid != pid {
            continue;
        }
        stdout.append(&mut status.stdout.clone());
        stderr.append(&mut status.stderr.clone());
        return_code = status.return_code;
        if !status.running {
            // Process stopped
            break;
        } else if status.return_code != 0 {
            // Process failed. Waiting for final message or timeout.
            continue;
        } else if let Ok(response) = serde_json::from_slice(&stdout) {
            // Succeed parsing response.
            return Ok(response);
        }
    }
    if return_code != 0 {
        bail!(String::from_utf8_lossy(&stderr).to_string())
    }
    match serde_json::from_slice(&stdout) {
        Ok(response) => Ok(response),
        Err(err) => {
            if !stderr.is_empty() {
                bail!(String::from_utf8_lossy(&stderr).to_string())
            } else {
                bail!(err)
            }
        }
    }
}
