use anyhow::bail;
use futures::lock::Mutex;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use tokio::fs;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{runtime_api::server, server::Server, Context, ErrorExt, EventEmitter};
use ya_runtime_sdk::{Error, ProcessStatus, RuntimeStatus};

use crate::deploy::Deployment;
use crate::vmrt::{runtime_dir, RuntimeData};
use crate::Runtime;

const FILE_TEST_IMAGE: &'static str = "self-test.gvmi";

pub(crate) async fn test() -> Result<(), Error> {
    run_self_test(verify_status).await;
    // Dead code. ya_runtime_api::server::run_async requires killing a process to stop
    Ok(())
}

pub(crate) fn verify_status(status: anyhow::Result<ProcessStatus>) -> anyhow::Result<String> {
    let Ok(status) = status else {
        bail!("Failed to get self test status: {err}");
    };
    if status.return_code == 0 {
        return Ok(String::from_utf8(status.stdout)?);
    }
    match String::from_utf8(status.stderr) {
        Ok(stderr) => anyhow::bail!(
            "Process failed, code: {}, stderr: {stderr}",
            status.return_code
        ),
        Err(err) => {
            anyhow::bail!(
                "Process failed, code: {}. Failed to parse err output: {err}",
                status.return_code
            )
        }
    }
}

pub(crate) async fn run_self_test<HANDLER>(handle_result: HANDLER)
where
    HANDLER: Fn(anyhow::Result<ProcessStatus>) -> anyhow::Result<String>,
{
    let work_dir = std::env::temp_dir();

    let deployment = self_test_deployment(&work_dir)
        .await
        .expect("Prepares self test img deployment");

    let runtime_data = RuntimeData {
        deployment: Some(deployment),
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
            let status = collect_process_status(&mut status_receiver, pid).await;
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

async fn self_test_deployment(work_dir: &PathBuf) -> anyhow::Result<Deployment> {
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

async fn collect_process_status(
    status_receiver: &mut mpsc::Receiver<ProcessStatus>,
    pid: u64,
) -> anyhow::Result<ProcessStatus> {
    log::debug!("Start listening on process: {pid}");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut return_code = 0;
    while let Ok(status) = status_receiver.recv() {
        if status.pid != pid {
            continue;
        }
        stdout.append(&mut status.stdout.clone());
        stderr.append(&mut status.stderr.clone());
        return_code = status.return_code;
        if !status.running {
            break;
        }
    }
    Ok(ProcessStatus {
        pid,
        running: false,
        return_code,
        stdout,
        stderr,
    })
}
