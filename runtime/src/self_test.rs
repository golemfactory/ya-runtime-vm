use futures::lock::Mutex;
use serde_json::Value;
use std::sync::{mpsc, Arc};
use tokio::fs;
use ya_runtime_sdk::runtime_api::server::RuntimeHandler;
use ya_runtime_sdk::{runtime_api::server, server::Server, Context, ErrorExt, EventEmitter};
use ya_runtime_sdk::{ProcessStatus, RuntimeStatus};

use crate::deploy::Deployment;
use crate::vmrt::{runtime_dir, RuntimeData};
use crate::Runtime;

const FILE_TEST_IMAGE: &'static str = "self-test.gvmi";

pub(crate) async fn test() -> anyhow::Result<()> {
    let work_dir = std::env::temp_dir();

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
    let runtime_data = RuntimeData {
        deployment: Some(deployment),
        ..Default::default()
    };
    let runtime = Runtime {
        data: Arc::new(Mutex::new(runtime_data)),
    };

    let mut status: Option<ProcessStatus> = None;
    server::run_async(|e| async {
        let ctx = Context::try_new().expect("Failed to initialize context");

        log::info!("Starting");
        let (status_sender, mut status_receiver) = mpsc::channel();
        let emitter = EventEmitter::spawn(ProcessOutputHandler {
            handler: Box::new(e),
            status_sender,
        });
        let start_response = crate::start(work_dir.clone(), runtime.data.clone(), emitter.clone())
            .await
            .expect("Failed to start runtime");
        log::info!("Response {:?}", start_response);

        let run: ya_runtime_sdk::RunProcess = server::RunProcess {
            bin: "/ya-self-test".into(),
            args: vec!["ya-self-test".into()],
            work_dir: "/data".into(),
            ..Default::default()
        };

        log::debug!("Starting. Runtime: {:?}", runtime.data);
        log::debug!("Run: {run:?}");

        let pid = crate::run_command(runtime.data.clone(), run)
            .await
            .expect("Can run command");

        let (final_status_sender, final_status_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let status = async {
                listen_process_status(&mut status_receiver, pid).expect("Can listen on process")
            }
            .await;
            final_status_sender.send(status)
        });
        status = Some(final_status_receiver.await.expect("Got status"));
        log::info!("Process finished: {status:?}");

        log::info!("Stopping runtime");
        crate::stop(runtime.data.clone())
            .await
            .expect("Failed to stop runtime");

        tokio::spawn(async move {
            // the server refuses to stop by itself; force quit
            std::process::exit(0);
        });

        let status = status.expect("Failed to run self test process");
        if status.return_code == 0 {
            let response: Value = serde_json::from_slice(&status.stdout)
                .expect("Cannot serialize self test stdout to json.");
            println!("{}", response.to_string())
        } else {
            let err_message = std::str::from_utf8(&status.stderr)
                .expect("Can read stderr as string.")
                .to_string();
            eprintln!("self test process failed: {err_message}");
        }

        Server::new(runtime, ctx)
    })
    .await;
    Ok(())
}

struct ProcessOutputHandler {
    status_sender: mpsc::Sender<ProcessStatus>,
    handler: Box<dyn RuntimeHandler + 'static>,
}

impl RuntimeHandler for ProcessOutputHandler {
    fn on_process_status<'a>(&self, status: ProcessStatus) -> futures::future::BoxFuture<'a, ()> {
        if let Err(err) = self.status_sender.send(status.clone()) {
            log::error!("Failed to send process status {err}");
        }
        self.handler.on_process_status(status)
    }

    fn on_runtime_status<'a>(&self, status: RuntimeStatus) -> futures::future::BoxFuture<'a, ()> {
        self.handler.on_runtime_status(status)
    }
}

fn listen_process_status(
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
    let running = false;
    Ok(ProcessStatus {
        pid,
        running,
        return_code,
        stdout,
        stderr,
    })
}
