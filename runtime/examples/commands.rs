use std::{
    clone::Clone,
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{process::Command, sync::Notify};
use ya_runtime_api::server::{self, ProcessStatus, RuntimeService};

struct ProcessData {
    status: Option<ProcessStatus>,
    died: Arc<Notify>,
}

impl ProcessData {
    fn new() -> Self {
        Self {
            status: None,
            died: Arc::new(Notify::new()),
        }
    }

    fn new_with_status(status: ProcessStatus) -> Self {
        Self {
            status: Some(status),
            died: Arc::new(Notify::new()),
        }
    }
}

struct Events(Arc<Mutex<HashMap<u64, ProcessData>>>);

impl Events {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn process_died(&self, pid: u64) -> Arc<Notify> {
        let mut processes = self.0.lock().unwrap();
        match processes.get(&pid) {
            None => {
                let data = ProcessData::new();
                let died = data.died.clone();
                processes.insert(pid, data);
                died
            }
            Some(data) => data.died.clone(),
        }
    }
}

impl server::RuntimeEvent for Events {
    fn on_process_status(&self, status: ProcessStatus) {
        log::debug!("event: {:?}", status);
        let mut processes = self.0.lock().unwrap();
        let process = processes.get_mut(&status.pid);
        match process {
            None => {
                processes.insert(status.pid, ProcessData::new_with_status(status));
            }
            Some(data) => {
                let was_running = match &data.status {
                    None => true,
                    Some(status) => status.running,
                };
                let died = was_running && !status.running;
                data.status.replace(status);
                if died {
                    data.died.notify();
                }
            }
        }
    }
}

impl Clone for Events {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut cmd = Command::new("cargo");
    cmd.env("RUST_LOG", "debug");
    cmd.arg("run")
        .arg("--package")
        .arg("ya-runtime-vm")
        .arg("--")
        .arg("--task-package")
        .arg(".")
        .arg("--workdir")
        .arg(".")
        .arg("start");

    let events = Events::new();

    let c = server::spawn(cmd, events.clone()).await?;

    {
        let result = c.hello("0.0.0x").await;
        log::info!("hello_result: {:?}", result);
    }

    {
        let run = server::RunProcess {
            bin: "/bin/ls".to_string(),
            args: vec!["ls", "-al", "."]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            work_dir: "/".to_string(),
            stdout: None,
            stderr: None,
        };
        log::info!("running {:?}", run);
        let pid = c
            .run_process(run)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?
            .pid;
        log::info!("pid: {}", pid);

        events.process_died(pid).notified().await;

        // TODO: get output
    }

    {
        let run = server::RunProcess {
            bin: "/bin/sleep".to_string(),
            args: vec!["10".to_string()],
            work_dir: "/".to_string(),
            stdout: None,
            stderr: None,
        };
        log::info!("running {:?}", run);
        let pid = c
            .run_process(run)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?
            .pid;
        log::info!("pid: {}", pid);

        c.kill_process(server::KillProcess {
            pid: pid,
            signal: 0, // TODO
        });
        events.process_died(pid).notified().await;
    }

    c.shutdown().await.map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(())
}
