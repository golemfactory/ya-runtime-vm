use futures::future::BoxFuture;
use futures::FutureExt;
use std::{
    clone::Clone,
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{sync::Notify};
use ya_runtime_sdk::runtime_api::server::{self, ProcessStatus, RuntimeStatus};

pub struct ProcessDataLocal {
    status: Option<ProcessStatus>,
    died: Arc<Notify>,
}

impl ProcessDataLocal {
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

pub struct EventsLocal(Arc<Mutex<HashMap<u64, ProcessDataLocal>>>);

impl EventsLocal {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn process_died(&self, pid: u64) -> Arc<Notify> {
        let mut processes = self.0.lock().unwrap();
        match processes.get(&pid) {
            None => {
                let data = ProcessDataLocal::new();
                let died = data.died.clone();
                processes.insert(pid, data);
                died
            }
            Some(data) => data.died.clone(),
        }
    }
}

impl server::RuntimeHandler for EventsLocal {
    fn on_process_status<'a>(&self, status: ProcessStatus) -> BoxFuture<'a, ()> {
        log::debug!("event: {:?}", status);
        let mut processes = self.0.lock().unwrap();
        let process = processes.get_mut(&status.pid);
        match process {
            None => {
                processes.insert(status.pid, ProcessDataLocal::new_with_status(status));
            }
            Some(data) => {
                let was_running = match &data.status {
                    None => true,
                    Some(status) => status.running,
                };
                let died = was_running && !status.running;
                data.status.replace(status);
                if died {
                    data.died.notify_one();
                }
            }
        }

        futures::future::ready(()).boxed()
    }

    fn on_runtime_status<'a>(&self, _status: RuntimeStatus) -> BoxFuture<'a, ()> {
        futures::future::ready(()).boxed()
    }
}

impl Clone for EventsLocal {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
