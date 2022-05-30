use futures::lock::Mutex;
use tokio::io;
use std::{collections::HashMap, sync::Arc};
use tokio::sync;

use crate::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use futures::future::FutureExt;

pub struct LocalNotifications {
    process_died: Mutex<HashMap<u64, Arc<sync::Notify>>>,
    output_available: Mutex<HashMap<u64, Arc<sync::Notify>>>,
}

impl LocalNotifications {
    pub fn new() -> Self {
        LocalNotifications {
            process_died: Mutex::new(HashMap::new()),
            output_available: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get_process_died_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.process_died.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    pub async fn get_output_available_notification(&self, id: u64) -> Arc<sync::Notify> {
        let notif = {
            let mut lock = self.output_available.lock().await;
            lock.entry(id)
                .or_insert(Arc::new(sync::Notify::new()))
                .clone()
        };

        notif
    }

    pub async fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                let _ = fd;
                //log::debug!("Process {} has output available on fd {}", id, fd);

                self.get_output_available_notification(id)
                    .await
                    .notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                let _ = reason;
                //log::debug!("Process {} died with {:?}", id, reason);
                self.get_process_died_notification(id).await.notify_one();
            }
        }
    }
}

pub struct LocalAgentCommunication {
    ln: Arc<LocalNotifications>,
    ga: Arc<Mutex<GuestAgent>>,
}

impl LocalAgentCommunication {
    pub fn get_ga(&self) -> Arc<Mutex<GuestAgent>> {
        self.ga.clone()
    }

    pub async fn run_command(&self, bin: &str, argv: &[&str]) -> io::Result<()> {
        let mut ga = self.ga.lock().await;
        let id = ga
            .run_process(
                bin,
                argv,
                None,
                0,
                0,
                &[
                    None,
                    Some(RedirectFdType::RedirectFdPipeBlocking(0x10000)),
                    Some(RedirectFdType::RedirectFdPipeBlocking(0x10000)),
                ],
                None,
            )
            .await?
            .expect("Run process failed");

        log::info!("Spawned process {} {:?} - id {}", bin, argv, id);
        let died = self.ln.get_process_died_notification(id).await;

        let output = self.ln.get_output_available_notification(id).await;

        loop {
            tokio::select! {
                _ = died.notified() => {
                    log::debug!("Process {id} terminated");
                    break;
                },
                _ = output.notified() => {
                    match ga.query_output(id, 1, 0, u64::MAX).await? {
                        Ok(out) => {
                            let s = String::from_utf8_lossy(&out);
                            log::info!("STDOUT {}:\n{}", id, s);
                            //io::stdout().write_all(&out).await?;
                        }
                        Err(_code) => log::info!("STDOUT empty"),
                    }

                    match ga.query_output(id, 2, 0, u64::MAX).await? {
                        Ok(out) => {
                            let s = String::from_utf8_lossy(&out);
                            log::info!("STDERR {}:\n{}", id, s);
                            //io::stdout().write_all(&out).await?;
                        }
                        Err(_code) => log::info!("STDERR empty"),
                    }
                 }
            }
        }

        Ok(())
    }
}
pub async fn start_local_agent_communication(
    manager_sock: &str,
) -> anyhow::Result<Arc<LocalAgentCommunication>> {
    let ln = Arc::new(LocalNotifications::new());
    let ln2 = ln.clone();
    let ga = GuestAgent::connected(manager_sock, 10, move |n, _g| {
        let notifications = ln2.clone();
        async move { notifications.clone().handle(n).await }.boxed()
    })
    .await?;
    Ok(Arc::new(LocalAgentCommunication { ln, ga }))
}
