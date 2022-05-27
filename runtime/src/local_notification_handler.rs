use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::{self, Mutex};
use crate::{
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType},
    vm::VMBuilder,
};

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
                log::debug!("Process {} has output available on fd {}", id, fd);

                self.get_output_available_notification(id)
                    .await
                    .notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.get_process_died_notification(id).await.notify_one();
            }
        }
    }
}

pub async fn run_process_with_output(
    ga: &mut GuestAgent,
    notifications: &LocalNotifications,
    bin: &str,
    argv: &[&str],
) -> io::Result<()> {
    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
            ],
            None,
        )
        .await?
        .expect("Run process failed");

    log::info!("Spawned process with id: {}", id);
    let died = notifications.get_process_died_notification(id).await;

    let output = notifications.get_output_available_notification(id).await;

    loop {
        tokio::select! {
            _ = died.notified() => {
                log::info!("Process {id} died");
                break;
            },
            _ = output.notified() => {
                match ga.query_output(id, 1, 0, u64::MAX).await? {
                    Ok(out) => {
                        log::info!("STDOUT Output {argv:?}:");
                        io::stdout().write_all(&out).await?;
                    }
                    Err(code) => log::info!("{argv:?} no data on STDOUT, reason {code}"),
                }

                match ga.query_output(id, 2, 0, u64::MAX).await? {
                    Ok(out) => {
                        log::error!("STDERR Output {argv:?}:");
                        io::stdout().write_all(&out).await?;
                    }
                    Err(code) => log::info!("{argv:?} no data on STDERR, reason {code}"),
                }
             }
        }
    }

    Ok(())
}
