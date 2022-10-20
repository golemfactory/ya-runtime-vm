use futures::lock::Mutex;
use std::{collections::HashMap, sync::Arc};
use tokio::io;
use tokio::sync;

use crate::demux_socket_comm::MAX_P9_PACKET_SIZE;
use crate::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use futures::future::FutureExt;
use std::convert::TryFrom;
use std::time::Duration;
use tokio::join;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;

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

async fn read_streams(
    is_finished: Arc<Mutex<i32>>,
    id: u64,
    ga: Arc<Mutex<GuestAgent>>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();

    let mut finishing = false;
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !finishing {
            let val = is_finished.lock().await;
            if *val == 1 {
                finishing = true;
            }
        }
        let mut ga = ga.lock().await;

        let stdout_read = match ga.query_output(id, 1, 0, u64::MAX).await? {
            Ok(out) => {
                //let s = String::from_utf8_lossy(&out);
                //log::info!("STDOUT {}:\n{}", id, s);
                //io::stdout().write_all(&out).await?;
                stdout.extend(out);
                true
            }
            Err(_code) => {
                false
                // log::info!("STDOUT empty") },
            }
        };

        let stderr_read = match ga.query_output(id, 2, 0, u64::MAX).await? {
            Ok(out) => {
                //let s = String::from_utf8_lossy(&out);
                //log::info!("STDERR {}:\n{}", id, s);
                //io::stdout().write_all(&out).await?;
                stderr.extend(out);
                true
            }
            Err(_code) => {
                //log::info!("STDERR empty")
                false
            }
        };

        if finishing && !stderr_read && !stdout_read {
            break;
        }
    }
    Ok((stdout, stderr))
}

pub struct LocalAgentCommunication {
    ln: Arc<LocalNotifications>,
    ga: Arc<Mutex<GuestAgent>>,
}

impl LocalAgentCommunication {
    pub fn get_ga(&self) -> Arc<Mutex<GuestAgent>> {
        self.ga.clone()
    }

    pub async fn run_bash_command(&self, cmd: &str) -> io::Result<()> {
        let argv = ["bash", "-c", &cmd];
        self.run_command("/bin/bash", &argv).await
    }

    pub async fn run_command(&self, bin: &str, argv: &[&str]) -> io::Result<()> {
        let id = {
            let mut ga = self.ga.lock().await;
            ga.run_process(
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
            .expect("Run process failed")
        };
        log::info!("Spawned process {} {:?} - id {}", bin, argv, id);
        let died = self.ln.get_process_died_notification(id).await;

        let _output = self.ln.get_output_available_notification(id).await;

        let common = Arc::new(Mutex::new(0));
        let future1 = read_streams(common.clone(), id, self.ga.clone());
        let common = common.clone();
        let future2 = async move {
            let _process_finished = died.notified().await;
            let mut val = common.lock().await;
            *val = 1;
        };
        let (res1, _res2) = join!(future1, future2);
        match res1 {
            Ok(r) => {
                let stdout = String::from_utf8_lossy(&r.0);
                let stderr = String::from_utf8_lossy(&r.1);

                log::info!("STDOUT {}:\n{}", id, stdout);
                log::info!("STDERR {}:\n{}", id, stderr);
            }
            Err(err) => {
                log::error!("COMMAND ENDED ERR: {} {:?}", id, err);
            }
        }

        Ok(())
    }

    pub async fn run_mount(&self, mount_args: &[ContainerVolume]) -> anyhow::Result<()> {
        let mut guest_agent = self.ga.lock().await;

        for ContainerVolume { name, path } in mount_args.iter() {
            let max_p9_packet_size = u32::try_from(MAX_P9_PACKET_SIZE).unwrap();

            if let Err(e) = guest_agent.mount(name, max_p9_packet_size, path).await? {
                log::error!("Mount failed at {name}, {path}, {e}")
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
