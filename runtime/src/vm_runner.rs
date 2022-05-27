use crate::demux_socket_comm::{start_demux_communication, DemuxSocketHandle, MAX_P9_PACKET_SIZE};
use crate::vm::VM;
use anyhow::anyhow;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc};
use std::time::Duration;
use tokio::process::Child;
use tokio::{
    io::{self, AsyncBufReadExt},
    spawn,
};
use tokio::{net::TcpStream, time::sleep};
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;
use ya_vm_file_server::InprocServer;
use crate::guest_agent_comm::{GuestAgent, Notification};
use futures::lock::Mutex;
use futures::future::FutureExt;

use ya_runtime_sdk::{
    runtime_api::{
        server,
    }, EventEmitter,
};
use crate::local_notification_handler::LocalNotifications;

pub struct VMRunner {
    instance: Option<Child>,
    vm: VM,
    ga: Option<Arc<Mutex<GuestAgent>>>
}

pub enum ReaderOutputType {
    StdOutput,
    StdError,
}

impl VMRunner {
    pub fn new(vm: VM) -> Self {
        return VMRunner { instance: None, vm, ga: None };
    }

    pub fn get_vm(&self) -> &VM {
        return &self.vm;
    }

    pub fn get_ga(&self) -> Arc<Mutex<GuestAgent>> {
        self.ga.clone().unwrap()
    }

    pub async fn run_vm(&mut self, runtime_dir: PathBuf) -> anyhow::Result<()> {
        #[cfg(windows)]
        let vm_executable = "vmrt.exe";
        #[cfg(unix)]
        let vm_executable = "vmrt";

        let mut cmd = self.vm.get_cmd(&runtime_dir.join(vm_executable));
        cmd.current_dir(runtime_dir);
        let mut instance = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = instance.stdout.take().ok_or(anyhow!("stdout take error"))?;
        let stderr = instance.stderr.take().ok_or(anyhow!("stdout take error"))?;
        spawn(VMRunner::reader_to_log(stdout, ReaderOutputType::StdOutput));
        spawn(VMRunner::reader_to_log(stderr, ReaderOutputType::StdError));

        self.instance = Some(instance);



        Ok(())
    }

    pub async fn start_guest_agent_communication(&mut self, eventEmmitter: EventEmitter) -> anyhow::Result<()> {
        let ga = GuestAgent::connected(
            self.vm.get_manager_sock(),
            10,
            move |notification, ga| {
                let mut emitter = eventEmmitter.clone();
                async move {
                    let status = VMRunner::notification_into_status(notification, ga).await;
                    emitter.emit(status).await;
                }.boxed()
            },
        ).await?;
        self.ga = Some(ga);
        Ok(())
    }

    pub async fn start_local_agent_communication(&mut self, notifications: Arc<LocalNotifications>) -> anyhow::Result<()> {
        let ga = GuestAgent::connected(self.vm.get_manager_sock(), 10, move |n, _g| {
            let notifications = notifications.clone();
            async move { notifications.clone().handle(n).await }.boxed()
        }).await?;
        self.ga = Some(ga);
        Ok(())
    }

    async fn connect_to_9p_endpoint(&self, tries: usize) -> anyhow::Result<TcpStream> {
        log::debug!("Connect to the 9P VM endpoint...");

        for _ in 0..tries {
            match TcpStream::connect(self.vm.get_9p_sock()).await {
                Ok(stream) => {
                    log::debug!("Connected to the 9P VM endpoint");
                    return Ok(stream);
                }
                Err(e) => {
                    log::debug!("Failed to connect to 9P VM endpoint: {e}");
                    // The VM is not ready yet, try again
                    sleep(Duration::from_secs(1)).await;
                }
            };
        }

        Err(anyhow!(
            "Failed to connect to the 9P VM endpoint after #{tries} tries"
        ))
    }

    /// Spawns tasks handling 9p communication for given mount points
    pub async fn start_9p_service(
        &self,
        work_dir: &Path,
        volumes: &[ContainerVolume],
    ) -> anyhow::Result<(Vec<InprocServer>, DemuxSocketHandle)> {
        log::debug!("Connecting to the 9P VM endpoint...");

        let vmp9stream = self.connect_to_9p_endpoint(10).await?;

        log::debug!("Spawn 9P inproc servers...");

        let mut runtime_9ps = vec![];

        for volume in volumes.iter() {
            let mount_point_host = work_dir
                .join(&volume.name)
                .to_str()
                .ok_or(anyhow!("cannot resolve 9P mount point"))?
                .to_string();

            log::debug!("Creating inproc 9p server with mount point {mount_point_host}");
            let runtime_9p = InprocServer::new(&mount_point_host);

            runtime_9ps.push(runtime_9p);
        }

        log::debug!("Connect to 9P inproc servers...");

        let mut p9streams = vec![];

        for server in &runtime_9ps {
            let client_stream = server.attach_client(MAX_P9_PACKET_SIZE);
            p9streams.push(client_stream);
        }

        let demux_socket_handle = start_demux_communication(vmp9stream, p9streams)?;

        // start_demux_communication(vm_stream, p9_streams);
        Ok((runtime_9ps, demux_socket_handle))
    }

    pub async fn stop_vm(
        &mut self,
        timeout: &Duration,
        kill_on_timeout: bool,
    ) -> anyhow::Result<()> {
        if let Some(instance) = self.instance.as_mut() {
            let stopped = tokio::select! {
                _ = tokio::time::sleep(*timeout) => {
                    log::warn!("Waiting for VM timed out");
                    if !kill_on_timeout {
                        return Err(anyhow!("Waiting for VM timed out"))
                    }
                    false
                }
                _ = instance.wait() => {
                    log::info!("VM closed successfully");
                    true
                }
            };
            if !stopped && kill_on_timeout {
                instance.start_kill()?;
                tokio::select! {
                    _ = tokio::time::sleep(*timeout) => {
                        log::error!("Cannot kill VM");
                        return Err(anyhow!("Cannot kill VM due to unknown reason"))
                    }
                    _ = instance.wait() => {
                        log::info!("VM killed successfully");
                        true
                    }
                };
            }
        };
        Ok(())
    }

    async fn reader_to_log<T: io::AsyncRead + Unpin>(reader: T, stream_type: ReaderOutputType) {
        let mut reader = io::BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => {
                    log::warn!("VM: reader.read_until returned 0");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(_) => {
                    let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                    match stream_type {
                        ReaderOutputType::StdOutput => {
                            log::debug!("VM: {}", String::from_utf8_lossy(&bytes).trim_end());
                        }
                        ReaderOutputType::StdError => {
                            log::debug!(
                                "VM Error Stream: {}",
                                String::from_utf8_lossy(&bytes).trim_end()
                            );
                        }
                    }
                    buf.clear();
                }
                Err(e) => log::error!("VM output error: {}", e),
            }
        }
    }

    async fn notification_into_status(
        notification: Notification,
        ga: Arc<Mutex<GuestAgent>>,
    ) -> server::ProcessStatus {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);

                let output = {
                    let result = {
                        let mut guard = ga.lock().await;
                        guard.query_output(id, fd as u8, 0, u64::MAX).await
                    };
                    match result {
                        Ok(Ok(vec)) => vec,
                        Ok(Err(e)) => {
                            log::error!("Remote error while querying output: {:?}", e);
                            Vec::new()
                        }
                        Err(e) => {
                            log::error!("Error querying output: {:?}", e);
                            Vec::new()
                        }
                    }
                };
                let (stdout, stderr) = match fd {
                    1 => (output, Vec::new()),
                    _ => (Vec::new(), output),
                };

                server::ProcessStatus {
                    pid: id,
                    running: true,
                    return_code: 0,
                    stdout,
                    stderr,
                }
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);

                // TODO: reason._type ?
                server::ProcessStatus {
                    pid: id,
                    running: false,
                    return_code: reason.status as i32,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
        }
    }
}
