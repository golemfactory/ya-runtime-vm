use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures::lock::Mutex;
use futures::FutureExt;
use mesh::rpc::RpcSend;
use mesh_worker::{launch_local_worker, WorkerHandle};
use openvmm_core::VmWorker;
use openvmm_defs::rpc::VmRpc;
use openvmm_defs::worker::VmWorkerParameters;
use tokio::spawn;
use vm_resource::IntoResource;

use ya_runtime_sdk::runtime_api::server;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::{serialize, ErrorExt, EventEmitter};

use crate::deploy::Deployment;
use crate::guest_agent_comm::{GuestAgent, Notification};

const DIR_RUNTIME: &str = "runtime";

#[derive(Default)]
pub struct RuntimeData {
    pub runtime: Option<WorkerHandle>,
    pub vm_rpc: Option<mesh::Sender<VmRpc>>,
    pub vpn: Option<ContainerEndpoint>,
    pub inet: Option<ContainerEndpoint>,
    pub deployment: Option<Deployment>,
    pub ga: Option<Arc<Mutex<GuestAgent>>>,
    pub pci_device_id: Option<Vec<String>>,
}

impl RuntimeData {
    pub fn runtime(&mut self) -> anyhow::Result<WorkerHandle> {
        self.runtime
            .take()
            .ok_or_else(|| anyhow::anyhow!("OpenVMM worker not available"))
    }

    pub fn deployment(&self) -> anyhow::Result<&Deployment> {
        self.deployment
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Runtime not deployed"))
    }

    pub fn ga(&self) -> anyhow::Result<Arc<Mutex<GuestAgent>>> {
        self.ga
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Runtime not started"))
    }
}

pub async fn start_vmrt(
    work_dir: PathBuf,
    runtime_data: Arc<Mutex<RuntimeData>>,
    emitter: EventEmitter,
) -> anyhow::Result<Option<serialize::json::Value>> {
    let runtime_dir = runtime_dir().or_err("Unable to resolve current directory")?;
    let temp_dir = std::env::temp_dir();
    let uid = uuid::Uuid::new_v4().simple().to_string();

    let mut data = runtime_data.lock().await;
    let deployment = data.deployment.clone().or_err("Missing deployment data")?;

    let manager_sock = temp_dir.join(format!("{}.sock", uid));
    let listener = unix_socket::UnixListener::bind(&manager_sock)
        .with_context(|| format!("binding guest agent socket {}", manager_sock.display()))?;
    let _manager_sock_cleanup = SocketPathCleanup(manager_sock.clone());
    let (cfg, vpn_endpoint, inet_endpoint, _socket_registrations) =
        crate::openvmm_adapter::build_config(
            &runtime_dir,
            &work_dir,
            &deployment,
            listener,
            data.vpn.as_ref(),
            data.inet.as_ref(),
            data.pci_device_id.as_deref().unwrap_or_default(),
        )?;
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .context("opening /dev/kvm for OpenVMM")?;
    let (vm_rpc, rpc_recv) = mesh::channel();
    let (notify_send, mut notify_recv) = mesh::channel();
    let params = VmWorkerParameters {
        hypervisor: hypervisor_resources::KvmHandle { kvm }.into_resource(),
        cfg,
        saved_state: None,
        shared_memory: None,
        rpc: rpc_recv,
        notify: notify_send,
    };
    let mut runtime = launch_local_worker::<VmWorker>(params)
        .await
        .context("launching embedded OpenVMM worker")?;
    if let Err(error) = vm_rpc.call(VmRpc::Resume, ()).await {
        runtime.stop();
        if let Err(stop_error) = runtime.join().await {
            log::error!("OpenVMM worker also failed while handling resume failure: {stop_error:#}");
        }
        return Err(error).context("resuming OpenVMM guest");
    }

    let ga_result = async {
        log::info!("Waiting for guest agent connection");
        let ga = GuestAgent::connected(manager_sock, 10, move |notification, ga| {
            let mut emitter = emitter.clone();
            async move {
                if let Some(status) = notification_into_status(notification, ga).await {
                    emitter.emit(status).await;
                }
            }
            .boxed()
        })
        .await?;
        log::info!("Guest agent connected");

        {
            let mut ga = ga.lock().await;
            for (idx, volume) in deployment.volumes.iter().enumerate() {
                log::info!("Mounting guest volume {} at {}", idx, volume.path);
                ga.mount(format!("mnt{}", idx).as_str(), volume.path.as_str())
                    .await?
                    .map_err(|error| {
                        anyhow::anyhow!("Guest failed to mount volume {}: {error:?}", volume.path)
                    })?;
                log::info!("Guest volume {} mounted", idx);
            }
        }
        anyhow::Ok(ga)
    }
    .await;
    let ga = match ga_result {
        Ok(ga) => ga,
        Err(error) => {
            runtime.stop();
            if let Err(stop_error) = runtime.join().await {
                log::error!("OpenVMM worker also failed while cleaning up startup: {stop_error:#}");
            }
            return Err(error);
        }
    };

    if let Some(endpoint) = vpn_endpoint {
        data.vpn.replace(endpoint);
    }
    if let Some(endpoint) = inet_endpoint {
        data.inet.replace(endpoint);
    }
    data.runtime.replace(runtime);
    data.vm_rpc.replace(vm_rpc);
    data.ga.replace(ga);

    let runtime_data_for_halt = runtime_data.clone();
    spawn(async move {
        match notify_recv.recv().await {
            Ok(reason) => {
                log::warn!("OpenVMM guest halted: {reason:?}");
                let mut worker = runtime_data_for_halt.lock().await.runtime.take();
                if let Some(mut worker) = worker.take() {
                    worker.stop();
                    if let Err(error) = worker.join().await {
                        log::error!("OpenVMM worker failed while stopping: {error:#}");
                    }
                }
            }
            Err(error) => log::debug!("OpenVMM halt channel closed: {error}"),
        }
    });

    Ok(None)
}

struct SocketPathCleanup(PathBuf);

impl Drop for SocketPathCleanup {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            if error.kind() != io::ErrorKind::NotFound {
                log::warn!(
                    "failed to remove guest agent socket {}: {error}",
                    self.0.display()
                );
            }
        }
    }
}

pub fn runtime_dir() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_path_buf()
        .join(DIR_RUNTIME))
}

async fn notification_into_status(
    notification: Notification,
    ga: Arc<Mutex<GuestAgent>>,
) -> Option<server::ProcessStatus> {
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

            Some(server::ProcessStatus {
                pid: id,
                running: true,
                return_code: 0,
                stdout,
                stderr,
            })
        }
        Notification::ProcessDied { id, reason } => {
            log::debug!("Process {} died with {:?}", id, reason);

            // TODO: reason._type ?
            Some(server::ProcessStatus {
                pid: id,
                running: false,
                return_code: reason.status as i32,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        Notification::SerialProbe { port } => {
            log::info!("Guest serial probe reached host through port {port}");
            None
        }
    }
}
