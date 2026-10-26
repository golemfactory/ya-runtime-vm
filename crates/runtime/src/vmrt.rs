use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures::FutureExt;
use futures::lock::Mutex;
use mesh::rpc::RpcSend;
use mesh_worker::{WorkerHandle, launch_local_worker};
use openvmm_core::VmWorker;
use openvmm_defs::rpc::VmRpc;
use openvmm_defs::worker::VmWorkerParameters;
use tokio::spawn;
use vmm_core_defs::HaltReason;

use ya_runtime_sdk::runtime_api::server;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::{ErrorExt, EventEmitter, serialize};

use crate::deploy::Deployment;
use crate::guest_agent_comm::{GuestAgent, Notification};

const DIR_RUNTIME: &str = "runtime";
const GUEST_AGENT_VSOCK_PORT: u32 = ya_vm_agent_protocol::VSOCK_PORT;

fn guest_halt_error(reason: &HaltReason) -> anyhow::Error {
    let mut message = format!(
        "OpenVMM guest halted: {reason:?}. See preceding OpenVMM errors for the underlying cause."
    );
    if cfg!(target_os = "linux") && matches!(reason, HaltReason::SingleStep { .. }) {
        // Upstream also reports fatal VMM errors as SingleStep. This is a
        // diagnostic hint, not proof of a competing hypervisor.
        message.push_str(" On Linux, inspect journalctl -k. If KVM reports 'vmread failed' or 'vmwrite failed', another native hypervisor such as VirtualBox may be interfering. Safely shut down its VMs and retry; do not force-kill running VMs or unload their modules.");
    }
    // Keep the hint and reason in one message: the SDK preserves Display but
    // does not retain anyhow's chain when serializing an error response.
    anyhow::anyhow!(message)
}

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

    // Guest-initiated connections to host port P are relayed by OpenVMM to
    // <base_path>_P. The backend runs in this process, without vhost-vsock.
    let vsock_base = temp_dir.join(format!("{}.sock", uid));
    let relay_listener = unix_socket::UnixListener::bind(&vsock_base)
        .context("binding embedded virtio-vsock relay")?;
    let _relay_sock_cleanup = SocketPathCleanup(vsock_base.clone());
    let manager_sock = temp_dir.join(format!("{}.sock_{}", uid, GUEST_AGENT_VSOCK_PORT));
    let mut manager_listener = crate::local_socket::LocalListener::bind(&manager_sock)
        .with_context(|| format!("binding guest agent socket {}", manager_sock.display()))?;
    let _manager_sock_cleanup = SocketPathCleanup(manager_sock.clone());
    let manager_vsock = virtio_resources::vsock::VirtioVsockHandle {
        guest_cid: 3,
        base_path: vsock_base.to_string_lossy().into_owned(),
        listener: relay_listener,
    };
    let (cfg, vpn_endpoint, inet_endpoint, _socket_registrations) =
        crate::openvmm_adapter::build_config(
            &runtime_dir,
            &work_dir,
            &deployment,
            manager_vsock,
            data.vpn.as_ref(),
            data.inet.as_ref(),
            data.pci_device_id.as_deref().unwrap_or_default(),
        )?;
    let (vm_rpc, rpc_recv) = mesh::channel();
    let (notify_send, mut notify_recv) = mesh::channel();
    let params = VmWorkerParameters {
        hypervisor: crate::host_platform::hypervisor()?,
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
        log::info!("Waiting for guest agent over virtio-vsock port {GUEST_AGENT_VSOCK_PORT}");
        let manager_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                tokio::select! {
                    stream = manager_listener.accept() => stream.context("accepting guest agent virtio-vsock connection"),
                    halt = notify_recv.recv() => match halt {
                        Ok(reason) => Err(guest_halt_error(&reason)),
                        Err(error) => Err(error).context("OpenVMM halt channel closed during startup"),
                    },
                }
            },
        )
        .await
        .context("guest agent virtio-vsock connection timed out")??;
        let ga = GuestAgent::from_stream(manager_stream, 10, move |notification, ga| {
            let emitter = emitter.clone();
            async move { deliver_notification(notification, ga, emitter).await }.boxed()
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
            let mut state = inspect::inspect("partition/vp", &runtime);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), state.resolve()).await;
            log::debug!("OpenVMM startup failure state: {}", state.results());
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
                match reason {
                    HaltReason::PowerOff | HaltReason::Reset | HaltReason::Hibernate => {
                        log::info!("OpenVMM guest halted: {reason:?}");
                    }
                    _ => log::error!("{}", guest_halt_error(&reason)),
                }
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
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            log::warn!(
                "failed to remove guest agent socket {}: {error}",
                self.0.display()
            );
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

/// Forwards guest events to the client in order, on a single task.
///
/// The guest reports an exit only after the output the process wrote has been
/// queried, so earlier events already carried it. The host still drains both
/// streams before the terminal status, so no byte can follow it. ExitAck is
/// sent last; for the entrypoint it lets the guest power off. Emitted statuses
/// are queued in order in the SDK, which writes them to the client even after
/// the VM has stopped.
async fn deliver_notification(
    notification: Notification,
    ga: Arc<Mutex<GuestAgent>>,
    mut emitter: EventEmitter,
) {
    let exited = match &notification {
        Notification::ProcessDied { id, .. } => Some(*id),
        _ => None,
    };
    if let Some(id) = exited {
        for fd in [1, 2] {
            loop {
                let output = query_output(&ga, id, fd).await;
                if output.is_empty() {
                    break;
                }
                emitter.emit(output_status(id, fd, output)).await;
            }
        }
    }
    if let Some(status) = notification_into_status(notification, ga.clone()).await {
        emitter.emit(status).await;
    }
    if let Some(id) = exited
        && let Err(error) = ga.lock().await.acknowledge_exit(id).await
    {
        log::debug!("Unable to acknowledge guest exit {id}: {error}");
    }
}

async fn query_output(ga: &Arc<Mutex<GuestAgent>>, id: u64, fd: u32) -> Vec<u8> {
    let result = ga
        .lock()
        .await
        .query_output(id, fd as u8, 0, u64::MAX)
        .await;
    match result {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            log::error!("Remote error while querying output: {:?}", e);
            Vec::new()
        }
        Err(e) => {
            log::error!("Error querying output: {:?}", e);
            Vec::new()
        }
    }
}

fn output_status(id: u64, fd: u32, output: Vec<u8>) -> server::ProcessStatus {
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

async fn notification_into_status(
    notification: Notification,
    ga: Arc<Mutex<GuestAgent>>,
) -> Option<server::ProcessStatus> {
    match notification {
        Notification::OutputAvailable { id, fd } => {
            log::debug!("Process {} has output available on fd {}", id, fd);
            Some(output_status(id, fd, query_output(&ga, id, fd).await))
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_halt_keeps_reason_and_conditional_recovery_hint() {
        let error = guest_halt_error(&HaltReason::SingleStep { vp: 2 }).to_string();
        assert!(error.contains("SingleStep { vp: 2 }"));
        assert!(error.contains("underlying cause"));
        assert_eq!(error.contains("journalctl -k"), cfg!(target_os = "linux"));
        assert!(
            !guest_halt_error(&HaltReason::PowerOff)
                .to_string()
                .contains("VirtualBox")
        );
    }
    use crate::{
        guest_agent_comm::{read_message, write_message},
        local_socket::LocalStream,
    };
    use ya_vm_agent_protocol::{
        Command, Event, ExitReason, ExitType, Message, OUTPUT_CHUNK, VERSION, Value,
    };

    struct Observe(tokio::sync::mpsc::UnboundedSender<server::ProcessStatus>);
    impl server::RuntimeHandler for Observe {
        fn on_process_status<'a>(
            &self,
            status: server::ProcessStatus,
        ) -> futures::future::BoxFuture<'a, ()> {
            let sender = self.0.clone();
            async move {
                tokio::task::yield_now().await;
                let _ = sender.send(status);
            }
            .boxed()
        }
        fn on_runtime_status<'a>(
            &self,
            _: server::RuntimeStatus,
        ) -> futures::future::BoxFuture<'a, ()> {
            async {}.boxed()
        }
    }
    #[tokio::test]
    async fn output_reaches_the_client_before_exit_even_with_early_wire_notification() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (host, mut guest) = LocalStream::pair().unwrap();
                write_message(&mut guest, &Message::Ready { version: VERSION })
                    .await
                    .unwrap();
                let (sender, mut statuses) = tokio::sync::mpsc::unbounded_channel();
                let emitter = EventEmitter::spawn(Observe(sender));
                let _agent = GuestAgent::from_stream(host, 2, move |event, agent| {
                    let emitter = emitter.clone();
                    async move { deliver_notification(event, agent, emitter).await }.boxed()
                })
                .await
                .unwrap();
                // Queue a terminal notification before answering any output query.
                // It must never overtake pending queries or the SDK emitter queue.
                for fd in [1, 2, 1, 2] {
                    write_message(
                        &mut guest,
                        &Message::Event(Event::OutputAvailable { id: 9, fd }),
                    )
                    .await
                    .unwrap();
                }
                write_message(
                    &mut guest,
                    &Message::Event(Event::ProcessDied {
                        id: 9,
                        reason: ExitReason {
                            status: 37,
                            type_: ExitType::Exited,
                        },
                    }),
                )
                .await
                .unwrap();
                let responder = tokio::spawn(async move {
                    // Four notified chunks, then the host's drain after the
                    // exit: a late stdout tail, then empty stdout and stderr.
                    for (expected, len) in [
                        (1, OUTPUT_CHUNK),
                        (2, OUTPUT_CHUNK),
                        (1, OUTPUT_CHUNK),
                        (2, OUTPUT_CHUNK),
                        (1, 7),
                        (1, 0),
                        (2, 0),
                    ] {
                        let Message::Request {
                            id,
                            command: Command::QueryOutput { fd, .. },
                        } = read_message(&mut guest).await.unwrap()
                        else {
                            panic!("expected output query");
                        };
                        assert_eq!(fd, expected);
                        tokio::task::yield_now().await;
                        write_message(
                            &mut guest,
                            &Message::Response {
                                id,
                                result: Ok(Value::Bytes(vec![fd; len])),
                            },
                        )
                        .await
                        .unwrap();
                    }
                    assert_eq!(
                        read_message(&mut guest).await.unwrap(),
                        Message::ExitAck { id: 9 }
                    );
                });
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                for index in 0..6 {
                    let status =
                        tokio::time::timeout(std::time::Duration::from_secs(3), statuses.recv())
                            .await
                            .unwrap()
                            .unwrap();
                    assert_eq!(status.pid, 9);
                    assert_eq!(status.running, index < 5);
                    stdout.extend(status.stdout);
                    stderr.extend(status.stderr);
                    if !status.running {
                        assert_eq!(status.return_code, 37);
                    }
                }
                assert_eq!(stdout, vec![1; 2 * OUTPUT_CHUNK + 7]);
                assert_eq!(stderr, vec![2; 2 * OUTPUT_CHUNK]);
                responder.await.unwrap();
            })
            .await;
    }
}
