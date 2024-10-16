use std::sync::Arc;

use libc::{CLD_DUMPED, CLD_EXITED, CLD_KILLED};
use nix::{
    sys::wait::{waitpid, WaitPidFlag},
    unistd::{Gid, Pid, Uid},
};
use prost::Message;
use rinit_protos::rinit::api;
use smol::{lock::Mutex, Async};

use crate::{
    die,
    enums::RedirectFdDesc,
    fs::mount_volume,
    io::{async_read_n, async_recv_u64},
    network::{add_network_hosts, net_if_addr, net_if_addr_to_hw_addr, net_if_hw_addr, net_route},
    process::{spawn_new_process, ExitReason, NewProcessArgs, ProcessDesc},
    utils::{CyclicBuffer, FdPipe, FdWrapper},
    DEV_INET, DEV_VPN,
};

async fn handle_run_process(
    request: &api::RunProcessRequest,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<Option<api::response::Command>> {
    let mut new_process_args = NewProcessArgs::default();

    let mut fd_desc = [
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
    ];

    new_process_args.bin = String::from_utf8(request.program.clone())
        .expect("Failed to convert binary name to string");

    new_process_args.args = request
        .args
        .iter()
        .map(|arg| String::from_utf8(arg.clone()).unwrap())
        .collect();

    new_process_args.envp = request
        .env
        .iter()
        .map(|env| String::from_utf8(env.clone()).unwrap())
        .collect();

    new_process_args.uid = Some(Uid::from_raw(request.uid()));
    new_process_args.gid = Some(Gid::from_raw(request.gid()));

    for rfd in &request.rfd {
        let fd = rfd.fd;

        if fd >= 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid input",
            ));
        }

        let redir_desc = if let Some(redirect) = rfd.redirect.as_ref() {
            match redirect {
                api::rfd::Redirect::Path(redir_path) => RedirectFdDesc::File(
                    String::from_utf8(redir_path.clone())
                        .expect("Failed to convert path to string"),
                ),
                api::rfd::Redirect::PipeBlocking(size) => RedirectFdDesc::PipeBlocking(FdPipe {
                    cyclic_buffer: CyclicBuffer::new(*size as usize),
                    fds: [None, None],
                }),
                api::rfd::Redirect::PipeCyclic(size) => RedirectFdDesc::PipeCyclic(FdPipe {
                    cyclic_buffer: CyclicBuffer::new(*size as usize),
                    fds: [None, None],
                }),
            }
        } else {
            RedirectFdDesc::Invalid
        };

        fd_desc[fd as usize] = redir_desc;
    }

    if let Some(work_dir) = &request.work_dir {
        new_process_args.cwd =
            String::from_utf8(work_dir.clone()).expect("Failed to convert cwd to string");
    }

    if let Some(is_entrypoint) = request.is_entrypoint {
        new_process_args.is_entrypoint = is_entrypoint;
    }

    log::info!(
        "    Spawning process '{}' with: uid={:?}, gid={:?}, args={:?}, env={:?}, cwd='{}', entry_point='{}'",
        new_process_args.bin,
        new_process_args.uid,
        new_process_args.gid,
        new_process_args.args,
        new_process_args.envp,
        new_process_args.cwd,
        new_process_args.is_entrypoint,
    );

    if new_process_args.bin.is_empty() || new_process_args.args.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid input",
        ));
    }

    match spawn_new_process(new_process_args, fd_desc, processes).await {
        Ok(process_id) => Ok(Some(api::response::Command::RunProcess(
            api::RunProcessResponse { process_id },
        ))),
        Err(e) => Err(e),
    }
}

async fn handle_kill_process(
    request: &api::KillProcessRequest,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<Option<api::response::Command>> {
    let process_id = request.process_id;

    if process_id == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid input",
        ));
    }

    let mut processes = processes.lock().await;

    let mut i = 0;
    let mut found = false;

    while i < processes.len() {
        if processes[i].id == process_id {
            found = true;
            break;
        }

        i += 1;
    }

    if found {
        let process = &mut processes[i];

        if process.is_alive {
            log::info!("Killing process: {}", process_id);

            process.child.kill()?
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Process is already dead",
            ));
        }
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Process not found",
        ));
    }

    Ok(Some(api::response::Command::KillProcess(
        api::KillProcessResponse {},
    )))
}

async fn handle_mount(
    request: &api::MountVolumeRequest,
) -> std::io::Result<Option<api::response::Command>> {
    let tag = String::from_utf8(request.tag.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert tag to string",
        )
    })?;
    let path = String::from_utf8(request.path.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert path to string",
        )
    })?;

    if tag.is_empty() || path.is_empty() || !path.starts_with("/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid input",
        ));
    }

    mount_volume(tag, path)?;

    Ok(Some(api::response::Command::MountVolume(
        api::MountVolumeResponse {},
    )))
}

async fn handle_net_ctl(
    request: &api::NetCtlRequest,
) -> std::io::Result<Option<api::response::Command>> {
    let address = String::from_utf8(request.addr.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert address to string",
        )
    })?;

    let mask = String::from_utf8(request.mask.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert mask to string",
        )
    })?;

    let gateway = String::from_utf8(request.gateway.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert gateway to string",
        )
    })?;

    let if_addr = String::from_utf8(request.if_addr.clone()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Failed to convert interface address to string",
        )
    })?;

    let if_kind = api::IfKind::try_from(request.if_kind).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid IfKind value")
    })?;

    let if_name = match if_kind {
        api::IfKind::IfkindVpn => DEV_VPN,
        api::IfKind::IfkindInet => DEV_INET,
    };

    if !if_addr.is_empty() {
        log::info!("Configuring '{}' with IP: {}", if_name, if_addr);

        if if_addr.contains(":") {
            // TODO(aljen): Handle IPV6
        } else {
            if mask.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid input",
                ));
            }

            net_if_addr(if_name, &if_addr, &mask)?;

            let hw_addr = net_if_addr_to_hw_addr(&if_addr);

            let result = net_if_hw_addr(if_name, &hw_addr)?;

            if result != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Failed to set HW address",
                ));
            }
        }
    }

    if !gateway.is_empty() {
        log::info!("Configuring '{}' with gateway: {}", if_name, gateway);

        if gateway.contains(":") {
            // TODO(aljen): Handle IPV6
        } else {
            let address = if !address.is_empty() {
                Some(address.as_str())
            } else {
                None
            };
            let mask = if !mask.is_empty() {
                Some(mask.as_str())
            } else {
                None
            };
            let result = net_route(if_name, address, mask, &gateway)?;

            if result != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Failed to set route",
                ));
            }
        }
    }

    Ok(Some(api::response::Command::NetCtl(api::NetCtlResponse {})))
}

async fn handle_net_host(
    request: &api::NetHostRequest,
) -> std::io::Result<Option<api::response::Command>> {
    let hosts: Vec<(String, String)> = request
        .hosts
        .iter()
        .map(|host| {
            let ip = String::from_utf8(host.ip.clone())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Failed to convert IP to string",
                    )
                })
                .unwrap_or_default();

            let hostname = String::from_utf8(host.hostname.clone())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Failed to convert hostname to string",
                    )
                })
                .unwrap_or_default();

            (ip, hostname)
        })
        .collect();

    add_network_hosts(&hosts)?;

    Ok(Some(api::response::Command::NetHost(
        api::NetHostResponse {},
    )))
}

async fn handle_quit(
    _request: &api::QuitRequest,
) -> std::io::Result<Option<api::response::Command>> {
    log::info!("Quitting...");

    Ok(Some(api::response::Command::Quit(api::QuitResponse {})))
}

fn encode_status(status: i32, reason_type: i32) -> ExitReason {
    let reason_type = match reason_type {
        CLD_EXITED => 0,
        CLD_KILLED => 1,
        CLD_DUMPED => 2,
        _ => {
            log::error!("Unknown status: {}", status);
            die!("Unknown status");
        }
    };

    ExitReason {
        status: status as u8,
        reason_type,
    }
}

pub async fn handle_sigchld(
    async_sig_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
    request_id: &mut u64,
) -> std::io::Result<Option<api::response::Command>> {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; std::mem::size_of::<libc::siginfo_t>()];

    log::info!("handle_sigchld start");

    log::info!("locking async_sig_fd");
    let mut async_sig_fd = async_sig_fd.lock().await;

    *request_id = 0;

    log::info!("Reading from async_sig_fd");
    let size = async_read_n(&mut async_sig_fd, &mut buf).await?;

    if size != std::mem::size_of::<libc::siginfo_t>() {
        log::error!(
            "Expected {} bytes, but got {}",
            std::mem::size_of::<libc::siginfo_t>(),
            size
        );
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), &mut siginfo as *mut _ as *mut u8, size);
    }

    if siginfo.si_signo != libc::SIGCHLD {
        log::error!("Expected SIGCHLD, but got {}", siginfo.si_signo);
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    let child_pid = siginfo._pad[0];
    if child_pid == -1 {
        log::error!("Zombie process with PID -1");
        return Ok(None);
    }

    let child_pid = Pid::from_raw(child_pid);

    if siginfo.si_code != libc::CLD_EXITED
        && siginfo.si_code != libc::CLD_KILLED
        && siginfo.si_code != libc::CLD_DUMPED
    {
        log::error!("Child did not exit normally: {}", siginfo.si_code);
        return Ok(None);
    }

    let wait_status = waitpid(child_pid, Some(WaitPidFlag::WNOHANG))?;
    let pid = wait_status.pid();

    if let Some(pid) = pid {
        log::info!("Process exited: {:?}", wait_status);

        if pid != child_pid {
            log::error!("Expected PID {}, but got {}", child_pid, pid);
            return Ok(None);
        }
    }

    let mut processes = processes.lock().await;

    let mut i = 0;
    let mut found = false;

    let mut proc_id = 0;

    while i < processes.len() {
        if processes[i].pid == child_pid {
            processes[i].is_alive = false;
            proc_id = processes[i].id;
            found = true;
            break;
        }

        i += 1;
    }

    if found {
        log::info!("Process found and marked as dead");
        processes.remove(i);
    }

    let exit_reason = encode_status(siginfo._pad[7], siginfo.si_code);
    println!("Exit reason: {:?}", exit_reason);

    let response = api::response::Command::ProcessDied(api::ProcessDiedNotification {
        pid: proc_id,
        exit_status: exit_reason.status as u32,
        reason_type: exit_reason.reason_type as u32,
    });

    Ok(Some(response))
}

pub async fn handle_message(
    async_cmds_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
    request_id: &mut u64,
) -> std::io::Result<Option<api::response::Command>> {
    let mut async_fd = async_cmds_fd.lock().await;

    let size = async_recv_u64(&mut async_fd).await? as usize;
    let mut buf = vec![0u8; size];

    async_read_n(&mut async_fd, &mut buf).await?;

    let request = api::Request::decode(buf.as_slice())?;

    *request_id = request.request_id;

    match request.command {
        Some(api::request::Command::Quit(quit)) => {
            log::trace!("   Quit message");
            handle_quit(&quit).await
        }
        Some(api::request::Command::RunProcess(run_process)) => {
            log::trace!("   Run process message");
            handle_run_process(&run_process, processes).await
        }
        Some(api::request::Command::KillProcess(kill_process)) => {
            log::trace!("   Kill process message");
            handle_kill_process(&kill_process, processes).await
        }
        Some(api::request::Command::MountVolume(mount_volume)) => {
            log::trace!("   Mount volume message");
            handle_mount(&mount_volume).await
        }
        Some(api::request::Command::QueryOutput(_query_output)) => {
            log::trace!("   Query output message");
            unimplemented!();
        }
        Some(api::request::Command::NetCtl(net_ctl)) => {
            log::trace!("   Net control message");
            handle_net_ctl(&net_ctl).await
        }
        Some(api::request::Command::NetHost(net_host)) => {
            log::trace!("   Net host message");
            handle_net_host(&net_host).await
        }
        Some(api::request::Command::UploadFile(_upload_file)) => {
            log::trace!("   Upload file message");
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Not implemented",
            ))
        }
        Some(api::request::Command::PutInput(_put_input)) => {
            log::trace!("   Put input message");
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Not implemented",
            ))
        }
        Some(api::request::Command::SyncFs(_sync_fs)) => {
            log::trace!("   Sync fs message");
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Not implemented",
            ))
        }
        _ => {
            die!("   Unknown message type");
        }
    }
}
