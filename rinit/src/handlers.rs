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
    enums::{MessageRunProcessType, MessageType, RedirectFdDesc, RedirectFdType},
    fs::mount_volume,
    io::{
        async_read_n, async_recv_bytes, async_recv_strings_array, async_recv_u32, async_recv_u64,
        async_recv_u8, async_send_response_ok, send_process_died, send_response_error,
        send_response_u64, MessageHeader,
    },
    process::{spawn_new_process, ExitReason, NewProcessArgs, ProcessDesc},
    utils::{CyclicBuffer, FdPipe, FdWrapper},
};

async fn handle_run_process_command(
    _request: &api::RunProcessRequest,
    _processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<api::response::Command> {
    Ok(api::response::Command::RunProcess(
        api::RunProcessResponse { process_id: 0 },
    ))
}

async fn handle_run_process(
    async_fd: &mut Async<FdWrapper>,
    msg_id: u64,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<()> {
    let mut done = false;

    let mut new_process_args = NewProcessArgs::default();

    let mut fd_desc = [
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
        RedirectFdDesc::Invalid,
    ];

    while !done {
        let cmd = async_recv_u8(async_fd).await?;
        let cmd = MessageRunProcessType::from_u8(cmd);

        match cmd {
            MessageRunProcessType::End => {
                // log::trace!("    Done");
                done = true;
            }
            MessageRunProcessType::Bin => {
                // log::trace!("    Binary");
                let bin = async_recv_bytes(async_fd).await?;
                new_process_args.bin =
                    String::from_utf8(bin).expect("Failed to convert binary name to string");
                log::trace!("     Binary: {}", new_process_args.bin);
            }
            MessageRunProcessType::Arg => {
                // log::trace!("    Arg");
                new_process_args.args = async_recv_strings_array(async_fd).await?;
                log::trace!("     Args: {:?}", new_process_args.args);
            }
            MessageRunProcessType::Env => {
                // log::trace!("    Env");
                new_process_args.envp = async_recv_strings_array(async_fd).await?;
                log::trace!("     Env: {:?}", new_process_args.envp);
            }
            MessageRunProcessType::Uid => {
                // log::trace!("    Uid");
                new_process_args.uid = Some(Uid::from_raw(async_recv_u32(async_fd).await?));
                log::trace!("     Uid: {:?}", new_process_args.uid);
            }
            MessageRunProcessType::Gid => {
                // log::trace!("    Gid");
                new_process_args.gid = Some(Gid::from_raw(async_recv_u32(async_fd).await?));
                log::trace!("     Gid: {:?}", new_process_args.gid);
            }
            MessageRunProcessType::Rfd => {
                // log::trace!("    Rfd");
                parse_fd_redit(async_fd, &mut fd_desc).await?;
                log::trace!("     Rfd: {:?}", fd_desc);
            }
            MessageRunProcessType::Cwd => {
                // log::trace!("    Cwd");
                let buf = async_recv_bytes(async_fd).await?;
                new_process_args.cwd =
                    String::from_utf8(buf).expect("Failed to convert cwd to string");
                log::trace!("     Cwd: {}", new_process_args.cwd);
            }
            MessageRunProcessType::Ent => {
                // log::trace!("    Ent");
                log::trace!("     Entrypoint -> true");
                new_process_args.is_entrypoint = true;
            }
        }
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
        send_response_error(async_fd, msg_id, libc::EFAULT as i32).await?;
        return Ok(());
    }

    match spawn_new_process(new_process_args, fd_desc, processes).await {
        Ok(proc_id) => {
            log::info!("    Process spawned: {}", proc_id);
            send_response_u64(async_fd, msg_id, proc_id).await?
        }
        Err(e) => {
            log::error!("    Failed to spawn process: {:?}", e);
            send_response_error(async_fd, msg_id, e.raw_os_error().unwrap_or(libc::EIO)).await?
        }
    }

    Ok(())
}

async fn parse_fd_redit(
    async_fd: &mut Async<FdWrapper>,
    fd_desc: &mut [RedirectFdDesc; 3],
) -> std::io::Result<()> {
    let fd = async_recv_u32(async_fd).await?;

    let redir_type_u8 = async_recv_u8(async_fd).await?;

    let redir_type = RedirectFdType::from_u8(redir_type_u8);

    log::trace!(
        "     Parsing fd: {} redirect: {} -> {:?}",
        fd,
        redir_type_u8,
        redir_type
    );

    let mut path = String::new();
    let mut cyclic_buffer_size = 0;

    match redir_type {
        RedirectFdType::File => {
            log::trace!("         File");
            let buf = async_recv_bytes(async_fd).await?;
            path = String::from_utf8(buf).expect("Failed to convert path to string");
            log::trace!("          Path: {}", path);
        }
        RedirectFdType::PipeBlocking => {
            log::trace!("        Pipe Blocking");
            cyclic_buffer_size = async_recv_u64(async_fd).await?;
            log::trace!("         Pipe: {}", cyclic_buffer_size);
        }
        RedirectFdType::PipeCyclic => {
            log::trace!("        Pipe Cyclic");
            cyclic_buffer_size = async_recv_u64(async_fd).await?;
            log::trace!("         Pipe: {}", cyclic_buffer_size);
        }
        RedirectFdType::Invalid => {
            log::trace!("        Invalid");
            todo!();
        }
    }

    if fd >= 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid input",
        ));
    }

    fd_desc[fd as usize] = match redir_type {
        RedirectFdType::File => RedirectFdDesc::File(path),
        RedirectFdType::PipeBlocking => {
            let fd_pipe = FdPipe {
                cyclic_buffer: CyclicBuffer::new(cyclic_buffer_size as usize),
                fds: [None, None],
            };
            RedirectFdDesc::PipeBlocking(fd_pipe)
        }
        RedirectFdType::PipeCyclic => {
            let fd_pipe = FdPipe {
                cyclic_buffer: CyclicBuffer::new(cyclic_buffer_size as usize),
                fds: [None, None],
            };
            RedirectFdDesc::PipeCyclic(fd_pipe)
        }
        RedirectFdType::Invalid => RedirectFdDesc::Invalid,
    };

    Ok(())
}

async fn handle_mount_command(
    request: &api::MountVolumeRequest,
) -> std::io::Result<api::response::Command> {
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

    Ok(api::response::Command::MountVolume(
        api::MountVolumeResponse {},
    ))
}

async fn handle_mount(async_fd: &mut Async<FdWrapper>, message_id: u64) -> std::io::Result<()> {
    let mut done = false;

    let mut tag = String::new();
    let mut path = String::new();

    while !done {
        let cmd = async_recv_u8(async_fd).await?;

        match cmd {
            // VOLUME_END
            0 => {
                // log::trace!("    Done");
                done = true;
            }
            // VOLUME_TAG
            1 => {
                // log::trace!("   Volume tag");
                let buf = async_recv_bytes(async_fd).await?;
                tag = String::from_utf8(buf).expect("Failed to convert tag to string");
                log::trace!("    Tag: {}", tag);
            }
            // VOLUME_PATH
            2 => {
                // log::trace!("   Volume path");
                let buf = async_recv_bytes(async_fd).await?;
                path = String::from_utf8(buf).expect("Failed to convert path to string");
                log::trace!("    Path: {}", path);
            }
            _ => {
                log::trace!("   Unknown command");
                send_response_error(async_fd, message_id, libc::EPROTONOSUPPORT as i32).await?;
            }
        }
    }

    if tag.is_empty() || path.is_empty() || !path.starts_with("/") {
        send_response_error(async_fd, message_id, libc::EINVAL as i32).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid input",
        ));
    }

    let result = mount_volume(tag, path);
    match result {
        Ok(_) => (),
        Err(e) => {
            send_response_error(async_fd, message_id, e.raw_os_error().unwrap_or(libc::EIO))
                .await?;
            return Err(e);
        }
    }

    async_send_response_ok(async_fd, message_id).await?;

    Ok(())
}

async fn handle_quit(async_fd: &mut Async<FdWrapper>, message_id: u64) -> std::io::Result<()> {
    log::info!("Quitting...");

    async_send_response_ok(async_fd, message_id).await?;

    die!("Exit");
}

async fn handle_quit_command(
    _request: &api::QuitRequest,
) -> std::io::Result<api::response::Command> {
    log::info!("Quitting...");

    // async_send_response_ok(async_fd, message_id).await?;

    // die!("Exit");

    Ok(api::response::Command::Quit(api::QuitResponse {}))
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
    async_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<()> {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let mut buf = [0u8; std::mem::size_of::<libc::siginfo_t>()];

    log::info!("Handling SIGCHLD");

    let mut async_fd = async_fd.lock().await;

    let size = async_read_n(&mut async_fd, &mut buf).await?;

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
        return Ok(());
    }

    let child_pid = Pid::from_raw(child_pid);

    if siginfo.si_code != libc::CLD_EXITED
        && siginfo.si_code != libc::CLD_KILLED
        && siginfo.si_code != libc::CLD_DUMPED
    {
        log::error!("Child did not exit normally: {}", siginfo.si_code);
        return Ok(());
    }

    let wait_status = waitpid(child_pid, Some(WaitPidFlag::WNOHANG))?;
    let pid = wait_status.pid();

    if let Some(pid) = pid {
        log::info!("Process exited: {:?}", wait_status);

        if pid != child_pid {
            log::error!("Expected PID {}, but got {}", child_pid, pid);
            return Ok(());
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

    send_process_died(&mut async_fd, proc_id, exit_reason).await?;

    Ok(())
}

pub async fn handle_message(
    async_fd: Arc<Mutex<Async<FdWrapper>>>,
    processes: Arc<Mutex<Vec<ProcessDesc>>>,
) -> std::io::Result<()> {
    let mut async_fd = async_fd.lock().await;

    let size = async_recv_u64(&mut async_fd).await? as usize;
    let mut buf = vec![0u8; size];

    println!("Reading message of size: {}", size);

    async_read_n(&mut async_fd, &mut buf).await?;

    let request = api::Request::decode(buf.as_slice())?;

    println!("Request: {:?}", request);

    // let mut buf = [0u8; 9];
    // let size = async_read_n(&mut async_fd, &mut buf).await?;

    // log::info!(" Handling message: {:?}, size: {}", buf, size);

    // let msg_header = MessageHeader::from_ne_bytes(&buf);
    // log::trace!("  Message header: {:?} ({})", msg_header, size);

    // let message_type = MessageType::from_u8(msg_header.msg_type);

    let response = match request.command {
        Some(api::request::Command::Quit(quit)) => {
            log::trace!("   Quit message");
            handle_quit_command(&quit).await
        }
        Some(api::request::Command::RunProcess(run_process)) => {
            log::trace!("   Run process message");
            handle_run_process_command(&run_process, processes).await
        }
        Some(api::request::Command::MountVolume(mount_volume)) => {
            log::trace!("   Mount volume message");
            handle_mount_command(&mount_volume).await
        }
        _ => {
            die!("   Unknown message type");
        }
    };

    match response {
        Ok(response) => {
            let response = api::Response {
                request_id: 0,
                command: Some(response),
            };

            // let mut buf = Vec::new();
            // response.encode(&mut buf)?;

            async_send_response_ok(&mut async_fd, 0).await?;
            // async_fd.write_all(&buf).await?;
        }
        Err(e) => {
            log::error!("Failed to handle message: {:?}", e);
            send_response_error(&mut async_fd, 0, e.raw_os_error().unwrap_or(libc::EIO)).await?;
        }
    }

    // match message_type {
    //     MessageType::Quit => {
    //         log::trace!("   Quit message");
    //         handle_quit(&mut async_fd, msg_header.msg_id).await?;
    //     }
    //     MessageType::RunProcess => {
    //         log::trace!("   Run process message");
    //         handle_run_process(&mut async_fd, msg_header.msg_id, processes).await?;
    //     }
    //     MessageType::KillProcess => {
    //         log::trace!("   Kill process message");
    //     }
    //     MessageType::MountVolume => {
    //         log::trace!("   Mount volume message");
    //         handle_mount(&mut async_fd, msg_header.msg_id).await?;
    //     }
    //     MessageType::UploadFile => {
    //         log::trace!("   Upload file message");
    //         send_response_error(
    //             &mut async_fd,
    //             msg_header.msg_id,
    //             libc::EPROTONOSUPPORT as i32,
    //         )
    //         .await?;
    //     }
    //     MessageType::QueryOutput => {
    //         log::trace!("   Query output message");
    //     }
    //     MessageType::PutInput => {
    //         log::trace!("   Put input message");
    //     }
    //     MessageType::SyncFs => {
    //         log::trace!("   Sync fs message");
    //     }
    //     MessageType::NetCtl => {
    //         log::trace!("   Net control message");
    //     }
    //     MessageType::NetHost => {
    //         log::trace!("   Net host message");
    //     }
    //     _ => {
    //         die!("   Unknown message type");
    //     }
    // }

    Ok(())
}
