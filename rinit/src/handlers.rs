use std::os::fd::AsRawFd;

use nix::sys::epoll::{Epoll, EpollEvent, EpollFlags, EpollTimeout};

use crate::{
    die,
    enums::{EpollFdType, MessageRunProcessType, MessageType, RedirectFdType},
    fs::mount_volume,
    io::{
        read_n, recv_bytes, recv_strings_array, recv_u32, recv_u64, recv_u8, send_response_error,
        send_response_ok, send_response_u64, MessageHeader,
    },
    process::{spawn_new_process, NewProcessArgs},
    CMDS_FD, SIG_FD,
};

fn handle_run_process(msg_id: u64) -> std::io::Result<()> {
    let mut done = false;

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") }.as_raw_fd();

    let mut new_process_args = NewProcessArgs::default();

    while !done {
        let cmd = recv_u8(cmds_fd).expect("Failed to read command");
        let cmd = MessageRunProcessType::from_u8(cmd);

        match cmd {
            MessageRunProcessType::End => {
                println!("    Done");
                done = true;
            }
            MessageRunProcessType::Bin => {
                println!("    Binary");
                let bin = recv_bytes(cmds_fd)?;
                new_process_args.bin =
                    String::from_utf8(bin).expect("Failed to convert binary name to string");
                println!("     Binary: {}", new_process_args.bin);
            }
            MessageRunProcessType::Arg => {
                println!("    Arg");
                new_process_args.args = recv_strings_array(cmds_fd)?;
                println!("     Args: {:?}", new_process_args.args);
            }
            MessageRunProcessType::Env => {
                println!("    Env");
                new_process_args.envp = recv_strings_array(cmds_fd)?;
                println!("     Env: {:?}", new_process_args.envp);
            }
            MessageRunProcessType::Uid => {
                println!("    Uid");
                new_process_args.uid = recv_u32(cmds_fd)?;
                println!("     Uid: {}", new_process_args.uid);
            }
            MessageRunProcessType::Gid => {
                println!("    Gid");
                new_process_args.gid = recv_u32(cmds_fd)?;
                println!("     Gid: {}", new_process_args.gid);
            }
            MessageRunProcessType::Rfd => {
                println!("    Rfd");
                let result = parse_fd_redit()?;
                println!("     Result: {:?}", result);
            }
            MessageRunProcessType::Cwd => {
                println!("    Cwd");
                let buf = recv_bytes(cmds_fd)?;
                new_process_args.cwd =
                    String::from_utf8(buf).expect("Failed to convert cwd to string");
                println!("     Cwd: {}", new_process_args.cwd);
            }
            MessageRunProcessType::Ent => {
                println!("    Ent");
                println!("     Entrypoint -> true");
                new_process_args.is_entrypoint = true;
            }
        }
    }

    println!(
        "    Spawning process '{}' with: uid={}, gid={}, args={:?}, env={:?}, cwd='{}', entry_point='{}'",
        new_process_args.bin,
        new_process_args.uid,
        new_process_args.gid,
        new_process_args.args,
        new_process_args.envp,
        new_process_args.cwd,
        new_process_args.is_entrypoint,
    );

    if new_process_args.bin.is_empty() || new_process_args.args.is_empty() {
        send_response_error(msg_id, libc::EFAULT as i32);
        return Ok(());
    }

    match spawn_new_process(new_process_args) {
        Ok(proc_id) => send_response_u64(msg_id, proc_id),
        Err(e) => send_response_error(msg_id, e.raw_os_error().unwrap_or(libc::EIO)),
    }

    Ok(())
}

fn parse_fd_redit() -> std::io::Result<()> {
    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") }.as_raw_fd();

    let fd = recv_u32(cmds_fd)?;
    let desc_type_u8 = recv_u8(cmds_fd)?;
    let desc_type = RedirectFdType::from_u8(desc_type_u8);

    let mut path = String::new();

    println!(
        "     Parsing fd redirect: {} -> {:?}",
        desc_type_u8, desc_type
    );

    match desc_type {
        RedirectFdType::File => {
            println!("         File");
            let buf = recv_bytes(cmds_fd)?;
            path = String::from_utf8(buf).expect("Failed to convert path to string");
            println!("          Path: {}", path);
        }
        RedirectFdType::PipeBlocking | RedirectFdType::PipeCyclic => {
            println!("        Pipe");
            let pipe = recv_u64(cmds_fd)?;
            println!("         Pipe: {}", pipe);
        }
        RedirectFdType::Invalid => {
            println!("        Invalid");
            todo!();
        }
    }

    Ok(())
}

fn handle_mount(message_id: u64) {
    let mut done = false;

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") }.as_raw_fd();

    let mut tag = String::new();
    let mut path = String::new();

    while !done {
        let cmd = recv_u8(cmds_fd).expect("Failed to read command");

        match cmd {
            // VOLUME_END
            0 => {
                println!("    Done");
                done = true;
            }
            // VOLUME_TAG
            1 => {
                println!("   Volume tag");
                let buf = recv_bytes(cmds_fd).expect("Failed to read tag");
                tag = String::from_utf8(buf).expect("Failed to convert tag to string");
                println!("    Tag: {}", tag);
            }
            // VOLUME_PATH
            2 => {
                println!("   Volume path");
                let buf = recv_bytes(cmds_fd).expect("Failed to read path");
                path = String::from_utf8(buf).expect("Failed to convert path to string");
                println!("    Path: {}", path);
            }
            _ => {
                println!("   Unknown command");
                send_response_error(message_id, libc::EPROTONOSUPPORT as i32);
            }
        }
    }

    if tag.is_empty() || path.is_empty() || !path.starts_with("/") {
        send_response_error(message_id, libc::EINVAL as i32);
        return;
    }

    let result = mount_volume(tag, path);
    match result {
        Ok(_) => (),
        Err(e) => {
            send_response_error(message_id, e.raw_os_error().unwrap_or(libc::EIO));
            return;
        }
    }

    send_response_ok(message_id);
}

fn handle_quit(message_id: u64) {
    println!("Quitting...");

    send_response_ok(message_id);

    die!("Exit");
}

fn handle_sigchld() -> std::io::Result<()> {
    let mut buf = [0u8; 128];

    let sig_fd = unsafe { SIG_FD.as_ref().expect("SIG_FD should be initialized") };

    nix::unistd::read(sig_fd.as_raw_fd(), &mut buf)?;

    // TODO(aljen): Handle SIGCHLD

    Ok(())
}

fn handle_message() -> std::io::Result<()> {
    let mut buf = [0u8; 9];

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };
    // let mut cmds_fd = unsafe { CMDS_FD.expect("CMDS_FD should be initialized") };

    // let result = cmds_fd.read(&mut buf);
    // let result = nix::unistd::read(cmds_fd.as_raw_fd(), &mut buf);
    let size = read_n(cmds_fd.as_raw_fd(), &mut buf)?;

    println!(" Handling message: {:?}", buf);

    let msg_header = MessageHeader::from_ne_bytes(&buf);
    println!("  Message header: {:?} ({})", msg_header, size);

    let message_type = MessageType::from_u8(msg_header.msg_type);

    match message_type {
        MessageType::Quit => {
            println!("   Quit message");
            handle_quit(msg_header.msg_id);
        }
        MessageType::RunProcess => {
            println!("   Run process message");
            handle_run_process(msg_header.msg_id)?;
        }
        MessageType::KillProcess => {
            println!("   Kill process message");
        }
        MessageType::MountVolume => {
            println!("   Mount volume message");
            handle_mount(msg_header.msg_id);
        }
        MessageType::UploadFile => {
            println!("   Upload file message");
            send_response_error(msg_header.msg_id, libc::EPROTONOSUPPORT as i32);
        }
        MessageType::QueryOutput => {
            println!("   Query output message");
        }
        MessageType::PutInput => {
            println!("   Put input message");
        }
        MessageType::SyncFs => {
            println!("   Sync fs message");
        }
        MessageType::NetCtl => {
            println!("   Net control message");
        }
        MessageType::NetHost => {
            println!("   Net host message");
        }
        _ => {
            die!("   Unknown message type");
        }
    }

    Ok(())
}

pub fn handle_messages(epoll: &Epoll) -> std::io::Result<()> {
    let mut events = [EpollEvent::empty()];

    epoll.wait(&mut events, EpollTimeout::NONE)?;

    println!("Event: {:?}", events[0]);
    let event = &events[0];

    let epoll_fd = EpollFdType::from_u64(event.data());

    if event.events() == EpollFlags::EPOLLERR && epoll_fd == EpollFdType::Out {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "EPOLLERR"));
    }

    match epoll_fd {
        EpollFdType::Cmds => {
            if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                println!("Command event");
                handle_message()?;
                // let mut buf = [0u8; 8];
                // g_cmds_fd.read_exact(&mut buf)?;

                // let cmd = u64::from_ne_bytes(buf);

                // println!("Command: {}", cmd);

                // if cmd == 0 {
                //     break;
                // }
            }
        }
        EpollFdType::Sig => {
            if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                println!("Signal event");
                handle_sigchld()?;
                // let mut buf = [0u8; 8];
                // SIG_FD.as_ref().unwrap().read_exact(&mut buf)?;

                // let siginfo = signal::siginfo_t::from_ne_bytes(buf);

                // println!("Signal: {}", siginfo.ssi_signo);
            }
        }
        EpollFdType::Out => {
            die!("Out not implemented");
        }
        EpollFdType::In => {
            if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                println!("In event [EPOLLIN]");
            } else if event.events() & EpollFlags::EPOLLHUP == EpollFlags::EPOLLHUP {
                println!("In event [EPOLLHUP]");
            }
        }
        _ => {
            die!("Unknown event");
        }
    }

    Ok(())
}
