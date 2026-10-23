use super::{boot, ROOT};
use anyhow::{Context, Result};
use rustix::{
    fs::{Mode, OFlags, ResolveFlags},
    process::{Pid, Signal, WaitOptions},
};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CString, OsString},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStringExt, process::CommandExt},
    },
    path::Path,
    process::{Command as ProcessCommand, Stdio},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
use ya_vm_agent_protocol::{
    AgentError, Command, Event, ExitReason, ExitType, Message, Redirect, Run, Value, MAX_FRAME,
    OUTPUT_CHUNK, VERSION,
};

type Writer = Arc<Mutex<File>>;
type Registry = Arc<Mutex<BTreeMap<u64, Process>>>;
struct Process {
    pid: Option<Pid>,
    output: [Arc<Output>; 2],
    entrypoint: bool,
}
struct Output {
    data: Mutex<VecDeque<u8>>,
    space: Condvar,
    capacity: usize,
    cyclic: bool,
}

pub fn write_message(writer: &Writer, message: &Message) -> io::Result<()> {
    let frame = ya_vm_agent_protocol::encode(message).map_err(io::Error::other)?;
    if frame.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut writer = writer.lock().unwrap();
    writer.write_all(&(frame.len() as u32).to_le_bytes())?;
    writer.write_all(&frame)?;
    writer.flush()
}
fn event(writer: &Writer, event: Event) {
    if let Err(e) = write_message(writer, &Message::Event(event)) {
        eprintln!("Sending guest event failed: {e}");
    }
}
fn read_message(reader: &mut File) -> Result<Message> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let mut frame = vec![0; ya_vm_agent_protocol::frame_len(size)?];
    reader.read_exact(&mut frame)?;
    Ok(ya_vm_agent_protocol::decode(&frame)?)
}

pub fn serve(mut stream: File) -> Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let processes: Registry = Arc::new(Mutex::new(BTreeMap::new()));
    let mut next_id = 0;
    start_reaper(processes.clone(), writer.clone());
    write_message(&writer, &Message::Ready { version: VERSION })?;
    eprintln!("Rust guest agent READY on virtio-vsock (postcard + CRC32C)");
    loop {
        let Message::Request { id, command } = read_message(&mut stream)? else {
            anyhow::bail!("expected agent request");
        };
        anyhow::ensure!(id != 0, "request ID cannot be zero");
        let quit = matches!(command, Command::Quit);
        let result = handle(command, &processes, &writer, &mut next_id).map_err(|error| {
            let errno = error
                .chain()
                .find_map(|e| {
                    e.downcast_ref::<io::Error>()
                        .and_then(io::Error::raw_os_error)
                })
                .or_else(|| {
                    error.chain().find_map(|e| {
                        e.downcast_ref::<rustix::io::Errno>()
                            .map(|e| e.raw_os_error())
                    })
                })
                .unwrap_or(22) as u32;
            eprintln!("Guest request {id}: {error:#}");
            AgentError {
                errno,
                message: format!("{error:#}"),
            }
        });
        if quit {
            rustix::fs::sync();
        }
        write_message(&writer, &Message::Response { id, result })?;
        if quit {
            // The host stops VmWorker after receiving this acknowledgement.
            // Rebooting here can discard the queued vsock response.
            loop {
                std::thread::park();
            }
        }
    }
}

fn handle(
    command: Command,
    processes: &Registry,
    writer: &Writer,
    next_id: &mut u64,
) -> Result<Value> {
    match command {
        Command::Run(run) => spawn(run, processes, writer, next_id),
        Command::Kill { id } => {
            let processes = processes.lock().unwrap();
            let pid = processes
                .get(&id)
                .and_then(|p| p.pid)
                .context("process is not running")?;
            rustix::process::kill_process_group(pid, Signal::KILL)?;
            Ok(Value::Ok)
        }
        Command::Mount { tag, path } => {
            let path = OsString::from_vec(path);
            let target = directory_in_root(Path::new(&path))?;
            let target_path = format!("/proc/self/fd/{}", target.as_raw_fd());
            boot::mount(
                &tag,
                Path::new(&target_path),
                "virtiofs",
                rustix::mount::MountFlags::NODEV | rustix::mount::MountFlags::NOSUID,
                "",
            )?;
            eprintln!("Mounted virtio-fs share {tag}");
            Ok(Value::Ok)
        }
        Command::Hosts { entries } => {
            let mut file = root_file(
                Path::new("/etc/hosts"),
                OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
            )?;
            for (host, ip) in entries {
                anyhow::ensure!(
                    !host.contains(['\r', '\n']) && !ip.contains(['\r', '\n']),
                    "invalid host entry"
                );
                writeln!(file, "{ip}\t{host}")?;
            }
            Ok(Value::Ok)
        }
        Command::Network(config) => {
            super::network::configure(config)?;
            Ok(Value::Ok)
        }
        Command::QueryOutput {
            id,
            fd,
            offset,
            len,
        } => {
            anyhow::ensure!(fd == 1 || fd == 2, "invalid output descriptor");
            let output = processes
                .lock()
                .unwrap()
                .get(&id)
                .context("unknown process")?
                .output[usize::from(fd - 1)]
            .clone();
            let mut data = output.data.lock().unwrap();
            let offset = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let len = usize::try_from(len)
                .unwrap_or(usize::MAX)
                .min(OUTPUT_CHUNK)
                .min(data.len() - offset);
            let bytes = data.drain(offset..offset + len).collect();
            let remaining = !data.is_empty();
            drop(data);
            output.space.notify_all();
            if remaining {
                event(
                    writer,
                    Event::OutputAvailable {
                        id,
                        fd: u32::from(fd),
                    },
                );
            }
            Ok(Value::Bytes(bytes))
        }
        Command::Quit => Ok(Value::Ok),
    }
}

pub fn root_file(path: &Path, flags: OFlags) -> Result<File> {
    let root = File::open(ROOT)?;
    Ok(rustix::fs::openat2(
        &root,
        path,
        flags | OFlags::CLOEXEC,
        if flags.contains(OFlags::CREATE) {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        },
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )?
    .into())
}
pub fn directory_in_root(path: &Path) -> Result<File> {
    use std::path::Component;
    anyhow::ensure!(path.is_absolute(), "mount path must be absolute");
    let mut dir = File::open(ROOT)?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                match rustix::fs::mkdirat(&dir, name, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                dir = rustix::fs::openat(
                    &dir,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?
                .into();
            }
            _ => anyhow::bail!("invalid mount path"),
        }
    }
    Ok(dir)
}

fn output(redirect: &Option<Redirect>) -> Arc<Output> {
    let (capacity, cyclic) = match redirect {
        Some(Redirect::Pipe { capacity, cyclic }) => {
            ((*capacity).clamp(1, MAX_FRAME as u64) as usize, *cyclic)
        }
        _ => (OUTPUT_CHUNK, true),
    };
    Arc::new(Output {
        data: Mutex::new(VecDeque::new()),
        space: Condvar::new(),
        capacity,
        cyclic,
    })
}
fn stdio(redirect: &Option<Redirect>, fd: usize) -> Result<Stdio> {
    match redirect {
        Some(Redirect::File(path)) => Ok(root_file(
            Path::new(&OsString::from_vec(path.clone())),
            if fd == 0 {
                OFlags::RDONLY
            } else {
                OFlags::WRONLY | OFlags::CREATE
            },
        )?
        .into()),
        Some(Redirect::Pipe { .. }) if fd != 0 => Ok(Stdio::piped()),
        Some(Redirect::Pipe { .. }) => anyhow::bail!("stdin streaming is unsupported"),
        None => Ok(Stdio::null()),
    }
}

fn spawn(run: Run, registry: &Registry, writer: &Writer, next_id: &mut u64) -> Result<Value> {
    let mut processes = registry.lock().unwrap();
    processes.retain(|_, p| {
        p.pid.is_some() || p.output.iter().any(|o| !o.data.lock().unwrap().is_empty())
    });
    anyhow::ensure!(
        processes.len() < 128,
        "too many processes with pending output"
    );
    anyhow::ensure!(
        run.uid != u32::MAX && run.gid != u32::MAX,
        "invalid uid/gid"
    );
    let mut command = ProcessCommand::new(OsString::from_vec(run.bin));
    if let Some(arg0) = run.argv.first() {
        command.arg0(OsString::from_vec(arg0.clone()));
    }
    command.args(
        run.argv
            .iter()
            .skip(1)
            .map(|s| OsString::from_vec(s.clone())),
    );
    if let Some(env) = run.env {
        command.env_clear();
        for var in env {
            let equal = var
                .iter()
                .position(|b| *b == b'=')
                .context("invalid process environment")?;
            anyhow::ensure!(equal != 0, "empty environment variable name");
            command.env(
                OsString::from_vec(var[..equal].to_vec()),
                OsString::from_vec(var[equal + 1..].to_vec()),
            );
        }
    }
    command
        .stdin(stdio(&run.fds[0], 0)?)
        .stdout(stdio(&run.fds[1], 1)?)
        .stderr(stdio(&run.fds[2], 2)?);
    command.process_group(0);
    let cwd = CString::new(run.cwd.unwrap_or_else(|| b"/".to_vec()))?;
    let uid = rustix::process::Uid::from_raw(run.uid);
    let gid = rustix::process::Gid::from_raw(run.gid);
    // SAFETY: only async-signal-safe syscalls run after fork, with prebuilt C strings.
    unsafe {
        command.pre_exec(move || {
            rustix::process::chroot(c"/mnt/newroot")?;
            rustix::process::chdir(cwd.as_c_str())?;
            rustix::thread::set_thread_groups(&[])?;
            rustix::thread::set_thread_res_gid(gid, gid, gid)?;
            rustix::thread::set_thread_res_uid(uid, uid, uid)?;
            Ok(())
        });
    }
    let mut child = command.spawn().context("spawning guest process")?;
    *next_id += 1;
    let id = *next_id;
    let outputs = [output(&run.fds[1]), output(&run.fds[2])];
    processes.insert(
        id,
        Process {
            pid: Pid::from_raw(child.id() as i32),
            output: outputs.clone(),
            entrypoint: run.entrypoint,
        },
    );
    if let Some(pipe) = child.stdout.take() {
        pump(pipe, outputs[0].clone(), id, 1, writer.clone());
    }
    if let Some(pipe) = child.stderr.take() {
        pump(pipe, outputs[1].clone(), id, 2, writer.clone());
    }
    // PID 1's single reaper owns waitpid for both tracked and orphaned children.
    drop(child);
    Ok(Value::Id(id))
}

fn pump(
    mut pipe: impl Read + Send + 'static,
    output: Arc<Output>,
    id: u64,
    fd: u32,
    writer: Writer,
) {
    std::thread::spawn(move || {
        let mut chunk = [0; 4096];
        loop {
            let n = match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let mut position = 0;
            while position < n {
                let mut data = output.data.lock().unwrap();
                while !output.cyclic && data.len() == output.capacity {
                    data = output.space.wait(data).unwrap();
                }
                let was_empty = data.is_empty();
                let count = (n - position).min(output.capacity);
                if output.cyclic {
                    let drop_count = (data.len() + count).saturating_sub(output.capacity);
                    data.drain(..drop_count);
                }
                let count = count.min(output.capacity - data.len());
                data.extend(&chunk[position..position + count]);
                position += count;
                drop(data);
                if was_empty {
                    event(&writer, Event::OutputAvailable { id, fd });
                }
            }
        }
    });
}

fn start_reaper(registry: Registry, writer: Writer) {
    std::thread::spawn(move || loop {
        match rustix::process::waitpid(None, WaitOptions::empty()) {
            Ok(Some((pid, status))) => {
                let mut processes = registry.lock().unwrap();
                if let Some((&id, process)) = processes.iter_mut().find(|(_, p)| p.pid == Some(pid))
                {
                    process.pid = None;
                    let entrypoint = process.entrypoint;
                    let reason = ExitReason {
                        status: status
                            .exit_status()
                            .or_else(|| status.terminating_signal())
                            .unwrap_or(0) as u8,
                        type_: if status.exited() {
                            ExitType::Exited
                        } else {
                            ExitType::Killed
                        },
                    };
                    drop(processes);
                    event(&writer, Event::ProcessDied { id, reason });
                    if entrypoint {
                        super::shutdown();
                    }
                }
            }
            Ok(None) | Err(rustix::io::Errno::CHILD) => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                eprintln!("Guest reaper: {e}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    });
}
