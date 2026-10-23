use super::{
    boot,
    signals::ChildSignals,
    transport::{self, Connection},
    ROOT,
};
use anyhow::{Context, Result};
use rustix::{
    event::epoll::{self, EventData, EventFlags},
    fd::{AsRawFd, OwnedFd},
    fs::{Mode, OFlags, ResolveFlags},
    process::{Pid, Signal, WaitOptions},
};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CString, OsString},
    fs::File,
    io::{self, Read, Write},
    os::unix::{ffi::OsStringExt, process::CommandExt},
    path::Path,
    process::{Command as ProcessCommand, Stdio},
};
use ya_vm_agent_protocol::{
    AgentError, Command, Event, ExitReason, ExitType, Message, Redirect, Run, Value, MAX_FRAME,
    OUTPUT_CHUNK, VERSION,
};

const MANAGER: u64 = 0;
const CHILDREN: u64 = 1;
const MAX_PROCESSES: usize = 128;

struct Process {
    pid: Option<Pid>,
    output: [Output; 2],
    exit: Option<ExitReason>,
    notified_exit: bool,
    entrypoint: bool,
}
struct Output {
    pipe: Option<File>,
    registered: bool,
    data: VecDeque<u8>,
    capacity: usize,
    cyclic: bool,
    notified: bool,
}
impl Output {
    fn new(redirect: &Option<Redirect>, pipe: Option<File>) -> Self {
        let (capacity, cyclic) = match redirect {
            Some(Redirect::Pipe { capacity, cyclic }) => {
                ((*capacity).clamp(1, MAX_FRAME as u64) as usize, *cyclic)
            }
            _ => (OUTPUT_CHUNK, true),
        };
        Self {
            pipe,
            registered: false,
            data: VecDeque::new(),
            capacity,
            cyclic,
            notified: false,
        }
    }
    fn readable(&self) -> bool {
        self.pipe.is_some() && (self.cyclic || self.data.len() < self.capacity)
    }
    fn append(&mut self, bytes: &[u8]) {
        debug_assert!(self.cyclic || self.data.len() + bytes.len() <= self.capacity);
        if self.cyclic {
            let bytes = &bytes[bytes.len().saturating_sub(self.capacity)..];
            let remove = (self.data.len() + bytes.len()).saturating_sub(self.capacity);
            self.data.drain(..remove);
            self.data.extend(bytes);
        } else {
            self.data.extend(bytes);
        }
    }
}

struct Reactor {
    poll: OwnedFd,
    signals: ChildSignals,
    connection: Connection,
    processes: BTreeMap<u64, Process>,
    next_id: u64,
    quitting: bool,
    shutdown: bool,
}
impl Reactor {
    fn new(stream: File) -> Result<Self> {
        let poll = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let signals = ChildSignals::new()?;
        let connection = Connection::new(stream)?;
        epoll::add(
            &poll,
            &signals.fd,
            EventData::new_u64(CHILDREN),
            EventFlags::IN,
        )?;
        epoll::add(
            &poll,
            &connection.stream,
            EventData::new_u64(MANAGER),
            EventFlags::IN | EventFlags::RDHUP,
        )?;
        Ok(Self {
            poll,
            signals,
            connection,
            processes: BTreeMap::new(),
            next_id: 0,
            quitting: false,
            shutdown: false,
        })
    }
    fn event(&mut self, event: Event) -> Result<()> {
        Ok(self.connection.queue(&Message::Event(event))?)
    }
    fn stream_interest(&self) -> Result<()> {
        let mut flags = EventFlags::RDHUP;
        if !self.quitting && self.connection.can_read() {
            flags |= EventFlags::IN;
        }
        if self.connection.wants_write() {
            flags |= EventFlags::OUT;
        }
        Ok(epoll::modify(
            &self.poll,
            &self.connection.stream,
            EventData::new_u64(MANAGER),
            flags,
        )?)
    }
    fn run(mut self) -> Result<()> {
        self.connection
            .queue(&Message::Ready { version: VERSION })?;
        eprintln!("Rust guest agent READY on virtio-vsock (single-threaded epoll)");
        loop {
            self.connection.flush()?;
            if self.shutdown && !self.connection.wants_write() {
                super::shutdown();
            }
            self.stream_interest()?;
            let mut events = [epoll::Event {
                data: EventData::new_u64(0),
                flags: EventFlags::empty(),
            }; 64];
            let ready = match epoll::wait(&self.poll, &mut events[..], None) {
                Ok(events) => events,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            };
            for event in &events[..ready] {
                let flags = event.flags;
                match event.data.u64() {
                    MANAGER => {
                        // Flush first so a slow receiver cannot starve commands.
                        self.connection.flush()?;
                        if flags.intersects(EventFlags::HUP | EventFlags::RDHUP | EventFlags::ERR) {
                            anyhow::bail!("manager connection closed");
                        }
                        for _ in 0..32 {
                            if self.quitting || !self.connection.can_read() {
                                break;
                            }
                            let Some(message) = self.connection.next()? else {
                                break;
                            };
                            self.request(message)?;
                        }
                    }
                    CHILDREN => {
                        self.signals.drain()?;
                        self.reap()?;
                    }
                    token if !self.quitting => {
                        self.read_output(token >> 2, (token & 3) as usize - 1)?
                    }
                    _ => {}
                }
            }
            if !self.quitting {
                self.completed()?;
            }
        }
    }
    fn request(&mut self, message: Message) -> Result<()> {
        let Message::Request { id, command } = message else {
            anyhow::bail!("expected agent request");
        };
        anyhow::ensure!(id != 0, "request ID cannot be zero");
        let quit = matches!(command, Command::Quit);
        let result = self.handle(command).map_err(|error| {
            let errno = error
                .chain()
                .find_map(|e| {
                    e.downcast_ref::<io::Error>()
                        .and_then(io::Error::raw_os_error)
                        .or_else(|| {
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
            self.quitting = true;
        }
        self.connection.queue(&Message::Response { id, result })?;
        if quit {
            // Stay alive after the ACK. The host owns VmWorker shutdown; a
            // guest reboot could discard the queued response in the backend.
            for process in self.processes.values_mut() {
                for output in &mut process.output {
                    if let Some(pipe) = output.pipe.take() {
                        if output.registered {
                            epoll::delete(&self.poll, &pipe)?;
                            output.registered = false;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn handle(&mut self, command: Command) -> Result<Value> {
        match command {
            Command::Run(run) => self.spawn(run),
            Command::Kill { id } => {
                let pid = self
                    .processes
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
                let output = &mut self
                    .processes
                    .get_mut(&id)
                    .context("unknown process")?
                    .output[usize::from(fd - 1)];
                let offset = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(output.data.len());
                let len = usize::try_from(len)
                    .unwrap_or(usize::MAX)
                    .min(OUTPUT_CHUNK)
                    .min(output.data.len() - offset);
                let bytes = output.data.drain(offset..offset + len).collect();
                output.notified = false;
                self.output_interest(id, usize::from(fd - 1))?;
                self.notify_output(id, usize::from(fd - 1))?;
                Ok(Value::Bytes(bytes))
            }
            Command::Quit => Ok(Value::Ok),
        }
    }
    fn output_interest(&mut self, id: u64, index: usize) -> Result<()> {
        let output = &mut self
            .processes
            .get_mut(&id)
            .context("unknown output process")?
            .output[index];
        let readable = output.readable();
        if let Some(pipe) = &output.pipe {
            if readable && !output.registered {
                epoll::add(
                    &self.poll,
                    pipe,
                    EventData::new_u64((id << 2) | (index + 1) as u64),
                    EventFlags::IN,
                )?;
                output.registered = true;
            } else if !readable && output.registered {
                // Remove, rather than merely disabling EPOLLIN: EPOLLHUP is
                // unconditional and would spin on a closed, full output pipe.
                epoll::delete(&self.poll, pipe)?;
                output.registered = false;
            }
        }
        Ok(())
    }
    fn notify_output(&mut self, id: u64, index: usize) -> Result<()> {
        let output = &mut self
            .processes
            .get_mut(&id)
            .context("unknown output process")?
            .output[index];
        if !output.data.is_empty() && !output.notified {
            output.notified = true;
            self.event(Event::OutputAvailable {
                id,
                fd: (index + 1) as u32,
            })?;
        }
        Ok(())
    }
    fn read_output(&mut self, id: u64, index: usize) -> Result<()> {
        let Some(process) = self.processes.get_mut(&id) else {
            return Ok(());
        };
        let Some(output) = process.output.get_mut(index) else {
            return Ok(());
        };
        let mut chunk = [0; 4096];
        // Bound work per event so continuously writing children cannot starve
        // requests, other pipes or SIGCHLD processing.
        for _ in 0..16 {
            if !output.readable() {
                break;
            }
            let amount = if output.cyclic {
                chunk.len()
            } else {
                chunk.len().min(output.capacity - output.data.len())
            };
            match output.pipe.as_mut().unwrap().read(&mut chunk[..amount]) {
                Ok(0) => {
                    if output.registered {
                        epoll::delete(&self.poll, output.pipe.as_ref().unwrap())?;
                        output.registered = false;
                    }
                    output.pipe.take();
                    break;
                }
                Ok(n) => output.append(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        self.output_interest(id, index)?;
        self.notify_output(id, index)
    }
    fn reap(&mut self) -> Result<()> {
        loop {
            match rustix::process::wait(WaitOptions::NOHANG) {
                Ok(Some((pid, status))) => {
                    if let Some(process) = self.processes.values_mut().find(|p| p.pid == Some(pid))
                    {
                        process.pid = None;
                        process.exit = Some(ExitReason {
                            status: status
                                .exit_status()
                                .or_else(|| status.terminating_signal())
                                .unwrap_or(0) as u8,
                            type_: if status.exited() {
                                ExitType::Exited
                            } else {
                                ExitType::Killed
                            },
                        });
                    }
                    // Also reap adopted/orphaned descendants, which have no
                    // protocol process ID and therefore produce no event.
                }
                Ok(None) | Err(rustix::io::Errno::CHILD) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn completed(&mut self) -> Result<()> {
        let mut events = Vec::new();
        for (&id, process) in &mut self.processes {
            // All output is acknowledged before the terminal event. This
            // prevents a final chunk from arriving with running=true later.
            if !process.notified_exit
                && process.exit.is_some()
                && process
                    .output
                    .iter()
                    .all(|o| o.pipe.is_none() && o.data.is_empty())
            {
                process.notified_exit = true;
                events.push(Event::ProcessDied {
                    id,
                    reason: process.exit.take().unwrap(),
                });
                self.shutdown |= process.entrypoint;
            }
        }
        for event in events {
            self.event(event)?;
        }
        Ok(())
    }
    fn spawn(&mut self, run: Run) -> Result<Value> {
        self.processes.retain(|_, p| !p.notified_exit);
        anyhow::ensure!(
            self.processes.len() < MAX_PROCESSES,
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
        let signal_mask = self.signals.child_mask();
        // SAFETY: only async-signal-safe syscalls run after fork, with prebuilt C strings.
        unsafe {
            command.pre_exec(move || {
                ChildSignals::restore_for_child(signal_mask)?;
                rustix::process::chroot(c"/mnt/newroot")?;
                rustix::process::chdir(cwd.as_c_str())?;
                rustix::thread::set_thread_groups(&[])?;
                rustix::thread::set_thread_res_gid(gid, gid, gid)?;
                rustix::thread::set_thread_res_uid(uid, uid, uid)?;
                Ok(())
            });
        }
        let mut child = command.spawn().context("spawning guest process")?;
        self.next_id += 1;
        let id = self.next_id;
        let pipes = [
            child.stdout.take().map(|p| File::from(OwnedFd::from(p))),
            child.stderr.take().map(|p| File::from(OwnedFd::from(p))),
        ];
        let setup = pipes.iter().flatten().try_for_each(transport::nonblocking);
        if let Err(error) = setup {
            let _ = rustix::process::kill_process_group(
                Pid::from_raw(child.id() as i32).unwrap(),
                Signal::KILL,
            );
            let _ = child.wait();
            return Err(error.into());
        }
        let [stdout, stderr] = pipes;
        self.processes.insert(
            id,
            Process {
                pid: Pid::from_raw(child.id() as i32),
                output: [
                    Output::new(&run.fds[1], stdout),
                    Output::new(&run.fds[2], stderr),
                ],
                entrypoint: run.entrypoint,
                exit: None,
                notified_exit: false,
            },
        );
        if let Err(error) = self
            .output_interest(id, 0)
            .and_then(|_| self.output_interest(id, 1))
        {
            self.processes.remove(&id);
            let _ = rustix::process::kill_process_group(
                Pid::from_raw(child.id() as i32).unwrap(),
                Signal::KILL,
            );
            let _ = child.wait();
            return Err(error);
        }
        // This single PID 1 event loop owns waitpid for tracked and orphaned children.
        drop(child);
        Ok(Value::Id(id))
    }
}

pub fn serve(stream: File) -> Result<()> {
    Reactor::new(stream)?.run()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn cyclic_output_keeps_the_tail_with_bounded_memory() {
        let mut output = Output::new(
            &Some(Redirect::Pipe {
                capacity: 3,
                cyclic: true,
            }),
            None,
        );
        output.append(b"ab");
        output.append(b"cdefgh");
        assert_eq!(output.data.iter().copied().collect::<Vec<_>>(), b"fgh");
        output.append(b"ij");
        assert_eq!(output.data.iter().copied().collect::<Vec<_>>(), b"hij");
    }
    #[test]
    fn full_closed_pipe_is_paused_then_resumed_after_output_query() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut reactor = Reactor::new(OwnedFd::from(stream).into()).unwrap();
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let read = File::from(read);
        transport::nonblocking(&read).unwrap();
        let mut write = File::from(write);
        write.write_all(b"abcdef").unwrap();
        drop(write);
        reactor.processes.insert(
            1,
            Process {
                pid: None,
                exit: None,
                notified_exit: false,
                entrypoint: false,
                output: [
                    Output::new(
                        &Some(Redirect::Pipe {
                            capacity: 3,
                            cyclic: false,
                        }),
                        Some(read),
                    ),
                    Output::new(&None, None),
                ],
            },
        );
        reactor.output_interest(1, 0).unwrap();
        reactor.read_output(1, 0).unwrap();
        assert!(!reactor.processes[&1].output[0].registered);
        let mut events = [epoll::Event {
            flags: EventFlags::empty(),
            data: EventData::new_u64(0),
        }; 4];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            epoll::wait(&reactor.poll, &mut events[..], Some(&timeout)).unwrap(),
            0,
            "EPOLLHUP must not spin while the buffer is full"
        );
        let query = || Command::QueryOutput {
            id: 1,
            fd: 1,
            offset: 0,
            len: u64::MAX,
        };
        assert_eq!(
            reactor.handle(query()).unwrap(),
            Value::Bytes(b"abc".to_vec())
        );
        assert!(reactor.processes[&1].output[0].registered);
        reactor.read_output(1, 0).unwrap();
        assert_eq!(
            reactor.handle(query()).unwrap(),
            Value::Bytes(b"def".to_vec())
        );
        reactor.read_output(1, 0).unwrap();
        assert!(reactor.processes[&1].output[0].pipe.is_none());
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn reaps_children_in_their_own_process_group() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut reactor = Reactor::new(OwnedFd::from(stream).into()).unwrap();
        let child = ProcessCommand::new("/bin/sh")
            .args(["-c", "exit 7"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32).unwrap();
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
        let mut fds = [rustix::event::PollFd::new(
            &pidfd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 3,
            tv_nsec: 0,
        };
        assert_eq!(rustix::event::poll(&mut fds, Some(&timeout)).unwrap(), 1);
        reactor.processes.insert(
            1,
            Process {
                pid: Some(pid),
                output: [Output::new(&None, None), Output::new(&None, None)],
                exit: None,
                notified_exit: false,
                entrypoint: false,
            },
        );
        reactor.reap().unwrap();
        assert!(reactor.processes[&1].pid.is_none());
        assert_eq!(reactor.processes[&1].exit.as_ref().unwrap().status, 7);
        drop(child);
    }
}
