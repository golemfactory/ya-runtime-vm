use super::{ROOT, boot, signals::ChildSignals, transport::Connection};
use super::{io::File, process};
use crate::error::{Context, Result};
use alloc::{
    collections::{BTreeMap, VecDeque},
    ffi::CString,
    vec::Vec,
};
use rustix::{
    event::epoll::{self, EventData, EventFlags},
    fd::{AsRawFd, OwnedFd},
    fs::{Mode, OFlags, ResolveFlags},
    process::{Pid, Signal, WaitOptions},
};
use ya_vm_agent_protocol::{
    AgentError, Command, Event, ExitReason, ExitType, MAX_FRAME, Message, OUTPUT_CHUNK, Redirect,
    Run, VERSION, Value,
};

const MANAGER: u64 = 0;
const CHILDREN: u64 = 1;
const MAX_PROCESSES: usize = 128;

struct Process {
    pid: Option<Pid>,
    output: [Output; 2],
    exit: Option<ExitReason>,
    notified_exit: bool,
    acknowledged_exit: bool,
    entrypoint: bool,
}
struct Output {
    pipe: Option<File>,
    registered: bool,
    data: VecDeque<u8>,
    capacity: usize,
    notified: bool,
    // Bytes left in the pipe when the process exited. Descendants may keep
    // the write end open, so the pipe is closed after these, not at EOF.
    remaining: Option<usize>,
}
impl Output {
    fn new(redirect: &Option<Redirect>, pipe: Option<File>) -> Self {
        // Cyclic pipes behave like blocking ones, as in the C init: a full
        // buffer pauses the pipe until QueryOutput, so no output is dropped.
        let capacity = match redirect {
            Some(Redirect::Pipe { capacity, .. }) => {
                (*capacity).clamp(1, MAX_FRAME as u64) as usize
            }
            _ => OUTPUT_CHUNK,
        };
        Self {
            pipe,
            registered: false,
            data: VecDeque::new(),
            capacity,
            notified: false,
            remaining: None,
        }
    }
    fn readable(&self) -> bool {
        self.pipe.is_some() && self.data.len() < self.capacity
    }
    fn append(&mut self, bytes: &[u8]) {
        debug_assert!(self.data.len() + bytes.len() <= self.capacity);
        self.data.extend(bytes);
    }
    fn close(&mut self, poll: &OwnedFd) -> Result<()> {
        if let Some(pipe) = self.pipe.take()
            && self.registered
        {
            epoll::delete(poll, &pipe)?;
            self.registered = false;
        }
        Ok(())
    }
}

struct Reactor {
    poll: OwnedFd,
    signals: ChildSignals,
    connection: Connection,
    processes: BTreeMap<u64, Process>,
    next_id: u64,
    environment: Vec<CString>,
    quitting: bool,
    shutdown: bool,
}
impl Reactor {
    fn new(stream: File, environment: Vec<CString>) -> Result<Self> {
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
            environment,
            quitting: false,
            shutdown: false,
        })
    }
    fn event(&mut self, event: Event) -> Result<()> {
        self.connection.queue(&Message::Event(event))
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
                            crate::bail!("manager connection closed");
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
        if let Message::ExitAck { id } = message {
            let process = self
                .processes
                .get_mut(&id)
                .context("acknowledging unknown process")?;
            crate::ensure!(
                process.notified_exit,
                "exit acknowledged before output was drained"
            );
            process.acknowledged_exit = true;
            self.shutdown |= process.entrypoint;
            return Ok(());
        }
        let Message::Request { id, command } = message else {
            crate::bail!("expected agent request");
        };
        crate::ensure!(id != 0, "request ID cannot be zero");
        let quit = matches!(command, Command::Quit);
        let result = self.handle(command).map_err(|error| {
            let errno = error.errno.map(|e| e.raw_os_error()).unwrap_or(22) as u32;
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
                    output.close(&self.poll)?;
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
                let target = directory_in_root(&path)?;
                let target_path = format!("/proc/self/fd/{}", target.as_raw_fd());
                boot::mount(
                    &tag,
                    &target_path,
                    "virtiofs",
                    rustix::mount::MountFlags::NODEV | rustix::mount::MountFlags::NOSUID,
                    "",
                )?;
                eprintln!("Mounted virtio-fs share {tag}");
                Ok(Value::Ok)
            }
            Command::Hosts { entries } => {
                let mut file = root_file_with_mode(
                    b"/etc/hosts",
                    OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
                    0o644,
                )?;
                for (host, ip) in entries {
                    crate::ensure!(
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
                crate::ensure!(fd == 1 || fd == 2, "invalid output descriptor");
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
            let amount = chunk
                .len()
                .min(output.capacity - output.data.len())
                .min(output.remaining.unwrap_or(usize::MAX));
            match output.pipe.as_mut().unwrap().read(&mut chunk[..amount]) {
                Ok(0) => {
                    output.close(&self.poll)?;
                    break;
                }
                Ok(n) => {
                    output.append(&chunk[..n]);
                    if let Some(remaining) = &mut output.remaining {
                        *remaining -= n;
                        if *remaining == 0 {
                            output.close(&self.poll)?;
                            break;
                        }
                    }
                }
                Err(e) if e == rustix::io::Errno::AGAIN => break,
                Err(e) if e == rustix::io::Errno::INTR => continue,
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
                        // Report the exit after draining what the process
                        // wrote, as the C init did, even if `cmd &` keeps
                        // the pipe open. Later descendant output is dropped.
                        for output in &mut process.output {
                            if let Some(pipe) = &output.pipe {
                                match rustix::io::ioctl_fionread(pipe)? {
                                    0 => output.close(&self.poll)?,
                                    n => output.remaining = Some(n as usize),
                                }
                            }
                        }
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
            }
        }
        for event in events {
            self.event(event)?;
        }
        Ok(())
    }
    fn spawn(&mut self, run: Run) -> Result<Value> {
        self.processes.retain(|_, p| !p.acknowledged_exit);
        crate::ensure!(
            self.processes.len() < MAX_PROCESSES,
            "too many processes with pending output"
        );
        let child = process::spawn(&run, &self.environment, self.signals.child_mask())?;
        self.next_id += 1;
        let id = self.next_id;
        let [stdout, stderr] = child.output;
        self.processes.insert(
            id,
            Process {
                pid: Some(child.pid),
                output: [
                    Output::new(&run.fds[1], stdout),
                    Output::new(&run.fds[2], stderr),
                ],
                entrypoint: run.entrypoint,
                exit: None,
                notified_exit: false,
                acknowledged_exit: false,
            },
        );
        if let Err(error) = self
            .output_interest(id, 0)
            .and_then(|_| self.output_interest(id, 1))
        {
            self.processes.remove(&id);
            let _ = rustix::process::kill_process_group(child.pid, Signal::KILL);
            let _ = process::wait_for(child.pid);
            return Err(error);
        }
        Ok(Value::Id(id))
    }
}
pub fn serve(stream: File, environment: Vec<CString>) -> Result<()> {
    Reactor::new(stream, environment)?.run()
}
/// Opens a path in the container root; created files are private (0600).
pub fn root_file(path: &[u8], flags: OFlags) -> Result<File> {
    root_file_with_mode(path, flags, 0o600)
}
/// Like [`root_file`], for world-readable system files such as /etc/hosts.
pub fn root_file_with_mode(path: &[u8], flags: OFlags, mode: u32) -> Result<File> {
    let root = File::open(ROOT)?;
    Ok(rustix::fs::openat2(
        &root,
        path,
        flags | OFlags::CLOEXEC,
        if flags.contains(OFlags::CREATE) {
            Mode::from_raw_mode(mode)
        } else {
            Mode::empty()
        },
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )?
    .into())
}
pub fn directory_in_root(path: &[u8]) -> Result<File> {
    crate::ensure!(path.starts_with(b"/"), "mount path must be absolute");
    let mut dir = File::open(ROOT)?;
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        crate::ensure!(component != b"..", "invalid mount path");
        match rustix::fs::mkdirat(&dir, component, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        dir = rustix::fs::openat(
            &dir,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::super::transport;
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn full_closed_pipe_is_paused_then_resumed_after_output_query() {
        // Cyclic pipes must not drop the oldest bytes; both kinds pause.
        for cyclic in [false, true] {
            let (stream, _peer) = UnixStream::pair().unwrap();
            let mut reactor = Reactor::new(OwnedFd::from(stream).into(), Vec::new()).unwrap();
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
                    acknowledged_exit: false,
                    entrypoint: false,
                    output: [
                        Output::new(
                            &Some(Redirect::Pipe {
                                capacity: 3,
                                cyclic,
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
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::{os::unix::process::CommandExt, process::Command as ProcessCommand};
    #[test]
    fn reaps_children_in_their_own_process_group() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut reactor = Reactor::new(OwnedFd::from(stream).into(), Vec::new()).unwrap();
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
                acknowledged_exit: false,
                entrypoint: false,
            },
        );
        reactor.reap().unwrap();
        assert!(reactor.processes[&1].pid.is_none());
        assert_eq!(reactor.processes[&1].exit.as_ref().unwrap().status, 7);
        drop(child);
    }
}

#[cfg(test)]
mod exit_order_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::{os::unix::process::CommandExt, process::Command as ProcessCommand};
    #[test]
    fn exit_is_reported_after_draining_output_left_by_the_process() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut reactor = Reactor::new(OwnedFd::from(socket).into(), Vec::new()).unwrap();
        let (out_read, out_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (err_read, err_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        // The test keeps both write ends open, like a background descendant
        // (`sh -c 'server &'`) that inherited them.
        let mut out_write = File::from(out_write);
        let _err_write = File::from(err_write);
        out_write.write_all(b"stdout tail").unwrap();
        let out = File::from(out_read);
        let err = File::from(err_read);
        super::super::transport::nonblocking(&out).unwrap();
        super::super::transport::nonblocking(&err).unwrap();
        let child = ProcessCommand::new("/bin/sh")
            .args(["-c", "exit 3"])
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
        let redirect = Some(Redirect::Pipe {
            capacity: 4,
            cyclic: true,
        });
        reactor.processes.insert(
            1,
            Process {
                pid: Some(pid),
                exit: None,
                notified_exit: false,
                acknowledged_exit: false,
                entrypoint: true,
                output: [
                    Output::new(&redirect, Some(out)),
                    Output::new(&redirect, Some(err)),
                ],
            },
        );
        reactor.output_interest(1, 0).unwrap();
        reactor.output_interest(1, 1).unwrap();
        reactor.reap().unwrap();
        assert!(reactor.processes[&1].output[1].pipe.is_none());
        let query = || Command::QueryOutput {
            id: 1,
            fd: 1,
            offset: 0,
            len: u64::MAX,
        };
        let mut output = Vec::new();
        for _ in 0..3 {
            reactor.read_output(1, 0).unwrap();
            reactor.completed().unwrap();
            assert!(
                !reactor.processes[&1].notified_exit,
                "exit must follow buffered output"
            );
            let Value::Bytes(bytes) = reactor.handle(query()).unwrap() else {
                panic!("expected output bytes");
            };
            output.extend(bytes);
        }
        assert_eq!(output, b"stdout tail");
        // The writers are still open; later output is not waited for.
        assert!(reactor.processes[&1].output[0].pipe.is_none());
        reactor.completed().unwrap();
        assert!(reactor.processes[&1].notified_exit);
        assert!(
            !reactor.shutdown,
            "entrypoint must stay alive until host ACK"
        );
        reactor.request(Message::ExitAck { id: 1 }).unwrap();
        assert!(reactor.shutdown);
        drop(child);
    }
}
