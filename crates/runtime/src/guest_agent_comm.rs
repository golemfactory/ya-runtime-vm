use crate::local_socket::LocalStream;
use futures::{SinkExt, StreamExt, channel::mpsc, future::BoxFuture, lock::Mutex};
use std::{io, path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
pub use ya_vm_agent_protocol::Event as Notification;
use ya_vm_agent_protocol::{
    AgentError, Command, MAX_FRAME, Message, Network, Redirect, Run, VERSION, Value,
};

pub enum RedirectFdType<'a> {
    RedirectFdFile(&'a [u8]),
    RedirectFdPipeBlocking(u64),
    RedirectFdPipeCyclic(u64),
}
pub type RemoteCommandResult<T> = Result<T, u32>;

pub struct GuestAgent {
    stream: WriteHalf<LocalStream>,
    last_msg_id: u64,
    responses: mpsc::Receiver<(u64, Result<Value, AgentError>)>,
    responses_reader_handle: Option<tokio::task::JoinHandle<io::Error>>,
}

pub(crate) async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Message> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await?;
    let mut frame = vec![0; ya_vm_agent_protocol::frame_len(prefix)?];
    stream.read_exact(&mut frame).await?;
    ya_vm_agent_protocol::decode(&frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub(crate) async fn write_message(
    stream: &mut (impl AsyncWrite + Unpin),
    message: &Message,
) -> io::Result<()> {
    let frame = ya_vm_agent_protocol::encode(message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if frame.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "agent frame exceeds size limit",
        ));
    }
    stream
        .write_all(&(frame.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(&frame).await
}

impl GuestAgent {
    pub(crate) async fn from_stream<F>(
        mut stream: LocalStream,
        timeout: u32,
        mut handler: F,
    ) -> io::Result<Arc<Mutex<Self>>>
    where
        F: FnMut(Notification, Arc<Mutex<Self>>) -> BoxFuture<'static, ()> + Send + 'static,
    {
        let ready = tokio::time::timeout(
            std::time::Duration::from_secs(timeout.into()),
            read_message(&mut stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "guest agent did not send READY"))??;
        if !matches!(ready, Message::Ready { version: VERSION }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest agent protocol version/READY mismatch",
            ));
        }
        log::info!("Guest agent READY received (postcard protocol {VERSION}, CRC32C)");
        let (read, write) = split(stream);
        let (responses_tx, responses) = mpsc::channel(16);
        let agent = Arc::new(Mutex::new(Self {
            stream: write,
            last_msg_id: 0,
            responses,
            responses_reader_handle: None,
        }));
        let (events_tx, mut events) = mpsc::unbounded();
        let agent_for_events = agent.clone();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                handler(event, agent_for_events.clone()).await;
            }
        });
        let reader = tokio::spawn(read_responses(read, responses_tx, events_tx));
        agent.lock().await.responses_reader_handle = Some(reader);
        Ok(agent)
    }

    pub async fn connected<F, P>(path: P, timeout: u32, handler: F) -> io::Result<Arc<Mutex<Self>>>
    where
        F: FnMut(Notification, Arc<Mutex<Self>>) -> BoxFuture<'static, ()> + Send + 'static,
        P: AsRef<Path>,
    {
        for attempt in 0..=timeout {
            match LocalStream::connect(path.as_ref()).await {
                Ok(stream) => return Self::from_stream(stream, timeout, handler).await,
                Err(e)
                    if attempt < timeout
                        && matches!(
                            e.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                        ) =>
                {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    pub async fn acknowledge_exit(&mut self, id: u64) -> io::Result<()> {
        write_message(&mut self.stream, &Message::ExitAck { id }).await
    }

    async fn call(&mut self, command: Command) -> io::Result<RemoteCommandResult<Value>> {
        self.last_msg_id += 1;
        let id = self.last_msg_id;
        write_message(&mut self.stream, &Message::Request { id, command }).await?;
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(30), self.responses.next())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "guest agent response timed out")
                })?;
        match response {
            Some((response_id, response)) if response_id == id => Ok(response.map_err(|e| {
                log::error!(
                    "Guest agent request {id}: {} (errno {})",
                    e.message,
                    e.errno
                );
                e.errno
            })),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest response ID mismatch",
            )),
            None => {
                let error = match self.responses_reader_handle.take() {
                    Some(handle) => handle.await.unwrap_or_else(io::Error::other),
                    None => io::Error::new(io::ErrorKind::BrokenPipe, "guest agent disconnected"),
                };
                Err(error)
            }
        }
    }

    async fn ok(&mut self, command: Command) -> io::Result<RemoteCommandResult<()>> {
        match self.call(command).await? {
            Ok(Value::Ok) => Ok(Ok(())),
            Err(e) => Ok(Err(e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected empty agent response",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn_new_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        cwd: Option<&str>,
        entrypoint: bool,
    ) -> io::Result<RemoteCommandResult<u64>> {
        let command = Command::Run(Run {
            bin: bin.as_bytes().to_vec(),
            argv: argv.iter().map(|s| s.as_bytes().to_vec()).collect(),
            env: env.map(|vars| vars.iter().map(|s| s.as_bytes().to_vec()).collect()),
            uid,
            gid,
            fds: std::array::from_fn(|i| {
                fds[i].as_ref().map(|fd| match fd {
                    RedirectFdType::RedirectFdFile(path) => Redirect::File(path.to_vec()),
                    RedirectFdType::RedirectFdPipeBlocking(capacity) => Redirect::Pipe {
                        capacity: *capacity,
                        cyclic: false,
                    },
                    RedirectFdType::RedirectFdPipeCyclic(capacity) => Redirect::Pipe {
                        capacity: *capacity,
                        cyclic: true,
                    },
                })
            }),
            cwd: cwd.map(|s| s.as_bytes().to_vec()),
            entrypoint,
        });
        match self.call(command).await? {
            Ok(Value::Id(id)) => Ok(Ok(id)),
            Err(e) => Ok(Err(e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected process ID",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        cwd: Option<&str>,
    ) -> io::Result<RemoteCommandResult<u64>> {
        self.spawn_new_process(bin, argv, env, uid, gid, fds, cwd, false)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn run_entrypoint(
        &mut self,
        bin: &str,
        argv: &[&str],
        env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        cwd: Option<&str>,
    ) -> io::Result<RemoteCommandResult<u64>> {
        self.spawn_new_process(bin, argv, env, uid, gid, fds, cwd, true)
            .await
    }
    pub async fn quit(&mut self) -> io::Result<RemoteCommandResult<()>> {
        self.ok(Command::Quit).await
    }
    pub async fn kill(&mut self, id: u64) -> io::Result<RemoteCommandResult<()>> {
        self.ok(Command::Kill { id }).await
    }
    pub async fn mount(&mut self, tag: &str, path: &str) -> io::Result<RemoteCommandResult<()>> {
        self.ok(Command::Mount {
            tag: tag.into(),
            path: path.as_bytes().to_vec(),
        })
        .await
    }
    pub async fn add_hosts<I, T, S>(&mut self, hosts: I) -> io::Result<RemoteCommandResult<()>>
    where
        I: Iterator<Item = (T, S)>,
        T: AsRef<str>,
        S: AsRef<str>,
    {
        self.ok(Command::Hosts {
            entries: hosts
                .map(|(name, ip)| (name.as_ref().into(), ip.as_ref().into()))
                .collect(),
        })
        .await
    }
    pub async fn create_network(
        &mut self,
        addr: &str,
        mask: &str,
        gateway: &str,
        iface: u16,
    ) -> io::Result<RemoteCommandResult<()>> {
        self.ok(Command::Network(Network {
            iface,
            addr: Some(addr.into()),
            mask: Some(mask.into()),
            gateway: Some(gateway.into()),
            if_addr: None,
        }))
        .await
    }
    pub async fn add_address(
        &mut self,
        addr: &str,
        mask: &str,
        iface: u16,
    ) -> io::Result<RemoteCommandResult<()>> {
        self.ok(Command::Network(Network {
            iface,
            addr: None,
            mask: Some(mask.into()),
            gateway: None,
            if_addr: Some(addr.into()),
        }))
        .await
    }
    pub async fn query_output(
        &mut self,
        id: u64,
        fd: u8,
        offset: u64,
        len: u64,
    ) -> io::Result<RemoteCommandResult<Vec<u8>>> {
        match self
            .call(Command::QueryOutput {
                id,
                fd,
                offset,
                len,
            })
            .await?
        {
            Ok(Value::Bytes(bytes)) => Ok(Ok(bytes)),
            Err(e) => Ok(Err(e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected output bytes",
            )),
        }
    }
}

async fn read_responses(
    mut stream: ReadHalf<LocalStream>,
    mut responses: mpsc::Sender<(u64, Result<Value, AgentError>)>,
    events: mpsc::UnboundedSender<Notification>,
) -> io::Error {
    loop {
        match read_message(&mut stream).await {
            Ok(Message::Response { id, result }) => {
                if responses.send((id, result)).await.is_err() {
                    return io::Error::new(io::ErrorKind::BrokenPipe, "response receiver closed");
                }
            }
            Ok(Message::Event(event)) => {
                let _ = events.unbounded_send(event);
            }
            Ok(_) => return io::Error::new(io::ErrorKind::InvalidData, "unexpected guest message"),
            Err(e) => return e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    #[tokio::test]
    async fn accepted_stream_waits_for_ready_then_completes_a_command() {
        let (host, mut guest) = LocalStream::pair().unwrap();
        let mut connection =
            tokio::spawn(GuestAgent::from_stream(host, 2, |_, _| async {}.boxed()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut connection)
                .await
                .is_err()
        );
        write_message(&mut guest, &Message::Ready { version: VERSION })
            .await
            .unwrap();
        let agent = connection.await.unwrap().unwrap();
        let copy = agent.clone();
        let mount = tokio::spawn(async move { copy.lock().await.mount("mnt0", "/out").await });
        let Message::Request {
            id,
            command: Command::Mount { .. },
        } = read_message(&mut guest).await.unwrap()
        else {
            panic!("expected mount")
        };
        write_message(
            &mut guest,
            &Message::Response {
                id,
                result: Ok(Value::Ok),
            },
        )
        .await
        .unwrap();
        assert!(mount.await.unwrap().unwrap().is_ok());
        agent
            .lock()
            .await
            .responses_reader_handle
            .take()
            .unwrap()
            .abort();
    }
    #[tokio::test]
    async fn refuses_incompatible_agent() {
        let (host, mut guest) = LocalStream::pair().unwrap();
        write_message(
            &mut guest,
            &Message::Ready {
                version: VERSION + 1,
            },
        )
        .await
        .unwrap();
        assert!(
            GuestAgent::from_stream(host, 2, |_, _| async {}.boxed())
                .await
                .is_err()
        );
    }
}
