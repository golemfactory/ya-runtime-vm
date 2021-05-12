use futures::channel::mpsc;
use futures::future::{BoxFuture, FutureExt};
use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
use std::path::Path;
use std::sync::Arc;
use std::{io, marker::PhantomData};
use tokio::{
    io::{split, AsyncWriteExt, ReadHalf, WriteHalf},
    net::UnixStream,
    spawn, time,
};

pub use crate::response_parser::Notification;
use crate::response_parser::{parse_one_response, GuestAgentMessage, Response, ResponseWithId};

#[repr(u8)]
enum MsgType {
    MsgQuit = 1,
    MsgRunProcess,
    MsgKillProcess,
    MsgMountVolume,
    #[allow(unused)]
    MsgUploadFile,
    MsgQueryOutput,
}

enum SubMsgQuitType {
    SubMsgEnd,
}

enum SubMsgRunProcessType<'a> {
    SubMsgEnd,
    SubMsgRunProcessBin(&'a [u8]),
    SubMsgRunProcessArg(&'a [&'a [u8]]),
    SubMsgRunProcessEnv(&'a [&'a [u8]]),
    SubMsgRunProcessUid(u32),
    SubMsgRunProcessGid(u32),
    SubMsgRunProcessRfd(u32, &'a RedirectFdType<'a>),
    SubMsgRunProcessCwd(&'a [u8]),
    SubMsgRunProcessEnt,
}

enum SubMsgKillProcessType {
    SubMsgEnd,
    SubMsgKillProcessId(u64),
}

enum SubMsgMountVolumeType<'a> {
    SubMsgEnd,
    SubMsgMountVolumeTag(&'a [u8]),
    SubMsgMountVolumePath(&'a [u8]),
}

enum SubMsgQueryOutputType {
    SubMsgEnd,
    SubMsgQueryOutputId(u64),
    SubMsgQueryOutputFd(u8),
    SubMsgQueryOutputOff(u64),
    SubMsgQueryOutputLen(u64),
}

pub enum RedirectFdType<'a> {
    RedirectFdFile(&'a [u8]),
    RedirectFdPipeBlocking(u64),
    RedirectFdPipeCyclic(u64),
}

struct Message<T> {
    buf: Vec<u8>,
    phantom: PhantomData<T>,
}

pub struct GuestAgent {
    stream: WriteHalf<UnixStream>,
    last_msg_id: u64,
    responses: mpsc::Receiver<ResponseWithId>,
    responses_reader_handle: Option<tokio::task::JoinHandle<io::Error>>,
}

trait EncodeInto {
    fn encode_into(&self, buf: &mut Vec<u8>);
}

trait SubMsgTrait<T>: EncodeInto {
    const TYPE: u8;
}

impl SubMsgTrait<SubMsgQuitType> for SubMsgQuitType {
    const TYPE: u8 = MsgType::MsgQuit as u8;
}

impl SubMsgTrait<SubMsgRunProcessType<'_>> for SubMsgRunProcessType<'_> {
    const TYPE: u8 = MsgType::MsgRunProcess as u8;
}

impl SubMsgTrait<SubMsgKillProcessType> for SubMsgKillProcessType {
    const TYPE: u8 = MsgType::MsgKillProcess as u8;
}

impl SubMsgTrait<SubMsgMountVolumeType<'_>> for SubMsgMountVolumeType<'_> {
    const TYPE: u8 = MsgType::MsgMountVolume as u8;
}

impl SubMsgTrait<SubMsgQueryOutputType> for SubMsgQueryOutputType {
    const TYPE: u8 = MsgType::MsgQueryOutput as u8;
}

impl EncodeInto for u8 {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_le_bytes());
    }
}

impl EncodeInto for u32 {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_le_bytes());
    }
}

impl EncodeInto for u64 {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.to_le_bytes());
    }
}

impl EncodeInto for [u8] {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        (self.len() as u64).encode_into(buf);
        buf.extend(self);
    }
}

impl EncodeInto for [&[u8]] {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        (self.len() as u64).encode_into(buf);
        for &a in self {
            a.encode_into(buf)
        }
    }
}

impl EncodeInto for SubMsgQuitType {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        0u8.encode_into(buf);
    }
}

impl EncodeInto for SubMsgRunProcessType<'_> {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            SubMsgRunProcessType::SubMsgEnd => {
                0u8.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessBin(path) => {
                1u8.encode_into(buf);
                path.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessArg(args) => {
                2u8.encode_into(buf);
                args.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessEnv(env) => {
                3u8.encode_into(buf);
                env.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessUid(uid) => {
                4u8.encode_into(buf);
                uid.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessGid(gid) => {
                5u8.encode_into(buf);
                gid.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessRfd(fd, redir_fd) => {
                6u8.encode_into(buf);
                fd.encode_into(buf);
                redir_fd.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessCwd(path) => {
                7u8.encode_into(buf);
                path.encode_into(buf);
            }
            SubMsgRunProcessType::SubMsgRunProcessEnt => {
                8u8.encode_into(buf);
            }
        }
    }
}

impl EncodeInto for RedirectFdType<'_> {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            RedirectFdType::RedirectFdFile(path) => {
                0u8.encode_into(buf);
                path.encode_into(buf);
            }
            RedirectFdType::RedirectFdPipeBlocking(size) => {
                1u8.encode_into(buf);
                size.encode_into(buf);
            }
            RedirectFdType::RedirectFdPipeCyclic(size) => {
                2u8.encode_into(buf);
                size.encode_into(buf);
            }
        }
    }
}

impl EncodeInto for SubMsgKillProcessType {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            SubMsgKillProcessType::SubMsgEnd => {
                0u8.encode_into(buf);
            }
            SubMsgKillProcessType::SubMsgKillProcessId(id) => {
                1u8.encode_into(buf);
                id.encode_into(buf);
            }
        }
    }
}

impl EncodeInto for SubMsgMountVolumeType<'_> {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            SubMsgMountVolumeType::SubMsgEnd => {
                0u8.encode_into(buf);
            }
            SubMsgMountVolumeType::SubMsgMountVolumeTag(tag) => {
                1u8.encode_into(buf);
                tag.encode_into(buf);
            }
            SubMsgMountVolumeType::SubMsgMountVolumePath(path) => {
                2u8.encode_into(buf);
                path.encode_into(buf);
            }
        }
    }
}

impl EncodeInto for SubMsgQueryOutputType {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            SubMsgQueryOutputType::SubMsgEnd => {
                0u8.encode_into(buf);
            }
            SubMsgQueryOutputType::SubMsgQueryOutputId(id) => {
                1u8.encode_into(buf);
                id.encode_into(buf);
            }
            SubMsgQueryOutputType::SubMsgQueryOutputFd(fd) => {
                2u8.encode_into(buf);
                fd.encode_into(buf);
            }
            SubMsgQueryOutputType::SubMsgQueryOutputOff(off) => {
                3u8.encode_into(buf);
                off.encode_into(buf);
            }
            SubMsgQueryOutputType::SubMsgQueryOutputLen(len) => {
                4u8.encode_into(buf);
                len.encode_into(buf);
            }
        }
    }
}

impl<T> Default for Message<T> {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            phantom: PhantomData,
        }
    }
}

impl<T> Message<T>
where
    T: SubMsgTrait<T>,
{
    fn create_header(&mut self, msg_id: u64) {
        self.buf.extend(&msg_id.to_le_bytes());
        self.buf.extend(&T::TYPE.to_le_bytes());
    }

    fn append_submsg<A: SubMsgTrait<T>>(&mut self, submsg: &A) {
        submsg.encode_into(&mut self.buf);
    }
}

impl<T> AsRef<Vec<u8>> for Message<T> {
    fn as_ref(&self) -> &Vec<u8> {
        &self.buf
    }
}

pub type RemoteCommandResult<T> = Result<T, /* exit code */ u32>;

fn reader<'f, F>(
    agent: Arc<Mutex<GuestAgent>>,
    mut stream: ReadHalf<UnixStream>,
    mut notification_handler: F,
    mut responses: mpsc::Sender<ResponseWithId>,
) -> BoxFuture<'f, io::Error>
where
    F: FnMut(Notification, Arc<Mutex<GuestAgent>>) -> BoxFuture<'static, ()> + Send + 'static,
{
    let (mut tx, rx) = mpsc::channel(8);
    spawn(async move {
        let _ = rx
            .for_each(|n| notification_handler(n, agent.clone()))
            .await;
    });
    async move {
        loop {
            match parse_one_response(&mut stream).await {
                Ok(msg) => match msg {
                    GuestAgentMessage::Notification(notification) => {
                        let _ = tx.send(notification).await;
                    }
                    GuestAgentMessage::Response(resp) => {
                        responses.send(resp).await.expect("failed to send response");
                    }
                },
                Err(err) => return err,
            }
        }
    }
    .boxed()
}

impl GuestAgent {
    pub async fn connected<F, P>(
        path: P,
        timeout: u32,
        notification_handler: F,
    ) -> io::Result<Arc<Mutex<GuestAgent>>>
    where
        F: FnMut(Notification, Arc<Mutex<GuestAgent>>) -> BoxFuture<'static, ()> + Send + 'static,
        P: AsRef<Path>,
    {
        let mut timeout_remaining = timeout;
        loop {
            match UnixStream::connect(&path).await {
                Ok(s) => {
                    let (stream_read, stream_write) = split(s);
                    let (response_send, response_receive) = mpsc::channel(10);
                    let ga = Arc::new(Mutex::new(GuestAgent {
                        stream: stream_write,
                        last_msg_id: 0,
                        responses: response_receive,
                        responses_reader_handle: None,
                    }));
                    let reader_handle = spawn(reader(
                        ga.clone(),
                        stream_read,
                        notification_handler,
                        response_send,
                    ));
                    ga.lock()
                        .await
                        .responses_reader_handle
                        .replace(reader_handle);
                    break Ok(ga);
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::NotFound => {
                        log::info!("Waiting for Guest Agent socket ...");
                        if timeout_remaining > 0 {
                            time::delay_for(time::Duration::from_secs(1)).await;
                            timeout_remaining -= 1;
                        } else {
                            break Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "Could not connect to the Guest Agent socket",
                            ));
                        }
                    }
                    _ => break Err(err),
                },
            };
        }
    }

    fn get_new_msg_id(&mut self) -> u64 {
        self.last_msg_id += 1;
        self.last_msg_id
    }

    async fn get_response(&mut self, msg_id: u64) -> io::Result<Response> {
        let ResponseWithId { id, resp } = match self.responses.next().await {
            Some(x) => x,
            None => {
                return Err(self
                    .responses_reader_handle
                    .take()
                    .unwrap()
                    .await
                    .unwrap_or_else(|join_error| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Unexpected error in reader task: {}", join_error),
                        )
                    }))
            }
        };

        if id != msg_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Got response with different ID",
            ));
        }
        Ok(resp)
    }

    fn match_error<T>(resp: Response) -> io::Result<RemoteCommandResult<T>> {
        match resp {
            Response::Err(code) => Ok(Err(code)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid response",
            )),
        }
    }

    async fn get_ok_response(&mut self, msg_id: u64) -> io::Result<RemoteCommandResult<()>> {
        match self.get_response(msg_id).await? {
            Response::Ok => Ok(Ok(())),
            x => GuestAgent::match_error(x),
        }
    }

    async fn get_u64_response(&mut self, msg_id: u64) -> io::Result<RemoteCommandResult<u64>> {
        match self.get_response(msg_id).await? {
            Response::OkU64(val) => Ok(Ok(val)),
            x => GuestAgent::match_error(x),
        }
    }

    async fn get_bytes_response(
        &mut self,
        msg_id: u64,
    ) -> io::Result<RemoteCommandResult<Vec<u8>>> {
        match self.get_response(msg_id).await? {
            Response::OkBytes(bytes) => Ok(Ok(bytes)),
            x => GuestAgent::match_error(x),
        }
    }

    pub async fn quit(&mut self) -> io::Result<RemoteCommandResult<()>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();

        msg.create_header(msg_id);

        msg.append_submsg(&SubMsgQuitType::SubMsgEnd);

        self.stream.write_all(msg.as_ref()).await?;

        self.get_ok_response(msg_id).await
    }

    async fn spawn_new_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        maybe_cwd: Option<&str>,
        is_entrypoint: bool,
    ) -> io::Result<RemoteCommandResult<u64>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();

        msg.create_header(msg_id);

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessBin(bin.as_bytes()));

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessArg(
            &argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
        ));

        if let Some(env) = maybe_env {
            msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessEnv(
                &env.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
            ));
        }

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessUid(uid));

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessGid(gid));

        fds.iter()
            .enumerate()
            .filter_map(|(i, fdr)| fdr.as_ref().map(|fdr| (i, fdr)))
            .for_each(|(i, fdr)| {
                msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessRfd(i as u32, fdr))
            });

        if let Some(cwd) = maybe_cwd {
            msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessCwd(cwd.as_bytes()));
        }

        if is_entrypoint {
            msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessEnt);
        }

        msg.append_submsg(&SubMsgRunProcessType::SubMsgEnd);

        self.stream.write_all(msg.as_ref()).await?;

        self.get_u64_response(msg_id).await
    }

    pub async fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        maybe_cwd: Option<&str>,
    ) -> io::Result<RemoteCommandResult<u64>> {
        self.spawn_new_process(
            bin, argv, maybe_env, uid, gid, fds, maybe_cwd, /*is_entrypoint=*/ false,
        )
        .await
    }

    pub async fn run_entrypoint(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType<'_>>; 3],
        maybe_cwd: Option<&str>,
    ) -> io::Result<RemoteCommandResult<u64>> {
        self.spawn_new_process(
            bin, argv, maybe_env, uid, gid, fds, maybe_cwd, /*is_entrypoint=*/ true,
        )
        .await
    }

    pub async fn kill(&mut self, id: u64) -> io::Result<RemoteCommandResult<()>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();

        msg.create_header(msg_id);

        msg.append_submsg(&SubMsgKillProcessType::SubMsgKillProcessId(id));

        msg.append_submsg(&SubMsgKillProcessType::SubMsgEnd);

        self.stream.write_all(msg.as_ref()).await?;

        self.get_ok_response(msg_id).await
    }

    pub async fn mount(&mut self, tag: &str, path: &str) -> io::Result<RemoteCommandResult<()>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();

        msg.create_header(msg_id);

        msg.append_submsg(&SubMsgMountVolumeType::SubMsgMountVolumeTag(tag.as_bytes()));

        msg.append_submsg(&SubMsgMountVolumeType::SubMsgMountVolumePath(
            path.as_bytes(),
        ));

        msg.append_submsg(&SubMsgMountVolumeType::SubMsgEnd);

        self.stream.write_all(msg.as_ref()).await?;

        self.get_ok_response(msg_id).await
    }

    pub async fn query_output(
        &mut self,
        id: u64,
        fd: u8,
        off: u64,
        len: u64,
    ) -> io::Result<RemoteCommandResult<Vec<u8>>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();

        msg.create_header(msg_id);

        msg.append_submsg(&SubMsgQueryOutputType::SubMsgQueryOutputId(id));
        msg.append_submsg(&SubMsgQueryOutputType::SubMsgQueryOutputFd(fd));
        msg.append_submsg(&SubMsgQueryOutputType::SubMsgQueryOutputOff(off));
        msg.append_submsg(&SubMsgQueryOutputType::SubMsgQueryOutputLen(len));

        msg.append_submsg(&SubMsgQueryOutputType::SubMsgEnd);

        self.stream.write_all(msg.as_ref()).await?;

        self.get_bytes_response(msg_id).await
    }
}
