use std::io::{self, prelude::*};
use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::{thread, time};

pub use crate::response_parser::Notification;
use crate::response_parser::{parse_one_response, GuestAgentMessage, Response};

#[repr(u8)]
enum MsgType {
    MsgQuit = 1,
    MsgRunProcess,
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

pub struct GuestAgent<F>
where
    F: FnMut(Notification) -> (),
{
    stream: UnixStream,
    last_msg_id: u64,
    notification_handler: F,
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

type RemoteCommandResult<T> = Result<T, /* exit code */ u32>;

impl<F> GuestAgent<F>
where
    F: FnMut(Notification) -> (),
{
    pub fn connected(
        path: &str,
        timeout: u32,
        notification_handler: F,
    ) -> io::Result<GuestAgent<F>> {
        let mut timeout_remaining = timeout;
        loop {
            match UnixStream::connect(path) {
                Ok(s) => {
                    break Ok(GuestAgent {
                        stream: s,
                        last_msg_id: 0,
                        notification_handler: notification_handler,
                    })
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::NotFound => {
                        println!("Waiting for Guest Agent socket ...");
                        if timeout_remaining > 0 {
                            thread::sleep(time::Duration::from_secs(1));
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

    fn get_one_response(&mut self) -> io::Result<GuestAgentMessage> {
        parse_one_response(&mut self.stream)
    }

    fn get_response(&mut self, msg_id: u64) -> io::Result<Response> {
        loop {
            match self.get_one_response()? {
                GuestAgentMessage::Notification(notification) => {
                    (self.notification_handler)(notification)
                }
                GuestAgentMessage::Response { id, resp } => {
                    break {
                        if id != msg_id {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Got response with different ID",
                            ));
                        }
                        Ok(resp)
                    }
                }
            }
        }
    }

    pub fn get_one_notification(&mut self) -> io::Result<Notification> {
        match self.get_one_response()? {
            GuestAgentMessage::Notification(notification) => Ok(notification),
            GuestAgentMessage::Response { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexptected response",
            )),
        }
    }

    pub fn quit(&mut self) -> io::Result<RemoteCommandResult<()>> {
        let mut msg = Message::default();
        let msg_id = self.get_new_msg_id();
        msg.create_header(msg_id);
        msg.append_submsg(&SubMsgQuitType::SubMsgEnd);
        self.stream.write_all(msg.as_ref())?;
        let ret = match self.get_response(msg_id)? {
            Response::Ok => Ok(()),
            Response::Err(code) => Err(code),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "quit: invalid response",
                ))
            }
        };
        Ok(ret)
    }

    pub fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType>; 3],
        maybe_cwd: Option<&str>,
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

        msg.append_submsg(&SubMsgRunProcessType::SubMsgEnd);

        self.stream.write_all(msg.as_ref())?;

        let ret = match self.get_response(msg_id)? {
            Response::OkU64(val) => Ok(val),
            Response::Err(code) => Err(code),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "run_process: invalid response",
                ))
            }
        };
        Ok(ret)
    }
}
