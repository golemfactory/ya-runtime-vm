use std::convert::TryFrom;
use std::io::{self, prelude::*};
use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::{thread, time};

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
}

pub enum RedirectFdType<'a> {
    RedirectFdFile(&'a [u8]),
    RedirectFdPipeBlocking(u64),
    RedirectFdPipeCyclic(u64),
}

enum Response {
    Ok,
    OkU64(u64),
    OkBytes(Vec<u8>),
    Err(u32),
}

#[derive(Debug)]
pub enum ExitReason {
    Exited(u8),
    Killed(u8),
    Dumped(u8),
}

impl TryFrom<u32> for ExitReason {
    type Error = io::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v >> 30 {
            0 => Ok(ExitReason::Exited((v & 0xff) as u8)),
            1 => Ok(ExitReason::Killed((v & 0xff) as u8)),
            2 => Ok(ExitReason::Dumped((v & 0xff) as u8)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid exit reason",
            )),
        }
    }
}

pub enum Notification {
    OutputAvailable { id: u64, fd: u32 },
    ProcessDied { id: u64, reason: ExitReason },
}

enum GuestAgentMessage {
    Response { id: u64, resp: Response },
    Notification(Notification),
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

    fn recv_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0; 1];
        self.stream.read_exact(&mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    fn recv_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0; 4];
        self.stream.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn recv_u64(&mut self) -> io::Result<u64> {
        let mut buf = [0; 8];
        self.stream.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn recv_bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.recv_u64()?;
        let mut buf = vec![0; len as usize];
        self.stream.read_exact(buf.as_mut_slice())?;
        Ok(buf)
    }

    fn get_one_response(&mut self) -> io::Result<GuestAgentMessage> {
        let id = self.recv_u64()?;

        let typ = self.recv_u8()?;
        match typ {
            0 => Ok(GuestAgentMessage::Response {
                id: id,
                resp: Response::Ok,
            }),
            1 => {
                let val = self.recv_u64()?;
                Ok(GuestAgentMessage::Response {
                    id: id,
                    resp: Response::OkU64(val),
                })
            }
            2 => {
                let buf = self.recv_bytes()?;
                Ok(GuestAgentMessage::Response {
                    id: id,
                    resp: Response::OkBytes(buf),
                })
            }
            3 => {
                let code = self.recv_u32()?;
                Ok(GuestAgentMessage::Response {
                    id: id,
                    resp: Response::Err(code),
                })
            }
            4 => {
                if id == 0 {
                    let proc_id = self.recv_u64()?;
                    let fd = self.recv_u32()?;
                    Ok(GuestAgentMessage::Notification(
                        Notification::OutputAvailable {
                            id: proc_id,
                            fd: fd,
                        },
                    ))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid response message ID",
                    ))
                }
            }
            5 => {
                if id == 0 {
                    let proc_id = self.recv_u64()?;
                    let reason = ExitReason::try_from(self.recv_u32()?)?;
                    Ok(GuestAgentMessage::Notification(Notification::ProcessDied {
                        id: proc_id,
                        reason: reason,
                    }))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid response message ID",
                    ))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid response type",
            )),
        }
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

    pub fn quit(&mut self) -> io::Result<Result<(), u32>> {
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
    ) -> io::Result<Result<u64, u32>> {
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
