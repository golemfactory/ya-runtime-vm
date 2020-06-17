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

#[repr(u8)]
#[derive(Debug)]
enum RespType {
    RespOk = 0,
    RespErr,
    NotifyOutputAvailable,
    NotifyProcessDied,
}

struct Message<T> {
    buf: Vec<u8>,
    phantom: PhantomData<T>,
}

pub struct GuestAgent {
    stream: UnixStream,
    last_msg_id: u64,
}

impl TryFrom<u8> for RespType {
    type Error = io::Error;

    fn try_from(x: u8) -> io::Result<Self> {
        match x {
            0 => Ok(RespType::RespOk),
            1 => Ok(RespType::RespErr),
            2 => Ok(RespType::NotifyOutputAvailable),
            3 => Ok(RespType::NotifyProcessDied),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid response type",
            )),
        }
    }
}

trait EncodeInto {
    fn encode_into(&self, buf: &mut Vec<u8>);
}

trait SubMsgTrait<T>: EncodeInto {
    fn get_type() -> u8;
}

impl SubMsgTrait<SubMsgQuitType> for SubMsgQuitType {
    fn get_type() -> u8 {
        MsgType::MsgQuit as u8
    }
}

impl SubMsgTrait<SubMsgRunProcessType<'_>> for SubMsgRunProcessType<'_> {
    fn get_type() -> u8 {
        MsgType::MsgRunProcess as u8
    }
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

fn new_quit_message() -> Message<SubMsgQuitType> {
    Message::<SubMsgQuitType> {
        buf: Vec::new(),
        phantom: PhantomData,
    }
}

fn new_run_process_message<'a>() -> Message<SubMsgRunProcessType<'a>> {
    Message::<SubMsgRunProcessType> {
        buf: Vec::new(),
        phantom: PhantomData,
    }
}

impl<T> Message<T>
where
    T: SubMsgTrait<T>,
{
    fn create_header(&mut self, msg_id: u64) {
        self.buf.extend(&msg_id.to_le_bytes());
        self.buf.extend(&T::get_type().to_le_bytes());
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

impl GuestAgent {
    pub fn connected(path: &str, timeout: u32) -> io::Result<GuestAgent> {
        let mut timeout_remaining = timeout;
        loop {
            match UnixStream::connect(path) {
                Ok(s) => {
                    break Ok(GuestAgent {
                        stream: s,
                        last_msg_id: 0,
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

    fn get_response(&mut self) -> io::Result<()> {
        let mut buf = [0; 8];
        self.stream.read_exact(&mut buf)?;
        let id = u64::from_le_bytes(buf);
        println!("Message ID: {}", id);

        let mut buf = [0; 1];
        self.stream.read_exact(&mut buf)?;
        let typ = RespType::try_from(buf[0])?;
        println!("Message type: {:?}", typ);
        match typ {
            RespType::RespOk => (),
            RespType::RespErr => {
                let mut buf = [0; 4];
                self.stream.read_exact(&mut buf)?;
                let code = u32::from_le_bytes(buf);
                println!("Error code: {}", code);
            }
            RespType::NotifyOutputAvailable => (),
            RespType::NotifyProcessDied => (),
        };
        Ok(())
    }

    pub fn quit(&mut self) -> io::Result<()> {
        let mut msg = new_quit_message();
        msg.create_header(self.get_new_msg_id());
        msg.append_submsg(&SubMsgQuitType::SubMsgEnd);
        self.stream.write_all(msg.as_ref())?;
        self.get_response()?;
        Ok(())
    }

    pub fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
        gid: u32,
        fds: &[Option<RedirectFdType>; 3],
    ) -> io::Result<()> {
        let mut msg = new_run_process_message();

        msg.create_header(self.get_new_msg_id());

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessBin(bin.as_bytes()));

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessArg(
            &argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
        ));

        match maybe_env {
            Some(env) => {
                msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessEnv(
                    &env.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
                ));
            }
            None => (),
        }

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessUid(uid));

        msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessGid(gid));

        for (i, maybe_fd_redir) in fds.iter().enumerate() {
            match maybe_fd_redir {
                Some(fd_redir) => msg.append_submsg(&SubMsgRunProcessType::SubMsgRunProcessRfd(
                    i as u32, fd_redir,
                )),
                None => (),
            }
        }

        msg.append_submsg(&SubMsgRunProcessType::SubMsgEnd);

        self.stream.write_all(msg.as_ref())?;
        self.get_response()?;
        Ok(())
    }
}
