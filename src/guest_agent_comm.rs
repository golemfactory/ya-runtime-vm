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

#[repr(u8)]
enum SubMsgQuitType {
    SubMsgEnd = 0,
}

#[repr(u8)]
enum SubMsgRunProcessType {
    SubMsgEnd = 0,
    SubMsgRunProcessBin,
    SubMsgRunProcessArg,
    SubMsgRunProcessEnv,
    SubMsgRunProcessUid,
    SubMsgRunProcessRfd,
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

trait SubMsgTrait: Into<u8> {
    fn get_type() -> MsgType;
}

impl SubMsgTrait for SubMsgQuitType {
    fn get_type() -> MsgType {
        MsgType::MsgQuit
    }
}

impl SubMsgTrait for SubMsgRunProcessType {
    fn get_type() -> MsgType {
        MsgType::MsgRunProcess
    }
}

impl Into<u8> for SubMsgQuitType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl Into<u8> for SubMsgRunProcessType {
    fn into(self) -> u8 {
        self as u8
    }
}

fn new_quit_message() -> Message<SubMsgQuitType> {
    Message::<SubMsgQuitType> {
        buf: Vec::new(),
        phantom: PhantomData,
    }
}

fn new_run_process_message() -> Message<SubMsgRunProcessType> {
    Message::<SubMsgRunProcessType> {
        buf: Vec::new(),
        phantom: PhantomData,
    }
}

impl<T: SubMsgTrait> Message<T> {
    fn create_header(&mut self, msg_id: u64) -> () {
        self.buf.extend_from_slice(&msg_id.to_le_bytes());
        self.buf
            .extend_from_slice(&(T::get_type() as u8).to_le_bytes());
    }

    fn append_submsg_type(&mut self, subtype: T) -> () {
        self.buf.extend(&subtype.into().to_le_bytes());
    }

    fn append_submsg_u32(&mut self, subtype: T, val: u32) -> () {
        self.append_submsg_type(subtype);
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    fn append_bytes(&mut self, bytes: &[u8]) -> () {
        self.buf.extend_from_slice(&bytes.len().to_le_bytes());
        self.buf.extend_from_slice(bytes);
    }

    fn append_submsg_bytes(&mut self, subtype: T, bytes: &[u8]) -> () {
        self.append_submsg_type(subtype);
        self.append_bytes(bytes);
    }

    fn append_submsg_array(&mut self, subtype: T, array: &[&[u8]]) -> () {
        self.append_submsg_type(subtype);
        self.buf.extend_from_slice(&array.len().to_le_bytes());
        for &a in array {
            self.append_bytes(&a);
        }
    }

    fn get_bytes(&mut self) -> &Vec<u8> {
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
        msg.append_submsg_type(SubMsgQuitType::SubMsgEnd);
        self.stream.write_all(msg.get_bytes())?;
        self.get_response()?;
        Ok(())
    }

    pub fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
    ) -> io::Result<()> {
        let mut msg = new_run_process_message();
        msg.create_header(self.get_new_msg_id());
        msg.append_submsg_bytes(SubMsgRunProcessType::SubMsgRunProcessBin, bin.as_bytes());
        msg.append_submsg_array(
            SubMsgRunProcessType::SubMsgRunProcessArg,
            &argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
        );
        match maybe_env {
            Some(env) => msg.append_submsg_array(
                SubMsgRunProcessType::SubMsgRunProcessEnv,
                &env.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
            ),
            None => (),
        }
        msg.append_submsg_u32(SubMsgRunProcessType::SubMsgRunProcessUid, uid);
        msg.append_submsg_type(SubMsgRunProcessType::SubMsgEnd);
        self.stream.write_all(msg.get_bytes())?;
        self.get_response()?;
        Ok(())
    }
}
