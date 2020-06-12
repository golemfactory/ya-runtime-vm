use std::io::{self, prelude::*};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::{thread, time};

#[repr(u8)]
enum MsgType {
    MsgQuit = 1,
    MsgRunProcess,
}

#[repr(u8)]
enum MsgSubType {
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

/* Is there a better way? */
impl RespType {
    fn from_u8(x: u8) -> Option<RespType> {
        match x {
            0 => Some(RespType::RespOk),
            1 => Some(RespType::RespErr),
            2 => Some(RespType::NotifyOutputAvailable),
            3 => Some(RespType::NotifyProcessDied),
            _ => None,
        }
    }
}

struct GuestAgent {
    stream: UnixStream,
    last_msg_id: u64,
}

impl GuestAgent {
    fn connected(path: &str) -> Result<GuestAgent, io::Error> {
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
                        thread::sleep(time::Duration::from_secs(1));
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

    fn create_header(msg_id: u64, typ: MsgType) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&msg_id.to_le_bytes());
        v.extend_from_slice(&(typ as u8).to_le_bytes());
        v
    }

    fn append_submsg_type(buf: &mut Vec<u8>, subtype: MsgSubType) -> () {
        buf.extend(&(subtype as u8).to_le_bytes());
    }

    fn append_submsg_u32(buf: &mut Vec<u8>, subtype: MsgSubType, val: u32) -> () {
        GuestAgent::append_submsg_type(buf, subtype);
        buf.extend_from_slice(&val.to_le_bytes());
    }

    fn append_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> () {
        buf.extend_from_slice(&bytes.len().to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    fn append_submsg_bytes(buf: &mut Vec<u8>, subtype: MsgSubType, bytes: &[u8]) -> () {
        GuestAgent::append_submsg_type(buf, subtype);
        GuestAgent::append_bytes(buf, bytes);
    }

    fn append_submsg_array(buf: &mut Vec<u8>, subtype: MsgSubType, array: &[&[u8]]) -> () {
        GuestAgent::append_submsg_type(buf, subtype);
        buf.extend_from_slice(&array.len().to_le_bytes());
        for &a in array {
            GuestAgent::append_bytes(buf, &a);
        }
    }

    fn get_response(&mut self) -> Result<(), io::Error> {
        let mut buf = [0; 8];
        self.stream.read_exact(&mut buf)?;
        let id = u64::from_le_bytes(buf);
        println!("Message ID: {}", id);

        let mut buf = [0; 1];
        self.stream.read_exact(&mut buf)?;
        let typ = RespType::from_u8(buf[0]).expect("Invalid response type!");
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

    fn quit(&mut self) -> Result<(), io::Error> {
        let mut buf = GuestAgent::create_header(self.get_new_msg_id(), MsgType::MsgQuit);
        GuestAgent::append_submsg_type(&mut buf, MsgSubType::SubMsgEnd);
        self.stream.write_all(&buf)?;
        self.get_response().unwrap();
        Ok(())
    }

    fn run_process(
        &mut self,
        bin: &[u8],
        argv: &[&[u8]],
        maybe_env: Option<&[&[u8]]>,
        uid: u32,
    ) -> Result<(), io::Error> {
        let mut buf = GuestAgent::create_header(self.get_new_msg_id(), MsgType::MsgRunProcess);
        GuestAgent::append_submsg_bytes(&mut buf, MsgSubType::SubMsgRunProcessBin, bin);
        GuestAgent::append_submsg_array(&mut buf, MsgSubType::SubMsgRunProcessArg, argv);
        match maybe_env {
            Some(env) => {
                GuestAgent::append_submsg_array(&mut buf, MsgSubType::SubMsgRunProcessEnv, env)
            }
            None => (),
        }
        GuestAgent::append_submsg_u32(&mut buf, MsgSubType::SubMsgRunProcessUid, uid);
        GuestAgent::append_submsg_type(&mut buf, MsgSubType::SubMsgEnd);
        self.stream.write_all(&buf)?;
        self.get_response().unwrap();
        Ok(())
    }
}

fn main() {
    let mut child = Command::new("qemu-system-x86_64")
        .args(&[
            "-m", "256m",
            "-nographic",
            "-vga", "none",
            "-kernel", "init-container/vmlinuz-virt",
            "-initrd", "init-container/initramfs.cpio.gz",
            "-no-reboot",
            "-net", "none",
            "-smp", "1",
            "-append", "console=ttyS0 panic=1",
            "-device", "virtio-serial",
            "-chardev", "socket,path=./manager.sock,server,nowait,id=manager_cdev",
            "-device", "virtserialport,chardev=manager_cdev,name=manager_port",
            "-drive", "file=./squashfs_drive,cache=none,readonly=on,format=raw,if=virtio"])
        .stdin(Stdio::null())
        .spawn()
        .expect("failed to spawn VM");

    let mut ga = GuestAgent::connected("./manager.sock").unwrap();

    let argv = vec!["a0".as_bytes(), "a1".as_bytes(), "a2".as_bytes()];
    ga.run_process("binary_name".as_bytes(), &argv, None, 0)
        .unwrap();
    println!("");

    ga.quit().unwrap();

    let e = child.wait().expect("failed to wait on child");
    println!("{:?}", e);
}
