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

impl RespType {
    fn from_u8(x: u8) -> io::Result<Self> {
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

struct GuestAgent {
    stream: UnixStream,
    last_msg_id: u64,
}

impl GuestAgent {
    fn connected(path: &str) -> io::Result<GuestAgent> {
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

    fn get_response(&mut self) -> io::Result<()> {
        let mut buf = [0; 8];
        self.stream.read_exact(&mut buf)?;
        let id = u64::from_le_bytes(buf);
        println!("Message ID: {}", id);

        let mut buf = [0; 1];
        self.stream.read_exact(&mut buf)?;
        let typ = RespType::from_u8(buf[0])?;
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

    fn quit(&mut self) -> io::Result<()> {
        let mut buf = GuestAgent::create_header(self.get_new_msg_id(), MsgType::MsgQuit);
        GuestAgent::append_submsg_type(&mut buf, MsgSubType::SubMsgEnd);
        self.stream.write_all(&buf)?;
        self.get_response()?;
        Ok(())
    }

    fn run_process(
        &mut self,
        bin: &str,
        argv: &[&str],
        maybe_env: Option<&[&str]>,
        uid: u32,
    ) -> io::Result<()> {
        let mut buf = GuestAgent::create_header(self.get_new_msg_id(), MsgType::MsgRunProcess);
        GuestAgent::append_submsg_bytes(&mut buf, MsgSubType::SubMsgRunProcessBin, bin.as_bytes());
        GuestAgent::append_submsg_array(
            &mut buf,
            MsgSubType::SubMsgRunProcessArg,
            &argv.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
        );
        match maybe_env {
            Some(env) => GuestAgent::append_submsg_array(
                &mut buf,
                MsgSubType::SubMsgRunProcessEnv,
                &env.iter().map(|s| s.as_bytes()).collect::<Vec<_>>(),
            ),
            None => (),
        }
        GuestAgent::append_submsg_u32(&mut buf, MsgSubType::SubMsgRunProcessUid, uid);
        GuestAgent::append_submsg_type(&mut buf, MsgSubType::SubMsgEnd);
        self.stream.write_all(&buf)?;
        self.get_response()?;
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

    let argv = ["a0", "a1", "a2"];
    ga.run_process("binary_name", &argv, None, 0).unwrap();
    println!("");

    ga.quit().unwrap();

    let e = child.wait().expect("failed to wait on child");
    println!("{:?}", e);
}
