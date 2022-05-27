use std::{collections::HashMap, env, fs, path::{Path, PathBuf}, sync::Arc};
use std::process::Stdio;
use std::time::Duration;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt}, spawn,
};
use tokio::{
    process::Child,
    sync::{self, Mutex},
};
use crate::{
    guest_agent_comm::{GuestAgent, Notification, RedirectFdType},
    vm::{VMBuilder, VM},
};

#[derive(Default)]
pub struct VMRunner {
    instance: Option<Child>,
}

pub enum ReaderOutputType {
    StdOutput,
    StdError
}

async fn reader_to_log<T: io::AsyncRead + Unpin>(reader: T, streamType: ReaderOutputType) {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => {
                log::warn!("VM: reader.read_until returned 0");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                match streamType {
                    ReaderOutputType::StdOutput => {
                        log::debug!("VM: {}", String::from_utf8_lossy(&bytes).trim_end());
                    },
                    ReaderOutputType::StdError => {
                        log::debug!("VM Error Stream: {}", String::from_utf8_lossy(&bytes).trim_end());
                    }
                }
                buf.clear();
            }
            Err(e) => log::error!("VM output error: {}", e),
        }
    }
}

/*
async fn reader_to_log_error<T: io::AsyncRead + Unpin>(reader: T) {
    let mut reader = io::BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => {
                log::warn!("VM ERROR: reader.read_until returned 0");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => {
                let bytes = strip_ansi_escapes::strip(&buf).unwrap();
                log::debug!(
                    "VM ERROR STREAM: {}",
                    String::from_utf8_lossy(&bytes).trim_end()
                );
                buf.clear();
            }
            Err(e) => log::error!("VM stderr error: {}", e),
        }
    }
}*/


impl VMRunner {
    pub fn run_vm(&mut self, vm: &VM, runtime_dir: PathBuf) {
        #[cfg(windows)]
            let vm_executable = "vmrt.exe";
        #[cfg(unix)]
            let vm_executable = "vmrt";


        let mut cmd = vm.create_cmd(&runtime_dir.join(vm_executable));
        cmd.current_dir(runtime_dir);
        let mut instance = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn().unwrap();

        let stdout = instance.stdout.take().unwrap();
        let stderr = instance.stderr.take().unwrap();
        spawn(reader_to_log(stdout, ReaderOutputType::StdOutput));
        spawn(reader_to_log(stderr, ReaderOutputType::StdError));

        self.instance = Some(instance);
    }
}