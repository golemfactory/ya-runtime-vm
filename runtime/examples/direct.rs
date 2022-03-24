use anyhow::anyhow;
use futures::FutureExt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio::{
    process::{Child, Command},
    sync,
};
use ya_runtime_vm::demux_socket_comm::{start_demux_communication, DemuxSocketHandle};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_vm_file_server::InprocServer;

struct Notifications {
    process_died: sync::Notify,
    output_available: sync::Notify,
}

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: sync::Notify::new(),
            output_available: sync::Notify::new(),
        }
    }

    fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);
                self.output_available.notify_one();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.process_died.notify_one();
            }
        }
    }
}

async fn run_process_with_output(
    ga: &mut GuestAgent,
    notifications: &Notifications,
    bin: &str,
    argv: &[&str],
) -> io::Result<()> {
    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
            ],
            None,
        )
        .await?
        .expect("Run process failed");

    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    notifications.output_available.notified().await;

    match ga.query_output(id, 1, 0, u64::MAX).await? {
        Ok(out) => {
            println!("Output:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => println!("Output query failed with: {}", code),
    }
    Ok(())
}

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("invalid manifest dir")
}

fn get_root_dir() -> PathBuf {
    get_project_dir().parent().unwrap().canonicalize().unwrap()
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    path.as_ref()
        .join(file.to_string())
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn spawn_vm<'a, P: AsRef<Path>>(temp_path: P, mount_args: &'a [(&'a str, impl ToString)]) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let socket_net_path = temp_path.as_ref().join(format!("net.sock"));

    let p9_sock = "127.0.0.1:9005";

    let chardev_tcp = |n, p: &str| {
        let addr: SocketAddr = p.parse().unwrap();
        format!(
            "socket,host={},port={},server,id={}",
            addr.ip(),
            addr.port(),
            n
        )
    };

    let chardev =
        |name, path: &PathBuf| format!("socket,path={},server,nowait,id={}", path.display(), name);

    let mut cmd = Command::new("/home/szym/golem/ya-runtime-vm-master/runtime/poc/runtime/vmrt");
    cmd.current_dir(runtime_dir).args(&[
        "-m",
        "256m",
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        join_as_string(&init_dir, "vmlinuz-virt").as_str(),
        "-initrd",
        join_as_string(&init_dir, "initramfs.cpio.gz").as_str(),
        "-no-reboot",
        "-net",
        "none",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-append",
        "console=ttyS0 panic=1",
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        format!(
            "socket,path={},server,nowait,id=manager_cdev",
            temp_path.as_ref().join("manager.sock").display()
        )
        .as_str(),
        "-chardev",
        chardev("net_cdev", &socket_net_path).as_str(),
        "-chardev",
        chardev_tcp("p9_cdev", &p9_sock).as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-device",
        "virtserialport,chardev=net_cdev,name=net_port",
        "-device",
        "virtserialport,chardev=p9_cdev,name=p9_port",
        "-drive",
        format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            root_dir.join("squashfs_drive").display()
        )
        .as_str(),
    ]);
    for (tag, path) in mount_args.iter() {
        cmd.args(&[
            "-virtfs",
            &format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = tag,
                path = path.to_string()
            ),
        ]);
    }
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn VM")
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let inner_path = temp_path.join("inner");

    std::fs::create_dir_all(&inner_path).expect("Failed to create a dir inside temp dir");

    let notifications = Arc::new(Notifications::new());
    let mount_args = [
        ("tag0", temp_path.display()),
        ("tag1", inner_path.display()),
    ];
    let mut child = spawn_vm(&temp_path, &mount_args);

    let (p9streams, muxer_handle) = start_9p_service(&mount_args).await.unwrap();

    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected(
        temp_path.join("manager.sock").as_os_str().to_str().unwrap(),
        10,
        move |n, _g| {
            let notifications = ns.clone();
            async move { notifications.clone().handle(n) }.boxed()
        },
    )
    .await?;
    let mut ga = ga_mutex.lock().await;

    for (i, (tag, _)) in mount_args.iter().enumerate() {
        ga.mount(tag, &format!("/mnt/mnt{}/{}", i, tag))
            .await?
            .expect("Mount failed");
    }

    run_process_with_output(&mut ga, &notifications, "/bin/ls", &["ls", "-al", "/mnt"]).await?;

    run_process_with_output(
        &mut ga,
        &notifications,
        "/bin/ls",
        &["ls", "-al", "/mnt/mnt1/tag1"],
    )
    .await?;

    test_write(&mut ga, &notifications).await?;

    test_start_and_kill(&mut ga, &notifications).await?;

    test_big_write(&mut ga, &notifications).await?;

    // ga.quit().await?.expect("Quit failed");

    let id = ga
        .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &NO_REDIR, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    /* VM should quit now. */
    let e = child.wait().await.expect("failed to wait on child");
    println!("{:?}", e);

    Ok(())
}

async fn connect_to_vm_9p_endpoint(address: &str, tries: i32) -> anyhow::Result<TcpStream> {
    log::debug!("Connect to the VM 9P endpoint...");

    for _ in 0..tries {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                log::debug!("Connected to the VM 9P endpoint");
                return Ok(stream);
            }
            Err(e) => {
                log::debug!("Failed to connect to the VM 9P endpoint: {e}");
                // The VM is not ready yet, try again
                sleep(Duration::from_secs(1)).await;
            }
        };
    }

    Err(anyhow!(
        "Failed to connect to the VM 9P endpoint after #{tries} tries"
    ))
}

// mount_args: &'a [(&'a str, impl ToString)]
async fn start_9p_service(
    mount_args: &[(&str, impl ToString)],
) -> anyhow::Result<(Vec<InprocServer>, DemuxSocketHandle)> {
    log::debug!("Connecting to the 9P VM endpoint...");
    let vmp9stream = connect_to_vm_9p_endpoint(&std::format!("127.0.0.1:{}", 9005), 10).await?;

    // TODO: make this common?
    log::debug!("Spawn 9P inproc servers...");

    let mut runtime_9ps = vec![];

    for (_, mount_point) in mount_args {
        let runtime_9p = InprocServer::new(&mount_point.to_string());
        runtime_9ps.push(runtime_9p);
    }

    log::debug!("Connect to 9P inproc servers...");

    let mut p9streams = vec![];

    for server in &runtime_9ps {
        let client_stream = server.attach_client();
        p9streams.push(client_stream);
    }

    let demux_socket_handle = start_demux_communication(vmp9stream, p9streams)?;

    // start_demux_communication(vm_stream, p9_streams);
    Ok((runtime_9ps, demux_socket_handle))
}

const NO_REDIR: [Option<RedirectFdType>; 3] = [None, None, None];

async fn test_big_write(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_big_write *****");
    let id = ga
        .run_process(
            "/bin/bash",
            &[
                "bash",
                "-c",
                "for i in {1..8000}; do echo -ne a >> /big; done; cat /big",
            ],
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                None,
            ],
            None,
        )
        .await
        .expect("Run process failed")
        .expect("Remote command failed");

    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    notifications.output_available.notified().await;

    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");

    println!("Big Output:");
    println!(
        "Big output 1: len: {} unexpected characters: {}",
        out.len(),
        out.iter().filter(|x| **x != 'a' as u8).count()
    );

    Ok(())
}

async fn test_start_and_kill(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_start_and_kill *****");

    let id = ga
        .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &NO_REDIR, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);

    ga.kill(id).await?.expect("Kill failed");

    // TODO: timeout
    notifications.process_died.notified().await;

    Ok(())
}

async fn test_write(ga: &mut GuestAgent, notifications: &Notifications) -> io::Result<()> {
    println!("***** test_write *****");

    let fds = [
        None,
        Some(RedirectFdType::RedirectFdFile(
            "/mnt/mnt1/tag1/write_test".as_bytes(),
        )),
        None,
    ];
    // Write something to the file
    let id = ga
        .run_process("/bin/echo", &["echo", "WRITE TEST"], None, 0, 0, &fds, None)
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;

    // Check it's there
    run_process_with_output(
        ga,
        &notifications,
        "/bin/cat",
        &["cat", "/mnt/mnt1/tag1/write_test"],
    )
    .await?;

    Ok(())
}
