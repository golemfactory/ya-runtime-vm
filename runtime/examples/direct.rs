use futures::FutureExt;
use std::path::{Path, PathBuf};
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use std::str;
use tokio::{
    process::{Child, Command},
    sync,
};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_runtime_vm::guest_agent_9p::{GuestAgent9p, Notification9p};
use futures::lock::Mutex;
use log::debug;
use tokio::net::TcpStream;
use tokio::time::{delay_for, Duration};
use ya_runtime_vm::raw_socket_comm::RawSocketCommunication;


struct Notifications {
    process_died: sync::Notify,
    output_available: sync::Notify,
}

struct Servers9p {


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
                self.output_available.notify();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.process_died.notify();
            }
        }
    }
}

impl Servers9p {


    fn handle(&self, notification: Notification9p) {
        log::debug!("Received 9p message, forward it to proper server with tag: {0}", notification.tag);
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
    get_project_dir().parent().unwrap().to_owned()
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    path.as_ref()
        .join(file.to_string())
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}
fn spawn_9p_server(mount_point : String, port: i32) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let mut cmd = Command::new("C:/scx1332/FileServer9p/rust-9p/example/unpfs/target/debug/unpfs.exe");

    cmd.current_dir(runtime_dir).args(&[
        "--mount-point",
        mount_point.as_str(),
        "--network-address",
        std::format!("127.0.0.1:{}", port).as_str(),
        "--network-protocol",
        "tcp"]);
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn p9 server")
}

fn spawn_vm<'a, P: AsRef<Path>>(temp_path: P, mount_args: &'a [(&'a str, impl ToString)]) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let mut cmd = Command::new("vmrt");
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
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
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

async fn simple_run_command(ga_mutex: &Arc<Mutex<GuestAgent>>, bin: &str, argv: &[&str], dir: &str, notifications: Option<&Arc<Notifications>>) -> io::Result<()> {
    let mut ga = ga_mutex.lock().await;

    log::debug!("Command started: {0}", argv.join(" "));
    //io::stdout().write_all(std::format!("Command started: {0}\n", argv.join(" ")).as_str().as_bytes())?;

    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                None,
                None,
            ],
            Some(dir),
        )
        .await?
        .expect("Run process failed");
    //println!("Spawned process with id: {}", id);
    if let Some(notifications) = notifications {
        notifications.process_died.notified().await;
        //notifications.output_available.notified().await;
    }
    delay_for(Duration::from_millis(1000)).await;
    log::debug!("{}", "QUERY OUTPUT");
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");

    //println!("Output:");
    log::debug!("{}", str::from_utf8(&out).unwrap_or("CANNOT CONVERT"));

    log::debug!("Command finished: {0}", argv.join(" "));

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let inner_path = temp_path.join("inner");

    std::fs::create_dir_all(&inner_path).expect("Failed to create a dir inside temp dir");
    let notifications = Arc::new(Notifications::new());

    log::info!("Temp path: {:?}", temp_path);
    let mount_args = [
        ("tag0", temp_path.display()),
        ("tag1", inner_path.display()),
    ];
    let should_spawn_vm = false;
    if should_spawn_vm {


        let _child = spawn_vm(&temp_path, &mount_args);
    }





    let ns = notifications.clone();
    let ga_mutex = GuestAgent::connected("127.0.0.1:9003", 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n) }.boxed()
    })
    .await?;



    log::debug!("Spawn p9 servers...");
    {
        for (i, (tag, _)) in mount_args.iter().enumerate() {
            let _ = spawn_9p_server(std::format!("C:/golem/ya-runtime-vm/runtime/temp{}", i), 9101 + i as i32);
        }
    }
    delay_for(Duration::from_millis(1000)).await;

    log::debug!("Connect to p9 servers...");

    let mut vmp9stream: std::net::TcpStream = std::net::TcpStream::connect(std::format!("127.0.0.1:{}", 9005))?;

    let mut p9streams: Vec<std::net::TcpStream> = vec![];
    {
        for (i, (tag, _)) in mount_args.iter().enumerate() {
            let mut stream = std::net::TcpStream::connect(std::format!("127.0.0.1:{}", 9101 + i as i32))?;
            p9streams.push(stream);
        }
    }

    let mut r = RawSocketCommunication::new();
    r.start_raw_comm(vmp9stream, p9streams);

    /*
    let servers9p = Arc::new(Servers9p{writeHalfs: p9streams});

    let ns9p = servers9p.clone();
    let ga_pp = GuestAgent9p::connected("127.0.0.1:9005", 10, move |n, _g| {
        let notifications = ns9p.clone();
        async move { notifications.clone().handle(n) }.boxed()
    }).await?;
*/
    {
        let mut ga = ga_mutex.lock().await;
        log::debug!("start_mount");
        for (i, (tag, _)) in mount_args.iter().enumerate() {
            ga.mount(tag, &format!("/mnt/mnt{}/{}", i, tag))
                .await?
                .expect("Mount failed");
        }
    }
    log::debug!("end mnt loop");
    delay_for(Duration::from_millis(1000)).await;
    log::debug!("end delay");

    let no_redir = [None, None, None];

    simple_run_command(&ga_mutex, "/bin/ls", &["ls", "-la"], "/mnt/mnt0/tag0", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;
    simple_run_command(&ga_mutex, "/bin/ls", &["ls", "-la"], "/dev", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;
    simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "mkdir /mnt/mnt0/tag0/host_files  > /result.log 2> /error.log; echo output:; cat /result.log; echo errors:;cat /error.log"], "/mnt", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;
    //simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "echo DUPA >> /dev/vport0p3"], "/dev", Some(&notifications)).await?;

    //simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "mount -t 9p -o trans=fd,rfdno=/dev/vport0p3,wfdno=/dev/vport0p3,version=9p2000.L hostshare /mnt/host_files > /result.log 2> /error.log; echo output:; cat /result.log; echo errors:;cat /error.log"], "/dev", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;

    if false {
        let mut ga = ga_mutex.lock().await;


        //run_ls(&ga_mutex, &notifications, "/").await?;
        //run_ls(&ga_mutex, &notifications, "/bin").await?;
        //run_ls(&ga_mutex, &notifications, "/dev").await?;
        //run_ls(&ga_mutex, &notifications, "/mnt").await?;
        //run_cat(&ga_mutex, &notifications, "/dev", ".env").await?;




        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/ls",
            &["ls", "-al", "/mnt/mnt1/tag1"],
        )
        .await?;

        let fds = [
            None,
            Some(RedirectFdType::RedirectFdFile("/write_test".as_bytes())),
            None,
        ];
        let mut ga = ga_mutex.lock().await;

        let id = ga
            .run_process("/bin/echo", &["echo", "WRITE TEST"], None, 0, 0, &fds, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;

        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/cat",
            &["cat", "/mnt/mnt1/tag1/write_test"],
        )
        .await?;

        let id = ga
            .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &no_redir, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);

        ga.kill(id).await?.expect("Kill failed");
        notifications.process_died.notified().await;

        let id = ga
            .run_process(
                "/bin/bash",
                &[
                    "bash",
                    "-c",
                    "for i in {1..30}; do echo -ne a >> /big; sleep 1; done; cat /big",
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
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.output_available.notified().await;
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 1: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x61).count()
        );
        notifications.output_available.notified().await;
        ga.quit().await?.expect("Quit failed");
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 2: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x61).count()
        );

        let id = ga
            .run_process(
                "/bin/bash",
                &[
                    "bash",
                    "-c",
                    "echo > /big; for i in {1..4000}; do echo -ne a >> /big; done; for i in {1..4096}; do echo -ne b >> /big; done; cat /big",
                ],
                None,
                0,
                0,
                &[
                    None,
                    Some(RedirectFdType::RedirectFdPipeCyclic(0x1000)),
                    None,
                ],
                None,
            )
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;
        notifications.output_available.notified().await;
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 1: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x62).count()
        );

        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!("Big output 2: {}, expected 0", out.len());

        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &no_redir, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;

        /* VM should quit now. */
        //let e = child.await.expect("failed to wait on child");
        //println!("{:?}", e);
    }
    r.finish_raw_comm();
    Ok(())
}
