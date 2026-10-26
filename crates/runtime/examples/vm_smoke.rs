//! Run via `mise run vm-test` on a host with KVM or WHP enabled.
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, ensure};
use futures::{FutureExt, future::BoxFuture, lock::Mutex};
use tokio::sync::mpsc;
use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::{
    EventEmitter,
    runtime_api::server::{self, RuntimeHandler},
};
use ya_runtime_vm::{
    deploy::Deployment, guest_agent_comm::RedirectFdType, network_mtu, vmrt::RuntimeData,
};

#[path = "vm_smoke/network.rs"]
mod network;

struct Events(mpsc::UnboundedSender<server::ProcessStatus>);
impl RuntimeHandler for Events {
    fn on_process_status<'a>(&self, status: server::ProcessStatus) -> BoxFuture<'a, ()> {
        let _ = self.0.send(status);
        async {}.boxed()
    }
    fn on_runtime_status<'a>(&self, _: server::RuntimeStatus) -> BoxFuture<'a, ()> {
        async {}.boxed()
    }
}

/// Process statuses in arrival order; statuses of the entrypoint, which runs
/// alongside other commands, are kept for it.
struct Statuses {
    receiver: mpsc::UnboundedReceiver<server::ProcessStatus>,
    entrypoint: Option<u64>,
    stashed: VecDeque<server::ProcessStatus>,
}
impl Statuses {
    async fn collect(&mut self, pid: u64) -> anyhow::Result<(Vec<u8>, Vec<u8>, i32)> {
        self.collect_up_to(pid, 1024 * 1024).await
    }
    async fn collect_up_to(
        &mut self,
        pid: u64,
        limit: usize,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, i32)> {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stashed = std::mem::take(&mut self.stashed);
        loop {
            let status = match stashed.pop_front() {
                Some(status) if status.pid == pid => status,
                Some(status) => {
                    self.stashed.push_back(status);
                    continue;
                }
                None => tokio::time::timeout(Duration::from_secs(10), self.receiver.recv())
                    .await?
                    .context("process event channel closed")?,
            };
            if status.pid != pid && Some(status.pid) == self.entrypoint {
                self.stashed.push_back(status);
                continue;
            }
            ensure!(status.pid == pid, "unexpected process ID {}", status.pid);
            out.extend(status.stdout);
            err.extend(status.stderr);
            ensure!(
                out.len() + err.len() <= limit,
                "unexpectedly large process output"
            );
            if !status.running {
                self.stashed.extend(stashed);
                return Ok((out, err, status.return_code));
            }
        }
    }
}

/// Output of the probe's `entrypoint` mode: numbered lines on both streams.
fn entrypoint_output() -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    for line in 0..ENTRYPOINT_LINES {
        out.extend(format!("OUT {line:07}\n").bytes());
        if line % 16 == 0 {
            err.extend(format!("ERR {line:07}\n").bytes());
        }
    }
    (out, err)
}
// 2.4 MB of stdout: about 600 times the runtime API's 4 KiB cyclic buffer.
const ENTRYPOINT_LINES: usize = 200_000;
const ENTRYPOINT_EXIT: i32 = 42;

async fn commands(
    data: Arc<Mutex<RuntimeData>>,
    mut events: Statuses,
    share: &Path,
    mode: &str,
) -> anyhow::Result<()> {
    let ga = data.lock().await.ga()?;
    let redirects = [
        None,
        Some(RedirectFdType::RedirectFdPipeBlocking(4096)),
        Some(RedirectFdType::RedirectFdPipeBlocking(4096)),
    ];
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "volumes"],
            None,
            0,
            0,
            &redirects,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("volume probe exec: {e}"))?;
    let (out, err, status) = events.collect(pid).await?;
    ensure!(
        status == 0 && out == b"VOLUMES_OK\n",
        "volume probe failed: {}",
        String::from_utf8_lossy(&err)
    );
    println!("VOLUMES_OK: explicit /tmp, /tmp/cache and /dev/shm/cache mounts remain visible");
    for role in 0..=1u8 {
        if (mode == "inet-only" && role == 0) || (mode == "vpn-only" && role == 1) {
            continue;
        }
        let (interface, route) = if role == 0 {
            (server::NetworkInterface::Vpn, "198.18.1.0")
        } else {
            // The runtime adds a default route for INET.
            (server::NetworkInterface::Inet, "")
        };
        let network = |address: String, mask: &str, gateway: String| server::Network {
            addr: route.into(),
            gateway,
            mask: mask.into(),
            if_addr: address,
        };
        let ipv4 = network(
            format!("10.{}.0.2", 71 + role),
            "24",
            format!("10.{}.0.1", 71 + role),
        );
        let ipv6 = network(
            format!("fd00:{}::2", 71 + role),
            "64",
            format!("fd00:{}::1", 71 + role),
        );
        let join = |networks| {
            ya_runtime_vm::join_network(
                data.clone(),
                server::CreateNetwork {
                    networks,
                    hosts: Default::default(),
                    interface: interface as i32,
                },
            )
        };
        join(vec![ipv4])
            .await
            .map_err(|e| anyhow::anyhow!("{interface:?} IPv4 network: {e:?}"))?;
        if role == 0 {
            // The guest rejects IPv6 below its 1280-byte minimum MTU.
            ensure!(
                join(vec![ipv6]).await.is_err(),
                "IPv6 was accepted on the {}-byte VPN MTU",
                network_mtu::VPN_MTU
            );
        } else {
            join(vec![ipv6])
                .await
                .map_err(|e| anyhow::anyhow!("{interface:?} IPv6 network: {e:?}"))?;
        }
    }
    let mtus = [
        server::NetworkInterface::Vpn,
        server::NetworkInterface::Inet,
    ]
    .map(|iface| network_mtu::guest_mtu(iface).to_string());
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "network", mode, &mtus[0], &mtus[1]],
            None,
            0,
            0,
            &redirects,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("network probe exec: {e}"))?;
    let (out, err, status) = events.collect(pid).await?;
    ensure!(
        status == 0,
        "network probe failed: {}",
        String::from_utf8_lossy(&err)
    );
    ensure!(out == format!("NETWORK_OK {mode}\n").as_bytes());
    if !err.is_empty() {
        log::info!("network probe: {}", String::from_utf8_lossy(&err).trim());
    }
    println!(
        "NETWORK_OK {mode}: host MTUs {}/{} applied; IPv4 and INET IPv6 packets up to the MTU crossed the expected Ethernet peers",
        mtus[0], mtus[1]
    );
    for (role, uid) in [("root", 0), ("user", 1000)] {
        let pid = ga
            .lock()
            .await
            .run_process(
                "/mnt/out/probe",
                &["probe", "files", role],
                None,
                uid,
                uid,
                &redirects,
                Some("/"),
            )
            .await?
            .map_err(|errno| anyhow::anyhow!("guest exec failed: errno={errno}"))?;
        let (out, err, status) = events.collect(pid).await?;
        ensure!(
            status == 0,
            "file probe failed: {}",
            String::from_utf8_lossy(&err)
        );
        ensure!(out == format!("FILES_OK {role}\n").as_bytes());
        ensure!(std::fs::read(share.join(role).join("renamed"))? == vec![b'Z'; 128]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file = std::fs::metadata(share.join(role).join("renamed"))?;
            ensure!(file.mode() & 0o7777 == 0o600);
            ensure!(file.uid() != 12345 && file.gid() != 23456);
            ensure!(std::fs::metadata(share.join(role))?.mode() & 0o7777 == 0o700);
        }
        println!("FILES_OK {role}: 3 MiB roundtrip, rename, truncate, host metadata");
    }
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "sleep"],
            None,
            0,
            0,
            &[None, None, None],
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("sleep exec: {e}"))?;
    ensure!(ga.lock().await.kill(pid).await?.is_ok());
    ensure!(events.collect(pid).await?.2 == 9);
    println!("KILL_OK");
    for _ in 0..16 {
        let pid = ga
            .lock()
            .await
            .run_process(
                "/mnt/out/probe",
                &["probe", "exit"],
                None,
                0,
                0,
                &[None, None, None],
                Some("/"),
            )
            .await?
            .map_err(|e| anyhow::anyhow!("rapid exec: {e}"))?;
        ensure!(events.collect(pid).await?.2 == 0);
    }
    println!("RAPID_EXITS_OK");
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["/mnt/out/probe", "background"],
            None,
            0,
            0,
            &redirects,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("background exec: {e}"))?;
    let (out, _, status) = events.collect(pid).await?;
    ensure!(status == 0 && out == b"BACKGROUND_STARTED\n");
    println!("BACKGROUND_EXIT_OK");
    // A relative working directory resolves inside the container root.
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "cwd"],
            None,
            1000,
            1000,
            &redirects,
            Some("mnt/out"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("relative cwd exec: {e}"))?;
    let (out, err, status) = events.collect(pid).await?;
    ensure!(
        status == 0 && out == b"/mnt/out\n",
        "relative cwd: status={status}, stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err)
    );
    println!("RELATIVE_CWD_OK");
    // The public runtime API uses cyclic output by default. Like the C init, a
    // full cyclic buffer applies backpressure; even a tiny one loses nothing.
    let cyclic = [
        None,
        Some(RedirectFdType::RedirectFdPipeCyclic(17)),
        Some(RedirectFdType::RedirectFdPipeCyclic(17)),
    ];
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "burst"],
            None,
            0,
            0,
            &cyclic,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("cyclic exec: {e}"))?;
    let (out, err, status) = events.collect(pid).await?;
    ensure!(
        status == 37 && out.len() == 262147 && err.len() == 196608,
        "cyclic output was truncated: status={status}, stdout={}, stderr={}",
        out.len(),
        err.len()
    );
    ensure!(out[..262144].iter().all(|b| *b == b'A') && out.ends_with(b"END"));
    ensure!(err.iter().all(|b| *b == b'B'));
    println!(
        "CYCLIC_OUTPUT_OK: stdout={}, stderr={}",
        out.len(),
        err.len()
    );
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "burst"],
            None,
            0,
            0,
            &redirects,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("burst exec: {e}"))?;
    let (out, err, status) = events.collect(pid).await?;
    ensure!(
        status == 37 && out.len() == 262147 && err.len() == 196608,
        "truncated output: status={status}, stdout={}, stderr={}",
        out.len(),
        err.len()
    );
    ensure!(out[..262144].iter().all(|b| *b == b'A') && out.ends_with(b"END"));
    ensure!(err.iter().all(|b| *b == b'B'));
    println!("OUTPUT_OK: stdout={}, stderr={}", out.len(), err.len());
    drop(ga);
    entrypoint_exit(data, events, mode).await
}

/// The entrypoint started with the VM (`start --start-entrypoint`) and waits
/// for a signal. All its output and its exit code must arrive, then the guest
/// powers off, and the runtime must keep answering without panics or hangs.
async fn entrypoint_exit(
    data: Arc<Mutex<RuntimeData>>,
    mut events: Statuses,
    mode: &str,
) -> anyhow::Result<()> {
    let entrypoint = events.entrypoint.context("missing entrypoint")?;
    let signal = ya_runtime_vm::run_command(
        data.clone(),
        server::RunProcess {
            bin: "/mnt/out/probe".into(),
            args: vec!["probe".into(), "signal-entrypoint".into()],
            ..Default::default()
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("signal exec: {e:?}"))?;
    ensure!(
        events.collect(signal).await?.2 == 0,
        "entrypoint signal failed"
    );
    let (out, err, status) = events
        .collect_up_to(entrypoint, 4 * 1024 * 1024)
        .await
        .context("collecting entrypoint output")?;
    let (expected_out, expected_err) = entrypoint_output();
    ensure!(
        status == ENTRYPOINT_EXIT,
        "entrypoint exit code {status}, expected {ENTRYPOINT_EXIT}"
    );
    ensure!(
        out == expected_out && err == expected_err,
        "entrypoint output differs: stdout {} of {} bytes, stderr {} of {} bytes",
        out.len(),
        expected_out.len(),
        err.len(),
        expected_err.len()
    );
    println!(
        "ENTRYPOINT_OUTPUT_OK: stdout={}, stderr={}, exit={status}",
        out.len(),
        err.len()
    );
    let reason = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(reason) = data.lock().await.halted() {
                break reason;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("entrypoint VM did not halt after exit acknowledgement")?;
    ensure!(reason == "PowerOff", "unexpected guest halt: {reason}");
    let call = Duration::from_secs(10);
    tokio::time::timeout(call, ya_runtime_vm::stop(data.clone()))
        .await
        .context("stop() hung after the guest halted")?
        .map_err(|e| anyhow::anyhow!("stop() after the guest halted: {e:?}"))?;
    let run = ya_runtime_vm::run_command(
        data.clone(),
        server::RunProcess {
            bin: "/mnt/out/probe".into(),
            args: vec!["probe".into(), "exit".into()],
            ..Default::default()
        },
    );
    ensure!(
        tokio::time::timeout(call, run).await?.is_err(),
        "run succeeded after the guest halted"
    );
    let kill = ya_runtime_vm::kill_command(
        data.clone(),
        server::KillProcess {
            pid: entrypoint,
            ..Default::default()
        },
    );
    ensure!(
        tokio::time::timeout(call, kill).await?.is_err(),
        "kill succeeded after the guest halted"
    );
    let interface = if mode == "inet-only" {
        server::NetworkInterface::Inet
    } else {
        server::NetworkInterface::Vpn
    };
    let join = ya_runtime_vm::join_network(
        data.clone(),
        server::CreateNetwork {
            interface: interface as i32,
            ..Default::default()
        },
    );
    ensure!(
        tokio::time::timeout(call, join).await?.is_err(),
        "network update succeeded after the guest halted"
    );
    ensure!(
        events.receiver.try_recv().is_err() && events.stashed.is_empty(),
        "unexpected process events after the entrypoint exit"
    );
    println!("ENTRYPOINT_SHUTDOWN_OK: guest {reason}; stop and later commands returned");
    Ok(())
}

async fn check(
    probe: &Path,
    image: &Path,
    mode: &str,
    transport: network::Transport,
) -> anyhow::Result<()> {
    println!("VM_CASE {mode} {transport:?}");
    let mut peers = Vec::new();
    for role in 0..=1 {
        if (mode == "inet-only" && role == 0) || (mode == "vpn-only" && role == 1) {
            continue;
        }
        peers.push((role, network::Peer::new(role, transport).await?));
    }
    let work = tempdir::TempDir::new("ya-runtime-vm-integration")?;
    let image = image.canonicalize()?;
    let deployment = Deployment::try_from_input(
        tokio::fs::File::open(&image).await?,
        1,
        512,
        std::slice::from_ref(&image),
        HashMap::from([
            (
                "/tmp".into(),
                VolumeMount::Ram {
                    size: "8mi".parse().expect("valid fixture size"),
                },
            ),
            (
                "/tmp/cache".into(),
                VolumeMount::Storage {
                    size: "4mi".parse().expect("valid fixture size"),
                    preallocate: None,
                    errors: None,
                },
            ),
            (
                "/dev/shm/cache".into(),
                VolumeMount::Ram {
                    size: "4mi".parse().expect("valid fixture size"),
                },
            ),
        ]),
        "golem".into(),
    )
    .await?;
    for mount in &deployment.mounts {
        if let VolumeMount::Storage { size, .. } = &mount.mount {
            // A tiny fixture disk; production image allocation is tested separately.
            std::fs::File::create(work.path().join(&mount.name))?.set_len(size.as_u64())?;
        }
    }
    ensure!(
        deployment.volumes.len() == 1 && deployment.volumes[0].path == "/mnt/out",
        "integration test expects the pinned self-test image"
    );
    let share = work.path().join(&deployment.volumes[0].name);
    std::fs::create_dir(&share)?;
    std::fs::copy(probe, share.join("probe"))?;
    std::fs::write(share.join("input"), b"host data")?;
    let secret = work.path().join("secret");
    std::fs::write(&secret, b"outside secret")?;
    let outside = work.path().join("outside");
    std::fs::create_dir(&outside)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for name in ["probe", "input"] {
            std::fs::set_permissions(share.join(name), std::fs::Permissions::from_mode(0o600))?;
        }
        symlink(&secret, share.join("outside-link"))?;
        symlink(&outside, share.join("outside-directory"))?;
    }
    #[cfg(windows)]
    {
        // Directory junctions do not require Windows developer mode or symlink privileges.
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(share.join("outside-directory"))
            .arg(&outside)
            .output()?;
        ensure!(
            output.status.success(),
            "junction setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::hard_link(&secret, share.join("outside-hardlink"))?;
    // Run the probe as the image entrypoint, as `start --start-entrypoint`.
    let mut deployment = deployment;
    deployment.config.entrypoint = Some(vec!["/mnt/out/probe".into()]);
    deployment.config.cmd = Some(vec!["entrypoint".into()]);
    let data = Arc::new(Mutex::new(RuntimeData {
        deployment: Some(deployment),
        ..Default::default()
    }));
    for (role, peer) in &peers {
        let mut runtime = data.lock().await;
        if *role == 0 {
            runtime.vpn = Some(peer.endpoint.clone());
        } else {
            runtime.inet = Some(peer.endpoint.clone());
        }
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let started = ya_runtime_vm::start_runtime(
        work.path().into(),
        data.clone(),
        EventEmitter::spawn(Events(tx)),
        true,
    )
    .await
    .map_err(|e| anyhow::anyhow!("start with entrypoint: {e:?}"))?
    .context("missing start response")?;
    let entrypoint = started["entrypoint"]["pid"]
        .as_u64()
        .context("start response has no entrypoint PID")?;
    let events = Statuses {
        receiver: rx,
        entrypoint: Some(entrypoint),
        stashed: VecDeque::new(),
    };
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        for (role, peer) in &mut peers {
            let exposed = {
                let runtime = data.lock().await;
                if *role == 0 {
                    runtime.vpn.clone()
                } else {
                    runtime.inet.clone()
                }
            }
            .context("missing exposed network endpoint")?;
            peer.attach(exposed).await?;
        }
        commands(data.clone(), events, &share, mode).await
    })
    .await
    .context("VM integration test timed out")
    .and_then(|result| result);
    let worker = data.lock().await.runtime.take();
    if let Some(mut worker) = worker {
        worker.stop();
        worker.join().await?;
    }
    result?;
    for (_, peer) in &peers {
        peer.verify()?;
    }
    ensure!(std::fs::read(secret)? == b"outside secret");
    ensure!(!share.join("guest-link").exists() && !share.join("guest-hardlink").exists());
    ensure!(std::fs::read_dir(outside)?.next().is_none());
    println!("OPENVMM_INTEGRATION_OK");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: vm_smoke <Linux probe ELF> <self-test.gvmi>"
    );
    tokio::task::LocalSet::new()
        .run_until(async {
            for (mode, transport) in [
                ("both", network::Transport::Udp),
                ("inet-only", network::Transport::Connect),
                ("vpn-only", network::Transport::Listen),
            ] {
                check(Path::new(&args[0]), Path::new(&args[1]), mode, transport).await?;
            }
            anyhow::Ok(())
        })
        .await
}
