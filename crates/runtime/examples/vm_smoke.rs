//! Run via `mise run vm-test` on a host with KVM or WHP enabled.
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use futures::{FutureExt, future::BoxFuture, lock::Mutex};
use tokio::sync::mpsc;
use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::{
    EventEmitter,
    runtime_api::server::{self, RuntimeHandler},
};
use ya_runtime_vm::{
    deploy::Deployment,
    guest_agent_comm::RedirectFdType,
    vmrt::{self, RuntimeData},
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

async fn collect(
    receiver: &mut mpsc::UnboundedReceiver<server::ProcessStatus>,
    pid: u64,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, i32)> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        let status = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await?
            .context("process event channel closed")?;
        ensure!(status.pid == pid, "unexpected process ID {}", status.pid);
        out.extend(status.stdout);
        err.extend(status.stderr);
        ensure!(
            out.len() + err.len() <= 1024 * 1024,
            "unexpectedly large process output"
        );
        if !status.running {
            return Ok((out, err, status.return_code));
        }
    }
}

async fn commands(
    data: Arc<Mutex<RuntimeData>>,
    mut events: mpsc::UnboundedReceiver<server::ProcessStatus>,
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
    let (out, err, status) = collect(&mut events, pid).await?;
    ensure!(
        status == 0 && out == b"VOLUMES_OK\n",
        "volume probe failed: {}",
        String::from_utf8_lossy(&err)
    );
    println!("VOLUMES_OK: explicit /tmp, /tmp/cache and /dev/shm/cache mounts remain visible");
    for role in 0..=1 {
        if (mode == "inet-only" && role == 0) || (mode == "vpn-only" && role == 1) {
            continue;
        }
        let mut agent = ga.lock().await;
        // IPv6 is unavailable on the VPN interface: its MTU is below 1280.
        for (address, mask, network, gateway) in [
            (
                format!("10.{}.0.2", 71 + role),
                "24",
                if role == 0 { "198.18.1.0" } else { "" },
                format!("10.{}.0.1", 71 + role),
            ),
            (
                format!("fd00:{}::2", 71 + role),
                "64",
                if role == 0 { "fdff:71::" } else { "" },
                format!("fd00:{}::1", 71 + role),
            ),
        ]
        .into_iter()
        .take(if role == 0 { 1 } else { 2 })
        {
            ensure!(
                agent.add_address(&address, mask, role).await?.is_ok(),
                "guest address update failed"
            );
            ensure!(
                agent
                    .create_network(
                        network,
                        if network.is_empty() { "" } else { mask },
                        &gateway,
                        role
                    )
                    .await?
                    .is_ok(),
                "guest route update failed"
            );
        }
    }
    let pid = ga
        .lock()
        .await
        .run_process(
            "/mnt/out/probe",
            &["probe", "network", mode],
            None,
            0,
            0,
            &redirects,
            Some("/"),
        )
        .await?
        .map_err(|e| anyhow::anyhow!("network probe exec: {e}"))?;
    let (out, err, status) = collect(&mut events, pid).await?;
    ensure!(
        status == 0,
        "network probe failed: {}",
        String::from_utf8_lossy(&err)
    );
    ensure!(out == format!("NETWORK_OK {mode}\n").as_bytes());
    if !err.is_empty() {
        log::info!("network probe: {}", String::from_utf8_lossy(&err).trim());
    }
    println!("NETWORK_OK {mode}: IPv4 and INET IPv6 packets crossed the expected Ethernet peers");
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
        let (out, err, status) = collect(&mut events, pid).await?;
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
    ensure!(collect(&mut events, pid).await?.2 == 9);
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
        ensure!(collect(&mut events, pid).await?.2 == 0);
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
    let (out, _, status) = collect(&mut events, pid).await?;
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
    let (out, err, status) = collect(&mut events, pid).await?;
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
    let (out, err, status) = collect(&mut events, pid).await?;
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
    for entrypoint in [false, true] {
        let args = ["probe", "burst"];
        let pid = if entrypoint {
            ga.lock()
                .await
                .run_entrypoint("/mnt/out/probe", &args, None, 0, 0, &redirects, Some("/"))
                .await?
        } else {
            ga.lock()
                .await
                .run_process("/mnt/out/probe", &args, None, 0, 0, &redirects, Some("/"))
                .await?
        }
        .map_err(|e| anyhow::anyhow!("burst exec: {e}"))?;
        let (out, err, status) = collect(&mut events, pid).await?;
        ensure!(
            status == 37 && out.len() == 262147 && err.len() == 196608,
            "truncated output: status={status}, stdout={}, stderr={}",
            out.len(),
            err.len()
        );
        ensure!(out[..262144].iter().all(|b| *b == b'A') && out.ends_with(b"END"));
        ensure!(err.iter().all(|b| *b == b'B'));
        println!(
            "OUTPUT_OK entrypoint={entrypoint}: stdout={}, stderr={}",
            out.len(),
            err.len()
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while data.lock().await.runtime.is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("entrypoint VM did not halt after exit acknowledgement")?;
    println!("ENTRYPOINT_SHUTDOWN_OK");
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
    vmrt::start_vmrt(
        work.path().into(),
        data.clone(),
        EventEmitter::spawn(Events(tx)),
    )
    .await?;
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
        commands(data.clone(), rx, &share, mode).await
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
