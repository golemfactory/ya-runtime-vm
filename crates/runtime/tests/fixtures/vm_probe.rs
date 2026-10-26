// Static Linux workload used by the native OpenVMM integration test.
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirEntryExt, MetadataExt, PermissionsExt, symlink};
use std::path::Path;

fn files(role: &str) {
    let share = Path::new("/mnt/out");
    let input = share.join("input");
    let metadata = fs::metadata(&input).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
        (0, 0, 0o777)
    );
    assert_eq!(fs::read(input).unwrap(), b"host data");
    // DNS and host lookups must work for non-root workloads too.
    for path in ["/etc/resolv.conf", "/etc/hosts"] {
        let mode = fs::metadata(path).unwrap().mode();
        assert_eq!(mode & 0o044, 0o044, "{path} mode {mode:o}");
    }
    assert!(
        fs::read_to_string("/etc/resolv.conf")
            .unwrap()
            .contains("nameserver 1.1.1.1")
    );
    assert!(
        fs::read_to_string("/etc/hosts")
            .unwrap()
            .contains("127.0.0.1\tlocalhost")
    );
    // glibc < 2.37 readdir() drops d_ino == 0; musl does not, so check it here.
    let listed: Vec<_> = fs::read_dir(share)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            assert_ne!(e.ino(), 0, "{:?} has d_ino 0", e.file_name());
            e.file_name()
        })
        .collect();
    assert!(listed.iter().any(|name| name == "input"), "{listed:?}");
    for name in ["outside-link", "outside-hardlink", "outside-directory"] {
        assert!(fs::symlink_metadata(share.join(name)).is_err());
        assert!(!listed.iter().any(|e| e == name));
    }
    assert!(symlink("/etc/passwd", share.join("guest-link")).is_err());
    assert!(fs::hard_link(share.join("input"), share.join("guest-hardlink")).is_err());
    let dir = share.join(role);
    fs::create_dir(&dir).unwrap();
    let file = dir.join("written");
    let bytes = vec![b'Z'; 3 * 1024 * 1024 + 37];
    fs::write(&file, &bytes).unwrap();
    assert_eq!(fs::read(&file).unwrap(), bytes);
    if role == "root" {
        fs::set_permissions(&file, fs::Permissions::from_mode(0o4777)).unwrap();
        std::os::unix::fs::chown(&file, Some(12345), Some(23456)).unwrap();
        let attr = fs::metadata(&file).unwrap();
        assert_eq!(
            (attr.uid(), attr.gid(), attr.mode() & 0o7777),
            (0, 0, 0o777)
        );
    }
    let renamed = dir.join("renamed");
    fs::rename(file, &renamed).unwrap();
    let file = fs::OpenOptions::new().write(true).open(&renamed).unwrap();
    file.set_len(128).unwrap();
    file.sync_all().unwrap();
    assert_eq!(fs::read(renamed).unwrap(), vec![b'Z'; 128]);
    println!("FILES_OK {role}");
}

fn network(mode: &str) {
    for role in 0..=1 {
        let enabled = !((mode == "inet-only" && role == 0) || (mode == "vpn-only" && role == 1));
        assert_eq!(
            Path::new(&format!("/sys/class/net/eth{role}")).exists(),
            enabled
        );
        if !enabled {
            continue;
        }
        let label = if role == 0 { "vpn" } else { "inet" };
        let mtu: usize = fs::read_to_string(format!("/sys/class/net/eth{role}/mtu"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(mtu, if role == 0 { 1220 } else { 1500 }, "eth{role} MTU");
        // IPv6 needs an MTU of at least 1280, so the VPN interface has none.
        for v6 in [false, true]
            .into_iter()
            .take(if role == 0 { 1 } else { 2 })
        {
            let source = if v6 {
                format!("[fd00:{}::2]:0", 71 + role)
            } else {
                format!("10.{}.0.2:0", 71 + role)
            };
            let remote = if v6 {
                format!("[fdff:{}::1]:{}", 71 + role, 18000 + role)
            } else {
                format!("198.{}.1.1:{}", 18 + role, 18000 + role)
            };
            // IPv6 DAD starts after the virtual link becomes ready, not when
            // the address netlink ACK arrives. Check its actual state and keep
            // a finite deadline; missing/failed addresses are not retried.
            let mut socket = None;
            let start = std::time::Instant::now();
            let mut first_state = None;
            for _ in 0..100 {
                match std::net::UdpSocket::bind(&source) {
                    Ok(value) => {
                        socket = Some(value);
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                        assert!(v6, "IPv4 address missing after netlink ACK: {source}");
                        let state = fs::read_to_string("/proc/net/if_inet6").unwrap();
                        let address: std::net::SocketAddrV6 = source.parse().unwrap();
                        let hex = format!("{:032x}", u128::from(*address.ip()));
                        let fields = state
                            .lines()
                            .find_map(|line| {
                                let fields: Vec<_> = line.split_whitespace().collect();
                                (fields.len() == 6 && fields[0] == hex).then_some(fields)
                            })
                            .unwrap_or_else(|| {
                                panic!("IPv6 address {source} disappeared: {state}")
                            });
                        let flags = u32::from_str_radix(fields[4], 16).unwrap();
                        assert_eq!(
                            flags & 0x08,
                            0,
                            "IPv6 duplicate-address detection failed: {source}: {state}"
                        );
                        assert_ne!(
                            flags & 0x40,
                            0,
                            "IPv6 bind failed without a tentative address: {source}: {state}"
                        );
                        first_state.get_or_insert(state);
                        std::thread::sleep(std::time::Duration::from_millis(100))
                    }
                    Err(e) => panic!("bind {source}: {e}"),
                }
            }
            let socket = socket.unwrap_or_else(|| {
                panic!(
                    "IPv6 DAD did not finish for {source}: {}",
                    fs::read_to_string("/proc/net/if_inet6").unwrap()
                )
            });
            if let Some(state) = first_state {
                eprintln!(
                    "IPv6 {source} became ready after {:?}; initial addresses: {state}",
                    start.elapsed()
                );
            }
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            socket.connect(&remote).unwrap();
            // The largest payload fits one frame: IP and UDP headers are 28/48 bytes.
            for size in [32, 257, mtu - if v6 { 48 } else { 28 }] {
                let tag = format!("REQ-{label}-{}-{size}", if v6 { 6 } else { 4 });
                let mut packet = vec![b'X'; size];
                packet[..tag.len()].copy_from_slice(tag.as_bytes());
                assert_eq!(socket.send(&packet).unwrap(), packet.len());
                let mut reply = vec![0; 2048];
                let received = socket.recv(&mut reply).unwrap();
                packet[..3].copy_from_slice(b"ACK");
                assert_eq!(&reply[..received], packet);
            }
        }
    }
    for (name, value) in [
        ("rmem_default", "1048576"),
        ("rmem_max", "2097152"),
        ("wmem_default", "1048576"),
        ("wmem_max", "2097152"),
    ] {
        let path = format!("/proc/sys/net/core/{name}");
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), value, "{path}");
    }
    println!("NETWORK_OK {mode}");
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("volumes") => {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata("/tmp/cache").unwrap().dev(),
                fs::metadata("/dev/vdb").unwrap().rdev()
            );
            assert_ne!(
                fs::metadata("/dev/shm/cache").unwrap().dev(),
                fs::metadata("/dev/shm").unwrap().dev()
            );
            fs::write("/tmp/cache/disk-marker", b"disk").unwrap();
            fs::write("/dev/shm/cache/ram-marker", b"ram").unwrap();
            let mut file = fs::File::create("/tmp/size-check").unwrap();
            let error = file.write_all(&vec![0; 9 * 1024 * 1024]).unwrap_err();
            assert_eq!(
                error.raw_os_error(),
                Some(28),
                "configured 8 MiB /tmp limit is missing"
            );
            drop(file);
            fs::remove_file("/tmp/size-check").unwrap();
            println!("VOLUMES_OK");
        }
        Some("network") => network(&args[2]),
        Some("files") => files(&args[2]),
        Some("burst") => {
            io::stdout().write_all(&vec![b'A'; 262144]).unwrap();
            io::stderr().write_all(&vec![b'B'; 196608]).unwrap();
            io::stdout().write_all(b"END").unwrap();
            std::process::exit(37);
        }
        Some("sleep") => std::thread::sleep(std::time::Duration::from_secs(60)),
        Some("background") => {
            // Like `sh -c 'server &'`: the descendant inherits stdout/stderr.
            std::process::Command::new(&args[0])
                .arg("sleep")
                .spawn()
                .unwrap();
            println!("BACKGROUND_STARTED");
        }
        Some("exit") => (),
        _ => panic!("unknown probe mode"),
    }
}
