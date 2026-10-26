use super::*;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

fn request(node: u64) -> Request {
    let header = fuse_in_header {
        len: size_of::<fuse_in_header>() as u32,
        opcode: 0,
        unique: 1,
        nodeid: node,
        uid: 1000,
        gid: 1000,
        pid: 1,
        padding: 0,
    };
    Request::new(header.as_bytes()).unwrap()
}
fn name(s: &str) -> &lx::LxStr {
    lx::LxStr::from_bytes(s.as_bytes())
}
fn setup() -> (tempdir::TempDir, SharedDir) {
    #[cfg(windows)]
    let _ = env_logger::Builder::new()
        .is_test(true)
        .filter_level(log::LevelFilter::Trace)
        .try_init();
    let temp = tempdir::TempDir::new("shared-dir-test").unwrap();
    std::fs::create_dir(temp.path().join("share")).unwrap();
    let fs = SharedDir::new(open_root(temp.path(), "share").unwrap()).unwrap();
    (temp, fs)
}
fn lookup(fs: &SharedDir, parent: u64, s: &str) -> fuse_entry_out {
    fs.lookup(&request(parent), name(s)).unwrap()
}
fn create(fs: &SharedDir, parent: u64, s: &str) -> fuse::CreateOut {
    fs.create(
        &request(parent),
        name(s),
        &fuse_create_in {
            flags: (lx::O_CREAT | lx::O_EXCL | lx::O_RDWR) as u32,
            mode: 0o777,
            umask: 0,
            padding: 0,
        },
    )
    .unwrap()
}
fn read(fs: &SharedDir, node: u64, fh: u64) -> Vec<u8> {
    fs.read(
        &request(node),
        &fuse_read_in {
            fh,
            size: 4096,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap()
}
fn write(fs: &SharedDir, node: u64, fh: u64, data: &[u8]) {
    let n = fs
        .write(
            &request(node),
            &fuse_write_in {
                fh,
                size: data.len() as u32,
                ..FromZeros::new_zeroed()
            },
            data,
        )
        .unwrap();
    assert_eq!(n, data.len());
}
fn release(fs: &SharedDir, node: u64, fh: u64) {
    fs.release(
        &request(node),
        &fuse_release_in {
            fh,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap();
}
fn list(fs: &SharedDir, node: u64) -> Vec<u8> {
    let fh = fs.open_dir(&request(node), 0).unwrap().fh;
    let mut data = Vec::new();
    let mut offset = 0;
    loop {
        let chunk = fs
            .read_dir(
                &request(node),
                &fuse_read_in {
                    fh,
                    offset,
                    size: 4096,
                    ..FromZeros::new_zeroed()
                },
            )
            .unwrap();
        if chunk.is_empty() {
            break;
        }
        // Resume after the last entry; host directory order is unspecified.
        let mut rest = chunk.as_slice();
        while let Ok((entry, _)) = fuse_dirent::read_from_prefix(rest) {
            offset = entry.off;
            let len = (size_of::<fuse_dirent>() + entry.namelen as usize).next_multiple_of(8);
            rest = rest.get(len..).unwrap_or_default();
        }
        data.extend_from_slice(&chunk);
    }
    fs.release_dir(
        &request(node),
        &fuse_release_in {
            fh,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap();
    data
}
fn contains(data: &[u8], s: &[u8]) -> bool {
    data.windows(s.len()).any(|b| b == s)
}

#[test]
fn simple_share_has_synthetic_permissions_and_preserves_host_permissions() {
    let (temp, fs) = setup();
    let root = FUSE_ROOT_ID;
    let file = create(&fs, root, "file");
    let id = file.entry.nodeid;
    write(&fs, id, file.open.fh, b"hello");
    assert_eq!(read(&fs, id, file.open.fh), b"hello");
    let before = std::fs::metadata(temp.path().join("share/file")).unwrap();
    let attr = fs
        .set_attr(
            &request(id),
            &fuse_setattr_in {
                valid: FATTR_MODE | FATTR_UID | FATTR_GID,
                mode: 0o4777,
                uid: 12345,
                gid: 23456,
                ..FromZeros::new_zeroed()
            },
        )
        .unwrap()
        .attr;
    assert_eq!((attr.uid, attr.gid, attr.mode), (0, 0, lx::S_IFREG | 0o777));
    let after = std::fs::metadata(temp.path().join("share/file")).unwrap();
    assert_eq!(before.permissions(), after.permissions());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(before.mode() & 0o7777, 0o600);
        assert_eq!(after.mode() & 0o7777, 0o600);
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
    }
    fs.set_attr(
        &request(id),
        &fuse_setattr_in {
            valid: FATTR_SIZE | FATTR_FH,
            size: 2,
            fh: file.open.fh,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap();
    assert_eq!(read(&fs, id, file.open.fh), b"he");
    fs.fsync(&request(id), file.open.fh, 0).unwrap();
    let dir = fs
        .mkdir(
            &request(root),
            name("sub"),
            &fuse_mkdir_in { mode: 0, umask: 0 },
        )
        .unwrap();
    assert_eq!(dir.attr.mode, lx::S_IFDIR | 0o777);
    fs.rename(&request(root), name("file"), dir.nodeid, name("renamed"), 0)
        .unwrap();
    assert_eq!(lookup(&fs, dir.nodeid, "renamed").nodeid, id);
    assert!(contains(&list(&fs, dir.nodeid), b"renamed"));
    let dh = fs.open_dir(&request(dir.nodeid), 0).unwrap().fh;
    fs.fsync_dir(&request(dir.nodeid), dh, 0).unwrap();
    fs.release_dir(
        &request(dir.nodeid),
        &fuse_release_in {
            fh: dh,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap();
    assert_eq!(read(&fs, id, file.open.fh), b"he");
    fs.unlink(&request(dir.nodeid), name("renamed")).unwrap();
    // Open files survive unlink; the pinned object is still the same file.
    assert_eq!(read(&fs, id, file.open.fh), b"he");
    release(&fs, id, file.open.fh);
    fs.forget(id, u64::MAX);
    fs.rmdir(&request(root), name("sub")).unwrap();
    fs.forget(dir.nodeid, 1);
    assert_eq!(fs.0.lock().nodes.len(), 1);
    assert!(fs.statfs(&request(root)).unwrap().bsize > 0);
}

#[test]
fn names_can_be_reused_while_old_handles_remain_open() {
    let (_temp, fs) = setup();
    let old = create(&fs, 1, "file");
    write(&fs, old.entry.nodeid, old.open.fh, b"old");
    fs.unlink(&request(1), name("file")).unwrap();
    let new = create(&fs, 1, "file");
    write(&fs, new.entry.nodeid, new.open.fh, b"new");
    assert_ne!(old.entry.nodeid, new.entry.nodeid);
    assert_eq!(read(&fs, old.entry.nodeid, old.open.fh), b"old");
    assert_eq!(read(&fs, new.entry.nodeid, new.open.fh), b"new");

    let first = fs
        .mkdir(
            &request(1),
            name("dir"),
            &fuse_mkdir_in {
                mode: 0o777,
                umask: 0,
            },
        )
        .unwrap();
    fs.rmdir(&request(1), name("dir")).unwrap();
    let second = fs
        .mkdir(
            &request(1),
            name("dir"),
            &fuse_mkdir_in {
                mode: 0o777,
                umask: 0,
            },
        )
        .unwrap();
    assert_ne!(first.nodeid, second.nodeid);
    create(&fs, second.nodeid, "new");
    assert!(contains(&list(&fs, second.nodeid), b"new"));
}

fn dirents(data: &[u8]) -> Vec<(u64, String)> {
    let mut entries = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (dirent, tail) = fuse_dirent::read_from_prefix(rest).unwrap();
        let name = &tail[..dirent.namelen as usize];
        entries.push((dirent.ino, String::from_utf8(name.to_vec()).unwrap()));
        rest = &rest[fuse_dirent_align(size_of::<fuse_dirent>() + name.len())..];
    }
    entries
}

#[test]
fn directory_entries_have_nonzero_inodes_matching_lookups() {
    let (temp, fs) = setup();
    let dir = fs
        .mkdir(
            &request(1),
            name("dir"),
            &fuse_mkdir_in {
                mode: 0o777,
                umask: 0,
            },
        )
        .unwrap();
    let file = create(&fs, dir.nodeid, "known");
    release(&fs, file.entry.nodeid, file.open.fh);
    std::fs::write(temp.path().join("share/dir/unknown"), b"").unwrap();
    let mut entries = dirents(&list(&fs, dir.nodeid));
    entries[2..].sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        entries,
        [
            (dir.nodeid, ".".into()),
            (1, "..".into()),
            (file.entry.nodeid, "known".into()),
            (UNKNOWN_INO, "unknown".into()),
        ]
    );
    assert!(entries.iter().all(|(ino, _)| *ino != 0));
    let root = dirents(&list(&fs, 1));
    assert_eq!(root[..2], [(1, ".".into()), (1, "..".into())]);
    assert!(root.contains(&(dir.nodeid, "dir".into())));
}

#[test]
fn rename_replaces_an_open_destination_without_redirecting_its_handle() {
    let (_temp, fs) = setup();
    let source = create(&fs, 1, "source");
    let target = create(&fs, 1, "target");
    write(&fs, source.entry.nodeid, source.open.fh, b"source");
    write(&fs, target.entry.nodeid, target.open.fh, b"target");
    fs.rename(&request(1), name("source"), 1, name("target"), 0)
        .unwrap();
    assert_eq!(lookup(&fs, 1, "target").nodeid, source.entry.nodeid);
    assert_eq!(read(&fs, source.entry.nodeid, source.open.fh), b"source");
    assert_eq!(read(&fs, target.entry.nodeid, target.open.fh), b"target");
    assert!(fs.lookup(&request(1), name("source")).is_err());
}

#[test]
fn file_and_directory_timestamps_can_be_changed_without_changing_permissions() {
    let (temp, fs) = setup();
    let file = create(&fs, 1, "file");
    let dir = fs
        .mkdir(
            &request(1),
            name("dir"),
            &fuse_mkdir_in {
                mode: 0o777,
                umask: 0,
            },
        )
        .unwrap();
    for (node, path) in [(file.entry.nodeid, "share/file"), (dir.nodeid, "share/dir")] {
        let path = temp.path().join(path);
        let before = std::fs::metadata(&path).unwrap().permissions();
        let result = fs
            .set_attr(
                &request(node),
                &fuse_setattr_in {
                    valid: FATTR_MTIME,
                    mtime: 1_000_000_000,
                    ..FromZeros::new_zeroed()
                },
            )
            .unwrap();
        assert_eq!(result.attr.mtime, 1_000_000_000);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.permissions(), before);
        assert_eq!(
            after
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_000_000_000
        );
    }
}

#[test]
fn guest_cannot_create_links_special_files_or_access_host_xattrs() {
    let (_temp, fs) = setup();
    let r = request(FUSE_ROOT_ID);
    assert_eq!(
        fs.symlink(&r, name("link"), name("/etc/passwd"))
            .unwrap_err(),
        lx::Error::EPERM
    );
    assert_eq!(fs.read_link(&r).unwrap_err(), lx::Error::EPERM);
    assert_eq!(fs.link(&r, name("hard"), 1).unwrap_err(), lx::Error::EPERM);
    for mode in [
        lx::S_IFLNK,
        lx::S_IFCHR,
        lx::S_IFBLK,
        lx::S_IFSOCK,
        lx::S_IFIFO,
    ] {
        assert_eq!(
            fs.mknod(
                &r,
                name("node"),
                &fuse_mknod_in {
                    mode,
                    rdev: 0,
                    umask: 0,
                    padding: 0
                }
            )
            .unwrap_err(),
            lx::Error::EPERM
        );
    }
    assert!(fs.set_xattr(&r, name("user.test"), b"data", 0).is_err());
    assert!(fs.get_xattr(&r, name("security.selinux"), 4096).is_err());
    let mut bad = vec![".", "..", "", "../outside", "/outside", "dir/file"];
    if cfg!(windows) {
        bad.extend([
            "dir\\file",
            "file:stream",
            "NUL",
            "con.txt",
            "COM1",
            "x.",
            "x ",
        ]);
    }
    for bad in bad {
        assert!(fs.lookup(&r, name(bad)).is_err(), "accepted {bad:?}");
        assert!(
            fs.create(&r, name(bad), &fuse_create_in::new_zeroed())
                .is_err(),
            "created {bad:?}"
        );
        assert!(fs.rename(&r, name("x"), 1, name(bad), 0).is_err());
    }
    assert_eq!(fs.0.lock().nodes.len(), 1);
}

#[cfg(unix)]
#[test]
fn host_symlinks_hardlinks_and_fifos_are_not_exported() {
    use std::os::unix::fs::symlink;
    let (temp, fs) = setup();
    let share = temp.path().join("share");
    std::fs::write(temp.path().join("outside"), b"secret").unwrap();
    symlink(temp.path().join("outside"), share.join("symlink")).unwrap();
    symlink("missing", share.join("dangling")).unwrap();
    std::fs::hard_link(temp.path().join("outside"), share.join("hardlink")).unwrap();
    let fifo = std::ffi::CString::new(share.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated test path, only creates a FIFO in TempDir.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for s in ["symlink", "dangling", "hardlink", "fifo"] {
        assert!(fs.lookup(&request(1), name(s)).is_err(), "exported {s}");
        assert!(
            fs.create(
                &request(1),
                name(s),
                &fuse_create_in {
                    flags: (lx::O_RDWR | lx::O_TRUNC) as u32,
                    ..FromZeros::new_zeroed()
                }
            )
            .is_err()
        );
        assert!(!contains(&list(&fs, 1), s.as_bytes()), "listed {s}");
    }
    assert_eq!(
        std::fs::read(temp.path().join("outside")).unwrap(),
        b"secret"
    );
    assert!(open_root(temp.path(), "../share").is_err());
    symlink(&share, temp.path().join("root-link")).unwrap();
    assert!(open_root(temp.path(), "root-link").is_err());
}

#[cfg(unix)]
#[test]
fn cached_directory_and_file_handles_resist_host_symlink_replacement() {
    use std::os::unix::fs::symlink;
    let (temp, fs) = setup();
    let share = temp.path().join("share");
    std::fs::create_dir(share.join("sub")).unwrap();
    std::fs::create_dir(temp.path().join("outside")).unwrap();
    std::fs::write(share.join("sub/file"), b"inside").unwrap();
    std::fs::write(temp.path().join("outside/file"), b"secret").unwrap();
    let dir = lookup(&fs, 1, "sub").nodeid;
    let file = lookup(&fs, dir, "file").nodeid;
    std::fs::rename(share.join("sub"), share.join("original")).unwrap();
    symlink(temp.path().join("outside"), share.join("sub")).unwrap();
    std::fs::remove_file(share.join("original/file")).unwrap();
    symlink(
        temp.path().join("outside/file"),
        share.join("original/file"),
    )
    .unwrap();
    let fh = fs.open(&request(file), lx::O_RDWR as u32).unwrap().fh;
    assert_eq!(read(&fs, file, fh), b"inside");
    write(&fs, file, fh, b"changed");
    create(&fs, dir, "new-file");
    assert!(share.join("original/new-file").exists());
    assert!(!temp.path().join("outside/new-file").exists());
    assert!(fs.lookup(&request(1), name("sub")).is_err());
    assert!(fs.lookup(&request(dir), name("file")).is_err());
    assert_eq!(
        std::fs::read(temp.path().join("outside/file")).unwrap(),
        b"secret"
    );
}

#[cfg(windows)]
#[test]
fn windows_junction_cannot_redirect_cached_directory() {
    let (temp, fs) = setup();
    let share = temp.path().join("share");
    std::fs::create_dir(share.join("sub")).unwrap();
    std::fs::create_dir(temp.path().join("outside")).unwrap();
    let dir = lookup(&fs, 1, "sub").nodeid;
    std::fs::rename(share.join("sub"), share.join("original")).unwrap();
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(share.join("sub"))
        .arg(temp.path().join("outside"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs.lookup(&request(1), name("sub")).is_err());
    assert!(!contains(&list(&fs, 1), b"sub"));
    create(&fs, dir, "file");
    assert!(share.join("original/file").exists());
    assert!(!temp.path().join("outside/file").exists());
    assert!(open_root(&share, "sub").is_err());
}

#[test]
fn forget_waits_for_handles_and_resources_are_bounded() {
    let (_temp, fs) = setup();
    let file = create(&fs, 1, "file");
    let id = file.entry.nodeid;
    fs.forget(id, 1);
    assert_eq!(fs.0.lock().nodes.len(), 2);
    write(&fs, id, file.open.fh, b"open");
    release(&fs, id, file.open.fh);
    assert_eq!(fs.0.lock().nodes.len(), 1);
    let id = lookup(&fs, 1, "file").nodeid;
    // Exercise the limit without consuming MAX_HANDLES real OS descriptors.
    let mut state = fs.0.lock();
    for i in 0..MAX_HANDLES as u64 {
        state.directories.insert(
            i,
            OpenDirectory {
                node: 1,
                entries: Vec::new(),
                bytes: 0,
            },
        );
    }
    drop(state);
    assert_eq!(fs.open(&request(id), 0).unwrap_err(), lx::Error::EMFILE);
    assert_eq!(fs.open_dir(&request(1), 0).unwrap_err(), lx::Error::EMFILE);
    fs.0.lock().directories.clear();
    let fh = fs.open(&request(id), 0).unwrap().fh;
    assert!(
        fs.write(
            &request(id),
            &fuse_write_in {
                fh,
                size: 1,
                ..FromZeros::new_zeroed()
            },
            b"x"
        )
        .is_err()
    );
    assert!(
        fs.read(
            &request(1),
            &fuse_read_in {
                fh,
                ..FromZeros::new_zeroed()
            }
        )
        .is_err()
    );
    assert!(
        fs.read(
            &request(id),
            &fuse_read_in {
                fh,
                size: MAX_IO as u32 + 1,
                ..FromZeros::new_zeroed()
            }
        )
        .is_err()
    );
    assert!(
        fs.read(
            &request(id),
            &fuse_read_in {
                fh,
                offset: u64::MAX,
                ..FromZeros::new_zeroed()
            }
        )
        .is_err()
    );
}

#[test]
fn fuse_negotiates_page_requests_that_fit_the_virtqueue() {
    struct Reply(Vec<u8>);
    impl fuse::ReplySender for Reply {
        fn send(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
            for buf in bufs {
                self.0.extend_from_slice(buf);
            }
            Ok(())
        }
    }
    let (_temp, fs) = setup();
    let session = fuse::Session::new(fs);
    let init = fuse_init_in {
        major: 7,
        minor: 32,
        max_readahead: 1024 * 1024,
        flags: FUSE_MAX_PAGES
            | FUSE_BIG_WRITES
            | FUSE_ASYNC_READ
            | FUSE_HANDLE_KILLPRIV
            | FUSE_WRITEBACK_CACHE,
        ..FromZeros::new_zeroed()
    };
    let header = fuse_in_header {
        len: (size_of::<fuse_in_header>() + size_of::<fuse_init_in>()) as u32,
        opcode: FUSE_INIT,
        unique: 1,
        ..FromZeros::new_zeroed()
    };
    let wire = [header.as_bytes(), init.as_bytes()].concat();
    let mut reply = Reply(Vec::new());
    session.dispatch(Request::new(wire.as_slice()).unwrap(), &mut reply, None);
    assert!(session.is_initialized());
    let head = fuse_out_header::read_from_bytes(&reply.0[..size_of::<fuse_out_header>()]).unwrap();
    assert_eq!(head.error, 0);
    let out = fuse_init_out::read_from_bytes(&reply.0[size_of::<fuse_out_header>()..]).unwrap();
    // 1 MiB page-backed writes overflowed the 256-entry ring with header/reply
    // buffers on our Linux 5.10 guest. Keep both reads and writes below it.
    assert!(out.max_pages as u32 + 2 < 256);
    assert!(out.max_write <= MAX_REQUEST && out.max_readahead <= MAX_REQUEST);
    assert_eq!(out.flags & (FUSE_WRITEBACK_CACHE | FUSE_HANDLE_KILLPRIV), 0);
}

#[test]
fn windows_name_rules_apply_only_on_windows() {
    for bad in ["", ".", "..", "a/b", "a\0b"] {
        assert!(component(bad.as_bytes()).is_err(), "{bad:?}");
    }
    let windows_only = [
        "a:b",
        "a\\b",
        "trailing.",
        "trailing ",
        "CON",
        "aux.c",
        "lpt1",
    ];
    for name in windows_only {
        assert_eq!(component(name.as_bytes()).is_ok(), cfg!(unix), "{name:?}");
    }
    #[cfg(unix)]
    {
        let (_temp, fs) = setup();
        let file = create(&fs, 1, "2026-10-26T01:00:00.log");
        release(&fs, file.entry.nodeid, file.open.fh);
        assert!(contains(&list(&fs, 1), b"2026-10-26T01:00:00.log"));
    }
}

#[test]
fn large_directories_fit_the_snapshot_budget() {
    let (temp, fs) = setup();
    let names = 20_000;
    for i in 0..names {
        std::fs::write(temp.path().join(format!("share/file-{i:08}")), b"").unwrap();
    }
    let entries = list(&fs, 1);
    assert!(contains(&entries, b"file-00019999"));
    let fh = fs.open_dir(&request(1), 0).unwrap().fh;
    let bytes = fs.0.lock().directory_bytes;
    assert_eq!(bytes, 2 * ENTRY_BYTES + 3 + names * (13 + ENTRY_BYTES));
    // Several concurrent listings of a 100k-entry directory stay in budget.
    const { assert!(8 * 100_000 * (24 + ENTRY_BYTES) < MAX_DIRECTORY_BYTES) };
    fs.release_dir(
        &request(1),
        &fuse_release_in {
            fh,
            ..FromZeros::new_zeroed()
        },
    )
    .unwrap();
    assert_eq!(fs.0.lock().directory_bytes, 0);
}
