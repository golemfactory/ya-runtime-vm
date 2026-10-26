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
    let fs = SharedDir::new(
        open_root(temp.path(), "share").unwrap(),
        ShareLimits::default(),
    )
    .unwrap();
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
    for bad in [
        ".",
        "..",
        "",
        "../outside",
        "/outside",
        "dir/file",
        "dir\\file",
        "file:stream",
        "NUL",
        "con.txt",
        "COM1",
        "x.",
        "x ",
    ] {
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
fn name_rules_do_not_depend_on_host_platform() {
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\0b",
        "a:b",
        "a\\b",
        "trailing.",
        "trailing ",
        "CON",
        "aux.c",
        "lpt1",
        "2026-10-26T01:00:00.log",
        "wild*card",
        "wild?card",
        "a<b",
        "a>b",
        "a|b",
        "a\"b",
        "line\nbreak",
        "conin$",
        "CONOUT$.txt",
        "con .txt",
        "com¹",
        "LPT².txt",
        "COM³",
    ] {
        assert_eq!(
            component(bad.as_bytes()).unwrap_err(),
            lx::Error::EINVAL,
            "{bad:?}"
        );
    }
    for bad in [
        b"invalid\xff".as_slice(),
        &[0xc0, 0xaf],
        &[0xed, 0xa0, 0x80],
    ] {
        assert_eq!(component(bad).unwrap_err(), lx::Error::EINVAL);
    }
    for valid in [
        "file.txt",
        "auxiliary.c",
        "2026-10-26T01-00-00.log",
        "zażółć.txt",
        "COM10",
    ] {
        assert!(component(valid.as_bytes()).is_ok(), "{valid:?}");
    }
}

#[test]
fn rejected_names_cannot_mutate_the_export() {
    let (temp, fs) = setup();
    let file = create(&fs, 1, "safe");
    release(&fs, file.entry.nodeid, file.open.fh);
    for bad in [
        "../outside",
        "file:stream",
        "CONIN$",
        "COM¹.txt",
        "con .txt",
        "wild*card",
        "line\nbreak",
    ] {
        assert_eq!(
            fs.lookup(&request(1), name(bad)).unwrap_err(),
            lx::Error::EINVAL
        );
        assert!(matches!(
            fs.create(&request(1), name(bad), &fuse_create_in::new_zeroed()),
            Err(lx::Error::EINVAL)
        ));
        assert_eq!(
            fs.mkdir(&request(1), name(bad), &fuse_mkdir_in::new_zeroed())
                .unwrap_err(),
            lx::Error::EINVAL
        );
        assert_eq!(
            fs.rename(&request(1), name("safe"), 1, name(bad), 0)
                .unwrap_err(),
            lx::Error::EINVAL
        );
        assert_eq!(
            fs.rename(&request(1), name(bad), 1, name("safe"), 0)
                .unwrap_err(),
            lx::Error::EINVAL
        );
        assert_eq!(
            fs.unlink(&request(1), name(bad)).unwrap_err(),
            lx::Error::EINVAL
        );
        assert_eq!(
            fs.rmdir(&request(1), name(bad)).unwrap_err(),
            lx::Error::EINVAL
        );
    }
    assert!(temp.path().join("share/safe").is_file());
    assert_eq!(
        std::fs::read_dir(temp.path().join("share"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn adding_a_host_hardlink_revokes_io_on_existing_guest_handles() {
    let (temp, fs) = setup();
    let file = create(&fs, 1, "file");
    let id = file.entry.nodeid;
    let fh = file.open.fh;
    write(&fs, id, fh, b"original");
    let outside = temp.path().join("outside");
    std::fs::hard_link(temp.path().join("share/file"), &outside).unwrap();
    assert_eq!(
        fs.open(&request(id), (lx::O_RDWR | lx::O_TRUNC) as u32)
            .unwrap_err(),
        lx::Error::EPERM
    );
    assert_eq!(
        fs.read(
            &request(id),
            &fuse_read_in {
                fh,
                size: 8,
                ..FromZeros::new_zeroed()
            }
        )
        .unwrap_err(),
        lx::Error::EPERM
    );
    assert_eq!(
        fs.write(
            &request(id),
            &fuse_write_in {
                fh,
                size: 1,
                ..FromZeros::new_zeroed()
            },
            b"x"
        )
        .unwrap_err(),
        lx::Error::EPERM
    );
    assert_eq!(
        fs.set_attr(
            &request(id),
            &fuse_setattr_in {
                valid: FATTR_SIZE | FATTR_FH,
                fh,
                size: 0,
                ..FromZeros::new_zeroed()
            }
        )
        .unwrap_err(),
        lx::Error::EPERM
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"original");
    std::fs::remove_file(&outside).unwrap();
    assert_eq!(read(&fs, id, fh), b"original");
    release(&fs, id, fh);
}

fn setup_limited(bytes: u64, entries: u64) -> (tempdir::TempDir, SharedDir) {
    let temp = tempdir::TempDir::new("shared-dir-quota").unwrap();
    std::fs::create_dir(temp.path().join("share")).unwrap();
    let fs = SharedDir::new(
        open_root(temp.path(), "share").unwrap(),
        ShareLimits {
            max_bytes: bytes,
            max_entries: entries,
        },
    )
    .unwrap();
    (temp, fs)
}
fn resize(fs: &SharedDir, node: u64, fh: u64, size: u64) -> lx::Result<fuse_attr_out> {
    fs.set_attr(
        &request(node),
        &fuse_setattr_in {
            valid: FATTR_SIZE | FATTR_FH,
            fh,
            size,
            ..FromZeros::new_zeroed()
        },
    )
}
fn write_at(fs: &SharedDir, node: u64, fh: u64, offset: u64, data: &[u8]) -> lx::Result<usize> {
    fs.write(
        &request(node),
        &fuse_write_in {
            fh,
            offset,
            size: data.len() as u32,
            ..FromZeros::new_zeroed()
        },
        data,
    )
}

#[test]
fn quota_covers_aggregate_sizes_append_sparse_writes_and_truncate() {
    let (_temp, fs) = setup_limited(8, 8);
    let a = create(&fs, 1, "a");
    let b = create(&fs, 1, "b");
    write(&fs, a.entry.nodeid, a.open.fh, b"12345");
    assert_eq!(
        write_at(&fs, b.entry.nodeid, b.open.fh, 0, b"1234").unwrap_err(),
        lx::Error::ENOSPC
    );
    assert_eq!(
        write_at(&fs, a.entry.nodeid, a.open.fh, 8, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    assert_eq!(
        resize(&fs, b.entry.nodeid, b.open.fh, u64::MAX).unwrap_err(),
        lx::Error::ENOSPC
    );
    assert!(read(&fs, b.entry.nodeid, b.open.fh).is_empty());
    let append = fs
        .open(
            &request(a.entry.nodeid),
            (lx::O_WRONLY | lx::O_APPEND) as u32,
        )
        .unwrap()
        .fh;
    assert_eq!(
        write_at(&fs, a.entry.nodeid, append, 0, b"more").unwrap_err(),
        lx::Error::ENOSPC
    );
    assert_eq!(read(&fs, a.entry.nodeid, a.open.fh), b"12345");
    resize(&fs, a.entry.nodeid, a.open.fh, 2).unwrap();
    write(&fs, b.entry.nodeid, b.open.fh, b"123456");
    assert_eq!(
        write_at(&fs, a.entry.nodeid, append, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    fs.open(
        &request(b.entry.nodeid),
        (lx::O_WRONLY | lx::O_TRUNC) as u32,
    )
    .unwrap();
    write_at(&fs, a.entry.nodeid, append, 0, b"x").unwrap();
}

#[test]
fn quota_is_not_refunded_by_forged_handles_forget_or_open_unlink() {
    let (_temp, fs) = setup_limited(8, 8);
    let a = create(&fs, 1, "a");
    let b = create(&fs, 1, "b");
    write(&fs, a.entry.nodeid, a.open.fh, b"12345678");
    assert_eq!(
        resize(&fs, a.entry.nodeid, b.open.fh, 0).unwrap_err(),
        lx::Error::EBADF
    );
    assert_eq!(
        write_at(&fs, b.entry.nodeid, b.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    fs.forget(a.entry.nodeid, u64::MAX);
    assert_eq!(
        write_at(&fs, b.entry.nodeid, b.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    fs.unlink(&request(1), name("a")).unwrap();
    assert_eq!(
        write_at(&fs, b.entry.nodeid, b.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    assert_eq!(read(&fs, a.entry.nodeid, a.open.fh), b"12345678");
    release(&fs, a.entry.nodeid, a.open.fh);
    write(&fs, b.entry.nodeid, b.open.fh, b"12345678");
    // Forget/release of a still-linked file must not refund its on-disk usage.
    fs.forget(b.entry.nodeid, u64::MAX);
    release(&fs, b.entry.nodeid, b.open.fh);
    let c = create(&fs, 1, "c");
    assert_eq!(
        write_at(&fs, c.entry.nodeid, c.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
}

#[test]
fn quota_tracks_rename_replacement_until_the_old_inode_is_released() {
    let (_temp, fs) = setup_limited(8, 8);
    let src = create(&fs, 1, "src");
    let dest = create(&fs, 1, "dest");
    write(&fs, src.entry.nodeid, src.open.fh, b"1234");
    write(&fs, dest.entry.nodeid, dest.open.fh, b"5678");
    fs.rename(&request(1), name("src"), 1, name("dest"), 0)
        .unwrap();
    let c = create(&fs, 1, "c");
    assert_eq!(
        write_at(&fs, c.entry.nodeid, c.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
    release(&fs, dest.entry.nodeid, dest.open.fh);
    fs.forget(dest.entry.nodeid, 1);
    write(&fs, c.entry.nodeid, c.open.fh, b"abcd");
    assert_eq!(read(&fs, src.entry.nodeid, src.open.fh), b"1234");
}

#[test]
fn entry_quota_covers_empty_files_and_directories_after_forget() {
    let (_temp, fs) = setup_limited(1024, 3);
    let file = create(&fs, 1, "file");
    fs.forget(file.entry.nodeid, 1);
    release(&fs, file.entry.nodeid, file.open.fh);
    let dir = fs
        .mkdir(&request(1), name("dir"), &fuse_mkdir_in::new_zeroed())
        .unwrap();
    assert!(matches!(
        fs.create(&request(1), name("extra"), &fuse_create_in::new_zeroed()),
        Err(lx::Error::ENOSPC)
    ));
    assert_eq!(
        fs.mkdir(&request(1), name("extra"), &fuse_mkdir_in::new_zeroed())
            .unwrap_err(),
        lx::Error::ENOSPC
    );
    fs.rmdir(&request(1), name("dir")).unwrap();
    // Its pinned inode is retained until FORGET, even without an open directory.
    assert!(matches!(
        fs.create(&request(1), name("extra"), &fuse_create_in::new_zeroed()),
        Err(lx::Error::ENOSPC)
    ));
    fs.forget(dir.nodeid, 1);
    create(&fs, 1, "extra");
}

#[test]
fn quota_allows_existing_files_at_capacity_and_refunds_failed_creation() {
    let (_temp, fs) = setup_limited(8, 3);
    let file = create(&fs, 1, "file");
    assert!(
        fs.mkdir(&request(1), name("file"), &fuse_mkdir_in::new_zeroed())
            .is_err()
    );
    create(&fs, 1, "other");
    // No new directory entry is allocated by CREATE without O_EXCL on an
    // existing name, even when the entry budget is full.
    let reopened = fs
        .create(
            &request(1),
            name("file"),
            &fuse_create_in {
                flags: lx::O_RDWR as u32,
                ..FromZeros::new_zeroed()
            },
        )
        .unwrap();
    assert_eq!(reopened.entry.nodeid, file.entry.nodeid);
}

#[test]
fn case_only_rename_does_not_refund_a_linked_files_charge() {
    let (_temp, fs) = setup_limited(8, 4);
    let file = create(&fs, 1, "file");
    write(&fs, file.entry.nodeid, file.open.fh, b"12345678");
    fs.rename(&request(1), name("file"), 1, name("FILE"), 0)
        .unwrap();
    fs.forget(file.entry.nodeid, 1);
    release(&fs, file.entry.nodeid, file.open.fh);
    let other = create(&fs, 1, "other");
    assert_eq!(
        write_at(&fs, other.entry.nodeid, other.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
}

#[test]
fn startup_quota_counts_existing_nested_contents() {
    let temp = tempdir::TempDir::new("shared-dir-existing-quota").unwrap();
    std::fs::create_dir_all(temp.path().join("share/sub")).unwrap();
    std::fs::write(temp.path().join("share/sub/file"), b"12345").unwrap();
    let new = |bytes, entries| {
        SharedDir::new(
            open_root(temp.path(), "share").unwrap(),
            ShareLimits {
                max_bytes: bytes,
                max_entries: entries,
            },
        )
    };
    assert!(new(4, 10).is_err());
    assert!(new(10, 2).is_err());
    let fs = new(5, 4).unwrap();
    let file = create(&fs, 1, "new");
    assert_eq!(
        write_at(&fs, file.entry.nodeid, file.open.fh, 0, b"x").unwrap_err(),
        lx::Error::ENOSPC
    );
}

#[test]
fn statfs_reports_only_the_share_budget_including_unlinked_pins() {
    let (_temp, fs) = setup_limited(8192, 3);
    let before = fs.statfs(&request(1)).unwrap();
    assert_eq!(
        (
            before.blocks,
            before.bfree,
            before.files,
            before.ffree,
            before.bsize
        ),
        (2, 2, 3, 2, 4096)
    );
    let file = create(&fs, 1, "file");
    resize(&fs, file.entry.nodeid, file.open.fh, 4096).unwrap();
    fs.unlink(&request(1), name("file")).unwrap();
    let pinned = fs.statfs(&request(1)).unwrap();
    assert_eq!((pinned.bfree, pinned.bavail, pinned.ffree), (1, 1, 1));
    fs.forget(file.entry.nodeid, 1);
    release(&fs, file.entry.nodeid, file.open.fh);
    let after = fs.statfs(&request(1)).unwrap();
    assert_eq!((after.bfree, after.ffree), (2, 2));
}

#[test]
fn hostile_wire_requests_are_rejected_without_mutating_host_files() {
    struct Reply(Vec<u8>);
    impl fuse::ReplySender for Reply {
        fn send(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<()> {
            assert!(buffers.iter().map(|b| b.len()).sum::<usize>() <= MAX_IO + 512);
            self.0 = buffers.iter().flat_map(|b| b.iter().copied()).collect();
            Ok(())
        }
    }
    fn dispatch(session: &fuse::Session, opcode: u32, node: u64, payload: &[u8]) -> i32 {
        let header = fuse_in_header {
            len: (size_of::<fuse_in_header>() + payload.len()) as u32,
            opcode,
            nodeid: node,
            unique: 37,
            uid: 0,
            gid: 0,
            ..FromZeros::new_zeroed()
        };
        let wire = [header.as_bytes(), payload].concat();
        let mut reply = Reply(Vec::new());
        session.dispatch(Request::new(wire.as_slice()).unwrap(), &mut reply, None);
        let (out, _) = fuse_out_header::read_from_prefix(&reply.0).unwrap();
        assert_eq!(out.unique, 37);
        assert_eq!(out.len as usize, reply.0.len());
        out.error
    }
    let (temp, fs) = setup_limited(1024, 8);
    let file = create(&fs, 1, "safe");
    write(&fs, file.entry.nodeid, file.open.fh, b"inside");
    std::fs::write(temp.path().join("outside"), b"secret").unwrap();
    let session = fuse::Session::new(fs);
    assert_eq!(
        dispatch(
            &session,
            FUSE_INIT,
            0,
            fuse_init_in {
                major: 7,
                minor: 31,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
        ),
        0
    );
    let mut cases = vec![
        (FUSE_LOOKUP, 1, b"../outside\0".to_vec()),
        (FUSE_LOOKUP, 1, b"CONIN$\0".to_vec()),
        (FUSE_SYMLINK, 1, b"link\0../outside\0".to_vec()),
        (
            FUSE_READ,
            file.entry.nodeid,
            fuse_read_in {
                fh: file.open.fh,
                size: u32::MAX,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
            .to_vec(),
        ),
        (
            FUSE_READ,
            1,
            fuse_read_in {
                fh: file.open.fh,
                size: 6,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
            .to_vec(),
        ),
        (
            FUSE_WRITE,
            file.entry.nodeid,
            [
                fuse_write_in {
                    fh: file.open.fh,
                    size: u32::MAX,
                    ..FromZeros::new_zeroed()
                }
                .as_bytes(),
                b"x",
            ]
            .concat(),
        ),
        (
            FUSE_WRITE,
            file.entry.nodeid,
            [
                fuse_write_in {
                    fh: file.open.fh,
                    offset: u64::MAX,
                    size: 1,
                    ..FromZeros::new_zeroed()
                }
                .as_bytes(),
                b"x",
            ]
            .concat(),
        ),
        (
            FUSE_SETATTR,
            file.entry.nodeid,
            fuse_setattr_in {
                valid: FATTR_SIZE | FATTR_FH,
                fh: u64::MAX,
                size: 0,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
            .to_vec(),
        ),
        (
            FUSE_READDIR,
            1,
            fuse_read_in {
                fh: u64::MAX,
                size: u32::MAX,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
            .to_vec(),
        ),
        (
            FUSE_RENAME,
            1,
            [
                fuse_rename_in { newdir: u64::MAX }.as_bytes(),
                b"safe\0outside\0",
            ]
            .concat(),
        ),
        (
            FUSE_IOCTL,
            file.entry.nodeid,
            fuse_ioctl_in {
                out_size: u32::MAX,
                ..FromZeros::new_zeroed()
            }
            .as_bytes()
            .to_vec(),
        ),
        (
            FUSE_SETUPMAPPING,
            file.entry.nodeid,
            fuse_setupmapping_in::new_zeroed().as_bytes().to_vec(),
        ),
    ];
    // Corrupt/truncate every fixed-layout operation without giving the backend
    // an opportunity to interpret guest lengths as allocation sizes.
    for opcode in [FUSE_READ, FUSE_WRITE, FUSE_SETATTR, FUSE_IOCTL, FUSE_RENAME] {
        for length in [0, 1, 7, 15] {
            cases.push((opcode, file.entry.nodeid, vec![0xff; length]));
        }
    }
    for (opcode, node, payload) in cases {
        assert!(
            dispatch(&session, opcode, node, &payload) < 0,
            "accepted opcode {opcode}"
        );
    }
    assert_eq!(
        std::fs::read(temp.path().join("share/safe")).unwrap(),
        b"inside"
    );
    assert_eq!(
        std::fs::read(temp.path().join("outside")).unwrap(),
        b"secret"
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("share"))
            .unwrap()
            .count(),
        1
    );
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
