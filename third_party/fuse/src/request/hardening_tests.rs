// Local regression tests for bounded decoding of untrusted virtio-fs requests.
use super::*;
use std::io::{Cursor, Read};

fn wire(opcode: u32, payload: &[u8]) -> Vec<u8> {
    let header = fuse_in_header {
        len: (size_of::<fuse_in_header>() + payload.len()) as u32,
        opcode,
        unique: 37,
        nodeid: 1,
        ..FromZeros::new_zeroed()
    };
    [header.as_bytes(), payload].concat()
}
fn rejects(bytes: &[u8]) {
    let request = Request::new(bytes).unwrap();
    assert!(matches!(
        request.operation(),
        FuseOperation::Invalid | FuseOperation::Error(_)
    ));
    assert_eq!(request.unique(), 37);
}

#[test]
fn rejects_declared_allocations_without_the_corresponding_payload() {
    // A regression must fail this test without allocating gigabytes on the
    // developer's machine or aborting the rest of the workspace test runner.
    #[cfg(target_os = "linux")]
    {
        const CHILD: &str = "YA_RUNTIME_FUSE_ALLOCATION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "request::hardening_tests::rejects_declared_allocations_without_the_corresponding_payload",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        // SAFETY: resource limits apply only to this child test process.
        unsafe {
            assert_eq!(
                libc::setrlimit(
                    libc::RLIMIT_CORE,
                    &libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0
                    }
                ),
                0
            );
            let limit = 128 * 1024 * 1024;
            assert_eq!(
                libc::setrlimit(
                    libc::RLIMIT_AS,
                    &libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit
                    }
                ),
                0
            );
        }
    }
    for size in [1024 * 1024 * 1024, u32::MAX] {
        let write = fuse_write_in {
            size,
            ..FromZeros::new_zeroed()
        };
        rejects(&wire(FUSE_WRITE, write.as_bytes()));
        let xattr = fuse_setxattr_in {
            size,
            ..FromZeros::new_zeroed()
        };
        rejects(&wire(
            FUSE_SETXATTR,
            &[xattr.as_bytes(), b"user.x\0"].concat(),
        ));
        let ioctl = fuse_ioctl_in {
            in_size: size,
            ..FromZeros::new_zeroed()
        };
        rejects(&wire(FUSE_IOCTL, ioctl.as_bytes()));
    }
    let mut bytes: &[u8] = b"abc";
    assert!(bytes.read_count(usize::MAX).is_err());
    assert_eq!(bytes, b"abc");
}

#[test]
fn rejects_underflow_truncation_and_trailing_transport_bytes() {
    let valid = wire(FUSE_INIT, fuse_init_in::new_zeroed().as_bytes());
    for len in [
        0,
        1,
        39,
        40,
        valid.len() as u32 - 1,
        valid.len() as u32 + 1,
        u32::MAX,
    ] {
        let mut input = valid.clone();
        input[..4].copy_from_slice(&len.to_ne_bytes());
        rejects(&input);
    }
    assert!(Request::new(&valid[..39]).is_err());
}

// The transport's string reader must not be used, even for valid names. It may
// allocate a descriptor-sized buffer before finding a NUL or rewind incorrectly.
struct Transport {
    bytes: Cursor<Vec<u8>>,
    available: usize,
    reads: usize,
}
impl Read for Transport {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if self.available > MAX_REQUEST_SIZE {
            assert_eq!(self.reads, 1);
        }
        self.bytes.read(dst)
    }
}
impl RequestReader for Transport {
    fn read_until(&mut self, _: u8) -> lx::Result<Vec<u8>> {
        panic!("unbounded transport string reader invoked")
    }
    fn remaining_len(&self) -> usize {
        self.available
    }
}

#[test]
fn oversized_transport_is_rejected_before_reading_or_allocating_payload() {
    let header = wire(FUSE_LOOKUP, &[]);
    for available in [MAX_REQUEST_SIZE, 1024 * 1024 * 1024, usize::MAX] {
        let request = Request::new(Transport {
            bytes: Cursor::new(header.clone()),
            available,
            reads: 0,
        })
        .unwrap();
        assert!(matches!(request.operation(), FuseOperation::Invalid));
    }
}

#[test]
fn parses_multiple_names_without_transport_rewinding() {
    let rename = fuse_rename_in { newdir: 9 };
    let input = wire(FUSE_RENAME, &[rename.as_bytes(), b"old\0new\0"].concat());
    let available = input.len() - size_of::<fuse_in_header>();
    let request = Request::new(Transport {
        bytes: Cursor::new(input),
        available,
        reads: 0,
    })
    .unwrap();
    match request.operation() {
        FuseOperation::Rename {
            arg,
            name,
            new_name,
        } => {
            assert_eq!(arg.newdir, 9);
            assert_eq!(name.as_bytes(), b"old");
            assert_eq!(new_name.as_bytes(), b"new");
        }
        other => panic!("unexpected operation: {other:?}"),
    }
}

#[test]
fn accepts_a_full_negotiated_one_mib_write() {
    let data = vec![0x5a; 1024 * 1024];
    let arg = fuse_write_in {
        size: data.len() as u32,
        ..FromZeros::new_zeroed()
    };
    let input = wire(FUSE_WRITE, &[arg.as_bytes(), &data].concat());
    let request = Request::new(input.as_slice()).unwrap();
    match request.operation() {
        FuseOperation::Write { data: actual, .. } => assert_eq!(actual.as_ref(), data),
        other => panic!("unexpected operation: {other:?}"),
    }
}
