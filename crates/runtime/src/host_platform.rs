use std::{fs::File, io};
use vm_resource::{IntoResource, Resource};

pub(crate) fn stderr_file() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(std::io::stderr().as_fd().try_clone_to_owned()?.into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(std::io::stderr().as_handle().try_clone_to_owned()?.into())
    }
}

#[cfg(target_os = "linux")]
const BLOCKED_SYSCALLS_X86_64: &[i64] = &[
    // Socket creation, binding, listening, and outbound connections
    // (all network endpoints are pre-bound/connected before harden_process,
    // and guest-agent vsock uses in-memory streams)
    41, // socket
    42, // connect
    49, // bind
    50, // listen
    53, // socketpair
    // Process creation via exec / fork (threads via clone/clone3 remain allowed)
    57,  // fork
    58,  // vfork
    59,  // execve
    322, // execveat
    // Filesystem links, special nodes, permissions, and ownership
    // (defense-in-depth beneath shared_dir / virtiofs)
    86,  // link
    88,  // symlink
    90,  // chmod
    91,  // fchmod
    92,  // chown
    93,  // fchown
    94,  // lchown
    133, // mknod
    259, // mknodat
    260, // fchownat
    265, // linkat
    266, // symlinkat
    268, // fchmodat
    452, // fchmodat2
    // Mounts, root changes, and file-handle escapes (shingled with cap-std)
    155, // pivot_root
    161, // chroot
    165, // mount
    166, // umount2
    304, // open_by_handle_at
    428, // open_tree
    429, // move_mount
    430, // fsopen
    431, // fsconfig
    432, // fsmount
    433, // fspick
    442, // mount_setattr
    // Kernel / cross-process attack surface
    101, // ptrace
    163, // acct
    167, // swapon
    168, // swapoff
    169, // reboot
    175, // init_module
    176, // delete_module
    179, // quotactl
    246, // kexec_load
    248, // add_key
    249, // request_key
    250, // keyctl
    272, // unshare
    298, // perf_event_open
    308, // setns
    310, // process_vm_readv
    311, // process_vm_writev
    312, // kcmp
    313, // finit_module
    320, // kexec_file_load
    321, // bpf
    323, // userfaultfd
    443, // quotactl_fd
];

#[cfg(target_os = "linux")]
fn build_seccomp_filter() -> io::Result<seccompiler::BpfProgram> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    let rules: BTreeMap<i64, Vec<SeccompRule>> = BLOCKED_SYSCALLS_X86_64
        .iter()
        .copied()
        .map(|syscall_nr| (syscall_nr, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(rustix::io::Errno::PERM.raw_os_error() as u32),
        TargetArch::x86_64,
    )
    .map_err(io::Error::other)?;
    BpfProgram::try_from(filter).map_err(io::Error::other)
}

pub(crate) fn harden_process() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        rustix::thread::set_no_new_privs(true)?;
        let filter = build_seccomp_filter()?;
        seccompiler::apply_filter_all_threads(&filter).map_err(io::Error::other)?;
    }
    Ok(())
}

pub(crate) fn hypervisor() -> anyhow::Result<Resource<hypervisor_resources::HypervisorKind>> {
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .context("opening /dev/kvm for OpenVMM")?;
        Ok(hypervisor_resources::KvmHandle { kvm }.into_resource())
    }
    #[cfg(windows)]
    {
        Ok(hypervisor_resources::WhpHandle::default().into_resource())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_compiles_and_blocks_dangerous_syscalls() {
        const CHILD_ENV: &str = "YA_VM_TEST_SECCOMP_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            harden_process().expect("harden_process should succeed in child process");

            let symlink_err = rustix::fs::symlinkat(
                "target",
                rustix::fs::CWD,
                "/tmp/ya-runtime-vm-seccomp-denied-symlink",
            )
            .expect_err("symlinkat must be blocked by seccomp");
            assert_eq!(symlink_err, rustix::io::Errno::PERM);

            let socket_err = std::net::UdpSocket::bind("127.0.0.1:0")
                .expect_err("socket creation must be blocked by seccomp");
            assert_eq!(socket_err.kind(), io::ErrorKind::PermissionDenied);

            let exec_err = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("true")
                .status()
                .expect_err("execve/fork must be blocked by seccomp");
            assert_eq!(exec_err.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let filter = build_seccomp_filter().expect("seccomp filter should compile");
        assert!(!filter.is_empty());

        let status = std::process::Command::new(
            std::env::current_exe().expect("resolving current test binary"),
        )
        .env(CHILD_ENV, "1")
        .arg("--exact")
        .arg("host_platform::tests::seccomp_filter_compiles_and_blocks_dangerous_syscalls")
        .arg("--nocapture")
        .status()
        .expect("spawning seccomp child test process");
        assert!(status.success(), "seccomp child test failed: {status}");
    }
}
