#define _GNU_SOURCE
#include <errno.h>
#include <seccomp.h>
#include <fcntl.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>

#define SYSROOT "/mnt/newroot"

#define NAMESPACES                             \
    (CLONE_NEWUSER | /* new user namespace */  \
     CLONE_NEWNS |   /* new mount namespace */ \
     0)

#define CHECK(x) ({                                                  \
    __typeof__(x) _x = (x);                                          \
    if (_x == -1)                                                    \
    {                                                                \
        fprintf(stderr, "Error at %s:%d: %m\n", __FILE__, __LINE__); \
        die();                                                       \
    }                                                                \
    _x;                                                              \
})

#define CHECK_BOOL(x) ({                                             \
    __typeof__(x) _x = (x);                                          \
    if (!_x)                                                         \
    {                                                                \
        fprintf(stderr, "Error at %s:%d: %m\n", __FILE__, __LINE__); \
        die();                                                       \
    }                                                                \
    _x;                                                              \
})

static noreturn void die(void)
{
    sync();

    while (1)
    {
        (void)reboot(RB_POWER_OFF);
        __asm__ volatile("hlt");
    }
}

static const char *allow_syscalls[] = {
    "_llseek",
    "_newselect",
    "accept",
    "accept4",
    "access",
    "adjtimex",
    "alarm",
    "bind",
    "brk",
    "capget",
    "capset",
    "chdir",
    "chmod",
    "chown",
    "chown32",
    "chroot",
    "clock_adjtime",
    "clock_adjtime64",
    "clock_getres",
    "clock_getres_time64",
    "clock_gettime",
    "clock_gettime64",
    "clock_nanosleep",
    "clock_nanosleep_time64",
    "clone",
    "clone3",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_ctl_old",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "epoll_wait_old",
    "eventfd",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise64",
    "fadvise64_64",
    "fallocate",
    "fanotify_mark",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchown32",
    "fchownat",
    "fcntl",
    "fcntl64",
    "fdatasync",
    "fgetxattr",
    "flistxattr",
    "flock",
    "fork",
    "fremovexattr",
    "fsetxattr",
    "fstat",
    "fstat64",
    "fstatat64",
    "fstatfs",
    "fstatfs64",
    "fsync",
    "ftruncate",
    "ftruncate64",
    "futex",
    "futex_time64",
    "futimesat",
    "get_mempolicy",
    "get_robust_list",
    "get_thread_area",
    "getcpu",
    "getcwd",
    "getdents",
    "getdents64",
    "getegid",
    "getegid32",
    "geteuid",
    "geteuid32",
    "getgid",
    "getgid32",
    "getgroups",
    "getgroups32",
    "getitimer",
    "getpeername",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getpriority",
    "getrandom",
    "getresgid",
    "getresgid32",
    "getresuid",
    "getresuid32",
    "getrlimit",
    "getrusage",
    "getsid",
    "getsockname",
    "getsockopt",
    "gettid",
    "gettimeofday",
    "getuid",
    "getuid32",
    "getxattr",
    "inotify_add_watch",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
    "io_cancel",
    "io_destroy",
    "io_getevents",
    "io_setup",
    "io_submit",
    "ioctl",
    "ioprio_get",
    "ioprio_set",
    "ipc",
    "keyctl",
    "kill",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    "lchown",
    "lchown32",
    "lgetxattr",
    "link",
    "linkat",
    "listen",
    "listxattr",
    "llistxattr",
    "lremovexattr",
    "lseek",
    "lsetxattr",
    "lstat",
    "lstat64",
    "madvise",
    "mbind",
    "membarrier",
    "memfd_create",
    "memfd_secret",
    "mincore",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mlock",
    "mlock2",
    "mlockall",
    "mmap",
    "mmap2",
    "mprotect",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "mremap",
#if 0
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
#endif
    "msync",
    "munlock",
    "munlockall",
    "munmap",
    "name_to_handle_at",
    "nanosleep",
    "newfstatat",
    "open",
    "open_tree",
    "openat",
    "openat2",
    "pause",
    "pidfd_getfd",
    "pidfd_open",
    "pidfd_send_signal",
    "pipe",
    "pipe2",
    "pivot_root",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "poll",
    "ppoll",
    "ppoll_time64",
    "prctl",
    "pread64",
    "preadv",
    "preadv2",
    "prlimit64",
    "process_mrelease",
    "process_vm_readv",
    "process_vm_writev",
    "pselect6",
    "pselect6_time64",
    "ptrace",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "read",
    "readahead",
    "readdir",
    "readlink",
    "readlinkat",
    "readv",
    "reboot",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "remap_file_pages",
    "removexattr",
    "rename",
    "renameat",
    "renameat2",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigqueueinfo",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "rt_tgsigqueueinfo",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_getscheduler",
    "sched_rr_get_interval",
    "sched_rr_get_interval_time64",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "sched_yield",
    "seccomp",
    "select",
#if 0
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "semtimedop_time64",
#endif
    "send",
    "sendfile",
    "sendfile64",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "set_mempolicy",
    "set_robust_list",
    "set_thread_area",
    "set_tid_address",
    "setfsgid",
    "setfsgid32",
    "setfsuid",
    "setfsuid32",
    "setgid",
    "setgid32",
    "setgroups",
    "setgroups32",
    "setitimer",
    "setpgid",
    "setpriority",
    "setregid",
    "setregid32",
    "setresgid",
    "setresgid32",
    "setresuid",
    "setresuid32",
    "setreuid",
    "setreuid32",
    "setrlimit",
    "setsid",
    "setsockopt",
    "setuid",
    "setuid32",
    "setxattr",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "shutdown",
    "sigaction",
    "sigaltstack",
    "signal",
    "signalfd",
    "signalfd4",
    "sigpending",
    "sigprocmask",
    "sigreturn",
    "sigsuspend",
    "socket",
    "socketcall",
    "socketpair",
    "splice",
    "stat",
    "stat64",
    "statfs",
    "statfs64",
    "statx",
    "symlink",
    "symlinkat",
    "sync",
    "sync_file_range",
    "syncfs",
    "syscall",
    "sysinfo",
    "syslog",
    "tee",
    "tgkill",
    "time",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_gettime64",
    "timer_settime",
    "timer_settime64",
    "timerfd",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_gettime64",
    "timerfd_settime",
    "timerfd_settime64",
    "times",
    "tkill",
    "truncate",
    "truncate64",
    "ugetrlimit",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "utime",
    "utimensat",
    "utimensat_time64",
    "utimes",
    "vfork",
    "wait4",
    "waitid",
    "waitpid",
    "write",
    "writev",
};

static const char *arm_syscalls[] = {
    "arm_fadvise64_64",
    "arm_sync_file_range",
    "breakpoint",
    "cacheflush",
    "set_tls",
    "sync_file_range2",
};

static const char *x86_syscalls[] = {
    "arch_prctl",
};

static const char *eperm_syscalls[] = {
    "bdflush",
    "bpf",
    "fanotify_init",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "io_pgetevents",
    "kexec_file_load",
    "kexec_load",
    "migrate_pages",
    "mount",
    "mount_setattr",
    "move_mount",
    "move_pages",
    "nfsservctl",
    "nice",
    "oldfstat",
    "oldlstat",
    "oldolduname",
    "oldstat",
    "olduname",
    "pciconfig_iobase",
    "pciconfig_read",
    "pciconfig_write",
    "perf_event_open",
    "quotactl",
    "setdomainname",
    "sethostname",
    "setns",
    "sgetmask",
    "ssetmask",
    "swapcontext",
    "swapoff",
    "swapon",
    "sysfs",
    "umount",
    "umount2",
    "unshare",
    "uselib",
    "userfaultfd",
    "ustat",
    "vm86",
    "vm86old",
    "vmsplice",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

static int capset(const cap_user_header_t hdrp, const cap_user_data_t datap)
{
    return syscall(SYS_capset, hdrp, datap);
}

static void
ya_runtime_add_syscalls(const scmp_filter_ctx ctx, const char *const *syscalls,
                        const size_t count, const uint32_t arch, const uint32_t action)
{
    for (size_t i = 0; i < count; ++i)
    {
        const int syscall_number = seccomp_syscall_resolve_name_rewrite(arch, syscalls[i]);
        if (syscall_number == __NR_SCMP_ERROR)
            abort();
        const int status = seccomp_rule_add(ctx, action, syscall_number, 0);
        if (status != 0)
            abort();
    }
}

static scmp_filter_ctx ctx;

void setup_sandbox(void)
{
    uint32_t const arch = seccomp_arch_native();
    ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));

    if (ctx == NULL)
        abort();

    ya_runtime_add_syscalls(ctx, allow_syscalls, ARRAY_SIZE(allow_syscalls), arch, SCMP_ACT_ALLOW);
    const int status = seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
                                        SCMP_SYS(personality), 1, SCMP_CMP64(0, SCMP_CMP_EQ, 0, 0));
    if (status != 0)
    {
        abort();
    }

    switch (arch)
    {
    case SCMP_ARCH_ARM:
    case SCMP_ARCH_AARCH64:
        ya_runtime_add_syscalls(ctx, arm_syscalls, ARRAY_SIZE(arm_syscalls),
                                arch, SCMP_ACT_ALLOW);
        break;
    case SCMP_ARCH_X86:
    case SCMP_ARCH_X86_64:
        ya_runtime_add_syscalls(ctx, x86_syscalls, ARRAY_SIZE(x86_syscalls),
                                arch, SCMP_ACT_ALLOW);
    default:
        break;
    }

    ya_runtime_add_syscalls(ctx, eperm_syscalls, ARRAY_SIZE(eperm_syscalls), arch, SCMP_ACT_ERRNO(EPERM));
    const int fd = memfd_create("fake", MFD_CLOEXEC);
    if (fd < 3)
        abort();
    if (seccomp_export_bpf(ctx, fd))
        abort();
}

void sandbox_apply(int child_pipe)
{
    if (seccomp_load(ctx))
        abort();

    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {0};

    for (int i = 0; i < _LINUX_CAPABILITY_U32S_3 * 32; ++i)
    {
        switch (i)
        {
        // CAP_AUDIT_CONTROL: no
        // CAP_AUDIT_READ: no
        // CAP_AUDIT_WRITE: no
        case CAP_BLOCK_SUSPEND:
        // case CAP_BPF:
        // case CAP_CHECKPOINT_RESTORE:
        case CAP_CHOWN:
        case CAP_DAC_OVERRIDE:
        case CAP_DAC_READ_SEARCH:
        case CAP_FOWNER:
        case CAP_FSETID:
        case CAP_IPC_LOCK:
        case CAP_IPC_OWNER:
        case CAP_KILL:
        case CAP_LEASE:
        case CAP_LINUX_IMMUTABLE:
        // case CAP_MKNOD:
        // case CAP_NET_ADMIN:
        case CAP_NET_BIND_SERVICE:
        case CAP_NET_BROADCAST:
        case CAP_NET_RAW:
        // case CAP_PERFMON:
        case CAP_SETGID:
        case CAP_SETFCAP:
        case CAP_SETPCAP:
        case CAP_SETUID:
        // case CAP_SYS_ADMIN:
        case CAP_SYS_BOOT:
        case CAP_SYS_CHROOT:
        // case CAP_SYS_MODULE:
        case CAP_SYS_NICE:
        case CAP_SYS_PACCT:
        case CAP_SYS_PTRACE:
        // case CAP_SYS_RAWIO
        case CAP_SYS_RESOURCE:
        // case CAP_SYS_TIME:
        // case CAP_SYS_TTY_CONFIG:
        // case CAP_SYSLOG:
        case CAP_WAKE_ALARM:
        {
            data[i / 32].permitted |= UINT32_C(1) << i % 32;
            data[i / 32].effective |= UINT32_C(1) << i % 32;
            break;
        }
        default:
            const int res = prctl(PR_CAPBSET_DROP, i);
            if (res != 0 && (res != -1 && errno == EINVAL))
                goto out;
        }
    }

    if (capset(&hdr, &*data))
    {
        goto out;
    }

out:
    if (child_pipe != -1)
    {
        char c = '\0';
        /* Can't do anything with errors here. */
        (void)write(child_pipe, &c, sizeof(c));
        close(child_pipe);
    }
    _exit(errno);
}

void get_namespace_fd(pid_t *global_pidfd, pid_t *global_zombie_pid, int *global_userns_fd, int *global_mountns_fd)
{
    int tmp_fd = CHECK(open("/user_namespace", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_EXCL | O_NOCTTY, 0600));
    CHECK(close(tmp_fd));
    tmp_fd = CHECK(open("/mount_namespace", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_EXCL | O_NOCTTY, 0600));
    CHECK(close(tmp_fd));
    char buf[sizeof "/proc//uid_map" + 10];
    struct clone_args args = {
        .flags = CLONE_CLEAR_SIGHAND |
                 CLONE_PIDFD | /* alloc a PID FD */
                 NAMESPACES,
        .pidfd = (uint64_t)global_pidfd,
        .child_tid = 0,
        .parent_tid = 0,
        .exit_signal = (uint64_t)SIGCHLD,
        .stack = 0,
        .stack_size = 0,
        .tls = 0,
        .set_tid = 0,
        .set_tid_size = 0,
        .cgroup = 0,
    };
    sigset_t set;
    CHECK(sigemptyset(&set));
    int fds[2], status = 0;
    CHECK_BOOL(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) == 0);
    errno = 0;
    *global_zombie_pid = syscall(SYS_clone3, &args, sizeof args);
    CHECK_BOOL(*global_zombie_pid >= 0);
    if (*global_zombie_pid == 0)
    {
        if (close(fds[0]))
            abort();
        if (mount(SYSROOT, SYSROOT, NULL, MS_BIND | MS_REC, NULL))
        {
            status = errno;
            goto bad;
        }
        if (mount(NULL, SYSROOT, NULL, MS_SLAVE | MS_REC, NULL))
        {
            status = errno;
            goto bad;
        }
        if (chdir(SYSROOT))
            abort();
        if (syscall(SYS_pivot_root, ".", "."))
        {
            status = errno;
            goto bad;
        }
        if (umount2(".", MNT_DETACH))
        {
            status = errno;
            goto bad;
        }
        if (chdir("/"))
        {
            status = errno;
        }
    bad:
        if (write(fds[1], &status, sizeof status) != sizeof status || shutdown(fds[1], SHUT_WR) != 0)
            _exit(1);
        (void)read(fds[1], &status, 1);
        _exit(0);
    }
    CHECK(*global_pidfd);
    /* parent */
    CHECK_BOOL(close(fds[1]) == 0);
    CHECK_BOOL(read(fds[0], &status, sizeof status) == sizeof status);
    errno = status;
    CHECK_BOOL(status == 0);
    int snprintf_res = snprintf(buf, sizeof buf, "/proc/%d/uid_map", *global_zombie_pid);
    CHECK_BOOL(snprintf_res >= (int)sizeof("/proc/1/uid_map") - 1);
    CHECK_BOOL(snprintf_res < (int)sizeof buf);
    for (int i = 0; i < 2; ++i)
    {
        const int uidmapfd = CHECK(open(buf, O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_WRONLY));
#define UIDMAP "0 0 4294967295"
        CHECK_BOOL(write(uidmapfd, UIDMAP, sizeof UIDMAP - 1) == sizeof UIDMAP - 1);
        CHECK_BOOL(close(uidmapfd) == 0);
        buf[snprintf_res - 7] = 'g';
    }
    static_assert(sizeof("ns/user") <= sizeof("uid_map"), "string size oops");
    static_assert(sizeof("ns/mnt") <= sizeof("uid_map"), "string size oops");
    snprintf_res = snprintf(buf, sizeof buf, "/proc/%d/ns/user", *global_zombie_pid);
    CHECK_BOOL(snprintf_res >= (int)sizeof "/proc/1/ns/user" - 1);
    CHECK_BOOL(snprintf_res < (int)sizeof "/proc/1/ns/user" + 9);
    CHECK(mount(buf, "/user_namespace", NULL, MS_BIND, NULL));
    *global_userns_fd = CHECK(open("/user_namespace", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY));
    snprintf_res = snprintf(buf, sizeof buf, "/proc/%d/ns/mnt", *global_zombie_pid);
    CHECK_BOOL(snprintf_res >= (int)sizeof "/proc/1/ns/mnt" - 1);
    CHECK_BOOL(snprintf_res < (int)sizeof "/proc/1/ns/mnt" + 9);
    CHECK(mount(buf, "/mount_namespace", NULL, MS_BIND, NULL));
    *global_mountns_fd = CHECK(open("/mount_namespace", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY));
    CHECK(write(fds[0], "", 1));
    int v;
    CHECK_BOOL(waitpid(*global_zombie_pid, &v, 0) == *global_zombie_pid);
    CHECK_BOOL(WIFEXITED(v));
    CHECK_BOOL(WEXITSTATUS(v) == 0);
}
