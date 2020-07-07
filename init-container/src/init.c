#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "communication.h"
#include "process_bookkeeping.h"
#include "proto.h"

// XXX: maybe obtain this with sysconf?
#define PAGE_SIZE 0x1000

#define DEFAULT_UID 0
#define DEFAULT_GID 0
#define DEFAULT_OUT_FILE_PERM S_IRWXU

#define OUTPUT_PATH_PREFIX "/var/tmp/guest_agent_private/fds"

struct new_process_args {
    char* bin;
    char** argv;
    char** envp;
    uint32_t uid;
    uint32_t gid;
    char* cwd;
    bool is_entrypoint;
};

extern char** environ;

static int g_cmds_fd = -1;
static int g_sig_fd = -1;

static struct process_desc* g_entrypoint_desc = NULL;

static noreturn void die(void) {
    sync();
    (void)close(g_sig_fd);
    (void)close(g_cmds_fd);

    while (1) {
        (void)reboot(RB_POWER_OFF);
        __asm__ volatile ("hlt");
    }
}

#define CHECK(x) ({                                                     \
    __typeof__(x) _x = (x);                                             \
    if (_x == -1) {                                                     \
        fprintf(stderr, "Error at %s:%d: %m\n", __FILE__, __LINE__);    \
        die();                                                          \
    }                                                                   \
    _x;                                                                 \
})

static void load_module(const char* path) {
    int fd = CHECK(open(path, O_RDONLY | O_CLOEXEC));
    CHECK(syscall(SYS_finit_module, fd, "", 0));
    CHECK(close(fd));
}

static void cleanup_fd_desc(struct redir_fd_desc* fd_desc) {
    switch (fd_desc->type) {
        case REDIRECT_FD_FILE:
            free(fd_desc->path);
            break;
        case REDIRECT_FD_PIPE_BLOCKING:
        case REDIRECT_FD_PIPE_CYCLIC:
            // TODO
            break;
        default:
            break;
    }
}

__attribute__((unused)) static void delete_proc(struct process_desc* proc_desc) {
    remove_process(proc_desc);
    for (size_t fd = 0; fd < 3; ++fd) {
        cleanup_fd_desc(&proc_desc->redirs[fd]);
    }
    free(proc_desc);
}

struct exit_reason {
    uint8_t status;
    uint8_t type;
};

static void send_process_died(uint64_t id, struct exit_reason reason) {
    struct msg_hdr resp = {
        .msg_id = 0,
        .type = NOTIFY_PROCESS_DIED,
    };

    CHECK(writen(g_cmds_fd, &resp, sizeof(resp)));
    CHECK(writen(g_cmds_fd, &id, sizeof(id)));
    CHECK(writen(g_cmds_fd, &reason.status, sizeof(reason.status)));
    CHECK(writen(g_cmds_fd, &reason.type, sizeof(reason.type)));
}

static struct exit_reason encode_status(int status, int type) {
    struct exit_reason exit_reason;

    switch (type) {
        case CLD_EXITED:
            exit_reason.type = 0;
            break;
        case CLD_KILLED:
            exit_reason.type = 1;
            break;
        case CLD_DUMPED:
            exit_reason.type = 2;
            break;
        default:
            fprintf(stderr, "Invalid exit reason to encode: %d\n", type);
            die();
    }

    exit_reason.status = (status & 0xff);

    return exit_reason;
}

static void handle_sigchld(void) {
    struct signalfd_siginfo siginfo = { 0 };

    if (read(g_sig_fd, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        fprintf(stderr, "Invalid signalfd read: %m\n");
        die();
    }

    if (siginfo.ssi_signo != SIGCHLD) {
        fprintf(stderr, "BUG: read unexpected signal from signalfd: %d\n",
                siginfo.ssi_signo);
        die();
    }

    uint32_t child_pid = siginfo.ssi_pid;

    if (siginfo.ssi_code != CLD_EXITED
            && siginfo.ssi_code != CLD_KILLED
            && siginfo.ssi_code != CLD_DUMPED) {
        /* Received spurious SIGCHLD - ignore it. */
        return;
    }

    pid_t w_pid = waitpid(child_pid, NULL, WNOHANG);
    if (w_pid != child_pid) {
        fprintf(stderr, "Error at waitpid: %d: %m\n", w_pid);
        die();
    }

    struct process_desc* proc_desc = find_process_by_pid(child_pid);
    if (!proc_desc) {
        /* This process was not tracked. */
        return;
    }

    proc_desc->is_alive = false;

    send_process_died(proc_desc->id, encode_status(siginfo.ssi_status,
                      siginfo.ssi_code));

    if (proc_desc == g_entrypoint_desc) {
        fprintf(stderr, "Entrypoint exited\n");
        CHECK(kill(-1, SIGKILL));
        die();
    }
}

static void setup_sigfd(void) {
    sigset_t set;
    CHECK(sigemptyset(&set));
    CHECK(sigaddset(&set, SIGCHLD));
    CHECK(sigprocmask(SIG_BLOCK, &set, NULL));
    g_sig_fd = CHECK(signalfd(g_sig_fd, &set, SFD_CLOEXEC));
}

static void create_dir(const char* path, mode_t mode) {
    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed with: %m\n", path);
        die();
    }
}

static void setup_agent_directories(void) {
    char* path = strdup(OUTPUT_PATH_PREFIX);
    if (!path) {
        fprintf(stderr, "setup_agent_directories OOM\n");
        die();
    }

    assert(path[0] == '/');

    char* next = path;
    while (1) {
        next = strchr(next + 1, '/');
        if (!next) {
            break;
        }
        *next = '\0';
        create_dir(path, S_IRWXU);
        *next = '/';
    }

    create_dir(path, S_IRWXU);

    free(path);
}

static void send_response_hdr(msg_id_t msg_id, enum GUEST_MSG_TYPE type) {
    struct msg_hdr resp = {
        .msg_id = msg_id,
        .type = type,
    };
    CHECK(writen(g_cmds_fd, &resp, sizeof(resp)));
}

static void send_response_ok(msg_id_t msg_id) {
    send_response_hdr(msg_id, RESP_OK);
}

static void send_response_err(msg_id_t msg_id, uint32_t ret_val) {
    send_response_hdr(msg_id, RESP_ERR);
    CHECK(writen(g_cmds_fd, &ret_val, sizeof(ret_val)));
}

static void send_response_u64(msg_id_t msg_id, uint64_t ret_val) {
    send_response_hdr(msg_id, RESP_OK_U64);
    CHECK(writen(g_cmds_fd, &ret_val, sizeof(ret_val)));
}

static void send_response_bytes(msg_id_t msg_id, char* buf, size_t len) {
    send_response_hdr(msg_id, RESP_OK_BYTES);
    CHECK(send_bytes(g_cmds_fd, buf, len));
}

static noreturn void handle_quit(msg_id_t msg_id) {
    send_response_ok(msg_id);
    die();
}

#define DEFAULT_FD_DESC {           \
        .type = REDIRECT_FD_FILE,   \
        .path = NULL,               \
    }

/* Assumes fd is either 0, 1 or 2.
 * Returns whether call was successful (setting errno on failures). */
static bool redirect_fd_to_path(int fd, const char* path) {
    assert(fd == 0 || fd == 1 || fd == 2);

    int source_fd = -1;
    if (fd == 0) {
        source_fd = open(path, O_RDONLY);
    } else {
        source_fd = open(path, O_WRONLY | O_CREAT, DEFAULT_OUT_FILE_PERM);
    }

    if (source_fd < 0) {
        return false;
    }

    if (source_fd != fd) {
        if (dup2(source_fd, fd) < 0) {
            int tmp_errno = errno;
            (void)close(source_fd);
            errno = tmp_errno;
            return false;
        }
        if (close(source_fd) < 0) {
            int tmp_errno = errno;
            (void)close(fd);
            errno = tmp_errno;
            return false;
        }
    }

    return true;
}

static noreturn void child_wrapper(int parent_pipe[2],
                                   struct new_process_args* new_proc_args,
                                   struct redir_fd_desc fd_descs[3]) {
    if (close(parent_pipe[0]) < 0) {
        goto out;
    }

    sigset_t set;
    if (sigemptyset(&set) < 0) {
        goto out;
    }
    if (sigprocmask(SIG_SETMASK, &set, NULL) < 0) {
        goto out;
    }

    if (new_proc_args->cwd) {
        if (chdir(new_proc_args->cwd) < 0) {
            goto out;
        }
    }

    for (int fd = 0; fd < 3; ++fd) {
        switch (fd_descs[fd].type) {
            case REDIRECT_FD_FILE:
                if (!redirect_fd_to_path(fd, fd_descs[fd].path)) {
                    goto out;
                }
                break;
            case REDIRECT_FD_PIPE_BLOCKING:
            case REDIRECT_FD_PIPE_CYCLIC:
                // TODO
                fprintf(stderr,
                        "Redir type %d not yet supported, ignoring (fd: %d)\n",
                        fd_descs[fd].type, fd);
                break;
            default:
                fprintf(stderr, "Unknown type in child_wrapper (BUG): %u\n",
                        fd_descs[fd].type);
                die();
        }
    }

    gid_t gid = new_proc_args->gid;
    if (setresgid(gid, gid, gid) < 0) {
        goto out;
    }

    uid_t uid = new_proc_args->uid;
    if (setresuid(uid, uid, uid) < 0) {
        goto out;
    }

    /* If execve returns we know an error happened. */
    (void)execve(new_proc_args->bin,
                 new_proc_args->argv,
                 new_proc_args->envp ?: environ);

out: ;
    int ecode = errno;
    char c = '\0';
    /* Can't do anything with errors here. */
    (void)write(parent_pipe[1], &c, sizeof(c));
    exit(ecode);
}

/* 0 is considered an invalid ID. */
static uint64_t get_next_id(void) {
    static uint64_t id = 0;
    return ++id;
}

static int create_process_fds_dir(uint64_t id) {
    char* path = NULL;
    if (asprintf(&path, OUTPUT_PATH_PREFIX "/%llu", id) < 0) {
        return -1;
    }

    if (mkdir(path, S_IRWXU) < 0) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}

static char* construct_output_path(uint64_t id, unsigned int fd) {
    char* path = NULL;
    if (asprintf(&path, OUTPUT_PATH_PREFIX "/%llu/%u", id, fd) < 0) {
        return NULL;
    }
    return path;
}

static uint32_t spawn_new_process(struct new_process_args* new_proc_args,
                                  struct redir_fd_desc fd_descs[3],
                                  uint64_t* id) {
    uint32_t ret = 0;

    if (new_proc_args->is_entrypoint && g_entrypoint_desc) {
        return EEXIST;
    }

    struct process_desc* proc_desc = calloc(1, sizeof(*proc_desc));
    if (!proc_desc) {
        return ENOMEM;
    }
    for (size_t fd = 0; fd < 3; ++fd) {
        proc_desc->redirs[fd].type = -1; // Invalid type
    }

    proc_desc->id = get_next_id();
    if (create_process_fds_dir(proc_desc->id) < 0) {
        ret = errno;
        goto out;
    }

    /* All these shenanigans with pipes are so that we can distinguish internal
     * failures from spawned process exiting. */
    int status_pipe[2] = { -1, -1 };
    if (pipe2(status_pipe, O_CLOEXEC | O_DIRECT) < 0) {
        ret = errno;
        goto out;
    }

    for (size_t fd = 0; fd < 3; ++fd) {
        proc_desc->redirs[fd].type = fd_descs[fd].type;
        switch (fd_descs[fd].type) {
            case REDIRECT_FD_FILE:
                if (fd_descs[fd].path) {
                    proc_desc->redirs[fd].path = strdup(fd_descs[fd].path);
                    if (!proc_desc->redirs[fd].path) {
                        ret = errno;
                        goto out;
                    }
                } else {
                    proc_desc->redirs[fd].path =
                        construct_output_path(proc_desc->id, fd);
                    if (!proc_desc->redirs[fd].path) {
                        ret = errno;
                        goto out;
                    }
                    int tmp_fd = open(proc_desc->redirs[fd].path,
                                      O_RDWR | O_CREAT | O_EXCL,
                                      S_IRWXU);
                    if (tmp_fd < 0 || close(tmp_fd) < 0) {
                        ret = errno;
                        goto out;
                    }
                }
                break;
            case REDIRECT_FD_PIPE_BLOCKING:
            case REDIRECT_FD_PIPE_CYCLIC:
                // TODO
                break;
            default:
                break;
        }
    }

    pid_t p = fork();
    if (p < 0) {
        ret = errno;
        goto out;
    } else if (p == 0) {
        child_wrapper(status_pipe, new_proc_args, proc_desc->redirs);
    }

    CHECK(close(status_pipe[1]));
    status_pipe[1] = -1;

    char c;
    ssize_t x = read(status_pipe[0], &c, sizeof(c));
    if (x < 0) {
        ret = errno;
        goto out;
    } else if (x > 0) {
        /* Process failed to spawn. */
        int status = 0;
        CHECK(waitpid(p, &status, 0));
        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            ret = 0x100 | WTERMSIG(status);
        } else {
            ret = ENOTRECOVERABLE;
        }
        goto out;
    } // else x == 0, which means successful process spawn.

    CHECK(close(status_pipe[0]));
    status_pipe[0] = -1;

    proc_desc->pid = p;
    proc_desc->is_alive = true;

    *id = proc_desc->id;

    add_process(proc_desc);
    if (new_proc_args->is_entrypoint) {
        g_entrypoint_desc = proc_desc;
    }
    proc_desc = NULL;

out:
    if (status_pipe[0] != -1) {
        CHECK(close(status_pipe[0]));
    }
    if (status_pipe[1] != -1) {
        CHECK(close(status_pipe[1]));
    }
    if (proc_desc) {
        for (size_t fd = 0; fd < 3; ++fd) {
            cleanup_fd_desc(&proc_desc->redirs[fd]);
        }
        free(proc_desc);
    }
    return ret;
}

static bool is_fd_buf_size_valid(size_t size) {
    return size > 0 && (size % PAGE_SIZE) == 0;
}

static uint32_t parse_fd_redir(struct redir_fd_desc fd_descs[3]) {
    uint32_t fd = 0;
    CHECK(recv_u32(g_cmds_fd, &fd));

    uint8_t type;
    CHECK(recv_u8(g_cmds_fd, &type));

    struct redir_fd_desc fd_desc = { .type = type };

    switch (type) {
        case REDIRECT_FD_FILE:
            CHECK(recv_bytes(g_cmds_fd, &fd_desc.path, NULL,
                             /*is_cstring=*/true));
            break;
        case REDIRECT_FD_PIPE_BLOCKING:
        case REDIRECT_FD_PIPE_CYCLIC:
            CHECK(recv_u64(g_cmds_fd, &fd_desc.buffer.size));
            fd_desc.buffer.buf = NULL;
            break;
        default:
            fprintf(stderr, "Unknown REDIRECT_FD_TYPE: %hhu\n", type);
            die();
    }

    /* We do this check so late, because we had to receive type specific data
     * anyway. */
    if (fd >= 3) {
        return EINVAL;
    }

    if (fd_desc.type == REDIRECT_FD_PIPE_BLOCKING
            || fd_desc.type == REDIRECT_FD_PIPE_CYCLIC) {
        if (!is_fd_buf_size_valid(fd_desc.buffer.size)) {
            return EINVAL;
        }
    }

    cleanup_fd_desc(&fd_descs[fd]);

    memcpy(&fd_descs[fd], &fd_desc, sizeof(fd_descs[fd]));

    return 0;
}

static void handle_run_process(msg_id_t msg_id) {
    bool done = false;
    uint32_t ret = 0;
    struct new_process_args new_proc_args = {
        .bin = NULL,
        .argv = NULL,
        .envp = NULL,
        .uid = DEFAULT_UID,
        .gid = DEFAULT_GID,
        .cwd = NULL,
        .is_entrypoint = false,
    };
    struct redir_fd_desc fd_descs[3] = {
        DEFAULT_FD_DESC,
        DEFAULT_FD_DESC,
        DEFAULT_FD_DESC,
    };
    uint64_t proc_id = 0;

    while (!done) {
        uint8_t subtype = 0;

        CHECK(recv_u8(g_cmds_fd, &subtype));

        switch (subtype) {
            case SUB_MSG_RUN_PROCESS_END:
                done = true;
                break;
            case SUB_MSG_RUN_PROCESS_BIN:
                CHECK(recv_bytes(g_cmds_fd, &new_proc_args.bin, NULL,
                                 /*is_cstring=*/true));
                break;
            case SUB_MSG_RUN_PROCESS_ARG:
                CHECK(recv_strings_array(g_cmds_fd, &new_proc_args.argv));
                break;
            case SUB_MSG_RUN_PROCESS_ENV:
                CHECK(recv_strings_array(g_cmds_fd, &new_proc_args.envp));
                break;
            case SUB_MSG_RUN_PROCESS_UID:
                CHECK(recv_u32(g_cmds_fd, &new_proc_args.uid));
                break;
            case SUB_MSG_RUN_PROCESS_GID:
                CHECK(recv_u32(g_cmds_fd, &new_proc_args.gid));
                break;
            case SUB_MSG_RUN_PROCESS_RFD: ;
                /* This error is recoverable - we report the first one found. We
                 * still need to consume the rest of sub-messages to keep
                 * the state consistent though. */
                uint32_t tmp_ret = parse_fd_redir(fd_descs);
                if (!ret) {
                    ret = tmp_ret;
                }
                break;
            case SUB_MSG_RUN_PROCESS_CWD:
                CHECK(recv_bytes(g_cmds_fd, &new_proc_args.cwd, NULL, /*is_cstring=*/true));
                break;
            case SUB_MSG_RUN_PROCESS_ENT:
                new_proc_args.is_entrypoint = true;
                break;
            default:
                fprintf(stderr, "Unknown MSG_RUN_PROCESS subtype: %hhu\n",
                        subtype);
                die();
        }
    }

    if (ret) {
        goto out;
    }
    if (!new_proc_args.bin) {
        ret = EFAULT;
        goto out;
    }
    if (!new_proc_args.argv) {
        ret = EFAULT;
        goto out;
    }

    ret = spawn_new_process(&new_proc_args, fd_descs, &proc_id);

out:
    free(new_proc_args.cwd);
    for (size_t i = 0; i < 3; ++i) {
        cleanup_fd_desc(&fd_descs[i]);
    }
    free_strings_array(new_proc_args.envp);
    free_strings_array(new_proc_args.argv);
    free(new_proc_args.bin);
    if (ret) {
        send_response_err(msg_id, ret);
    } else {
        send_response_u64(msg_id, proc_id);
    }
}

static uint32_t do_kill_process(uint64_t id) {
    struct process_desc* proc_desc = find_process_by_id(id);
    if (!proc_desc) {
        return EINVAL;
    }

    if (!proc_desc->is_alive) {
        return ESRCH;
    }

    if (kill(proc_desc->pid, SIGKILL) < 0) {
        return errno;
    }

    return 0;
}

static void handle_kill_process(msg_id_t msg_id) {
    bool done = false;
    uint32_t ret = 0;
    uint64_t id = 0;

    while (!done) {
        uint8_t subtype = 0;

        CHECK(recv_u8(g_cmds_fd, &subtype));

        switch (subtype) {
            case SUB_MSG_KILL_PROCESS_END:
                done = true;
                break;
            case SUB_MSG_KILL_PROCESS_ID:
                CHECK(recv_u64(g_cmds_fd, &id));
                break;
            default:
                fprintf(stderr, "Unknown MSG_KILL_PROCESS subtype: %hhu\n",
                        subtype);
                die();
        }
    }

    if (!id) {
        ret = EINVAL;
        goto out;
    }

    ret = do_kill_process(id);

out:
    if (ret) {
        send_response_err(msg_id, ret);
    } else {
        send_response_ok(msg_id);
    }
}

static uint32_t do_query_output(uint64_t id, uint64_t off, char** buf_ptr,
                                uint64_t* len_ptr) {
    uint32_t ret = 0;
    char* buf = MAP_FAILED;
    off_t len = 0;

    struct process_desc* proc_desc = find_process_by_id(id);
    if (!proc_desc) {
        return ESRCH;
    }

    if (proc_desc->redirs[1].type != REDIRECT_FD_FILE) {
        return EOPNOTSUPP;
    }

    int fd = open(proc_desc->redirs[1].path, O_RDONLY);
    if (fd < 0) {
        return errno;
    }

    len = lseek(fd, 0, SEEK_END);
    if (len == (off_t)-1) {
        ret = errno;
        goto out;
    }

    if (off >= len) {
        ret = ENXIO;
        goto out;
    }
    len -= off;

    if (*len_ptr < len) {
        len = *len_ptr;
    }

    if (lseek(fd, off, SEEK_SET) == (off_t)-1) {
        ret = errno;
        goto out;
    }

    buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
               -1, 0);
    if (buf == MAP_FAILED) {
        ret = errno;
        goto out;
    }

again: ;
    ssize_t real_len = read(fd, buf, len);
    if (real_len < 0) {
        if (errno == EINTR) {
            goto again;
        }
        ret = errno;
        goto out;
    }

    *buf_ptr = buf;
    buf = MAP_FAILED;
    *len_ptr = real_len;

out:
    if (buf != MAP_FAILED) {
        CHECK(munmap(buf, len));
    }
    close(fd);
    return ret;
}

static void handle_query_output(msg_id_t msg_id) {
    bool done = false;
    uint32_t ret = 0;
    uint64_t id = 0;
    uint64_t off = 0;
    uint64_t len = 0;
    char* buf = NULL;

    while (!done) {
        uint8_t subtype = 0;
        CHECK(recv_u8(g_cmds_fd, &subtype));

        switch (subtype) {
            case SUB_MSG_QUERY_OUTPUT_END:
                done = true;
                break;
            case SUB_MSG_QUERY_OUTPUT_ID:
                CHECK(recv_u64(g_cmds_fd, &id));
                break;
            case SUB_MSG_QUERY_OUTPUT_OFF:
                CHECK(recv_u64(g_cmds_fd, &off));
                break;
            case SUB_MSG_QUERY_OUTPUT_LEN:
                CHECK(recv_u64(g_cmds_fd, &len));
                break;
            default:
                fprintf(stderr, "Unknown MSG_QUERY_OUTPUT subtype: %hhu\n",
                        subtype);
                die();
        }
    }

    if (!id || !len) {
        ret = EINVAL;
        goto out;
    }

    ret = do_query_output(id, off, &buf, &len);

out:
    if (ret) {
        send_response_err(msg_id, ret);
    } else {
        send_response_bytes(msg_id, buf, len);
        CHECK(munmap(buf, len));
    }
}

static void handle_message(void) {
    struct msg_hdr msg_hdr;

    CHECK(readn(g_cmds_fd, &msg_hdr, sizeof(msg_hdr)));

    switch (msg_hdr.type) {
        case MSG_QUIT:
            fprintf(stderr, "Exiting\n");
            handle_quit(msg_hdr.msg_id);
        case MSG_RUN_PROCESS:
            fprintf(stderr, "MSG_RUN_PROCESS\n");
            handle_run_process(msg_hdr.msg_id);
            break;
        case MSG_KILL_PROCESS:
            fprintf(stderr, "MSG_KILL_PROCESS\n");
            handle_kill_process(msg_hdr.msg_id);
            break;
        case MSG_QUERY_OUTPUT:
            fprintf(stderr, "MSG_QUERY_OUTPUT\n");
            handle_query_output(msg_hdr.msg_id);
            break;
        case MSG_MOUNT_VOLUME:
        case MSG_UPLOAD_FILE:
        case MSG_PUT_INPUT:
        case MSG_SYNC_FS:
            fprintf(stderr, "Not implemented yet!\n");
            send_response_err(msg_hdr.msg_id, EPROTONOSUPPORT);
            die();
        default:
            fprintf(stderr, "Unknown message type: %hhu\n", msg_hdr.type);
            send_response_err(msg_hdr.msg_id, ENOPROTOOPT);
            die();
    }
}

static noreturn void main_loop(void) {
    while (1) {
        struct pollfd fds[] = {
            { .fd = g_cmds_fd, .events = POLLIN },
            { .fd = g_sig_fd, .events = POLLIN },
        };

        int ret = poll(fds, sizeof(fds) / sizeof(fds[0]), -1);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            fprintf(stderr, "poll failed: %m\n");
            die();
        }

        if (fds[0].revents & (POLLNVAL | POLLERR)) {
            fprintf(stderr, "poll error event: 0x%04hx\n", fds[0].revents);
            die();
        }
        if (fds[1].revents & (POLLNVAL | POLLERR)) {
            fprintf(stderr, "poll error event: 0x%04hx\n", fds[1].revents);
            die();
        }

        if (fds[0].revents & POLLIN) {
            handle_message();
        }
        if (fds[1].revents & POLLIN) {
            handle_sigchld();
        }
    }
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    create_dir("/dev", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

    CHECK(mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID,
                "mode=0755,size=2M"));

    load_module("/virtio.ko");
    load_module("/virtio_ring.ko");
    load_module("/virtio_pci.ko");
    load_module("/virtio_console.ko");
    load_module("/virtio_blk.ko");
    load_module("/squashfs.ko");
    load_module("/overlay.ko");

    g_cmds_fd = CHECK(open("/dev/vport0p1", O_RDWR | O_CLOEXEC));

    CHECK(mkdir("/mnt", S_IRWXU));
    CHECK(mkdir("/mnt/ro", S_IRWXU));
    CHECK(mkdir("/mnt/rw", S_IRWXU));
    CHECK(mkdir("/mnt/work", S_IRWXU));
    CHECK(mkdir("/mnt/newroot",
                S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH));

    CHECK(mount("/dev/vda", "/mnt/ro", "squashfs", MS_RDONLY, ""));

    CHECK(umount2("/dev", MNT_DETACH));

    CHECK(mount("overlay", "/mnt/newroot", "overlay", 0,
                "lowerdir=/mnt/ro,upperdir=/mnt/rw,workdir=/mnt/work"));

    CHECK(chdir("/mnt/newroot"));
    CHECK(mount(".", "/", "none", MS_MOVE, NULL));
    CHECK(chroot("."));
    CHECK(chdir("/"));

    setup_agent_directories();

    setup_sigfd();

    main_loop();
}
