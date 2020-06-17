#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "communication.h"
#include "proto.h"

#define DEFAULT_UID 0
#define DEFAULT_GID 0
#define DEFAULT_OUT_FILE_PERM (S_IRWXU)

extern char** environ;

static int g_cmds_fd = -1;

static noreturn void die(void) {
    sync();
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

/* Since we set SA_NODEFER, this handler needs to be reentrant. */
static void sigchld_handler(int sig, siginfo_t* info, void* uctx) {
    (void)sig; // We know it's SIGCHLD.
    (void)uctx;
    pid_t child_pid = info->si_pid;
    int status = 0;

    int ret = waitpid(child_pid, &status, WNOHANG);
    if (ret <= 0) {
        /* Eiter child is still alive or an error occured (but nothing fatal can
         * happen here). */
        return;
    }

    // TODO: check whether this is a child process we care about (spawned task)
    (void)child_pid;
}

static void add_child_handler(void) {
    struct sigaction act = {
        .sa_sigaction = sigchld_handler,
        .sa_flags = SA_NOCLDSTOP | SA_NODEFER | SA_RESTART | SA_SIGINFO,
    };
    CHECK(sigaction(SIGCHLD, &act, NULL));
}

static void send_response(msg_id_t msg_id, uint32_t ret_val) {
    struct msg_hdr resp = {
        .msg_id = msg_id,
        .type = !ret_val ? RESP_OK : RESP_ERR,
    };

    CHECK(writen(g_cmds_fd, &resp, sizeof(resp)));
    if (ret_val) {
        CHECK(writen(g_cmds_fd, &ret_val, sizeof(ret_val)));
    }
}

static noreturn void handle_quit(msg_id_t msg_id) {
    send_response(msg_id, 0);
    die();
}

struct redir_fd_desc {
    enum REDIRECT_FD_TYPE type;
    union {
        char* path;
        size_t size;
    };
};

#define DEFAULT_FD_BUF_SIZE 0x10000
#define DEFAULT_FD_DESC {                   \
        .type = REDIRECT_FD_PIPE_BLOCKING,  \
        .size = DEFAULT_FD_BUF_SIZE         \
    }

static void cleanup_fd_desc(struct redir_fd_desc* fd_desc) {
    if (fd_desc->type == REDIRECT_FD_FILE) {
        free(fd_desc->path);
    }
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

static noreturn void child_wrapper(int parent_pipe[2], char* bin, char** argv,
                                   char** envp, uid_t uid, gid_t gid,
                                   struct redir_fd_desc fd_descs[3]) {
    if (!envp) {
        envp = environ;
    }

    if (close(parent_pipe[0]) < 0) {
        goto out;
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
                fprintf(stderr, "Not yet supported (fd: %d)\n", fd);
                break;
            default:
                fprintf(stderr, "Unknown type in child_wrapper (BUG): %u\n",
                        fd_descs[fd].type);
                die();
        }
    }

    if (setresgid(gid, gid, gid) < 0) {
        goto out;
    }

    if (setresuid(uid, uid, uid) < 0) {
        goto out;
    }

    /* If execve returns we know an error happened. */
    (void)execve(bin, argv, envp);

out: ;
    int ecode = errno;
    char c = '\0';
    /* Can't do anything with errors here. */
    (void)write(parent_pipe[1], &c, sizeof(c));
    exit(ecode);
}

static uint32_t spawn_new_process(char* bin, char** argv, char** envp,
                                  uid_t uid, gid_t gid,
                                  struct redir_fd_desc fd_descs[3]) {
    uint32_t ret = 0;

    /* All these shenanigans with pipes are so that we can distinguish internal
     * failures from spanwed process exiting. */
    int status_pipe[2];
    if (pipe2(status_pipe, O_CLOEXEC | O_DIRECT) < 0) {
        return errno;
    }

    pid_t p = fork();
    if (p < 0) {
        ret = errno;
        CHECK(close(status_pipe[0]));
        CHECK(close(status_pipe[1]));
        return ret;
    } else if (p == 0) {
        child_wrapper(status_pipe, bin, argv, envp, uid, gid, fd_descs);
    }

    CHECK(close(status_pipe[1]));

    char c;
    ssize_t x = read(status_pipe[0], &c, sizeof(c));
    if (x < 0) {
        ret = errno;
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
    } // else x == 0, which means successful process spawn.

    CHECK(close(status_pipe[0]));

    // TODO: remove once child processes are bookkeeped
    if (x == 0) {
        (void)waitpid(p, NULL, 0);
    }
    return ret;
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
            CHECK(recv_u64(g_cmds_fd, &fd_desc.size));
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

    cleanup_fd_desc(&fd_descs[fd]);

    memcpy(&fd_descs[fd], &fd_desc, sizeof(fd_descs[fd]));

    return 0;
}

static void handle_run_process(msg_id_t msg_id) {
    bool done = false;
    uint32_t ret = 0;
    char* bin = NULL;
    char** argv = NULL;
    char** envp = NULL;
    uint32_t uid = DEFAULT_UID;
    uint32_t gid = DEFAULT_GID;
    struct redir_fd_desc fd_descs[3] = {
        DEFAULT_FD_DESC,
        DEFAULT_FD_DESC,
        DEFAULT_FD_DESC,
    };

    while (!done) {
        uint8_t subtype = 0;

        CHECK(recv_u8(g_cmds_fd, &subtype));

        switch (subtype) {
            case SUB_MSG_RUN_PROCESS_END:
                done = true;
                break;
            case SUB_MSG_RUN_PROCESS_BIN:
                CHECK(recv_bytes(g_cmds_fd, &bin, NULL,
                                 /*is_cstring=*/true));
                break;
            case SUB_MSG_RUN_PROCESS_ARG:
                CHECK(recv_strings_array(g_cmds_fd, &argv));
                break;
            case SUB_MSG_RUN_PROCESS_ENV:
                CHECK(recv_strings_array(g_cmds_fd, &envp));
                break;
            case SUB_MSG_RUN_PROCESS_UID:
                CHECK(recv_u32(g_cmds_fd, &uid));
                break;
            case SUB_MSG_RUN_PROCESS_GID:
                CHECK(recv_u32(g_cmds_fd, &gid));
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
            default:
                fprintf(stderr, "Unknown MSG_RUN_PROCESS subtype: %hhu\n",
                        subtype);
                die();
        }
    }

    if (ret) {
        goto out;
    }
    if (!bin) {
        ret = EFAULT;
        goto out;
    }
    if (!argv) {
        ret = EFAULT;
        goto out;
    }

    ret = spawn_new_process(bin, argv, envp, uid, gid, fd_descs);

out:
    for (size_t i = 0; i < 3; ++i) {
        cleanup_fd_desc(&fd_descs[i]);
    }
    free_strings_array(envp);
    free_strings_array(argv);
    free(bin);
    send_response(msg_id, ret);
}

static noreturn void handle_messages(void) {
    while (1) {
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
            case MSG_MOUNT_VOLUME:
            case MSG_UPLOAD_FILE:
            case MSG_QUERY_OUTPUT:
            case MSG_PUT_INPUT:
            case MSG_SYNC_FS:
                fprintf(stderr, "Not implemented yet!\n");
                send_response(msg_hdr.msg_id, EPROTONOSUPPORT);
                break;
            default:
                fprintf(stderr, "Unknown message type: %hhu\n", msg_hdr.type);
                send_response(msg_hdr.msg_id, ENOPROTOOPT);
                die();
        }
    }
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    int x = mkdir("/dev", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (x == -1 && errno != EEXIST) {
        err(1, "mkdir /dev");
    }

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

    add_child_handler();

    handle_messages();
}
