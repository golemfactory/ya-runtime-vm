#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "proto.h"

#define CHECK(x) ({         \
    __typeof__(x) _x = (x); \
    if (_x == -1) {         \
        err(1, #x);         \
    }                       \
    _x;                     \
})

#define DEFAULT_UID 0

extern char** environ;

static int g_cmds_fd = -1;

static void load_module(const char* path) {
    int fd = CHECK(open(path, O_RDONLY));
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

static void do_cleanups(void) {
    CHECK(close(g_cmds_fd));
}

static noreturn void die(void) {
    do_cleanups();

    while (1) {
        CHECK(reboot(RB_POWER_OFF));
        __asm__ volatile ("hlt");
    }
}

static int readn(int fd, void* buf, size_t size) {
    while (size) {
        ssize_t ret = read(fd, buf, size);
        if (ret == 0) {
            puts("Waiting for host connection ...");
            sleep(1);
            continue;
        }
        if (ret < 0) {
            /* `errno` should be set. */
            return -1;
        }
        buf = (char*)buf + ret;
        size -= ret;
    }
    return 0;
}

static int recv_u64(int fd, uint64_t* res) {
    return readn(fd, res, sizeof(*res));
}

static int recv_u32(int fd, uint32_t* res) {
    return readn(fd, res, sizeof(*res));
}

static int recv_bytes(int fd, char** buf_ptr, uint64_t* size_ptr,
                      bool is_cstring) {
    uint64_t size = 0;

    if (recv_u64(fd, &size) < 0) {
        return -1;
    }

    char* buf = malloc(size + (is_cstring ? 1 : 0));
    if (!buf) {
        return -1;
    }

    if (readn(fd, buf, size) < 0) {
        int tmp_errno = errno;
        free(buf);
        errno = tmp_errno;
        return -1;
    }

    if (is_cstring) {
        buf[size] = '\0';
    }

    *buf_ptr = buf;
    *size_ptr = size;

    return 0;
}

static void free_strings_array(char** array) {
    if (!array) {
        return;
    }

    for (size_t i = 0; array[i]; ++i) {
        free(array[i]);
    }
    free(array);
}

static int recv_strings_array(int fd, char*** array_ptr) {
    uint64_t size = 0;
    int ret = -1;

    if (recv_u64(fd, &size) < 0) {
        return -1;
    }

    char** array = calloc(size + 1, sizeof(*array));
    if (!array) {
        return -1;
    }

    for (uint64_t i = 0; i < size; ++i) {
        uint64_t tmp;
        if (recv_bytes(fd, &array[i], &tmp, /*is_cstring=*/true) < 0) {
            goto out;
        }
    }

    *array_ptr = array;
    array = NULL;
    ret = 0;

out:
    if (array) {
        int tmp_errno = errno;
        free_strings_array(array);
        errno = tmp_errno;
    }
    return ret;
}

static int writen(int fd, void* buf, size_t size) {
    while (size) {
        ssize_t ret = write(fd, buf, size);
        if (ret == 0) {
            puts("Waiting for host connection ...");
            sleep(1);
            continue;
        }
        if (ret < 0) {
            /* `errno` should be set. */
            return -1;
        }
        buf = (char*)buf + ret;
        size -= ret;
    }
    return 0;
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

static void print_strings_array(char** strings) {
    for (unsigned i = 0; *strings; strings++, i++) {
        printf("%u: %s\n", i, *strings);
    }
}

static uint32_t spawn_new_process(uid_t uid, char* bin, char** argv,
                                  char** envp) {
    if (!envp) {
        envp = environ;
    }
    printf("uid: %u\n", uid);
    printf("Binary: %s\n", bin);
    puts("ARGV:");
    print_strings_array(argv);
    puts("ENV:");
    print_strings_array(envp);

    return 0;
}

static void handle_run_process(msg_id_t msg_id) {
    bool done = false;
    char* bin = NULL;
    char** argv = NULL;
    char** envp = NULL;
    uint32_t uid = DEFAULT_UID;

    while (!done) {
        uint8_t subtype = 0;
        CHECK(readn(g_cmds_fd, &subtype, sizeof(subtype)));
        switch (subtype) {
            case SUB_MSG_END:
                done = true;
                break;
            case SUB_MSG_RUN_PROCESS_BIN: ; // got to love C
                uint64_t bin_len = 0;
                CHECK(recv_bytes(g_cmds_fd, &bin, &bin_len,
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
            case SUB_MSG_RUN_PROCESS_RFD:
                break;
            default:
                fprintf(stderr, "Unknown MSG_RUN_PROCESS subtype: %hhu\n",
                        subtype);
                die();
        }
    }

    uint32_t ret;

    if (!bin) {
        ret = EFAULT;
        goto out;
    }
    if (!argv) {
        ret = EFAULT;
        goto out;
    }

    ret = spawn_new_process(uid, bin, argv, envp);

out:
    send_response(msg_id, ret);
    free_strings_array(envp);
    free_strings_array(argv);
    free(bin);
}

static noreturn void handle_messages(void) {
    while (1) {
        struct msg_hdr msg_hdr;

        CHECK(readn(g_cmds_fd, &msg_hdr, sizeof(msg_hdr)));

        switch (msg_hdr.type) {
            case MSG_QUIT:
                fprintf(stderr, "Exiting\n");
                send_response(msg_hdr.msg_id, 0);
                die();
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

    g_cmds_fd = CHECK(open("/dev/vport0p1", O_RDWR));

    CHECK(mkdir("/mnt", S_IRWXU));
    CHECK(mkdir("/mnt/ro", S_IRWXU));
    CHECK(mkdir("/mnt/rw", S_IRWXU));
    CHECK(mkdir("/mnt/work", S_IRWXU));
    CHECK(mkdir("/mnt/newroot", S_IRWXU));

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
