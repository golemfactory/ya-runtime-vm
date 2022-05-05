#define _GNU_SOURCE

#include "communication_p9.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

// TODO: is it a good value?
#define MAX_P9_VOLUMES (100)
#define MAX_PACKET_SIZE (16384)

int g_p9_fd = -1;
// TODO: add unmount?
static int g_p9_current_channel = 0;
static int g_p9_socket_fds[MAX_P9_VOLUMES][2];

static pthread_t g_p9_tunnel_thread_sender;

static int read_exact(int fd, void* buf, size_t size) {
    int bytes_read = 0;
    while (size) {
        ssize_t ret = read(fd, buf, size);
        if (ret == 0) {
            return 0;
        }
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* `errno` should be set. */
            return ret;
        }
        bytes_read += ret;
        buf = (char*)buf + ret;
        size -= ret;
    }
    return bytes_read;
}

static int write_exact(int fd, const void* buf, size_t size) {
    int bytes_written = 0;
    while (size) {
        ssize_t ret = write(fd, buf, size);
        if (ret == 0) {
            puts("written: WAITING FOR HOST (2) ...");
            sleep(1);
            continue;
        }
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            /* `errno` should be set. */
            return -1;
        }
        bytes_written += ret;
        buf = (char*)buf + ret;
        size -= ret;
    }
    return bytes_written;
}

static void handle_data_on_sock(char* buffer, uint32_t buffer_size) {
    uint8_t channel    = -1;
    int     bytes_read = read_exact(g_p9_fd, &channel, sizeof(channel));

    // fprintf(stderr, "data on sock for channel %d\n", (int32_t)channel);

    if (bytes_read == 0) {
        fprintf(stderr, "No data on g_p9_fd\n");
        goto error;
    }

    if (bytes_read != sizeof(channel)) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(channel)\n");
        goto error;
    }

    uint16_t packet_size = 0;
    bytes_read           = read_exact(g_p9_fd, &packet_size, sizeof(packet_size));

    if (bytes_read != sizeof(packet_size)) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(packet_size)\n");
        goto error;
    }

    if (packet_size > MAX_PACKET_SIZE) {
        fprintf(stderr, "Error: Maximum packet size exceeded: packet_size > MAX_PACKET_SIZE\n");
        goto error;
    }

    bytes_read = read_exact(g_p9_fd, buffer, packet_size);
    if (bytes_read != packet_size) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != packet_size\n");
        goto error;
    }

#if WIN_P9_EXTRA_DEBUG_INFO
    fprintf(stderr, "RECEIVE MESSAGE %ld\n", bytes_read);
#endif
    if (bytes_read == -1) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read == -1\n");
        goto error;
    }

    if (write_exact(g_p9_socket_fds[channel][1], buffer, bytes_read) == -1) {
        fprintf(stderr, "Error writing to g_p9_socket_fds\n");
        goto error;
    }

error:;
}

void handle_data_on_channel(int channel, char* buffer, uint32_t buffer_size) {
    ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer, buffer_size, 0);

    if (bytes_read == 0) {
        fprintf(stderr, "No data on channel %u\n", channel);
        goto error;
    }

    TRY_OR_GOTO(bytes_read, error);

#if WIN_P9_EXTRA_DEBUG_INFO
    fprintf(stderr, "send message to channel %d, length: %ld\n", channel, bytes_read);
#endif

    TRY_OR_GOTO(write_exact(g_p9_fd, &channel, 1), error);

    uint16_t bytes_read_to_send = (uint16_t)bytes_read;
    assert(sizeof(bytes_read_to_send) == 2);

    TRY_OR_GOTO(write_exact(g_p9_fd, &bytes_read_to_send, sizeof(bytes_read_to_send)), error);
    TRY_OR_GOTO(write_exact(g_p9_fd, buffer, bytes_read), error);

error:;
}

static void* poll_9p_messages(void* data) {
    (void)data;

    fprintf(stderr, "POLL: P9 sender started polling\n");
    int   epoll_fd = -1;
    char* buffer   = NULL;

    buffer = malloc(MAX_PACKET_SIZE);

    if (buffer == NULL) {
        fprintf(stderr, "Failed to allocate the message buffer\n");
        goto error;
    }

    epoll_fd = TRY_OR_GOTO(epoll_create1(EPOLL_CLOEXEC), error);

    fprintf(stderr, "POLL: P9 adding descriptors\n");

    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        int channel_rx = g_p9_socket_fds[i][1];

        struct epoll_event event = {};
        event.events             = EPOLLIN;
        event.data.fd            = channel_rx;

        TRY_OR_GOTO(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel_rx, &event), error);
    }

    fprintf(stderr, "POLL: P9 adding g_p9_fd\n");

    struct epoll_event event = {};
    event.events             = EPOLLIN;
    event.data.fd            = g_p9_fd;

    TRY_OR_GOTO(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_p9_fd, &event), error);

    while (1) {
        struct epoll_event event = {};

        // TODO: future improvement in reducing number of syscalls might be to set up
        // FD's in non-blocking mode, epoll in edge triggered mode, increase number of events
        // https://eklitzke.org/blocking-io-nonblocking-io-and-epoll

        if (epoll_wait(epoll_fd, &event, 1, -1) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                fprintf(stderr, "POLL: wait continue %m\n");
                continue;
            }
            fprintf(stderr, "POLL: wait failed: %m\n");
            goto error;
        }

        if (event.events & EPOLLNVAL) {
            fprintf(stderr, "epoll error event: 0x%04hx\n", event.events);
            goto error;
        }

        for (int channel = 0; channel < MAX_P9_VOLUMES; channel++) {
            int channel_rx = g_p9_socket_fds[channel][1];
            if (event.data.fd == channel_rx) {
                handle_data_on_channel(channel, buffer, MAX_PACKET_SIZE);
            }
        }

        if (event.data.fd == g_p9_fd) {
            handle_data_on_sock(buffer, MAX_PACKET_SIZE);
        }
    }

error:
    close(epoll_fd);
    free(buffer);
    return NULL;
}

// TODO: create Twrite request that exceeds hardcoded packet size
// TODO: do highly concurrent write requests from rust side to see congestion in this part of code
int initialize_p9_communication() {
    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        if (socketpair(AF_LOCAL, SOCK_STREAM, 0, g_p9_socket_fds[i]) != 0) {
            fprintf(stderr, "Error: Failed to create a socket pair for channel %d, errno: %m\n", i);
            goto error;
        }
    }

    TRY_OR_GOTO(pthread_create(&g_p9_tunnel_thread_sender, NULL, &poll_9p_messages, NULL), error);
    return 0;

error:
    return -1;
}

uint32_t do_mount_p9(const char* tag, char* path) {
    int channel = g_p9_current_channel++;

    fprintf(stderr, "Starting mount: tag: %s, path: %s, channel %d\n", tag, path, channel);

    static const uint32_t CMD_SIZE = 256;
    char                  mount_cmd[CMD_SIZE];
    int                   mount_socket_fd = g_p9_socket_fds[channel][0];

    if (channel >= MAX_P9_VOLUMES) {
        fprintf(stderr, "ERROR: channel >= MAX_P9_VOLUMES\n");
        goto error;
    }

    // TODO: leave like that? Or add sockets lazily?

    TRY_OR_GOTO(
        snprintf(mount_cmd, CMD_SIZE, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L", mount_socket_fd, mount_socket_fd),
        error);

    TRY_OR_GOTO(mount(tag, path, "9p", 0, mount_cmd), error);

    fprintf(stderr, "Mount finished.\n");
    return 0;
error:
    fprintf(stderr, "Mount failed.\n");
    return -1;
}
