// #define _GNU_SOURCE

#include "communication_p9.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
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

#define USE_URING 1
#define MAX_P9_VOLUMES (16)
#define MAX_PACKET_SIZE (65536 * 2 + 3)
// #define MAX_PACKET_SIZE (16384)

int g_p9_fd = -1;
static int g_p9_current_channel = 0;
static int g_p9_socket_fds[MAX_P9_VOLUMES][2];

static pthread_t g_p9_tunnel_thread_sender;

// static int write_exact(int fd, const void* buf, size_t size) {
//     int bytes_written = 0;
//     while (size) {
//         ssize_t ret = write(fd, buf, size);
//         if (ret == 0) {
//             puts("written: WAITING FOR HOST (2) ...");
//             sleep(1);
//             continue;
//         }
//         if (ret < 0) {
//             if (errno == EINTR) {
//                 continue;
//             }
//             /* `errno` should be set. */
//             return -1;
//         }
//         bytes_written += ret;
//         buf = (char*)buf + ret;
//         size -= ret;
//     }
//     return bytes_written;
// }

#if USE_URING == 1

// TODO: idea of using chains for copy fds, that's what exactly happens here
// https://blogs.oracle.com/linux/post/an-introduction-to-the-io-uring-asynchronous-io-framework

static void write_on_ring(struct io_uring* ring, char* buffer, uint32_t size, int fd) {
    struct io_uring_sqe* sqe;
    struct io_uring_cqe* cqe;

    int ret = 0;
    int wc = 0;
    size_t wo = 0;

    fprintf(stderr, "request to write %u bytes on fd %d\n", size, fd);

    static int cnt = 0;

    while (wo < size) {
        if (!(sqe = io_uring_get_sqe(ring))) {
            fprintf(stderr, "Unable to get sqe!\n");
            goto error;
        }

        io_uring_prep_write(sqe, fd, buffer + wo, size - wo, 0);
        sqe->user_data = ((unsigned long long )0xdeadbeef) << 32 | cnt++;
        sqe->flags |= IOSQE_FIXED_FILE;

        fprintf(stderr, "submit\n");
        io_uring_submit(ring);

        fprintf(stderr, "wait\n");
        if ((ret = io_uring_wait_cqe(ring, &cqe)) < 0) {
            fprintf(stderr, "wait cqe failed!\n");

            goto error;
        }

        wc = cqe->res;
        fprintf(stderr, "$$$ write on fd: %d, bytes: %d user data 0x%llX\n", fd, wc, cqe->user_data);

        io_uring_cqe_seen(ring, cqe);
        if (wc < 0) {
            fprintf(stderr, "write failed!\n");
            goto error;
        }
        wo += wc;
        fprintf(stderr, "wo %ld, size %d\n", wo, size);
    }

error:
    if (cqe) {
        io_uring_cqe_seen(ring, cqe);
    }
}

static void handle_data_on_sock(struct io_uring* ring, char* buffer, uint32_t buffer_size) {
    (void)buffer_size;
    uint8_t channel = buffer[0];

    uint16_t packet_size = ((uint16_t*)(buffer + 1))[0];

    char* msg = buffer + 3;

    fprintf(stderr, "got response for channel %u, packet_size %u, buffer_size %u\n", channel, packet_size, buffer_size);
    // if (write_exact(g_p9_socket_fds[channel][1], msg, packet_size) == -1) {
    //     fprintf(stderr, "Error writing to g_p9_socket_fds\n");
    //     goto error;
    // }

    write_on_ring(ring, msg, packet_size, channel);

// error:;
}

void handle_data_on_channel(struct io_uring* ring, uint8_t channel, char* buffer, uint32_t buffer_size) {

    char *buf = malloc(buffer_size + 3);

    uint16_t bytes_read_to_send = (uint16_t)buffer_size;

    buf[0] = channel;
    ((uint16_t*)(buf + 1))[0] = bytes_read_to_send;

    memcpy(buf + 3, buffer, buffer_size);
    write_on_ring(ring, buf, buffer_size + 3, MAX_P9_VOLUMES);
    free(buf);

    // TRY_OR_GOTO(write_exact(g_p9_fd, &channel, 1), error);
    // TRY_OR_GOTO(write_exact(g_p9_fd, &bytes_read_to_send, sizeof(bytes_read_to_send)), error);
    // TRY_OR_GOTO(write_exact(g_p9_fd, buffer, buffer_size), error);

    // TODO: that could be a chain
    // write_on_ring(ring, (char*)&channel, 1, g_p9_fd);
    // write_on_ring(ring, (char*)&bytes_read_to_send, sizeof(bytes_read_to_send), g_p9_fd);
    // write_on_ring(ring, buffer, buffer_size, g_p9_fd);


    // error:;
}

static void* poll_9p_messages(void* data) {
    (void)data;
// TODO: find good value
#define QUEUE_DEPTH MAX_P9_VOLUMES + 1
    fprintf(stderr, "POLL: P9 INIT IO_URING\n");

    char* buffer = NULL;
    // TODO: read as much data as possible parse packets locally
    struct io_uring ring_for_read;
    struct io_uring ring_for_write;

    const int FDS_SIZE = MAX_P9_VOLUMES + 1;
    int fds[FDS_SIZE];

    char armed_events[FDS_SIZE];
    memset(armed_events, 0, FDS_SIZE);

    TRY_OR_GOTO(io_uring_queue_init(QUEUE_DEPTH, &ring_for_read, 0), error);
    TRY_OR_GOTO(io_uring_queue_init(QUEUE_DEPTH, &ring_for_write, 0), error);


    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        fds[i] = g_p9_socket_fds[i][1];
    }

    fds[MAX_P9_VOLUMES] = g_p9_fd;

    fprintf(stderr, "POLL: P9 register files\n");
    TRY_OR_GOTO(io_uring_register_files(&ring_for_read, fds, FDS_SIZE), error);
    // TODO: hopefully fds can be shared among rings
    TRY_OR_GOTO(io_uring_register_files(&ring_for_write, fds, FDS_SIZE), error);


    // Alloc buffer for each fd
    buffer = malloc(MAX_PACKET_SIZE * FDS_SIZE);

    if (buffer == NULL) {
        fprintf(stderr, "Failed to allocate the message buffer\n");
        goto error;
    }

    struct io_uring_sqe* sqe;
    struct io_uring_cqe* cqe;

    while (1) {
        int new_events = 0;

        for (int i = 0; i < FDS_SIZE; i++) {
            if (armed_events[i] == 0) {
                // No event for that fd
                if (!(sqe = io_uring_get_sqe(&ring_for_read))) {
                    fprintf(stderr, "POLL: P9 failed to allocate sqe!\n");
                    goto error;
                }

                io_uring_prep_read(sqe, i, buffer + i * MAX_PACKET_SIZE, MAX_PACKET_SIZE, 0);
                sqe->user_data = ((unsigned long long)0xc0fee) << 32 | i;
                sqe->flags |= IOSQE_FIXED_FILE;

                armed_events[i] = 1;
                new_events++;
            }  // else event already in a buffer, no need to add another
        }

        // TODO: there should be no difference
        if (new_events > 0) {
            io_uring_submit(&ring_for_read);
        }


        // TODO: consider: unsigned io_uring_peek_batch_cqe
        TRY_OR_GOTO(io_uring_wait_cqe(&ring_for_read, &cqe), error);


        if (cqe->res <= 0) {
            fprintf(stderr, "POLL: P9 cqe with data 0x%llX, returned error %d!\n", cqe->user_data, cqe->res);
            // goto error;
            continue;
        }

        int channel = cqe->user_data;

        // cqe in user_data has info which fd has avaliable data, get that part of global buffer
        // and pass it accordingly
        char* buf = buffer + channel * MAX_PACKET_SIZE;
        int bytes_read = cqe->res;

        io_uring_cqe_seen(&ring_for_read, cqe);

        if (channel < MAX_P9_VOLUMES) {
            handle_data_on_channel(&ring_for_write, channel, buf, bytes_read);
        } else {
            handle_data_on_sock(&ring_for_write, buf, bytes_read);
        }

        // Mark this fd event was consumed, and needs another seq to be created
        armed_events[channel] = 0;
    }

error:
    fprintf(stderr, "POLL: P9 thread is leaving!\n");

    io_uring_unregister_files(&ring_for_read);
    io_uring_queue_exit(&ring_for_read);
    free(buffer);
    return NULL;
}

#else

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

static void handle_data_on_sock(char* buffer, uint32_t buffer_size) {
    uint8_t channel = -1;
    int bytes_read = read_exact(g_p9_fd, &channel, sizeof(channel));

    // fprintf(stderr, "data on sock for channel %d\n", (int32_t)channel);

    if (bytes_read == 0) {
        // fprintf(stderr, "No data on g_p9_fd\n");
        goto error;
    }

    if (bytes_read != sizeof(channel)) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(channel)\n");
        goto error;
    }

    uint16_t packet_size = 0;
    bytes_read = read_exact(g_p9_fd, &packet_size, sizeof(packet_size));

    if (bytes_read != sizeof(packet_size)) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(packet_size)\n");
        goto error;
    }

    if (packet_size > buffer_size) {
        fprintf(stderr, "Error: Maximum packet size exceeded: packet_size > buffer_size\n");
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

    fprintf(stderr, "POLL: P9 INIT EPOLL\n");
    int epoll_fd = -1;
    char* buffer = NULL;

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
        event.events = EPOLLIN;
        event.data.fd = channel_rx;

        TRY_OR_GOTO(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel_rx, &event), error);
    }

    fprintf(stderr, "POLL: P9 adding g_p9_fd\n");

    struct epoll_event event = {};
    event.events = EPOLLIN;
    event.data.fd = g_p9_fd;

    TRY_OR_GOTO(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_p9_fd, &event), error);

    while (1) {
        struct epoll_event event = {};

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
    fprintf(stderr, "POLL: P9 thread is leaving!\n");

    close(epoll_fd);
    free(buffer);
    return NULL;
}

#endif  // USE_URING

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
    char mount_cmd[CMD_SIZE];
    int mount_socket_fd = g_p9_socket_fds[channel][0];

    if (channel >= MAX_P9_VOLUMES) {
        fprintf(stderr, "ERROR: channel >= MAX_P9_VOLUMES\n");
        goto error;
    }

    TRY_OR_GOTO(snprintf(mount_cmd, CMD_SIZE, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L,msize=65536",
                         mount_socket_fd, mount_socket_fd),
                error);

    TRY_OR_GOTO(mount(tag, path, "9p", 0, mount_cmd), error);

    fprintf(stderr, "Mount finished.\n");
    return 0;
error:
    fprintf(stderr, "Mount failed.\n");
    return -1;
}
