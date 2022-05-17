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
#define HEADER_SIZE (3)
#define MAX_PACKET_SIZE (65536 + HEADER_SIZE)

int g_p9_fd = -1;
static int g_p9_current_channel = 0;
static int g_p9_socket_fds[MAX_P9_VOLUMES][2];

static pthread_t g_p9_tunnel_thread_sender;

#if USE_URING == 1

// TODO: idea of using chains for copy fds, that's what exactly happens here
// https://blogs.oracle.com/linux/post/an-introduction-to-the-io-uring-asynchronous-io-framework

// TODO: reorder fields
struct read_metadata {
    // TODO: used only in socket pairs
    uint8_t channel;

    char* buffer;
    int32_t reader_cursor;
    struct iovec io;
};

struct write_metadata {
    uint8_t channel;
    uint16_t packet_size;
    char* buffer;
    int32_t writer_cursor;
    uint16_t msg_bytes_left;
};

struct metadata {
    int32_t reader_cursor;
    int32_t writer_cursor;
    uint8_t channel;

    uint8_t channel_to_write;

    // # of write events in progress
    int commited_write;

    // TODO: used in socketpair
    int link;

    char* buffer;
    int msg_bytes_left;

    union {
        // writer
        struct {
            uint16_t packet_size;
        };

        // reader
        struct {
            // TODO: used only in socket pairs
            struct iovec io;
        };
        // struct write_metadata;
        // struct read_metadata;
    };
};

static void enqueue_channel_event(uint8_t channel, char* buffer, struct io_uring* ring, struct metadata* meta) {
    meta->channel = channel;
    meta->link = 0;
    meta->buffer = buffer;
    meta->reader_cursor = 0;
    meta->writer_cursor = 0;
    meta->msg_bytes_left = 0;
    meta->channel_to_write = -1;
    meta->commited_write = 0;
    meta->io.iov_base = buffer + 3;
    meta->io.iov_len = MAX_PACKET_SIZE;

    // read from channel
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);

    io_uring_prep_readv(sqe, g_p9_socket_fds[channel][1], &meta->io, 1, 0);

    io_uring_sqe_set_data(sqe, meta);
}

static void enqueue_socket_event(char* buffer, struct io_uring* ring, struct metadata* meta) {
    meta->channel = MAX_P9_VOLUMES;
    meta->link = 0;
    meta->buffer = buffer;
    meta->channel_to_write = -1;
    meta->commited_write = 0;

    meta->reader_cursor = 0;
    meta->writer_cursor = 0;
    meta->msg_bytes_left = 0;

    meta->io.iov_base = buffer;
    meta->io.iov_len = MAX_PACKET_SIZE;

    // read from channel
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, g_p9_fd, &meta->io, 1, 0);

    // sqe->user_data = ((unsigned long long)0xc0fe0) << 32 | i;
    io_uring_sqe_set_data(sqe, meta);
}

// #define URING_TRACE

static void* poll_9p_messages(void* data) {
    (void)data;
// TODO: find good value
#define QUEUE_DEPTH (MAX_P9_VOLUMES + 1) * 3
    fprintf(stderr, "POLL: P9 INIT IO_URING\n");

    char* buffer = NULL;
    // TODO: read as much data as possible parse packets locally
    struct io_uring ring;

    const int FDS_SIZE = MAX_P9_VOLUMES + 1;
    TRY_OR_GOTO(io_uring_queue_init(QUEUE_DEPTH, &ring, 0), error);

    // Alloc buffer for each fd
    buffer = malloc(MAX_PACKET_SIZE * FDS_SIZE);

    if (buffer == NULL) {
        fprintf(stderr, "Failed to allocate the message buffer\n");
        goto error;
    }

    struct io_uring_sqe* sqe;
    struct io_uring_cqe* cqe;

    //////////////////
    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        fprintf(stderr, "register for %d\n", i);

        // No event for that fd
        struct metadata* meta = malloc(sizeof(struct metadata));
        enqueue_channel_event(i, buffer + i * MAX_PACKET_SIZE, &ring, meta);
    }

    // read from gp9 -> write to sock
    {
        fprintf(stderr, "register for sock \n");
        // No event for that fd
        struct metadata* meta = malloc(sizeof(struct metadata));
        enqueue_socket_event(buffer + MAX_P9_VOLUMES * MAX_PACKET_SIZE, &ring, meta);
    }

    io_uring_submit(&ring);

    /////////////////////

    while (1) {
        sqe = NULL;
        // TODO: consider: unsigned io_uring_peek_batch_cqe
        TRY_OR_GOTO(io_uring_wait_cqe(&ring, &cqe), error);

        struct metadata* meta = io_uring_cqe_get_data(cqe);

        // TODO: sometimes res is == 0, why?
        if (cqe->res < 0) {
            fprintf(stderr, "POLL: P9 cqe with data 0x%llX, returned error %d!\n", cqe->user_data, cqe->res);
            fprintf(stderr, "got cqe for channel %d, link %d\n", meta->channel, meta->link);

            goto error;
        }

#ifdef URING_TRACE
        fprintf(stderr, "got cqe for channel %d, link %d result %d\n", meta->channel, meta->link, cqe->res);
#endif

        int new_event = 0;

        if (meta->channel < MAX_P9_VOLUMES) {
            // got data from socketpair
            if (meta->link == 0) {
#ifdef URING_TRACE
                fprintf(stderr, "read %d bytes\n", cqe->res);
#endif
                meta->buffer[0] = meta->channel;

                // TODO: handle short read - get data from 9p message?
                ((uint16_t*)(meta->buffer + 1))[0] = cqe->res;

                int p9_size = ((int*)(meta->buffer + HEADER_SIZE))[0];

                int16_t tag = ((uint16_t*)(meta->buffer + HEADER_SIZE + 4 + 1))[0];

                if (cqe->res != p9_size) {
                    fprintf(stderr, "SHORT READ from socket pair read %d 9p size %d tag %d\n", cqe->res, p9_size, tag);
                    goto error;
                }

                meta->link++;

                meta->msg_bytes_left = cqe->res + HEADER_SIZE;
                meta->writer_cursor = 0;

                // write preppended header
                sqe = io_uring_get_sqe(&ring);

                io_uring_prep_write(sqe, g_p9_fd, meta->buffer, meta->msg_bytes_left, 0);
                io_uring_sqe_set_data(sqe, meta);

            } else if (meta->link == 1) {
                meta->msg_bytes_left -= cqe->res;
                meta->writer_cursor += cqe->res;

                if (meta->msg_bytes_left == 0) {
                    // requeue this event
                    enqueue_channel_event(meta->channel, meta->buffer, &ring, meta);
                } else {
#ifdef URING_TRACE
                    fprintf(stderr, "SHORT WRITE TO SOCKET: Scheduling another %d bytes\n", meta->msg_bytes_left);
#endif
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, g_p9_fd, meta->buffer + meta->writer_cursor, meta->msg_bytes_left, 0);
                    io_uring_sqe_set_data(sqe, meta);
                }
            }
        } else {
            // assumption:
            // there can be at most one message in the buffer (kernel will not send another req)
            // without previous reply

            if (meta->link == 0) {
                // Reading message phase

                // move producer cursor
                meta->reader_cursor += cqe->res;

                if (meta->reader_cursor > HEADER_SIZE) {
                    // Able to parse header
                    meta->channel_to_write = meta->buffer[0];
                    meta->packet_size = ((uint16_t*)(meta->buffer + 1))[0];
#ifdef URING_TRACE
                    fprintf(stderr, "Parsed header: channel %d, packet_size %d\n", meta->channel_to_write,
                            meta->packet_size);
#endif
                    if (meta->reader_cursor == meta->packet_size + HEADER_SIZE) {
                        // Read full message
                        // Switch to writing phase
                        meta->link = 1;

                        meta->msg_bytes_left = meta->packet_size;
                        meta->writer_cursor = HEADER_SIZE;

                        sqe = io_uring_get_sqe(&ring);

                        io_uring_prep_write(sqe, g_p9_socket_fds[meta->channel_to_write][1],
                                            meta->buffer + meta->writer_cursor, meta->msg_bytes_left, 0);
                        io_uring_sqe_set_data(sqe, meta);
                    } else {
                        // Schedule another read
                        int buffer_free_space = MAX_PACKET_SIZE - meta->reader_cursor;
#ifdef URING_TRACE
                        fprintf(stderr, "SHORT READ! Scheduling to read %d bytes, reader_cursor %d\n",
                                buffer_free_space, meta->reader_cursor);
#endif
                        sqe = io_uring_get_sqe(&ring);

                        io_uring_prep_read(sqe, g_p9_fd, meta->buffer + meta->reader_cursor, buffer_free_space, 0);
                        io_uring_sqe_set_data(sqe, meta);
                    }
                } else {
                    // TODO: read less than header, handle that later
                    // fprintf(stderr, "read incomplete header!\n");
                    // Schedule another read
                    int buffer_free_space = MAX_PACKET_SIZE - meta->reader_cursor;
#ifdef URING_TRACE
                    fprintf(stderr, "SHORT READ! Scheduling to read %d bytes, reader_cursor %d\n", buffer_free_space,
                            meta->reader_cursor);
#endif
                    sqe = io_uring_get_sqe(&ring);

                    io_uring_prep_read(sqe, g_p9_fd, meta->buffer + meta->reader_cursor, buffer_free_space, 0);
                    io_uring_sqe_set_data(sqe, meta);
                    // goto error;
                }

            } else if (meta->link == 1) {

                // write
                meta->msg_bytes_left -= cqe->res;
                meta->writer_cursor += cqe->res;

                if (meta->msg_bytes_left > 0) {
#ifdef URING_TRACE
                    fprintf(stderr, "SHORT WRITE! Scheduling to write left %d bytes\n", meta->msg_bytes_left);
#endif
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, g_p9_socket_fds[meta->channel_to_write][1],
                                        meta->buffer + meta->writer_cursor, meta->msg_bytes_left, 0);
                } else {
#ifdef URING_TRACE
                    fprintf(stderr, "Wrote whole buffer\n");
#endif
                    meta->link = 0;
                    meta->reader_cursor = 0;
                    meta->channel_to_write = -1;
                    meta->packet_size = -1;

                    sqe = io_uring_get_sqe(&ring);

                    io_uring_prep_read(sqe, g_p9_fd, meta->buffer, MAX_PACKET_SIZE, 0);
                    io_uring_sqe_set_data(sqe, meta);
                }
            }
        }

        io_uring_cqe_seen(&ring, cqe);

        // Some event(s) were put on a queue
        if (sqe) {
            io_uring_submit(&ring);
        }
    }

error:
    fprintf(stderr, "POLL: P9 thread is leaving!\n");

    io_uring_unregister_files(&ring);
    io_uring_queue_exit(&ring);
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

    if (channel > MAX_P9_VOLUMES) {
        fprintf(stderr, "invalid channel! %d\n", (int32_t)channel);
        goto error;
    }

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

    if (packet_size == 0) {
        fprintf(stderr, "Got 0 bytes as packet size from header!\n");
        goto error;
    }

    if (bytes_read != sizeof(packet_size)) {
        fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(packet_size)\n");
        goto error;
    }

    if (packet_size > buffer_size) {
        fprintf(stderr, "Error: Maximum packet size exceeded: packet_size > buffer_size\n");
        goto error;
    }

    // fprintf(stderr, "reading %d bytes..\n", packet_size);

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

    // fprintf(stderr, "writing %d bytes to %d channel\n", bytes_read, channel);
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

    TRY_OR_GOTO(snprintf(mount_cmd, CMD_SIZE, "trans=fd,rfdno=%d,wfdno=%d,debug=0xff,version=9p2000.L,msize=65536",
                         mount_socket_fd, mount_socket_fd),
                error);

    TRY_OR_GOTO(mount(tag, path, "9p", 0, mount_cmd), error);

    fprintf(stderr, "Mount finished.\n");
    return 0;
error:
    fprintf(stderr, "Mount failed.\n");
    return -1;
}
