// #define _GNU_SOURCE

#include "communication_p9.h"

#include <sys/mount.h>
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

#define URING 1
#define EPOLL 2
#define THREAD 3

#define USE URING

#define MAX_P9_VOLUMES (16)
#define HEADER_SIZE (3)
#define MAX_PACKET_SIZE (65536 + HEADER_SIZE)

int g_p9_fd = -1;
static int g_p9_current_channel = 0;
static int g_p9_socket_fds[MAX_P9_VOLUMES][2];

#if USE != THREAD
static pthread_t g_p9_tunnel_thread_sender;
#endif

#if USE == URING

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
    meta->io.iov_base = buffer + HEADER_SIZE;
    meta->io.iov_len = MAX_PACKET_SIZE - HEADER_SIZE;

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

    meta->reader_cursor = 0;
    meta->writer_cursor = 0;
    meta->msg_bytes_left = 0;

    meta->io.iov_base = buffer;
    meta->io.iov_len = MAX_PACKET_SIZE * MAX_P9_VOLUMES;

    // read from channel
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_readv(sqe, g_p9_fd, &meta->io, 1, 0);

    // sqe->user_data = ((unsigned long long)0xc0fe0) << 32 | i;
    io_uring_sqe_set_data(sqe, meta);
}

int min(int a, int b) {
    return a < b ? a : b;
}

struct c_buffer {
    char* buffer;
    int size;
    int occupied;

    int reader_cursor;
    int writer_cursor;
};

struct c_buffer* cb_new(char* buffer, int size) {
    struct c_buffer* res = malloc(sizeof(struct c_buffer));

    res->buffer = buffer;
    res->size = size;
    res->occupied = 0;
    res->reader_cursor = 0;
    res->writer_cursor = 0;

    return res;
}

// returns number of contigious bytes free to write
int cb_write_space(struct c_buffer* cb) {
    if (cb->writer_cursor == cb->reader_cursor) {
        assert(cb->occupied == cb->size || cb->occupied == 0);
        if (cb->occupied == cb->size) {
            return 0;
        } else {
            return cb->size - cb->writer_cursor;
        }
    } else if (cb->writer_cursor > cb->reader_cursor) {
        return cb->size - cb->writer_cursor;
    } else {
        return cb->reader_cursor - cb->writer_cursor;
    }
}

// returns number of contigious bytes free to read
int cb_read_space(struct c_buffer* cb) {
    if (cb->reader_cursor == cb->writer_cursor) {
        assert(cb->occupied == cb->size || cb->occupied == 0);
        if (cb->occupied == cb->size) {
            return cb->size - cb->reader_cursor;
        } else {
            return 0;
        }

    } else if (cb->reader_cursor < cb->writer_cursor) {
        return cb->writer_cursor - cb->reader_cursor;
    } else {
        return cb->size - cb->reader_cursor;
    }
}

// get number of stored bytes
int cb_len(struct c_buffer* cb) {
    return cb->occupied;
}

// returns total number of avaliable bytes to write
int cb_avaliable(struct c_buffer* cb) {
    return cb->size - cb->occupied;
}

void cb_advance_reader(struct c_buffer* cb, int size) {
    cb->reader_cursor = (cb->reader_cursor + size) % cb->size;
    cb->occupied -= size;
}

void cb_advance_writer(struct c_buffer* cb, int size) {
    cb->writer_cursor = (cb->writer_cursor + size) % cb->size;
    cb->occupied += size;
}

// reads exact amount of bytes from buffer, returns -1 if there is no enough
// data or requested read is <= 0 bytes
bool cb_read_exact(struct c_buffer* cb, char* dst, int dst_size) {
    if (cb_len(cb) < dst_size || dst_size <= 0) {
        return false;
    }

    int read = 0;
    int dst_offset = 0;
    while (read < dst_size) {
        int chunk = min(dst_size, cb_read_space(cb));
        memcpy(dst + dst_offset, cb->buffer + cb->reader_cursor, chunk);
        cb_advance_reader(cb, chunk);
        read += chunk;
        dst_offset += chunk;
    }

    return true;
}

// write exact src_size bytes to buffer, returns false otherwise
bool cb_write_exact(struct c_buffer* cb, const char* src, int src_size) {
    if (cb_avaliable(cb) < src_size) {
        return false;
    }

    int written = 0;
    int src_offset = 0;

    while (written < src_size) {
        int chunk = min(src_size, cb_write_space(cb));
        memcpy(cb->buffer + cb->writer_cursor, src + src_offset, chunk);
        cb_advance_writer(cb, chunk);
        written += chunk;
        src_offset += chunk;
    }

    return true;
}

enum framing_state { parsing_header, reading_payload, message_ready };
struct socket_framing {
    struct c_buffer* cb;

    struct metadata* meta;
    enum framing_state state;
};

struct socket_framing* sf_new(char* buffer, int size) {
    struct socket_framing* res = malloc(sizeof(struct socket_framing));

    res->cb = cb_new(buffer, size);
    res->state = parsing_header;
    res->meta = malloc(sizeof(struct metadata));
    res->meta->buffer = malloc(MAX_PACKET_SIZE);

    return res;
}

void sf_free(struct socket_framing *sf) {
    free(sf->meta->buffer);
    free(sf->meta);
    free(sf);
}

// Returns meta struct if there is avaliable message to write
struct metadata* sf_pop_message(struct socket_framing* ctx) {
    if (ctx->state == parsing_header) {
        if (cb_read_exact(ctx->cb, ctx->meta->buffer, HEADER_SIZE)) {
            // successfully read the header
            ctx->meta->channel_to_write = ctx->meta->buffer[0];
            ctx->meta->packet_size = ((uint16_t*)(ctx->meta->buffer + 1))[0];
            ctx->meta->msg_bytes_left = ctx->meta->packet_size;
            ctx->meta->channel = MAX_P9_VOLUMES;
            ctx->meta->link = 1;
            ctx->meta->reader_cursor = 0;
            ctx->meta->writer_cursor = HEADER_SIZE;

#ifdef URING_TRACE
            fprintf(stderr, "read the header channel %d, packet size %d\n", ctx->meta->channel_to_write,
                    ctx->meta->packet_size);
#endif
            ctx->state = reading_payload;
        }  // TODO: else
    }

    if (ctx->state == reading_payload) {
        if (cb_read_exact(ctx->cb, ctx->meta->buffer + HEADER_SIZE, ctx->meta->packet_size)) {
            // whole message is in meta buffer
            ctx->state = message_ready;
        }
    }

    if (ctx->state == message_ready) {
        ctx->state = parsing_header;

        struct metadata* ready = ctx->meta;

        // TODO: Oh god
        ctx->meta = malloc(sizeof(struct metadata));
        ctx->meta->buffer = malloc(MAX_PACKET_SIZE);

        return ready;
    }

    return NULL;
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

    // Alloc buffer for each fd + buffer for socket,
    // that in worst case can hold full messages for all channels

    // TODO: assumption, at most one message in buffer per channel
    buffer = malloc(MAX_PACKET_SIZE * MAX_P9_VOLUMES + MAX_PACKET_SIZE * MAX_P9_VOLUMES);

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

    fprintf(stderr, "submit\n");
    io_uring_submit(&ring);

    /////////////////////

    struct metadata* write_queue[MAX_P9_VOLUMES + 1];
    // memset(write_queue, 0, sizeof(struct metadata) * MAX_P9_VOLUMES);
    int write_queue_end = 0;
    int write_queue_start = 0;

    bool write_in_progress = false;

    fprintf(stderr, "socket framing\n");

    struct socket_framing* response_framer =
        sf_new(buffer + MAX_P9_VOLUMES * MAX_PACKET_SIZE, MAX_P9_VOLUMES * MAX_PACKET_SIZE);

    while (1) {
        sqe = NULL;

        // TODO: consider: unsigned io_uring_peek_batch_cqe
        TRY_OR_GOTO(io_uring_wait_cqe(&ring, &cqe), error);

        struct metadata* meta = io_uring_cqe_get_data(cqe);

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

            // fprintf(stderr, "CHANNEL: %d\n", meta->channel);

            // got data from socketpair
            if (meta->link == 0) {
                meta->buffer[0] = meta->channel;

                // TODO: handle short read - get data from 9p message?
                ((uint16_t*)(meta->buffer + 1))[0] = cqe->res;

                int p9_size = ((int*)(meta->buffer + HEADER_SIZE))[0];

                int16_t tag = ((uint16_t*)(meta->buffer + HEADER_SIZE + 4 + 1))[0];

                fprintf(stderr, "p9_size %d\n", p9_size);

                // TODO: handle short read here
                if (cqe->res != p9_size) {
                    fprintf(stderr, "SHORT READ from socket pair %d read %d 9p size %d tag %d ignored...\n", meta->channel,
                            cqe->res, p9_size, tag);
                    fflush(stderr);
                    // goto error;
                }

                // switch to write
                meta->link++;

                meta->msg_bytes_left = cqe->res + HEADER_SIZE;
                meta->writer_cursor = 0;

                write_queue[write_queue_end] = meta;
                write_queue_end = (write_queue_end + 1) % MAX_P9_VOLUMES;

            } else if (meta->link == 1) {
                meta->msg_bytes_left -= cqe->res;
                meta->writer_cursor += cqe->res;

                if (meta->msg_bytes_left == 0) {
                    // requeue this event
                    enqueue_channel_event(meta->channel, meta->buffer, &ring, meta);

                    write_queue[write_queue_start] = NULL;

                    write_queue_start = (write_queue_start + 1) % MAX_P9_VOLUMES;
                    write_in_progress = false;
                } else {
#ifdef URING_TRACE
                    fprintf(stderr, "SHORT WRITE TO SOCKET: Scheduling another %d bytes\n", meta->msg_bytes_left);
#endif
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, g_p9_fd, meta->buffer + meta->writer_cursor, meta->msg_bytes_left, 0);
                    io_uring_sqe_set_data(sqe, meta);
                }
            }

            // TODO: this will fail if put on a queue MAX_P9_VOLUMES messages at once
            if (write_queue_start != write_queue_end && write_in_progress == false) {
                // write preppended header
                sqe = io_uring_get_sqe(&ring);

                meta = write_queue[write_queue_start];

                if (!meta) {
                    fprintf(stderr, "Got null meta\n");
                    goto error;
                }

                io_uring_prep_write(sqe, g_p9_fd, meta->buffer, meta->msg_bytes_left, 0);
                io_uring_sqe_set_data(sqe, meta);
                write_in_progress = true;
            }
        } else {
            // assumption:
            // there can be at most one message in the buffer per channel (kernel will not send another req
            // without previous reply)

            if (meta->link == 0) {
                cb_advance_writer(response_framer->cb, cqe->res);

                // New data arrived, pop all ready messages, and enqueue them
                struct metadata* write_message = NULL;

                while ((write_message = sf_pop_message(response_framer))) {
#ifdef URING_TRACE
                    fprintf(stderr, "enqueue write response to channel %d, size %d\n", write_message->channel_to_write,
                            write_message->packet_size);
#endif
                    // Buffer contains full message, start write procedure
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, g_p9_socket_fds[write_message->channel_to_write][1],
                                        write_message->buffer + write_message->writer_cursor,
                                        write_message->msg_bytes_left, 0);
                    io_uring_sqe_set_data(sqe, write_message);
                }

                // update metadata, schedule another read
                int avaliable = cb_write_space(response_framer->cb);

#ifdef URING_TRACE
                fprintf(stderr, "avaliable for response %d\n", avaliable);
#endif
                meta->buffer = response_framer->cb->buffer + response_framer->cb->writer_cursor;
                meta->msg_bytes_left = avaliable;

                sqe = io_uring_get_sqe(&ring);

                if (!sqe) {
                    fprintf(stderr, "sqe == null!\n");
                    goto error;
                }

                io_uring_prep_read(sqe, g_p9_fd, meta->buffer, meta->msg_bytes_left, 0);
                io_uring_sqe_set_data(sqe, meta);

            } else if (meta->link == 1) {
                // write response
                meta->msg_bytes_left -= cqe->res;
                meta->writer_cursor += cqe->res;

                if (meta->msg_bytes_left > 0) {
#ifdef URING_TRACE
                    fprintf(stderr, "SHORT WRITE! Scheduling to write left %d bytes\n", meta->msg_bytes_left);
#endif
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_write(sqe, g_p9_socket_fds[meta->channel_to_write][1],
                                        meta->buffer + meta->writer_cursor, meta->msg_bytes_left, 0);
                    io_uring_sqe_set_data(sqe, meta);
                } else {
#ifdef URING_TRACE
                    fprintf(stderr, "Wrote whole buffer\n");
#endif
                    // Discard unneeded meta
                    free(meta->buffer);
                    free(meta);
                }
            }
        }

        io_uring_cqe_seen(&ring, cqe);

        // fprintf(stderr, "queue start %d, queue end %d write in progress %d\n", write_queue_start, write_queue_end,
        //         write_in_progress);
        // fflush(stderr);

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
    sf_free(response_framer);

    return NULL;
}
#endif

#if USE == EPOLL

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

#endif

#if USE == THREAD
pthread_mutex_t g_p9_tunnel_mutex_sender;
pthread_t g_p9_tunnel_thread_receiver;
pthread_t g_p9_tunnel_thread_sender[MAX_P9_VOLUMES];

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

static void* tunnel_from_p9_virtio_to_sock(void* data) {
    const int bufferSize = MAX_PACKET_SIZE;
    char* buffer = malloc(bufferSize);

    if (data != NULL) {
        fprintf(stderr, "tunnel_from_p9_virtio_to_sock: data != NULL\n");
        return NULL;
    }

    while (true) {
        ssize_t bytes_read = 0;

        uint8_t channel = 0;
        bytes_read = read_exact(g_p9_fd, &channel, sizeof(channel));
        if (bytes_read == 0) {
            goto success;
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
    }
success:
    free(buffer);
    return (void*)0;
error:
    free(buffer);
    return (void*)-1;
}

static void* tunnel_from_p9_sock_to_virtio(void* data) {
    intptr_t channel_wide_int = (intptr_t)data;
    uint8_t channel = channel_wide_int;
    assert(channel_wide_int < MAX_P9_VOLUMES);
    assert(channel == channel_wide_int);

#if WIN_P9_EXTRA_DEBUG_INFO
    fprintf(stderr, "P9 sender thread started channel: %d\n", channel);
#endif

    const int bufferSize = MAX_PACKET_SIZE;
    char* buffer = malloc(bufferSize);

    while (true) {
        ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer, bufferSize, 0);
        // fprintf(stderr, "tunnel_from_p9_sock_to_virtio: bytes read %d channel %d errno %m\n", bytes_read, channel);

        if (bytes_read == 0) {
            free(buffer);
            return NULL;
        }

        if (bytes_read == -1) {
            free(buffer);
            return (void*)(int64_t)errno;
        }

        if (pthread_mutex_lock(&g_p9_tunnel_mutex_sender)) {
            fprintf(stderr, "pthread_mutex_lock failed\n");
            return (void*)(int64_t)errno;
        }
#if WIN_P9_EXTRA_DEBUG_INFO
        fprintf(stderr, "send message to channel %d, length: %ld\n", channel, bytes_read);
#endif

        bool write_succeeded = true;

        if (write_exact(g_p9_fd, &channel, 1) == -1) {
            fprintf(stderr, "Failed write g_p9_fd 1\n");
            write_succeeded = false;
            goto mutex_unlock;
        }
        uint16_t bytes_read_to_send = (uint16_t)bytes_read;
        assert(sizeof(bytes_read_to_send) == 2);
        if (write_exact(g_p9_fd, &bytes_read_to_send, sizeof(bytes_read_to_send)) == -1) {
            fprintf(stderr, "Failed write g_p9_fd 2\n");
            write_succeeded = false;
            goto mutex_unlock;
        }
        if (write_exact(g_p9_fd, buffer, bytes_read) == -1) {
            fprintf(stderr, "Failed write g_p9_fd 3\n");
            write_succeeded = false;
            goto mutex_unlock;
        }

    mutex_unlock:
        if (pthread_mutex_unlock(&g_p9_tunnel_mutex_sender)) {
            fprintf(stderr, "pthread_mutex_unlock failed\n");
            return (void*)(int64_t)errno;
        }
        if (!write_succeeded) {
            fprintf(stderr, "tunnel_from_p9_sock_to_virtio: write_succeeded failed channel %d errno %m\n", channel);
            return (void*)(int64_t)errno;
        }
    }
}

int initialize_p9_communication() {
    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        g_p9_socket_fds[i][0] = -1;
        g_p9_socket_fds[i][1] = -1;
    }

    if (pthread_mutex_init(&g_p9_tunnel_mutex_sender, NULL) == -1) {
        fprintf(stderr, "Error: pthread_mutex_init error\n");
        return -1;
    }
    if (pthread_create(&g_p9_tunnel_thread_receiver, NULL, &tunnel_from_p9_virtio_to_sock, NULL) == -1) {
        fprintf(stderr, "Error: pthread_create failed pthread_create(&g_p9_tunnel_thread_receiver...\n");
        return -1;
    }

    return 0;
}

uint32_t do_mount_p9(const char* tag, char* path) {
    uint8_t channel = g_p9_current_channel++;

    if (channel >= MAX_P9_VOLUMES) {
        fprintf(stderr, "ERROR: channel >= MAX_P9_VOLUMES\n");
        return -1;
    }
    if (g_p9_socket_fds[channel][0] != -1 || g_p9_socket_fds[channel][1] != -1) {
        fprintf(stderr, "Error: Looks like do mount called twice with the same channel\n");
        return -1;
    }

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, g_p9_socket_fds[channel]) == -1) {
        return errno;
    }

    // TODO: there could be one thread with poll
    // for every socket pair we need one reader
    uintptr_t channel_wide_int = channel;
    if (pthread_create(&g_p9_tunnel_thread_sender[channel], NULL, &tunnel_from_p9_sock_to_virtio,
                       (void*)channel_wide_int) == -1) {
        fprintf(stderr, "Error: pthread_create failed\n");
        return -1;
    }

    tag = tag;
    char* mount_cmd = NULL;
    int mount_socked_fd = g_p9_socket_fds[channel][0];
    // TODO: snprintf
    int buf_size = asprintf(&mount_cmd, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L,msize=65536", mount_socked_fd,
                            mount_socked_fd);
    if (buf_size < 0) {
        free(mount_cmd);
        return errno;
    }
    fprintf(stderr, "Starting mount: tag: %s, path: %s\n", tag, path);
    if (mount(tag, path, "9p", 0, mount_cmd) < 0) {
        fprintf(stderr, "Mount finished with error: %d\n", errno);
        return errno;
    }

    fprintf(stderr, "Mount finished.\n");
    free(mount_cmd);
    return 0;
}
#else
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

    TRY_OR_GOTO(snprintf(mount_cmd, CMD_SIZE, "trans=fd,rfdno=%d,wfdno=%d,debug=0xff,version=9p2000.L,msize=32000",
                         mount_socket_fd, mount_socket_fd),
                error);

    TRY_OR_GOTO(mount(tag, path, "9p", 0, mount_cmd), error);

    fprintf(stderr, "Mount finished.\n");
    return 0;
error:
    fprintf(stderr, "Mount failed.\n");
    return -1;
}

#endif
