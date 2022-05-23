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
#include <sys/reboot.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mount.h>

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

#ifndef NDEBUG
#define LOG_DEBUG(args...) fprinf(stderr, args)
#else 
#define LOG_DEBUG(args...) do { } while(0)
#endif


#if USE == URING

// TODO: idea of using chains for copy fds, that's what exactly happens here
// https://blogs.oracle.com/linux/post/an-introduction-to-the-io-uring-asynchronous-io-framework

struct metadata_base;

typedef int cb_func_t(struct io_uring *ring, struct metadata_base *state, int res);

struct metadata_base {
  cb_func_t *cb;
  int link;
  int cmds;
};

struct metadata_write_s {
    struct metadata_base base;
    int fd;
    int to_write_tasks;
    struct iovec bv[2*MAX_P9_VOLUMES];
    struct metadata_base *waiters[2*MAX_P9_VOLUMES];
};


static void io_read(struct io_uring *ring, struct metadata_base *state, int fd, char *buf, size_t len) {
    if (state->cmds++!= 0) {
      fprintf(stderr, "FATAL: on read task locked: %d\n", state->cmds);
    }
    if (len == 0) {
      fprintf(stderr, "FATAL: empty read\n");
    }
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, state);
    sqe->flags |= IOSQE_ASYNC;
}

static void io_write(struct io_uring *ring, struct metadata_base *state, int fd, char *buf, size_t len) {
    if (state->cmds++ != 0) {
      fprintf(stderr, "FATAL: on write task locked: %d\n", state->cmds);
    }
    if (len == 0) {
      fprintf(stderr, "FATAL: empty write\n");
    }
      struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, state);
    sqe->flags |= IOSQE_ASYNC;
}


// #define URING_TRACE
// 
// Read(n):: task czytania z ntego clienta 9p
// ReadS:: task czytania z serwera
// Write(n):: task zapisu
// WriteS:: task zapusu do serwera
//
//
static int send_to_write(struct io_uring *ring, struct metadata_write_s *write_s, char * buf, size_t len, struct metadata_base *waiter) {
    LOG_DEBUG(stderr, "write_s=%p, buf=%p, size=%lu\n", write_s, buf, len);
    int idx = write_s->to_write_tasks++;
    write_s->bv[idx].iov_base = buf;
    write_s->bv[idx].iov_len = len;
    write_s->waiters[idx] = waiter;
    if (write_s->base.link == 0 && write_s->to_write_tasks == 1) {
      return (write_s->base.cb)(ring, &write_s->base, 0);
    }
    return 0;
}

struct metadata_read_n {
    struct metadata_base base;
    int fd;
    uint8_t channel;
    int32_t reader_cursor;
    char* buffer;
    struct metadata_write_s *write_s;
};

static int task_read_n(struct io_uring *ring, struct metadata_read_n *state, int res);

static struct metadata_read_n *new_task_read_n(int fd, uint8_t channel, struct metadata_write_s *write_s, char *buffer) {
  struct metadata_read_n *_this = calloc(1, sizeof(struct metadata_read_n));
  _this->base.cb = (cb_func_t *)task_read_n;
  _this->fd=  fd;
  _this->channel = channel;
  _this->buffer = buffer;
  _this->write_s = write_s;
  return _this;
}

static int task_read_n(struct io_uring *ring, struct metadata_read_n *state, int res) {
  uint32_t p9_size;

  for(;;) {
    LOG_DEBUG(stderr, "task_read_n %d link=%d\n", res, state->base.link);
    switch(state->base.link) {
    
      case 0: {
        io_read(ring, &state->base, state->fd, state->buffer+HEADER_SIZE, MAX_PACKET_SIZE-HEADER_SIZE);
        state->base.link = 1;
        return 0;
      }
      case 1:
        state->reader_cursor+=res;
        if (state->reader_cursor >= 4) {
          p9_size = ((uint32_t*)(state->buffer + HEADER_SIZE))[0];
        }
        else {
          p9_size = 0;
        }

        if (state->reader_cursor < 4 || state->reader_cursor < p9_size) {
          io_read(ring, &state->base, state->fd, 
              state->buffer + HEADER_SIZE + state->reader_cursor, 
              MAX_PACKET_SIZE - HEADER_SIZE - state->reader_cursor 
          );
          return  0;
        }
        state->buffer[0] = state->channel;
        ((uint16_t*)(state->buffer + 1))[0] = p9_size;      
        state->base.link = 2;
        if (p9_size > 0) {
          LOG_DEBUG(stderr, "sending %d bytes\n", p9_size);
          return send_to_write(ring, state->write_s, state->buffer, p9_size+HEADER_SIZE, &state->base);
        }
    
      case 2:
        p9_size = ((uint32_t*)(state->buffer + HEADER_SIZE))[0];
        /*fprintf(stderr, "new packet to send p9_size=%d reader_cursor=%d [%02x %02x %02x %02x %02x]\n", p9_size, state->reader_cursor,
            state->buffer[3], state->buffer[4], state->buffer[5], state->buffer[6], state->buffer[7]
            );*/
        if (p9_size < state->reader_cursor) {
          memmove(state->buffer + HEADER_SIZE, state->buffer + HEADER_SIZE + p9_size, state->reader_cursor - p9_size);
          state->reader_cursor -= p9_size;
          state->base.link = 1;
          res = 0;
          continue;
        }
        state->reader_cursor = 0;
        state->base.link = 0;
        continue;   
    }
  }
}

static inline int min_int(int a, int b) {
  return a<b ? a : b;
}

static int task_write_s(struct io_uring *ring, struct metadata_write_s *state, int res) {
  int i;

   for(;;) {
    LOG_DEBUG(stderr, "task_write_s res=%d link=%d\n", res, state->base.link);
    switch(state->base.link) {
      case 0:
        if (state->to_write_tasks == 0) {
          LOG_DEBUG(stderr, "write buf is empty\n");

          return 0;
        }

        /*struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        io_uring_prep_writev(sqe, state->fd, state->bv, state->to_write_tasks, 0);
        io_uring_sqe_set_data(sqe, state);
        */

        size_t wbytes = state->bv[0].iov_len;
        io_write(ring, &state->base, state->fd, state->bv[0].iov_base, wbytes);
        state->base.link = 1;
        return 0;
      case 1:
        i = 0;
        LOG_DEBUG(stderr, "write tasks=%d res=%d\n", state->to_write_tasks, res);
        for (; i<state->to_write_tasks; ++i) {
          if (state->bv[i].iov_len <= res) {
            res -= state->bv[i].iov_len; 
          }
          else {
            state->bv[i].iov_base += res;
            state->bv[i].iov_len -= res;
            break;
          }
        }
        LOG_DEBUG(stderr, "write closed jobs=%d\n", i);
        // i = ostatni do końca niezapisany bufor.
        for (int j=0; j<i; j++) {
          (state->waiters[j]->cb)(ring, state->waiters[j], 0);
        }
        state->to_write_tasks -= i;
        memmove(state->waiters, state->waiters+i, sizeof(state->waiters[0])*(state->to_write_tasks));
        memmove(state->bv, state->bv+i, sizeof(state->bv[0])*(state->to_write_tasks));
        res=0;
        state->base.link = 0;
        continue;
      }
   }
}

struct metadata_write_s *new_task_write_s(int fd) {
  struct metadata_write_s *_this = calloc(1, sizeof(struct metadata_write_s));
  _this->base.cb = (cb_func_t *)task_write_s;
  _this->fd = fd;
  return _this;
}



struct metadata_read_s {
  struct metadata_base base;
  char buf[1024*1024];
  int read_pos;
  int write_pos;
  int fd;
};

static int sync_read_s(struct io_uring *ring, struct metadata_read_s *state) {
  fprintf(stderr, "start sync\n");
  int res = read(state->fd, state->buf + state->read_pos, sizeof(state->buf) - state->read_pos);
  fprintf(stderr, "end sync %d\n", res);
  state->read_pos+=res;
  return 0;
}

static int task_read_s(struct io_uring *ring, struct metadata_read_s *state, int res) {
  uint16_t packet_size;
  uint8_t channel;
  struct io_uring_sqe* sqe;
  LOG_DEBUG("task_read_s %d %p link=%d\n", res, state, state->base.link);

  for(;;) { switch(state->base.link) {
    case 0:
      io_read(ring, &state->base, state->fd, state->buf + state->read_pos, sizeof(state->buf) - state->read_pos);
        state->base.link = 1;
        return 0;
    case 1: {
         state->read_pos += res;
         int in_buffer = state->read_pos - state->write_pos;
         if (in_buffer < HEADER_SIZE) {
            io_read(ring, &state->base, state->fd, state->buf + state->read_pos, sizeof(state->buf) - state->read_pos);
            return 0;
         }
         channel = *((uint8_t *)state->buf);
         packet_size = *(uint16_t *)(state->buf+1);
         if (in_buffer < packet_size) {
            io_read(ring, &state->base, state->fd, state->buf + state->read_pos, sizeof(state->buf) - state->read_pos);
            return 0;
        }
        state->write_pos = HEADER_SIZE;
        io_write(ring, &state->base, g_p9_socket_fds[channel][1], state->buf + state->write_pos, packet_size);
        state->base.link = 3;
        return 0;
      }
    case 3: {
        channel = *((uint8_t *)state->buf);
        packet_size = *(uint16_t *)(state->buf+1);
        state->write_pos += res;
        LOG_DEBUG("task_read_s channel=%d packet_size=%d write_pos=%d\n", channel, packet_size, state->write_pos);

        if (state->write_pos < packet_size + HEADER_SIZE) {
          io_write(ring, &state->base, g_p9_socket_fds[channel][1], state->buf + state->write_pos, packet_size - state->write_pos + HEADER_SIZE);
          return 0;
        }
        if (state->write_pos < state->read_pos) {
          memmove(state->buf, state->buf+packet_size+HEADER_SIZE, state->read_pos - state->write_pos);
        }
        state->read_pos -= state->write_pos;
        state->write_pos = 0;
        state->base.link = 0;
        LOG_DEBUG("task_read_s write done!!!\n");
        continue;
    }
  } }
}

static struct metadata_read_s *new_task_read_s(int fd) {
   struct metadata_read_s *_this = calloc(1, sizeof(struct metadata_read_s));
  _this->base.cb = (cb_func_t *)task_read_s;
  _this->fd = fd;
  return _this;
} 

static void* poll_9p_messages(void* data) {
    (void)data;
// TODO: find good value
#define QUEUE_DEPTH (MAX_P9_VOLUMES + 1) * 3
    fprintf(stderr, "POLL: P9 INIT IO_URING\n");

    char* buffer = NULL;
    // TODO: read as much data as possible parse packets locally
    struct io_uring ring;

    const int FDS_SIZE = MAX_P9_VOLUMES + 1;
    TRY_OR_GOTO(io_uring_queue_init(1024 * 16, &ring, 0), error);

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

    struct metadata_write_s *write_s = new_task_write_s(g_p9_fd);

    int fds[MAX_P9_VOLUMES+1];
    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
      fds[i] = g_p9_socket_fds[i][1];
    }
    fds[MAX_P9_VOLUMES] = g_p9_fd;
    io_uring_register_files(&ring, fds, MAX_P9_VOLUMES+1);

    //////////////////
    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        struct metadata_read_n *reader = new_task_read_n(g_p9_socket_fds[i][1], i, write_s, buffer + i*MAX_PACKET_SIZE);
        LOG_DEBUG("new task %d %p\n", i, reader);
        task_read_n(&ring, reader, 0);
        LOG_DEBUG("new task %d started\n", i);
    }
    task_write_s(&ring, write_s, 0);

    struct metadata_read_s *read_s = new_task_read_s(g_p9_fd);
    task_read_s(&ring, read_s, 0);

    int n_submit = io_uring_submit(&ring);
    LOG_DEBUG("submit: %d\n", n_submit);

    while (1) {
        sqe = NULL;
        struct __kernel_timespec tv = { .tv_sec = 10, .tv_nsec = 0 };

        int uwret = io_uring_wait_cqe_timeout(&ring, &cqe, &tv);
        if (uwret == -62) {
            fprintf(stderr, "timeout write_s(%d/%d) read_s(%d/%d)\n", 
                write_s->base.link, write_s->to_write_tasks,
                read_s->base.link, read_s->read_pos);
            if (read_s->read_pos >3) {
              int channel = *((uint8_t *)read_s->buf);
              int packet_size = *(uint16_t *)(read_s->buf+1);
              fprintf(stderr, "in buf channel=%d, packet=%d\n\n", channel, packet_size);
            }

            for (int i=0; i<20&& i<read_s->read_pos; ++i) {
              fprintf(stderr, "%02x ", (uint8_t)read_s->buf[i]);
            }
            fprintf(stderr, "\n");
            if (read_s->read_pos == 0 && read_s->base.link == 1) {
              read_s->buf[read_s->read_pos] = 0;
            }
            //task_read_s(&ring, read_s, 0);
            continue;
        }
        if (uwret < 0) {
          goto error;
        }
        if (cqe->res < 0) {
            fprintf(stderr, "POLL: P9 cqe with data 0x%llX, returned error %d!\n", cqe->user_data, cqe->res);
            goto error;
        }

        struct metadata_base* meta = io_uring_cqe_get_data(cqe);
        --meta->cmds;
        if ((meta->cb)(&ring, meta, cqe->res) != 0) {
          fprintf(stderr, "POLL: P9 cqe with data 0x%llX, callback failed\n", cqe->user_data);
          goto error;
        }
        io_uring_cqe_seen(&ring, cqe);

        //int ret = io_uring_submit(&ring);
        //LOG_DEBUG("submited=%d %x\n", ret, ring.flags);
    }

error:
    fprintf(stderr, "POLL: P9 thread is leaving!\n");

    io_uring_unregister_files(&ring);
    io_uring_queue_exit(&ring);
    free(buffer);

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
    int buf_size = asprintf(&mount_cmd, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L,debug=1", mount_socked_fd,
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

    TRY_OR_GOTO(snprintf(mount_cmd, CMD_SIZE, "trans=fd,rfdno=%d,wfdno=%d,debug=1,version=9p2000.L",
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
