#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
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

#include "communication_win_p9.h"
#include "common.h"

int g_p9_fd = -1;
int g_p9_current_channel = 0;
int g_p9_socket_fds[MAX_P9_VOLUMES][2];
// pthread_t g_p9_tunnel_thread_sender[MAX_P9_VOLUMES];
pthread_mutex_t g_p9_tunnel_mutex_sender;
pthread_t g_p9_tunnel_thread_receiver;
static pthread_t g_p9_tunnel_thread_sender;

//TODO: - move it somewhere else
// int create_dir_path(char* path);

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

static void* tunnel_from_p9_virtio_to_sock(void *data) {
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


// static void* tunnel_from_p9_sock_to_virtio(void *data) {
//     intptr_t channel_wide_int = (intptr_t)data;
//     uint8_t channel = channel_wide_int;
//     assert(channel_wide_int < MAX_P9_VOLUMES);
//     assert(channel == channel_wide_int);

// #if WIN_P9_EXTRA_DEBUG_INFO
//     fprintf(stderr, "P9 sender thread started channel: %d\n", channel);
// #endif

//     const int bufferSize = MAX_PACKET_SIZE;
//     char* buffer = malloc(bufferSize);

//     while (true) {
//         ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer, bufferSize, 0);

//         if (bytes_read == 0) {
//             free(buffer);
//             return NULL;
//         }

//         if (bytes_read == -1) {
//             free(buffer);
//             return (void*)(int64_t)errno;
//         }

//         if (pthread_mutex_lock(&g_p9_tunnel_mutex_sender)) {
//             fprintf(stderr, "pthread_mutex_lock failed\n");
//             return (void*)(int64_t)errno;
//         }
// #if WIN_P9_EXTRA_DEBUG_INFO
//         fprintf(stderr, "send message to channel %d, length: %ld\n", channel, bytes_read);
// #endif

//         bool write_succeeded = true;

//         if (write_exact(g_p9_fd, &channel, 1) == -1) {
//             fprintf(stderr, "Failed write g_p9_fd 1\n");
//             write_succeeded = false;
//             goto mutex_unlock;
//         }
//         uint16_t bytes_read_to_send = (uint16_t)bytes_read;
//         assert(sizeof(bytes_read_to_send) == 2);
//         if (write_exact(g_p9_fd, &bytes_read_to_send, sizeof(bytes_read_to_send)) == -1) {
//             fprintf(stderr, "Failed write g_p9_fd 2\n");
//             write_succeeded = false;
//             goto mutex_unlock;
//         }
//         if (write_exact(g_p9_fd, buffer, bytes_read) == -1) {
//             fprintf(stderr, "Failed write g_p9_fd 3\n");
//             write_succeeded = false;
//             goto mutex_unlock;
//         }

// mutex_unlock:
//         if (pthread_mutex_unlock(&g_p9_tunnel_mutex_sender)) {
//             fprintf(stderr, "pthread_mutex_unlock failed\n");
//             return (void*)(int64_t)errno;
//         }
//         if (!write_succeeded) {
//             return (void*)(int64_t)errno;
//         }
//     }
// }

void handle_data_on_channel(int channel) {
    // fprintf(stderr, "POLL: handling data on channel %d\n", channel);

    // TODO: don't do allocations over and over
    const int bufferSize = MAX_PACKET_SIZE;
    char* buffer = malloc(bufferSize);

    ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer, bufferSize, 0);

    if (bytes_read == 0) {
        free(buffer);
        // TODO: GOTO error
        return;
    }

    // TODO: CHECK macro?
    if (bytes_read == -1) {
        free(buffer);
        // TODO: GOTO error
        fprintf(stderr, "failed while reading bytes %m\n");
        return;

    }

    if (pthread_mutex_lock(&g_p9_tunnel_mutex_sender)) {
        // TODO: goto error
        free(buffer);
        fprintf(stderr, "pthread_mutex_lock failed %m\n");
        return;
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
        return;
    }
    if (!write_succeeded) {
        return;
    }

}

static void* tunnel_from_p9_sock_to_virtio(void *data) {
    (void)data;

    fprintf(stderr, "POLL: P9 sender started polling\n");

    // TODO: pre C99?
    int epoll_fd = -1;
    epoll_fd = CHECK_NO_FATAL(epoll_create1(EPOLL_CLOEXEC));

    fprintf(stderr, "POLL: P9 adding descriptors\n");

    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        int channel_rx = g_p9_socket_fds[i][1];

        // TODO: read about that struct fields
        struct epoll_event event = {};
        event.events = EPOLLIN;
        event.data.fd = channel_rx;

        CHECK_NO_FATAL(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel_rx, &event));
    }

    // const int bufferSize = MAX_PACKET_SIZE;
    // char* buffer = malloc(bufferSize);

    while (1) {
        struct epoll_event event = {};


        // TODO: max event set to 1, but I don't think that's a problem
        if (epoll_wait(epoll_fd, &event, 1, -1) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                fprintf(stderr, "POLL: continue %m\n");
                continue;
            }
            fprintf(stderr, "epoll failed: %m\n");
            // TODO: goto error?
            return NULL;
        }

        if (event.events & EPOLLNVAL) {
            fprintf(stderr, "epoll error event: 0x%04hx\n", event.events);
            // TODO: goto error?
            return NULL;
        }

        for (int channel = 0; channel < MAX_P9_VOLUMES; channel++) {
            int channel_rx = g_p9_socket_fds[channel][1];
            if (event.data.fd == channel_rx) {
                handle_data_on_channel(channel);
            }
        }
    }

    // TODO: return anything meaningful?
    return NULL;
}

// TODO: create Twrite request that exceeds hardcoded packet size
// TODO: do highly concurrent write requests from rust side to see congestion in this part of code
int initialize_p9_socket_descriptors() {
    // for (int i = 0; i < MAX_P9_VOLUMES; i++) {
    //     g_p9_socket_fds[i][0] = -1;
    //     g_p9_socket_fds[i][1] = -1;
    // }

    for (int i = 0; i < MAX_P9_VOLUMES; i++) {
        if (socketpair(AF_LOCAL, SOCK_STREAM, 0, g_p9_socket_fds[i]) == -1) {
            fprintf(stderr, "Error: Failed to create a socket pair for channel %d, errno: %d\n", i, errno);
            return errno;
        }


        // TODO: make fds nonblocking?
        // TODO: great article:
        // https://eklitzke.org/blocking-io-nonblocking-io-and-epoll
        // make_nonblocking(g_p9_socket_fds[i][1]);
    }

    if (pthread_mutex_init(&g_p9_tunnel_mutex_sender, NULL) == -1) {
        fprintf(stderr, "Error: pthread_mutex_init error\n");
        return -1;
    }
	if (pthread_create(&g_p9_tunnel_thread_receiver, NULL, &tunnel_from_p9_virtio_to_sock, NULL) == -1) {
        fprintf(stderr, "Error: pthread_create failed pthread_create(&g_p9_tunnel_thread_receiver...\n");
        return -1;
	}

    if (pthread_create(&g_p9_tunnel_thread_sender, NULL, &tunnel_from_p9_sock_to_virtio, NULL) == -1) {
        fprintf(stderr, "Error: pthread_create failed pthread_create(&g_p9_tunnel_thread_sender...\n");
        return -1;
	}

    return 0;
}

uint32_t do_mount_win_p9(const char* tag, uint8_t channel, char* path) {
    if (channel >= MAX_P9_VOLUMES) {
        fprintf(stderr, "ERROR: channel >= MAX_P9_VOLUMES\n");
        return -1;
    }

    // if (g_p9_socket_fds[channel][0] != -1 || g_p9_socket_fds[channel][1] != -1) {
    //     fprintf(stderr, "Error: Looks like do mount called twice with the same channel\n");
    //     return -1;
    // }

    // if (socketpair(AF_LOCAL, SOCK_STREAM, 0, g_p9_socket_fds[channel]) == -1) {
    //     return errno;
    // }


    // TODO: it will condense to epoll_ctl(ADD)

    fprintf(stderr, "@@@@@@@@@@@@@@@@@@Creating a thread for channel %u\n", (unsigned) channel);

    // TODO: there could be one thread with poll
    //for every socket pair we need one reader
    // uintptr_t channel_wide_int = channel;
    // if (pthread_create(&g_p9_tunnel_thread_sender[channel], NULL, &tunnel_from_p9_sock_to_virtio, (void*) channel_wide_int) == -1) {
    //     fprintf(stderr, "Error: pthread_create failed\n");
    //     return -1;
    // }

    tag = tag;
    char* mount_cmd = NULL;
    int mount_socket_fd = g_p9_socket_fds[channel][0];
    // TODO: snprintf
    int buf_size = asprintf(&mount_cmd, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L", mount_socket_fd, mount_socket_fd);
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
