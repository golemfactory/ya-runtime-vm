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

int g_p9_fd = -1;
int g_p9_current_channel = 0;
int g_p9_socket_fds[MAX_P9_VOLUMES][2];
pthread_t g_p9_tunnel_thread_sender[MAX_P9_VOLUMES];
pthread_mutex_t g_p9_tunnel_mutex_sender;
pthread_t g_p9_tunnel_thread_receiver;

//HACK - move it somewhere else
int create_dir_path(char* path);

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
    const int bufferSize = MAX_DEMUX_P9_MESSAGE_SIZE;
    char* buffer = malloc(bufferSize + sizeof(uint32_t) + sizeof(uint8_t));

    //experimental - set thread affinity to get better performance on Windows?
    {
        pthread_t thread;
        thread = pthread_self();
        pthread_attr_t attr;
        cpu_set_t cpus;
        pthread_attr_init(&attr);
        CPU_ZERO(&cpus);
        CPU_SET(1, &cpus);
        pthread_setaffinity_np(thread, sizeof(cpus), &cpus);
    }

    if (data != NULL) {
        fprintf(stderr, "tunnel_from_p9_virtio_to_sock: data != NULL\n");
        return NULL;
    }

    while (true) {
        ssize_t bytes_read = 0;

        bytes_read = read_exact(g_p9_fd, buffer, sizeof(uint8_t) + sizeof(uint32_t));
        if (bytes_read == 0) {
            goto success;
        }

        if (bytes_read != sizeof(uint8_t) + sizeof(uint32_t)) {
            fprintf(stderr, "Error during read from g_p9_fd: bytes_read != sizeof(channel)\n");
            goto error;
        }
        uint8_t channel = *(uint8_t*)buffer;
        uint32_t packet_size = *(uint32_t*)(&buffer[1]);

        if (packet_size > MAX_DEMUX_P9_MESSAGE_SIZE) {
            fprintf(stderr, "Error: Maximum packet size exceeded: packet_size > MAX_PACKET_SIZE\n");
            goto error;
        }

        bytes_read = read_exact(g_p9_fd, buffer + sizeof(uint32_t) + sizeof(uint8_t), packet_size);
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
        if (write_exact(g_p9_socket_fds[channel][1], buffer + sizeof(uint32_t) + sizeof(uint8_t), bytes_read) == -1) {
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


static void* tunnel_from_p9_sock_to_virtio(void *data) {
    intptr_t channel_wide_int = (intptr_t)data;
    uint8_t channel = channel_wide_int;
    assert(channel_wide_int < MAX_P9_VOLUMES);
    assert(channel == channel_wide_int);

#if WIN_P9_EXTRA_DEBUG_INFO
    fprintf(stderr, "P9 sender thread started channel: %d\n", channel);
#endif

    const int bufferSize = MAX_DEMUX_P9_MESSAGE_SIZE;
    char* buffer = malloc(sizeof(uint8_t) + sizeof(uint32_t) + bufferSize);

    //experimental - set thread affinity to get better performance on Windows?
    {
        pthread_t thread;
        thread = pthread_self();
        pthread_attr_t attr;
        cpu_set_t cpus;
        pthread_attr_init(&attr);
        CPU_ZERO(&cpus);
        CPU_SET(1, &cpus);
        pthread_setaffinity_np(thread, sizeof(cpus), &cpus);
    }

    while (true) {
        ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer + sizeof(uint32_t) + sizeof(uint8_t), bufferSize, 0);

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

        *((uint8_t*)buffer) = channel;
        *((uint32_t*)&buffer[1]) = (uint32_t)bytes_read;

        if (write_exact(g_p9_fd, buffer, bytes_read + sizeof(uint8_t) + sizeof(uint32_t)) == -1) {
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
            return (void*)(int64_t)errno;
        }
    }
}

int initialize_p9_socket_descriptors() {
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

uint32_t do_mount_win_p9(const char* tag, uint8_t channel, uint32_t max_p9_message_size, char* path) {
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
    //for every socket pair we need one reader
    uintptr_t channel_wide_int = channel;
    if (pthread_create(&g_p9_tunnel_thread_sender[channel], NULL, &tunnel_from_p9_sock_to_virtio, (void*) channel_wide_int) == -1) {
        fprintf(stderr, "Error: pthread_create failed\n");
        return -1;
    }

    tag = tag;
    char* mount_cmd = NULL;
    int mount_socked_fd = g_p9_socket_fds[channel][0];
    // TODO: snprintf
    int buf_size = asprintf(&mount_cmd, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L,msize=%d", mount_socked_fd, mount_socked_fd, max_p9_message_size);
    if (buf_size < 0) {
        free(mount_cmd);
        return errno;
    }
    fprintf(stderr, "Starting mount: tag: %s, path: %s\n", tag, path);
    fprintf(stderr, "Mount command: %s\n", mount_cmd);
    if (mount(tag, path, "9p", 0, mount_cmd) < 0) {
        fprintf(stderr, "Mount finished with error: %d\n", errno);
        return errno;
    }

    fprintf(stderr, "Mount finished.\n");
    free(mount_cmd);
    return 0;
}
