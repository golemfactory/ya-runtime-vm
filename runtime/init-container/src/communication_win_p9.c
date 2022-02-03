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

int read_exact(int fd, void* buf, size_t size) {
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




static void* tunnel_from_p9_virtio_to_sock() {
    const int bufferSize = MAX_PACKET_SIZE;
    char* buffer = malloc(bufferSize);

    while (true) {
        ssize_t bytes_read = 0;

        uint8_t channel = 0;
        bytes_read = read_exact(g_p9_fd, &channel, sizeof(channel));
        if (bytes_read == 0) {
            goto success;
        }

        if (bytes_read != sizeof(channel)) {
            printf("Error during read from g_p9_fd: bytes_read != sizeof(channel)\n");
            goto error;
        }

        uint16_t packet_size = 0;
        bytes_read = read_exact(g_p9_fd, &packet_size, sizeof(packet_size));
        if (bytes_read != sizeof(packet_size)) {
            printf("Error during read from g_p9_fd: bytes_read != sizeof(packet_size)\n");
            goto error;
        }

        if (packet_size > MAX_PACKET_SIZE) {
            printf("Error: Maximum packet size exceeded: packet_size > MAX_PACKET_SIZE\n");
            goto error;
        }

        bytes_read = read_exact(g_p9_fd, buffer, packet_size);
        if (bytes_read != packet_size) {
            printf("Error during read from g_p9_fd: bytes_read != packet_size\n");
            goto error;
        }

        printf("RECEIVE MESSAGE %ld\n", bytes_read);
        if (bytes_read == -1) {
            printf("Error during read from g_p9_fd: bytes_read == -1\n");
            goto error;
        }
        if (write(g_p9_socket_fds[channel][1], buffer, bytes_read) == -1) {
            printf("Error writing to g_p9_socket_fds");
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

    printf("P9 sender thread started channel: %d\n", channel);

    const int bufferSize = MAX_PACKET_SIZE;
    char* buffer = malloc(bufferSize);

    while (true) {
        ssize_t bytes_read = recv(g_p9_socket_fds[channel][1], buffer, bufferSize, 0);

        if (pthread_mutex_lock(&g_p9_tunnel_mutex_sender)) {
            printf("pthread_mutex_lock failed");
            return (void*)(int64_t)errno;
        }
        printf("send message to channel %d, length: %ld\n", channel, bytes_read);

        if (bytes_read == 0) {
            free(buffer);
            return NULL;
        }
        if (bytes_read == -1) {
            free(buffer);
            return (void*)(int64_t)errno;
        }
        if (write(g_p9_fd, &channel, 1) == -1) {
            return (void*)(int64_t)errno;
        }
        uint16_t bytes_read_to_send = (uint16_t)bytes_read;
        assert(sizeof(bytes_read_to_send) == 2);
        if (write(g_p9_fd, &bytes_read_to_send, sizeof(bytes_read_to_send)) == -1) {
            return (void*)(int64_t)errno;
        }
        if (write(g_p9_fd, buffer, bytes_read) == -1) {
            return (void*)(int64_t)errno;
        }

        if (pthread_mutex_unlock(&g_p9_tunnel_mutex_sender)) {
            printf("pthread_mutex_unlock failed");
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
        printf("Error: pthread_mutex_init error");
        return -1;
    }
	if (pthread_create(&g_p9_tunnel_thread_receiver, NULL, &tunnel_from_p9_virtio_to_sock, NULL) == -1) {
        printf("Error: pthread_create failed pthread_create(&g_p9_tunnel_thread_receiver...");
        return -1;
	}

    return 0;
}

uint32_t do_mount_win_p9(const char* tag, uint8_t channel, char* path) {
    if (channel >= MAX_P9_VOLUMES) {
        printf("ERROR: channel >= MAX_P9_VOLUMES");
        return -1;
    }
    if (g_p9_socket_fds[channel][0] != -1 || g_p9_socket_fds[channel][1] != -1) {
        printf("Error: Looks like do mount called twice with the same channel");
        return -1;
    }

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, g_p9_socket_fds[channel]) == -1) {
        return errno;
    }

    //for every socket pair we need one reader
    uintptr_t channel_wide_int = channel;
    if (pthread_create(&g_p9_tunnel_thread_sender[channel], NULL, &tunnel_from_p9_sock_to_virtio, (void*) channel_wide_int) == -1) {
        printf("Error: pthread_create failed");
        return -1;
    }

    tag = tag;
    char* mount_cmd = NULL;
    if (create_dir_path(path) < 0) {
        return errno;
    }

    int mount_socked_fd = g_p9_socket_fds[channel][0];
    int buf_size = asprintf(&mount_cmd, "trans=fd,rfdno=%d,wfdno=%d,version=9p2000.L", mount_socked_fd, mount_socked_fd);
    if (buf_size < 0) {
        free(mount_cmd);
        return errno;
    }

    //DEBUG CODE - TODO REMOVE
    /*for (int i = 0; i < 10; i++) {
        write(mount_socked_fd, mount_cmd, buf_size);
        usleep(100 * 1000);
    }*/

    printf("Starting mount: ");
    if (mount(tag, path, "9p", 0, mount_cmd) < 0) {
        printf("Mount finished with error: %d", errno);
        return errno;
    }
    printf("Mount finished");
    free(mount_cmd);
    return 0;
}
