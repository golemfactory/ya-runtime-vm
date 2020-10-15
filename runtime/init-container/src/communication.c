#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "communication.h"
#include "cyclic_buffer.h"

int readn(int fd, void* buf, size_t size) {
    while (size) {
        ssize_t ret = read(fd, buf, size);
        if (ret == 0) {
            puts("Waiting for host connection ...");
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
        buf = (char*)buf + ret;
        size -= ret;
    }
    return 0;
}

int recv_u64(int fd, uint64_t* res) {
    return readn(fd, res, sizeof(*res));
}

int recv_u32(int fd, uint32_t* res) {
    return readn(fd, res, sizeof(*res));
}

int recv_u8(int fd, uint8_t* res) {
    return readn(fd, res, sizeof(*res));
}

int recv_bytes(int fd, char** buf_ptr, uint64_t* size_ptr,
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
    if (size_ptr) {
        *size_ptr = size;
    }

    return 0;
}

void free_strings_array(char** array) {
    if (!array) {
        return;
    }

    for (size_t i = 0; array[i]; ++i) {
        free(array[i]);
    }
    free(array);
}

int recv_strings_array(int fd, char*** array_ptr) {
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
        if (recv_bytes(fd, &array[i], NULL, /*is_cstring=*/true) < 0) {
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

int writen(int fd, const void* buf, size_t size) {
    while (size) {
        ssize_t ret = write(fd, buf, size);
        if (ret == 0) {
            puts("Waiting for host connection ...");
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
        buf = (char*)buf + ret;
        size -= ret;
    }
    return 0;
}

int send_bytes(int fd, const char* buf, uint64_t size) {
    if (writen(fd, &size, sizeof(size)) < 0) {
        return -1;
    }

    return writen(fd, buf, size);
}

int send_bytes_cyclic_buffer(int fd, struct cyclic_buffer* cb, uint64_t size) {
    size_t cb_data_size = cyclic_buffer_data_size(cb);
    if (size > cb_data_size) {
        size = cb_data_size;
    }

    if (writen(fd, &size, sizeof(size)) < 0) {
        return -1;
    }

    while (size) {
        ssize_t ret = cyclic_buffer_write(fd, cb, size);
        if (ret == 0) {
            puts("Waiting for host connection ...");
            sleep(1);
            continue;
        }
        if (ret < 0) {
            return -1;
        }
        size -= ret;
    }
    return 0;
}
