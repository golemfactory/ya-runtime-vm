#include <errno.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

#include "cyclic_buffer.h"

int cyclic_buffer_init(struct cyclic_buffer* cb, const size_t size) {
    cb->buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (cb->buf == MAP_FAILED) {
        return -1;
    }

    cb->size = size;
    cb->begin = cb->buf;
    cb->end = cb->buf;
    return 0;
}

int cyclic_buffer_deinit(struct cyclic_buffer* cb) {
    if (cb->buf == MAP_FAILED || !cb->size) {
        return 0;
    }
    const int ret = munmap(cb->buf, cb->size);
    cb->buf = MAP_FAILED;
    return ret;
}

size_t cyclic_buffer_data_size(const struct cyclic_buffer* cb) {
    const char* data_begin = cb->begin;
    const char* data_end = cb->end;

    if (data_begin < data_end) {
        return data_end - data_begin;
    }
    if (data_begin > data_end) {
        return cb->size - (data_begin - data_end);
    }

    // data_begin == data_end
    if (data_begin == cb->buf) {
        /* Buffer is completely empty. */
        return 0;
    }

    /* Buffer is completely full. */
    return cb->size;
}

size_t cyclic_buffer_free_size(const struct cyclic_buffer* cb) {
    return cb->size - cyclic_buffer_data_size(cb);
}

static size_t min(const size_t a, const size_t b) {
    return a < b ? a : b;
}

ssize_t cyclic_buffer_read(const int fd, struct cyclic_buffer* cb, size_t count) {
    ssize_t got = 0;
    size_t free_space = cyclic_buffer_free_size(cb);

    while (count && free_space) {
        bool fixup_end = false;
        if (cb->end == cb->buf + cb->size) {
            cb->end = cb->buf;
            fixup_end = true;
        }

        const size_t this_read_size = min(free_space, min(cb->buf + cb->size - cb->end, count));
        const ssize_t ret = read(fd, cb->end, this_read_size);
        if (ret <= 0) {
            if (fixup_end) {
                cb->end = cb->buf + cb->size;
            }

            if (ret == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }

            /* We have just seen an error, but let's ignore it if we have
                 * already read some data before. */
            if (got == 0) {
                got = -1;
            }
            break;
        }

        cb->end += ret;
        count -= ret;
        got += ret;
        free_space = cyclic_buffer_free_size(cb);

        if ((size_t)ret < this_read_size) {
            /* Not enough data to fill the whole request. */
            break;
        }
    }

    return got;
}

ssize_t cyclic_buffer_write(const int fd, struct cyclic_buffer* cb, size_t count) {
    ssize_t wrote = 0;
    size_t available_data = cyclic_buffer_data_size(cb);

    while (count && available_data) {
        const size_t this_write_size = min(available_data, min(cb->buf + cb->size - cb->begin, count));
        const ssize_t ret = write(fd, cb->begin, this_write_size);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            /* We have just seen an error, but let's ignore it if we have
                 * already written some data before. */
            if (wrote == 0) {
                wrote = -1;
            }
            break;
        }

        if (ret == 0) {
            break;
        }

        cb->begin += ret;
        if (cb->begin == cb->end) {
            // buffer is empty
            cb->begin = cb->buf;
            cb->end = cb->buf;
        } else if (cb->begin == cb->buf + cb->size) {
            cb->begin = cb->buf;
        }
        count -= ret;
        wrote += ret;
        available_data = cyclic_buffer_data_size(cb);

        if ((size_t)ret < this_write_size) {
            /* Short write. */
            break;
        }
    }

    return wrote;
}
