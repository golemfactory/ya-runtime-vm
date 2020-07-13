#include <errno.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cyclic_buffer.h"

int cyclic_buffer_init(struct cyclic_buffer* cb, size_t size) {
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
    int ret = munmap(cb->buf, cb->size);
    cb->buf = MAP_FAILED;
    return ret;
}

size_t cyclic_buffer_data_size(struct cyclic_buffer* cb) {
    char* data_begin = cb->begin;
    char* data_end = cb->end;

    if (data_begin < data_end) {
        return data_end - data_begin;
    } else if (data_begin > data_end) {
        return cb->size - (data_begin - data_end);
    } else { // data_begin == data_end
        if (data_begin == cb->buf) {
            /* Buffer is completely empty. */
            return 0;
        } else {
            /* Buffer is completely full. */
            return cb->size;
        }
    }
}

size_t cyclic_buffer_free_size(struct cyclic_buffer* cb) {
    return cb->size - cyclic_buffer_data_size(cb);
}

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

ssize_t cyclic_buffer_read(int fd, struct cyclic_buffer* cb, size_t count) {
    ssize_t got = 0;
    size_t orig_cb_size = cyclic_buffer_data_size(cb);

    while (count) {
        bool fixup_end = false;
        if (cb->end == cb->buf + cb->size) {
            cb->end = cb->buf;
            fixup_end = true;
        }

        size_t this_read_size = min(cb->buf + cb->size - cb->end, count);
        ssize_t ret = read(fd, cb->end, this_read_size);
        if (ret <= 0) {
            if (fixup_end) {
                cb->end = cb->buf + cb->size;
            }

            if (ret == 0) {
                break;
            } else if (errno == EINTR) {
                continue;
            } else {
                /* We have just seen an error, but let's ignore it if we have
                 * already read some data before. */
                if (got == 0) {
                    got = -1;
                }
                break;
            }
        }

        cb->end += ret;
        count -= ret;
        got += ret;

        if ((size_t)ret < this_read_size) {
            /* Not enough data to fill the whole request. */
            break;
        }
    }

    if (got > 0) {
        size_t x = orig_cb_size + got;
        if (x > cb->size) {
            x = cb->size;
        }

        if (cb->buf + x <= cb->end) {
            cb->begin = cb->end - x;
        } else {
            cb->begin = cb->end + (cb->size - x);
        }
    }

    return got;
}

ssize_t cyclic_buffer_write(int fd, struct cyclic_buffer* cb, size_t count) {
    ssize_t wrote = 0;
    size_t orig_cb_size = cyclic_buffer_data_size(cb);

    count = min(count, orig_cb_size);

    while (count) {
        size_t this_write_size = min(cb->buf + cb->size - cb->begin, count);
        ssize_t ret = write(fd, cb->begin, this_write_size);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                /* We have just seen an error, but let's ignore it if we have
                 * already written some data before. */
                if (wrote == 0) {
                    wrote = -1;
                }
                break;
            }
        } else if (ret == 0) {
            break;
        }

        cb->begin += ret;
        if (cb->begin == cb->buf + cb->size) {
            cb->begin = cb->buf;
        }
        count -= ret;
        wrote += ret;

        if ((size_t)ret < this_write_size) {
            /* Short write. */
            break;
        }
    }

    if (wrote >= 0 && (size_t)wrote == orig_cb_size) {
        /* The buffer is empty. */
        cb->begin = cb->buf;
        cb->end = cb->buf;
    }

    return wrote;
}
