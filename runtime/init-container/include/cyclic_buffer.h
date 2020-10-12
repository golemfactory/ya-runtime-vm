#ifndef _CYCLIC_BUFFER_H
#define _CYCLIC_BUFFER_H

/*
 * Struct describing a cyclic buffer.
 * `buf` - pointer to the beginning of the buffer,
 * `size` - size of the buffer,
 * `begin` - pointer to the beginning of the currently stored data,
 *           must be in `[buf, buf+size)`,
 * `end` - pointer to the end of the currently stored data,
 *         must be in `[buf, buf+size)`,
 * If `begin == end` then either:
 * - `begin == buf` - buffer is empty,
 * - `begin != buf` - buffer is full.
 * If the buffer is full and `begin == buf`, then `end == buf + size`.
 */
struct cyclic_buffer {
    char* buf;
    size_t size;
    char* begin;
    char* end;
};

/*
 * Initializes the buffer.
 * Returns 0 on success and -1 on error (error code in `errno`).
 */
int cyclic_buffer_init(struct cyclic_buffer* cb, size_t size);
/*
 * Destroys the buffer, freeing all internal resources.
 * Returns 0 on success and -1 on error (error code in `errno`).
 * Errors are most likely unrecoverable (e.g. `munmap` failed).
 */
int cyclic_buffer_deinit(struct cyclic_buffer* cb);

/* Returns the size of data in the buffer. */
size_t cyclic_buffer_data_size(struct cyclic_buffer* cb);
/* Returns the size of the free space in the buffer. */
size_t cyclic_buffer_free_size(struct cyclic_buffer* cb);

/*
 * Reads at most `count` bytes from `fd` into the buffer.
 * This functions has exactly same sematics as `read`, except that it handles
 * `EINTR` internally.
 * Note that `count` could be greater than the buffer capacity, in which case
 * least recently read data will be overwritten (if there is enought data to be
 * read).
 * If this `fd` is in blocking mode this might block, even if there is some
 * (but less than `count`) data available, thus non-blocking mode is prefered.
 */
ssize_t cyclic_buffer_read(int fd, struct cyclic_buffer* cb, size_t count);

/*
 * Writes at most `count` bytes from buffer into `fd`.
 * This functions has exactly same sematics as `write`, except that it handles
 * `EINTR` internally.
 * Might write less data than requests if there is not enought data in buffer
 * or due to normal short write.
 * If this `fd` is in blocking mode this might block, even if some bytes (but
 * less than `count`) were already written, thus non-blocking mode is prefered.
 */
ssize_t cyclic_buffer_write(int fd, struct cyclic_buffer* cb, size_t count);

#endif // _CYCLIC_BUFFER_H
