#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cyclic_buffer.h"

static void pipe_to_cb(int p[2], struct cyclic_buffer* cb, char* buf, size_t size) {
    ssize_t ret = write(p[1], buf, size);
    if (ret < 0) {
        err(1, "write");
    } else if ((size_t)ret != size) {
        errx(1, "write returned: %zd", ret);
    }

    ret = cyclic_buffer_read(p[0], cb, size);
    if (ret < 0) {
        err(1, "cyclic_buffer_read");
    } else if ((size_t)ret != size) {
        errx(1, "cyclic_buffer_read returned: %zd", ret);
    }
}

static void pipe_from_cb(int p[2], struct cyclic_buffer* cb, char* buf, size_t size) {
    ssize_t ret = cyclic_buffer_write(p[1], cb, size);
    if (ret < 0) {
        err(1, "cyclic_buffer_write");
    } else if ((size_t)ret != size) {
        errx(1, "cyclic_buffer_write returned: %zd", ret);
    }

    ret = read(p[0], buf, size);
    if (ret < 0) {
        err(1, "read");
    } else if ((size_t)ret != size) {
        errx(1, "read returned: %zd", ret);
    }
}

#define BUF_SIZE 0x1000

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    struct cyclic_buffer cb;
    if (cyclic_buffer_init(&cb, BUF_SIZE) < 0) {
        err(1, "cyclic_buffer_init");
    }

    size_t size = cyclic_buffer_data_size(&cb);
    if (size != 0) {
        errx(1, "wrong data size of empty buffer: %zu", size);
    }

    size = cyclic_buffer_free_size(&cb);
    if (size != BUF_SIZE) {
        errx(1, "wrong free size of empty buffer: %zu", size);
    }

    int p_in[2];
    if (pipe(p_in) < 0) {
        err(1, "pipe");
    }
    int p_out[2];
    if (pipe(p_out) < 0) {
        err(1, "pipe");
    }

    char buf[BUF_SIZE] = { 0 };
    char buf_out[BUF_SIZE] = { 0 };

    memset(buf, 'a', 7);
    pipe_to_cb(p_in, &cb, buf, 7);
    size = cyclic_buffer_data_size(&cb);
    if (size != 7) {
        errx(1, "wrong data size of buffer ('a'): %zu", size);
    }

    memset(buf, 'b', BUF_SIZE - 7);
    pipe_to_cb(p_in, &cb, buf, BUF_SIZE - 7);
    size = cyclic_buffer_data_size(&cb);
    if (size != BUF_SIZE) {
        errx(1, "wrong data size of buffer ('b'): %zu", size);
    }

    pipe_from_cb(p_out, &cb, buf_out, BUF_SIZE);

    memset(buf, 'a', 7);
    memset(buf + 7, 'b', BUF_SIZE - 7);

    if (memcmp(buf, buf_out, BUF_SIZE) != 0) {
        errx(1, "got wrong data from cyclic buffer");
    }

    memset(buf, 'c', BUF_SIZE/2);
    pipe_to_cb(p_in, &cb, buf, BUF_SIZE/2);
    size = cyclic_buffer_data_size(&cb);
    if (size != BUF_SIZE/2) {
        errx(1, "wrong data size of buffer ('c'): %zu", size);
    }

    memset(buf, 'd', BUF_SIZE);
    pipe_to_cb(p_in, &cb, buf, BUF_SIZE);
    size = cyclic_buffer_data_size(&cb);
    if (size != BUF_SIZE) {
        errx(1, "wrong data size of buffer ('d'): %zu", size);
    }

    memset(buf_out, '\0', BUF_SIZE);
    memset(buf, 'd', BUF_SIZE);

    pipe_from_cb(p_out, &cb, buf_out, BUF_SIZE);

    if (memcmp(buf, buf_out, BUF_SIZE) != 0) {
        errx(1, "got wrong data from cyclic buffer");
    }

    if (cyclic_buffer_deinit(&cb) != 0) {
        err(1, "cyclic_buffer_deinit failed");
    }

    puts("Test OK");
    return 0;
}
