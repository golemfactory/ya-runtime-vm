#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cyclic_buffer.h"

#define BUF_SIZE 0x1000

struct test_setup {
    struct cyclic_buffer cb;
    int p_in[2];
    int p_out[2];
    char buf_in[BUF_SIZE];
    char buf_out[BUF_SIZE];
} test_setup;

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

static void assert_size_equal(ssize_t expected, ssize_t actual, char* msg) {
    if (expected != actual) {
        errx(2, "%s size did not match. expected: %zu, actual: %zu", msg, expected, actual);
    }
}

static void assert_buffers_match(struct test_setup* setup) {
    if (memcmp(setup->buf_in, setup->buf_out, BUF_SIZE) != 0) {
        err(3, "Output data does not match input buffer data");
    }
}

static void check_cb_invariants(struct test_setup* setup, size_t expected_data_size) {
    struct cyclic_buffer* cb = &setup->cb;
    assert_size_equal(expected_data_size, cyclic_buffer_data_size(cb), "Data");

    size_t expected_free_space = BUF_SIZE - expected_data_size;
    assert_size_equal(expected_free_space, cyclic_buffer_free_size(cb), "Free space");
}

static ssize_t read_into_cb(int pipe, struct cyclic_buffer* cb, size_t size) {
    size_t free_space = cyclic_buffer_free_size(cb);
    size_t expected_read = min(free_space, size);
    char* begin = cb->begin;
    int ret = cyclic_buffer_read(pipe, cb, size);
    if (ret < 0) {
        errx(4, "'cyclic_buffer_read' failed with error code: %zd", ret);
    }

    assert_size_equal(expected_read, ret, "'cyclic_buffer_read' read");

    if (begin != cb->begin) {
        err(5, "Start of available data pointer moved while reading into buffer.");
    }

    return ret;
}

static ssize_t pipe_to_cb(struct test_setup* setup, size_t size) {
    int ret = write(setup->p_in[1], setup->buf_in, size);
    if (ret < 0) {
        errx(6, "Write to pipe failed with error code: %zd", ret);
    }

    assert_size_equal(size, ret, "Pipe write");

    size_t read_size = read_into_cb(setup->p_in[0], &setup->cb, size);

    return read_size;
}

static ssize_t write_from_cb(int pipe, struct cyclic_buffer* cb, size_t size) {
    size_t available_data = cyclic_buffer_data_size(cb);
    size_t expected_write = min(available_data, size);
    char* end = cb->end;
    int ret = cyclic_buffer_write(pipe, cb, size);
    if (ret < 0) {
        errx(8, "'cyclic_buffer_write' failed with error code: %zd", ret);
    }

    assert_size_equal(expected_write, ret, "'cyclic_buffer_write' write");

    if (end != cb->end && (cb->begin != cb->end || cb->begin != cb->buf)) {
        err(9, "End of available data pointer moved while writing from buffer.");
    }

    return ret;
}

static ssize_t pipe_from_cb(struct test_setup* setup, size_t size) {
    ssize_t write_size = write_from_cb(setup->p_out[1], &setup->cb, size);
    if (write_size > 0) {
        ssize_t ret = read(setup->p_out[0], setup->buf_out, write_size);
        if (ret < 0) {
            errx(10, "Read from pipe failed with error code: %zd", ret);
        }

        assert_size_equal(write_size, ret, "Pipe read");
    }

    return write_size;
}

static void close_pipe(int p[2]) {
    close(p[1]);
    close(p[0]);
}

static void run_test(char* test_name, void (*test_block)(struct test_setup*)) {
    printf("Running test: %s ", test_name);
    struct test_setup setup;
    if (cyclic_buffer_init(&setup.cb, BUF_SIZE) < 0) {
        err(42, "'cyclic_buffer_init' failed");
    }
    if (pipe(setup.p_in) < 0) {
        err(42, "pipe in");
    }
    if (pipe(setup.p_out) < 0) {
        err(42, "pipe out");
    }
    memset(setup.buf_in, 0, BUF_SIZE);
    memset(setup.buf_out, 0, BUF_SIZE);
    (*test_block)(&setup);
    close_pipe(setup.p_in);
    close_pipe(setup.p_out);
    if (cyclic_buffer_deinit(&setup.cb) != 0) {
        err(42, "'cyclic_buffer_deinit' failed");
    }
    printf("... PASSED\n");
}

void test_empty_buffer(struct test_setup* setup) {
    check_cb_invariants(setup, 0);
    assert_size_equal(0, pipe_from_cb(setup, BUF_SIZE), "Read");
    check_cb_invariants(setup, 0);
}

void test_full_buffer(struct test_setup* setup) {
    memset(setup->buf_in, 'a', BUF_SIZE);
    assert_size_equal(BUF_SIZE, pipe_to_cb(setup, BUF_SIZE), "Write");
    check_cb_invariants(setup, BUF_SIZE);

    assert_size_equal(0, pipe_to_cb(setup, BUF_SIZE), "Write");
    check_cb_invariants(setup, BUF_SIZE);
}

void test_more_data_in_pipe_than_capacity(struct test_setup* setup) {
    memset(setup->buf_in, 'a', BUF_SIZE);
    assert_size_equal(BUF_SIZE, pipe_to_cb(setup, BUF_SIZE), "Write");
    assert_size_equal(0, pipe_to_cb(setup, BUF_SIZE), "Write");
    check_cb_invariants(setup, BUF_SIZE);

    assert_size_equal(42, pipe_from_cb(setup, 42), "Read");
    check_cb_invariants(setup, BUF_SIZE - 42);
    memset(setup->buf_in, 0, BUF_SIZE);
    memset(setup->buf_in, 'a', 42);
    assert_buffers_match(setup);

    assert_size_equal(42, read_into_cb(setup->p_in[0], &setup->cb, BUF_SIZE), "Read remaining from pipe");
    check_cb_invariants(setup, BUF_SIZE);
    assert_size_equal(BUF_SIZE, pipe_from_cb(setup, BUF_SIZE), "Read");
    check_cb_invariants(setup, 0);
    memset(setup->buf_in, 'a', BUF_SIZE);
    assert_buffers_match(setup);

    memset(setup->buf_out, 0, BUF_SIZE);
    assert_size_equal(BUF_SIZE - 42, read_into_cb(setup->p_in[0], &setup->cb, BUF_SIZE - 42), "Read remaining from pipe");
    check_cb_invariants(setup, BUF_SIZE - 42);
    assert_size_equal(BUF_SIZE - 42, pipe_from_cb(setup, BUF_SIZE - 42), "Read");
    memset(setup->buf_in, 0, BUF_SIZE);
    memset(setup->buf_in, 'a', BUF_SIZE - 42);
    assert_buffers_match(setup);
}

void test_buffer_with_some_data(struct test_setup* setup) {
    memset(setup->buf_in, 'a', 7);
    assert_size_equal(7, pipe_to_cb(setup, 7), "Write");
    check_cb_invariants(setup, 7);
    assert_size_equal(7, pipe_from_cb(setup, BUF_SIZE), "Read");
    check_cb_invariants(setup, 0);
    assert_size_equal(0, pipe_from_cb(setup, BUF_SIZE), "Read");
    check_cb_invariants(setup, 0);
    assert_buffers_match(setup);
}

void test_buffer_never_empty(struct test_setup* setup) {
    memset(setup->buf_in, 'a', BUF_SIZE);
    assert_size_equal(BUF_SIZE, pipe_to_cb(setup, BUF_SIZE), "Write");
    check_cb_invariants(setup, BUF_SIZE);
    assert_size_equal(BUF_SIZE / 2 - 42, pipe_from_cb(setup, BUF_SIZE / 2 - 42), "Read");
    check_cb_invariants(setup, BUF_SIZE / 2 + 42);
    memset(setup->buf_in, 0, BUF_SIZE);
    memset(setup->buf_in, 'a', BUF_SIZE / 2 - 42);
    assert_buffers_match(setup);
    assert_size_equal(BUF_SIZE / 2, pipe_from_cb(setup, BUF_SIZE / 2), "Read");
    check_cb_invariants(setup, 42);
    memset(setup->buf_in, 'a', BUF_SIZE / 2);
    assert_buffers_match(setup);
    // run for 24 rounds, this should force crossing the boundary at different points in the data
    int batch_size = BUF_SIZE - BUF_SIZE / 24;
    for(int i = 1; i < 25; i++) {
        memset(setup->buf_in, 'a' + i, batch_size);
        assert_size_equal(batch_size, pipe_to_cb(setup, batch_size), "Batch write");
        check_cb_invariants(setup, batch_size + 42);
        assert_size_equal(batch_size, pipe_from_cb(setup, batch_size), "Batch read");
        check_cb_invariants(setup, 42);
        memset(setup->buf_in, 'a' + i - 1, 42); // the first 42 characters are from the previous batch
        assert_buffers_match(setup);
    }
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    run_test("emtpy buffer", test_empty_buffer);
    run_test("full buffer", test_full_buffer);
    run_test("buffer with some data", test_buffer_with_some_data);
    run_test("buffer never empty, pointer going around the boundary", test_buffer_never_empty);
    run_test("more data in pipe than capacity", test_more_data_in_pipe_than_capacity);

    puts("Test OK");
    return 0;
}
