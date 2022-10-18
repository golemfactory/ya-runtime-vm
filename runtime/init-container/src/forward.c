#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <threads.h>
#include <unistd.h>

typedef struct cpu_set_t { unsigned long __bits[128/sizeof(long)]; } cpu_set_t;

#include <liburing.h>

#include "forward.h"

#define QUEUE_DEPTH         8

static int working = true;
struct timespec sleep_tsc = {
    .tv_sec = 0,
    .tv_nsec = 500 * 1000 * 1000
};

struct fwd_args {
    int *fds;
    uint16_t read_sz;
    bool read_hdr;
    bool write_hdr;
};

union b_u16 {
    uint16_t i;
    char b[2];
};

int fwd(void *data);

int fwd_start(
    int rfd,
    int wfd,
    uint16_t read_sz,
    char read_hdr,
    char write_hdr
) {
    thrd_t th;
    int ret, *fds = 0;
    struct fwd_args *args = 0;

    if (!(fds = malloc(2 * sizeof(int)))) {
        ret = -ENOMEM;
        goto err;
    }
    if (!(args = malloc(sizeof(struct fwd_args)))) {
        ret = -ENOMEM;
        goto err;
    }

    fds[0] = rfd;
    fds[1] = wfd;
    args->fds = fds;
    args->read_sz = read_sz;
    args->read_hdr = read_hdr;
    args->write_hdr = write_hdr;

    if ((ret = thrd_create(&th, fwd, (void*) args)) != thrd_success) {
        goto err;
    }
    return thrd_detach(th);

err:
    if (fds) free(fds);
    if (args) free(args);
    return ret;
}

void fwd_stop() {
    working = false;
}

int read_fd(
    struct io_uring *ring,
    int fd,
    char *dst,
    uint16_t count,
    char exact
) {
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    int ret = 0;
    uint16_t rc = 0;
    uint16_t ro = 0;

    while (working && ro < count) {
        if (!(sqe = io_uring_get_sqe(ring))) {
            return -1;
        }

        io_uring_prep_read(sqe, fd, dst + ro, count - ro, 0);
        sqe->flags |= IOSQE_FIXED_FILE;

        io_uring_submit(ring);
        if ((ret = io_uring_wait_cqe(ring, &cqe)) < 0) {
            return ret;
        }

        rc = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (rc <= 0) {
            thrd_sleep(&sleep_tsc, 0);
            continue;
        }
        ro += rc;

        if (!exact) {
            break;
        }
    }

    return ro;
}

int write_fd(
    struct io_uring *ring,
    int fd,
    char *src,
    uint16_t count
) {
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    int ret = 0;
    int wc = 0;
    size_t wo = 0;

    while (working && wo < count) {
        if (!(sqe = io_uring_get_sqe(ring))) {
            return -1;
        }

        io_uring_prep_write(sqe, fd, src + wo, count - wo, 0);
        sqe->flags |= IOSQE_FIXED_FILE;

        io_uring_submit(ring);
        if ((ret = io_uring_wait_cqe(ring, &cqe)) < 0) {
            return ret;
        }

        wc = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (wc < 0) {
            return -2;
        }
        wo += wc;
    }

    return 0;
}


int fwd(void *data) {
    struct io_uring ring;
    struct fwd_args *args = (struct fwd_args*) data;

    union b_u16 sz;
    int  ret = 0, rfd = 0, wfd = 1;
    char exact = 0;
    char *buf = 0;

    if (!(buf = malloc(args->read_sz))) {
        ret = -ENOMEM;
        goto end;
    }

    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if ((ret = io_uring_register_files(&ring, args->fds, 2)) < 0) {
        goto end;
    }

    while (working) {
        if (args->read_hdr) {
            exact = 1;
            if ((ret = read_fd(&ring, rfd, buf, 2, exact)) < 0) {
                goto end;
            }
            sz.b[0] = buf[0];
            sz.b[1] = buf[1];
        } else {
            exact = 0;
            sz.i = args->read_sz;
        }
        if ((ret = read_fd(&ring, rfd, buf, sz.i, exact)) < 0) {
            goto end;
        }

        sz.i = ret;

        if (args->write_hdr) {
            if ((ret = write_fd(&ring, wfd, sz.b, 2)) < 0) {
                goto end;
            }
        }
        if ((ret = write_fd(&ring, wfd, buf, sz.i)) < 0) {
            goto end;
        }
    }

end:
    io_uring_unregister_files(&ring);
    free(args->fds);
    free(args);
    if (buf) free(buf);
    return ret;
}
