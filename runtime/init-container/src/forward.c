#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <threads.h>
#include <unistd.h>

#include "forward.h"

#define QUEUE_DEPTH         8

static int working = true;

struct fwd_args {
    int *fds;
    int read_sz;
};

int fwd(void *data);

int fwd_start(int rfd, int wfd, int read_sz) {
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

int fwd(void *data) {
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int rc, wc, ret = 0;
    char *buf = 0;

    struct fwd_args *args = (struct fwd_args*) data;

    if (!(buf = malloc(args->read_sz))) {
        ret = -ENOMEM;
        goto end;
    }

    struct timespec sleep_tsc = {
        .tv_sec = 0,
        .tv_nsec = 500 * 1000 * 1000
    };

    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if ((ret = io_uring_register_files(&ring, args->fds, 2)) < 0) {
        goto end;
    }

    while (working) {
        if (!(sqe = io_uring_get_sqe(&ring))) {
            ret = -1;
            goto end;
        }
        io_uring_prep_read(sqe, 0, buf, args->read_sz, 0);
        sqe->flags |= IOSQE_FIXED_FILE;

        io_uring_submit(&ring);
        if ((ret = io_uring_wait_cqe(&ring, &cqe)) < 0) {
            goto end;
        }

        rc = cqe->res;
        io_uring_cqe_seen(&ring, cqe);
        if (rc <= 0) {
            thrd_sleep(&sleep_tsc, 0);
            continue;
        }

        int ws = 0;
        while (ws < rc) {
            if (!(sqe = io_uring_get_sqe(&ring))) {
                ret = -1;
                goto end;
            }
            io_uring_prep_write(sqe, 1, buf + ws, rc - ws, 0);
            sqe->flags |= IOSQE_FIXED_FILE;

            io_uring_submit(&ring);
            if ((ret = io_uring_wait_cqe(&ring, &cqe)) < 0) {
                goto end;
            }

            wc = cqe->res;
            io_uring_cqe_seen(&ring, cqe);
            if (wc < 0) {
                ret = -2;
                goto end;
            }
            ws += wc;
        }
    }
end:
    io_uring_unregister_files(&ring);
    free(args->fds);
    free(args);
    if (buf) free(buf);
    return ret;
}
