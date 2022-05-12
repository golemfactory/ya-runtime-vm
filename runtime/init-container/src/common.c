#include "common.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

int make_nonblocking(int fd) {
    // TODO: !!!???
    errno     = 0;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1 && errno) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

int create_dir_path(char* path) {
    assert(path[0] == '/');

    char* next = path;
    while (1) {
        next = strchr(next + 1, '/');
        if (!next) {
            break;
        }
        *next   = '\0';
        int ret = mkdir(path, DEFAULT_DIR_PERMS);
        *next   = '/';
        if (ret < 0 && errno != EEXIST) {
            return -1;
        }
    }

    if (mkdir(path, DEFAULT_DIR_PERMS) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}