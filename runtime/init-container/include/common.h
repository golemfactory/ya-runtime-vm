#pragma once

// Set NOBLOCK flag for given descriptor
int make_nonblocking(int fd);

int create_dir_path(char* path);

#define CHECK_NO_FATAL(x) ({                                            \
    __typeof__(x) _x = (x);                                             \
    if (_x == -1) {                                                     \
        fprintf(stderr, "Error at %s:%d: %m\n", __FILE__, __LINE__);    \
    }                                                                   \
    _x;                                                                 \
})

#define DEFAULT_DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)