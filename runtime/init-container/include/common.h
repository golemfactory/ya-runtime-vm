#pragma once

// Set NOBLOCK flag for given descriptor
int make_nonblocking(int fd);

int create_dir_path(char* path);

#define TRY_OR_GOTO(x, label) ({                                                                \
    __typeof__(x) _x = (x);                                                                     \
    if (_x < 0) {                                                                               \
        fprintf(stderr, "Error at %s:%d returned %d, errno: %m\n", __FILE__, __LINE__, _x);     \
        goto label;                                                                             \
    }                                                                                           \
    _x;                                                                                         \
})

#define DEFAULT_DIR_PERMS (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)