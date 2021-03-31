#ifndef _FORWARD_H
#define _FORWARD_H

#include <sys/types.h>

int fwd_start(
    int rfd,
    int wfd,
    uint16_t read_sz,
    char read_hdr,
    char write_hdr
);
void fwd_stop();

#endif // _FORWARD_H
