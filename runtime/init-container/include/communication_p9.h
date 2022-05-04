#ifndef _COMMUNICATION_WIN_P9_H
#define _COMMUNICATION_WIN_P9_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>


int initialize_p9_socket_descriptors();
uint32_t do_mount_p9(const char* tag, char* path);

extern int g_p9_fd;
#endif // _COMMUNICATION_WIN_P9_H