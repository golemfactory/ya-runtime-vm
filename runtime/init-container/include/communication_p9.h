#ifndef _COMMUNICATION_WIN_P9_H
#define _COMMUNICATION_WIN_P9_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>


int initialize_p9_communication();
uint32_t do_mount_p9(const char* tag, uint32_t max_p9_message_size, char* path);

extern int g_p9_fd;
#endif // _COMMUNICATION_WIN_P9_H