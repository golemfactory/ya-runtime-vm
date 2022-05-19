#ifndef _COMMUNICATION_WIN_P9_H
#define _COMMUNICATION_WIN_P9_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>


int initialize_p9_socket_descriptors();
uint32_t do_mount_win_p9(const char* tag, uint8_t channel, uint32_t max_p9_message_size, char* path);

#define MAX_P9_VOLUMES (100)
//this variable has nothing to do with max p9 message size, it's just read buffer for demux communication
#define MAX_DEMUX_P9_MESSAGE_SIZE (0x80000) //524288
extern int g_p9_fd;
extern int g_p9_current_channel;
extern int g_p9_socket_fds[MAX_P9_VOLUMES][2];

extern pthread_t g_p9_tunnel_thread_sender[MAX_P9_VOLUMES];
extern pthread_mutex_t g_p9_tunnel_mutex_sender;
extern pthread_t g_p9_tunnel_thread_receiver;

#endif // _COMMUNICATION_WIN_P9_H