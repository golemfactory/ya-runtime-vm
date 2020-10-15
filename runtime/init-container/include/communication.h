#ifndef _COMMUNICATION_H
#define _COMMUNICATION_H

#include <stdbool.h>
#include <stdint.h>

#include "cyclic_buffer.h"

int readn(int fd, void* buf, size_t size);

int recv_u64(int fd, uint64_t* res);
int recv_u32(int fd, uint32_t* res);
int recv_u8(int fd, uint8_t* res);
int recv_bytes(int fd, char** buf_ptr, uint64_t* size_ptr,
                      bool is_cstring);

int recv_strings_array(int fd, char*** array_ptr);

void free_strings_array(char** array);

int writen(int fd, const void* buf, size_t size);

int send_bytes(int fd, const char* buf, uint64_t size);

int send_bytes_cyclic_buffer(int fd, struct cyclic_buffer* cb, uint64_t size);

#endif // _COMMUNICATION_H
