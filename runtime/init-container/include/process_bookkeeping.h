#ifndef _PROCESS_BOOKKEEPING_H
#define _PROCESS_BOOKKEEPING_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "cyclic_buffer.h"
#include "proto.h"

struct redir_fd_desc {
    enum REDIRECT_FD_TYPE type;
    union {
        /* For REDIRECT_FD_FILE */
        char* path;
        /* For REDIRECT_FD_PIPE_* */
        struct {
            struct cyclic_buffer cb;
            int fds[2];
            bool closed;
            // needed to send notification
            uint64_t process_desc_id;
        } buffer;
    };
};

struct process_desc {
    uint64_t id;
    pid_t pid;
    bool is_alive;
    int32_t ssi_status;
    int32_t ssi_code;
    struct redir_fd_desc redirs[3];
    struct process_desc* prev;
    struct process_desc* next;
};

void add_process(struct process_desc* proc_desc);
void remove_process(struct process_desc* proc_desc);
struct process_desc* find_process_by_id(uint64_t id);
struct process_desc* find_process_by_pid(pid_t pid);

#endif // _PROCESS_BOOKKEEPING_H
