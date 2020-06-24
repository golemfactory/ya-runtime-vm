#ifndef _PROCESS_BOOKKEEPING_H
#define _PROCESS_BOOKKEEPING_H

#include <stdint.h>
#include <sys/types.h>

struct process_desc {
    uint64_t id;
    pid_t pid;
    struct process_desc* prev;
    struct process_desc* next;
};

void add_process(struct process_desc* proc_desc);
void remove_process(struct process_desc* proc_desc);
struct process_desc* find_process_by_id(uint64_t id);
struct process_desc* find_process_by_pid(pid_t pid);

#endif // _PROCESS_BOOKKEEPING_H
