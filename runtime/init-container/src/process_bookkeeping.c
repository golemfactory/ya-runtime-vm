#include <stddef.h>

#include "process_bookkeeping.h"

static struct process_desc* g_all_processes = NULL;

void add_process(struct process_desc* proc_desc) {
    proc_desc->next = g_all_processes;
    proc_desc->prev = NULL;
    if (g_all_processes) {
        g_all_processes->prev = proc_desc;
    }
    g_all_processes = proc_desc;
}

void remove_process(struct process_desc* proc_desc) {
    if (g_all_processes == proc_desc) {
        g_all_processes = proc_desc->next;
        if (g_all_processes) {
            g_all_processes->prev = NULL;
        }
    } else {
        if (proc_desc->prev) {
            proc_desc->prev->next = proc_desc->next;
        }
        if (proc_desc->next) {
            proc_desc->next->prev = proc_desc->prev;
        }
    }
}

struct process_desc* find_process_by_id(uint64_t id) {
    struct process_desc* proc_desc = g_all_processes;
    while (proc_desc) {
        if (proc_desc->id == id) {
            return proc_desc;
        }
        proc_desc = proc_desc->next;
    }
    return NULL;
}

struct process_desc* find_process_by_pid(pid_t pid) {
    struct process_desc* proc_desc = g_all_processes;
    while (proc_desc) {
        if (proc_desc->pid == pid) {
            return proc_desc;
        }
        proc_desc = proc_desc->next;
    }
    return NULL;
}
