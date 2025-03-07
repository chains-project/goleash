// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>


#ifndef TARGET_CMD
#define TARGET_CMD "default_comm"
#endif

#define PROCESS_NAME_SIZE 100
#define PATH_SIZE 256
#define MAX_STACK_DEPTH 32

#define EVENT_SYS_ENTER 0
#define EVENT_SYS_EXIT 1

char __license[] SEC("license") = "Dual MIT/GPL";

static char target_process_name[PROCESS_NAME_SIZE] = TARGET_CMD;

// Represents a system call event with process and execution details
struct event {
    u32 pid;
    u64 syscall_id;
    u8  process_name[PROCESS_NAME_SIZE];
    u32 stack_trace_id;
    char exec_path[PATH_SIZE];
    char exec_args[PATH_SIZE];
    int exec_fd;      
    u8 event_type;
};

// Ring buffer for event transmission
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Stack trace storage
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stacktraces SEC(".maps");

// Target process tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, char[PATH_SIZE]);
} temp_exec_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} temp_stack_ids SEC(".maps");

const struct event *unused __attribute__((unused));

// Helper function to compare strings
static __always_inline int strcmp(const char *s1, const char *s2, int max_size) {
    for (int i = 0; i < max_size; i++) {
        if (s1[i] != s2[i]) return 0;
        if (s1[i] == '\0') return 1;
    }
    return 1;
}

SEC("tracepoint/raw_syscalls/sys_enter")
// SEC("tracepoint/syscalls/sys_enter_*")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
    
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 *tracked_pid = bpf_map_lookup_elem(&target_process_map, &pid);

	if (!tracked_pid) {
        char current_process[PROCESS_NAME_SIZE];
        bpf_get_current_comm(&current_process, sizeof(current_process));

        // Check if the current comm matches the target comm
        if (strcmp(current_process, target_process_name, sizeof(target_process_name))) {
            u32 value = pid;
			bpf_map_update_elem(&target_process_map, &pid, &value, BPF_ANY);
        } else {
            return 0;
        }
    } else if (pid != *tracked_pid) {
        return 0;
	}

    // Event creation and population
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) return 0;
	
    e->event_type = EVENT_SYS_ENTER;
	bpf_get_current_comm(&e->process_name, PROCESS_NAME_SIZE);
	e->pid = pid;
	e->syscall_id = ctx->id;
    int stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);
    e->stack_trace_id = (stack_id >= 0) ? stack_id : 0;

    // Store exec path for execve and execveat syscalls
    if (ctx->id == 59 || ctx->id == 322) {

        int stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);
        if (stack_id >= 0) {
            bpf_map_update_elem(&temp_stack_ids, &pid, &stack_id, BPF_ANY);
        }

        const char *path = (char *)ctx->args[0];
        char exec_path[PATH_SIZE];
        bpf_probe_read_user_str(exec_path, sizeof(exec_path), path);
        bpf_map_update_elem(&temp_exec_paths, &pid, &exec_path, BPF_ANY);
    }

	bpf_ringbuf_submit(e, 0);
	return 0;
}


SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
   
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *tracked_pid = bpf_map_lookup_elem(&target_process_map, &pid);

    if (!tracked_pid || pid != *tracked_pid) {
        return 0;
    }

    if (ctx->id != 59 && ctx->id != 322) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->event_type = EVENT_SYS_EXIT;
    bpf_get_current_comm(&e->process_name, PROCESS_NAME_SIZE);
    e->pid = pid;
    e->syscall_id = ctx->id;

    // Retrieve stored exec_path and stack_id for execve syscalls
    u32 *stored_stack_id = bpf_map_lookup_elem(&temp_stack_ids, &pid);
    if (stored_stack_id) {
        e->stack_trace_id = *stored_stack_id;
        bpf_map_delete_elem(&temp_stack_ids, &pid);
    }

    char *stored_path = bpf_map_lookup_elem(&temp_exec_paths, &pid);
    if (stored_path) {
        __builtin_memcpy(e->exec_path, stored_path, PATH_SIZE);
        bpf_map_delete_elem(&temp_exec_paths, &pid);
    }

    bpf_ringbuf_submit(e, 0);
        
    return 0;
    
}



