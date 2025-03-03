// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef TARGET_CMD
#define TARGET_CMD "default_comm"
#endif

#define COMM_SIZE 100
#define MAX_STACK_DEPTH 32

char __license[] SEC("license") = "Dual MIT/GPL";

static char target_comm[COMM_SIZE] = TARGET_CMD;

struct event {
    u32 pid;
    u64 syscall;
    u8  comm[COMM_SIZE];
	u32 stack_id;

    // Binary-related fields
    char binary_path[256];
    char args[256];
    int fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stacktraces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

const struct event *unused __attribute__((unused));


static __always_inline int str_compare(const char *str1, const char *str2, int size) {
    for (int i = 0; i < size; i++) {
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
        if (str1[i] == '\0')
            return 0;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
// SEC("tracepoint/syscalls/sys_enter_*")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 *target_pid_ptr = bpf_map_lookup_elem(&target_pid_map, &pid);

	if (!target_pid_ptr) {
        char comm[COMM_SIZE];
        bpf_get_current_comm(&comm, sizeof(comm));

        // Check if the current comm matches the target comm
        if (str_compare(comm, target_comm, sizeof(target_comm)) == 0) {
			u32 value = pid;
			bpf_map_update_elem(&target_pid_map, &pid, &value, BPF_ANY);
        } else {
            return false;
        }
    } else if (pid != *target_pid_ptr) {
        return false;
	}

    struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	// Populate the event with pid, comm, and syscall
	bpf_get_current_comm(&e->comm, COMM_SIZE);
	e->pid = pid;
	e->syscall = ctx->id;
    // bpf_printk("SYSCALL %d\n", e->syscall);
    

    // Populate the event with binary info (for execve and execveat)
    if (ctx->id == 59 || ctx->id == 322) {
        
        const char *pathname = (char *)ctx->args[0];
        bpf_probe_read_user_str(e->binary_path, sizeof(e->binary_path), pathname);

        /*
        // Copy arguments TODO. The following only copy the first.
        const char **argv = (const char **)ctx->args[1];
        char *first_arg;
        bpf_probe_read_user(&first_arg, sizeof(first_arg), &argv[0]);
        bpf_probe_read_user_str(e->args, sizeof(e->args), first_arg);
        
        // For execveat, get the fd
        if (ctx->id == 322) {
            e->fd = (int)ctx->args[0];
        }
        */
    }
    
    
    // Populate the event with the stack trace
    int stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
        e->stack_id = stack_id;
    } else {
        e->stack_id = 0; // Invalid stack id
    }

	// Submit the event to the ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
