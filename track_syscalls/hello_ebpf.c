// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_SIZE 100
#define MAX_STACK_DEPTH 20


char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u64 syscall;
    u8  comm[TASK_COMM_SIZE];
	u32 stack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1000);
} stacktraces SEC(".maps");

const struct event *unused __attribute__((unused));


const volatile int pid_target = 5329;

static inline int str_compare(const char *str1, const char *str2, int size) {
    for (int i = 0; i < size; i++) {
        if (str1[i] != str2[i])
            return str1[i] - str2[i];
        if (str1[i] == '\0')
            return 0;
    }
    return 0;
}



SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {

	// Get the command of the current process
	// and check if it matches the target
	char comm[TASK_COMM_SIZE];
    bpf_get_current_comm(&comm, sizeof(comm));
	if (str_compare(comm, "coredns", TASK_COMM_SIZE) != 0)
		return false;


	// Get the current process ID and check 
	// if it matches the target
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
	
	// bpf_printk("Process ID: %d enter sys openat\n", pid);
	//if (pid_target != pid)
	//   return false;

	
	if (ctx->id != 39) 
		return false;
	

	// Allocate space in the ring buffer for the event
    struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	// Populate the event structure with pid, syscall number, 
	// command and stack trace
	e->pid = pid;
	e->syscall = ctx->id;
	bpf_get_current_comm(&e->comm, TASK_COMM_SIZE);
    e->stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);

	// Submit the event to the ring buffer
	bpf_ringbuf_submit(e, 0);

	return 0;
}
