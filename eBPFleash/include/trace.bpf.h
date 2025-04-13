#include "vmlinux.h"
#include "function_vals.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <sys/syscall.h>

#define BPF_MAX_VAR_SIZ	(1 << 29)

#ifndef TARGET_CMD
#define TARGET_CMD "default_comm"
#endif

#define MAX_PROCESS_NAMES 10
#define PROCESS_NAME_SIZE 100
#define PATH_SIZE 256
#define MAX_STACK_DEPTH 32

#define EVENT_SYS_ENTER 0
#define EVENT_SYS_EXIT 1

// Represents a system call event with process and execution details
struct event {
    u32 pid;
    u64 syscall_id;
    u8  process_name[PROCESS_NAME_SIZE];
    u32 stack_trace_id;
    char exec_path[PATH_SIZE];
    char exec_args[PATH_SIZE];
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
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u8);
} tracked_pids_map SEC(".maps");

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

// Map which uses instruction address as key and function parameter info as the value.
struct {
    __uint(max_entries, 42);
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, function_parameter_list_t);
} arg_map SEC(".maps");

const struct event *unused __attribute__((unused));

static char target_process_name[PROCESS_NAME_SIZE] = TARGET_CMD;