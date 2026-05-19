#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <sys/syscall.h>

#define BPF_MAX_VAR_SIZ	(1 << 29)

#ifndef TARGET_CMD
#define TARGET_CMD "default_comm"
#endif

#define MAX_PROCESS_NAMES 10
#define PROCESS_NAME_SIZE 256
#define PATH_SIZE 256
#define MAX_STACK_DEPTH 32
#define COMM_SIZE 16   // kernel TASK_COMM_LEN

#define EVENT_SYS_ENTER   0
#define EVENT_SYS_EXIT    1
// Emitted from sched_process_exec / sched_process_fork when a tgid starts being
// tracked. Lets userspace build a tgid -> comm cache without paying for
// bpf_get_current_comm on every syscall (Fix 3).
#define EVENT_TRACK_START 2

// Note: bpf_task_pt_regs is provided as helper id 175 by bpf_helper_defs.h
// (signature `long (*)(struct task_struct *)`). Used by trace_syscall_enter
// to grab user_ip / user_sp without doing a full stack walk, which feeds
// the callsite-seen pre-filter (Fix 1b). Cast the return to pt_regs*.

// Per-event payload union. Only populated for EVENT_TRACK_START (comm) and
// EVENT_SYS_EXIT (exec_path); plain sys_enter events leave it untouched.
union event_payload {
    char comm[COMM_SIZE];
    char exec_path[PATH_SIZE];
};

// Represents a system call event with process and execution details.
//
// Shrunk by Fix 2: dropped the per-event process_name[256] field (userspace
// now caches tgid -> comm from EVENT_TRACK_START lifecycle events). Total
// goes from ~544 B to ~288 B, ~half the ringbuf reserve cost on admitted
// events.
struct event {
    u8  event_type;
    u32 pid;
    u64 syscall_id;
    u32 stack_trace_id;
    u64 kernel_ts;   // bpf_ktime_get_ns() at event creation; used to measure consumer lag
    union event_payload payload;
};

// Probe diagnostics counters.
//
// All counters here are touched ONLY on cold paths (event admission or
// failure), never per-syscall. The hot path of trace_syscall_enter does
// no probe_stats writes at all, so the BPF program adds zero diagnostic
// overhead to syscall throughput measurements.
//
// PERCPU_ARRAY anyway, so even if a counter ever moves onto the hot path
// the increments stay contention-free.
//
// Index 0: ringbuf reservation failures (consumer too slow → buffer full → event dropped).
// Index 1: bpf_get_stackid failures (stack walk failed, e.g. Go relocatable goroutine stacks).
// Index 2: enter events admitted past dedup (or execve, which bypasses dedup);
//          these are the events that attempt a ringbuf reserve.
//
// Removed previously: a per-syscall "any-PID syscall count" (was index 4) —
// added ~30 ns per syscall and falsified the very measurement it supported.
// Also removed: a "tracked-PID syscall count" (was index 2) on the hot
// path — replaced by deriving the same number from perf's clean baseline.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u64);
} probe_stats SEC(".maps");


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

// Target process tracking.
//
// A small BPF_MAP_TYPE_HASH keyed by TGID. We tried BPF_MAP_TYPE_TASK_STORAGE
// and it regressed throughput ~33% on coredns: task_storage attaches to
// task_struct, so the negative-lookup fast path (which fires for every
// untracked syscall in the system) loses the cache locality this small
// hash table enjoys. Hash wins for "filter out most syscalls" patterns.
//
// Workers and child processes are inserted at fork time by trace_fork.
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

// Key for the seen_pairs deduplication map.
// Explicit padding keeps the struct layout deterministic for bytewise map comparison.
struct seen_key {
    u64 syscall_id;
    u32 stack_trace_id;
    u32 _pad;
};

// Deduplication map for build mode: tracks (syscall_id, stack_trace_id) pairs
// that have already been emitted. Once a pair is in this map, subsequent
// identical events carry no new allowlist information and are discarded in the
// kernel before touching the ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, struct seen_key);
    __type(value, u8);
} seen_pairs SEC(".maps");

// Fix 1b: cheap callsite pre-filter. Hashes (tgid, syscall_id, user_ip,
// user_sp_hint) — all readable without walking the stack — and short-circuits
// every syscall whose callsite has already been fully processed.
// user_sp is shifted >> 16 so we differentiate goroutine stacks (different
// 64 KB regions) but stay stable across normal call-frame variation within
// the same goroutine.
struct callsite_key {
    u64 syscall_id;
    u64 user_ip;
    u64 user_sp_hint;
    u32 tgid;
    u32 _pad;
};

// Fix 7: BPF_MAP_TYPE_LRU_PERCPU_HASH instead of LRU_HASH — each CPU keeps its
// own dedup table so the hot-path lookup is uncontended. Cost: memory grows
// linearly in core count (max_entries * nr_cpus). Semantically equivalent for
// our set-based trace-store: an unlucky workload migrating across CPUs may
// admit a small number of duplicate ringbuf events for the same callsite,
// but the persisted state is identical.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct callsite_key);
    __type(value, u8);
} callsite_seen SEC(".maps");

const struct event *unused __attribute__((unused));

static char target_process_name[PROCESS_NAME_SIZE] = TARGET_CMD;