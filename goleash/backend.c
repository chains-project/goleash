// +build ignore

#include "include/trace.bpf.h"
#include "include/target_names.h"
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Helper function to compare strings
static __always_inline int strcmp(const char *s1, const char *s2, int max_size) {
    for (int i = 0; i < max_size; i++) {
        if (s1[i] != s2[i]) return s1[i] - s2[i]; 
        if (s1[i] == '\0') return 0;
    }
    return 0;
}

static const char target_process_names[MAX_PROCESS_NAMES][PROCESS_NAME_SIZE] = TARGET_PROCESS_NAMES;



// DETECT NEW TARGETS via Exec.
// On a matching comm, insert the current TGID into tracked_pids_map. Then,
// if the tgid is tracked (either freshly matched or already-tracked but
// exec'ing a different binary), emit an EVENT_TRACK_START lifecycle event so
// userspace can keep its tgid -> comm cache fresh — used in place of
// per-syscall bpf_get_current_comm (Fix 3).
SEC("tracepoint/sched/sched_process_exec")
int trace_exec_event(struct trace_event_raw_sched_process_exec *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[PROCESS_NAME_SIZE];

    // The kernel has already updated the process name to the new binary.
    bpf_get_current_comm(&comm, sizeof(comm));

    // Heavy logic (loop + string compare) happens HERE, not in sys_enter.
    #pragma unroll
    for (int i = 0; i < MAX_PROCESS_NAMES; i++) {
        if (strcmp(comm, target_process_names[i], sizeof(target_process_names[i])) == 0) {
            u8 one = 1;
            bpf_map_update_elem(&tracked_pids_map, &pid, &one, BPF_ANY);
            break;
        }
    }

    // Emit lifecycle event for any currently-tracked tgid (refresh path).
    if (bpf_map_lookup_elem(&tracked_pids_map, &pid)) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (e) {
            e->event_type    = EVENT_TRACK_START;
            e->pid           = pid;
            e->syscall_id    = 0;
            e->stack_trace_id = 0;
            e->kernel_ts     = bpf_ktime_get_ns();
            __builtin_memcpy(e->payload.comm, comm, COMM_SIZE);
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

// PROPAGATE TRACKING TO NEW PROCESSES / THREADS.
//
// Kept as tp_btf (instead of the original tracepoint/sched/sched_process_fork)
// because that one exposed parent_pid/child_pid as the task's TID, not its
// TGID — so threads spawned by non-main threads of a tracked process would
// silently miss the lookup (the map is keyed by TGID). tp_btf hands us
// trusted task pointers, from which we read tgid directly.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(trace_fork, struct task_struct *parent, struct task_struct *child) {
    u32 parent_tgid = BPF_CORE_READ(parent, tgid);
    if (!bpf_map_lookup_elem(&tracked_pids_map, &parent_tgid))
        return 0;

    u32 child_tgid = BPF_CORE_READ(child, tgid);

    // Skip thread clones (CLONE_THREAD): the new thread shares its parent's
    // tgid, so tracked_pids_map already covers it and userspace's tgid -> comm
    // cache already has the right entry. Without this, every new OS thread of
    // a tracked Go process emits a redundant lifecycle event.
    if (child_tgid == parent_tgid)
        return 0;

    u8 one = 1;
    bpf_map_update_elem(&tracked_pids_map, &child_tgid, &one, BPF_ANY);

    // Lifecycle event: tell userspace the child's comm (inherited from the
    // parent at fork time) so its tgid -> comm cache stays populated for
    // fork-propagated tracked pids (Fix 3).
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->event_type    = EVENT_TRACK_START;
        e->pid           = child_tgid;
        e->syscall_id    = 0;
        e->stack_trace_id = 0;
        e->kernel_ts     = bpf_ktime_get_ns();
        BPF_CORE_READ_STR_INTO(&e->payload.comm, child, comm);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// CLEANUP on process death.
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    // Only act on main-thread exit (the process is truly dying).
    if (pid != tgid) {
        return 0;
    }

    bpf_map_delete_elem(&tracked_pids_map, &tgid);
    bpf_map_delete_elem(&temp_stack_ids, &tgid);
    bpf_map_delete_elem(&temp_exec_paths, &tgid);
    return 0;
}


// -----------------------------------------------------------------------------
// 2. INSTRUMENTATION LOGIC (High Frequency / Hot Path)
// -----------------------------------------------------------------------------

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {

    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    // Fast exit if process is not tracked. Hash lookup on a small, hot
    // table; the BPF program returns here for most syscalls system-wide.
    // No counter increments on the hot path: any "syscall count" we need
    // for benchmark normalization comes from perf's clean baseline run.
    if (!bpf_map_lookup_elem(&tracked_pids_map, &current_pid))
        return 0;

    long syscall_id = BPF_CORE_READ(ctx, id);

    // ---- Fix 1b: callsite pre-filter -----------------------------------
    // Read user RIP + RSP from pt_regs — two register reads, no stack walk.
    // If we've already done the full work for this (tgid, syscall_id,
    // user_ip, user_sp_hint) we return without bpf_get_stackid (the
    // expensive call). Skipped for exec(*) so the sys_exit handler still
    // gets its exec_path + stack_id stashed every invocation.
    if (syscall_id != SYS_execve && syscall_id != SYS_execveat) {
        struct task_struct *task = bpf_get_current_task_btf();
        struct pt_regs *uregs = (struct pt_regs *)bpf_task_pt_regs(task);
        struct callsite_key ck = {
            .syscall_id   = (u64)syscall_id,
            .user_ip      = uregs ? (u64)BPF_CORE_READ(uregs, ip) : 0,
            .user_sp_hint = uregs ? (u64)BPF_CORE_READ(uregs, sp) >> 16 : 0,
            .tgid         = current_pid,
            ._pad         = 0,
        };
        if (bpf_map_lookup_elem(&callsite_seen, &ck))
            return 0;
        u8 one = 1;
        bpf_map_update_elem(&callsite_seen, &ck, &one, BPF_ANY);
    }

    int stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);
    u32 stack_trace_id = (stack_id >= 0) ? (u32)stack_id : 0;

    // Deduplication on (syscall_id, stack_trace_id). For exec(*) this is
    // skipped because each invocation must stash exec_path + stack_id for
    // the sys_exit handler.
    //
    // We deliberately do NOT cache by (tgid, syscall_id) to skip the stack
    // walk on subsequent syscalls. Doing so would silently drop later-
    // appearing distinct stacks for an already-seen (tgid, syscall_id),
    // including stacks that resolve to different callerPackages — making
    // build-mode allowlists incomplete and enforce-mode kills spurious.
    //
    // Fix 6: lookup-then-update instead of BPF_NOEXIST update. The common
    // "already seen" case becomes a single read-only hash probe (no bucket
    // write lock). Race: two CPUs may both miss and both write the same
    // pair, yielding at-most-one duplicate ringbuf event — harmless because
    // the userspace trace-store is set-based and idempotent.
    if (syscall_id != SYS_execve && syscall_id != SYS_execveat) {
        struct seen_key sk = {};
        sk.syscall_id = (u64)syscall_id;
        sk.stack_trace_id = stack_trace_id;
        if (bpf_map_lookup_elem(&seen_pairs, &sk))
            return 0;
        u8 seen_val = 1;
        bpf_map_update_elem(&seen_pairs, &sk, &seen_val, BPF_ANY);
    }

    // Diagnostic (cold path — only fires per unique (syscall, stack)):
    // event has passed dedup (or is exec) and is about to attempt a
    // ringbuf reserve. Counts unique admitted events.
    {
        u32 k = 2;
        u64 *c = bpf_map_lookup_elem(&probe_stats, &k);
        if (c) __sync_fetch_and_add(c, 1);
    }

    // New (syscall, stack) pair — count stack failures only for unique events,
    // so the counter reflects allowlist entries with unresolved stacks, not noise.
    if (stack_id < 0) {
        u32 fail_key = 1;
        u64 *fails = bpf_map_lookup_elem(&probe_stats, &fail_key);
        if (fails) __sync_fetch_and_add(fails, 1);
    }
    
    // Clean up temp maps
    bpf_map_delete_elem(&temp_stack_ids, &tgid);
    bpf_map_delete_elem(&temp_exec_paths, &tgid);
    return 0;
}


// -----------------------------------------------------------------------------
// 2. INSTRUMENTATION LOGIC (High Frequency / Hot Path)
// -----------------------------------------------------------------------------

    // Reserve ring buffer and emit event.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        // Ring buffer is full: consumer is not draining fast enough.
        u32 drop_key = 0;
        u64 *drops = bpf_map_lookup_elem(&probe_stats, &drop_key);
        if (drops) __sync_fetch_and_add(drops, 1);
        return 0;
    }

    e->event_type = EVENT_SYS_ENTER;
    e->pid = current_pid;
    e->syscall_id = (u64)syscall_id;
    e->stack_trace_id = stack_trace_id;
    e->kernel_ts = bpf_ktime_get_ns();
    // payload left untouched: userspace resolves comm via its tgid -> comm
    // cache populated from EVENT_TRACK_START events (Fix 2/3).

    // If a tracked process calls execve, stash the path and stack ID so
    // we can retrieve them at sys_exit and record the spawned binary.
    if (syscall_id == SYS_execve || syscall_id == SYS_execveat) {
        if (stack_id >= 0)
            bpf_map_update_elem(&temp_stack_ids, &current_pid, &stack_id, BPF_ANY);

        const char *filename_ptr = NULL;
        unsigned long args[2];
        bpf_probe_read_kernel(&args, sizeof(args), &ctx->args[0]);
        filename_ptr = (syscall_id == SYS_execve) ? (const char *)args[0]
                                                   : (const char *)args[1];
        char exec_path[PATH_SIZE];
        if (bpf_probe_read_user_str(exec_path, sizeof(exec_path), filename_ptr) > 0)
            bpf_map_update_elem(&temp_exec_paths, &current_pid, exec_path, BPF_ANY);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}




SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Fast filter matching trace_syscall_enter.
    if (!bpf_map_lookup_elem(&tracked_pids_map, &pid))
        return 0;

    // We only care about exit events if they are EXECVE/EXECVEAT
    if (ctx->id != SYS_execve && ctx->id != SYS_execveat) {
        return 0;
    }

    // bpf_printk("DEBUG: Execve EXIT caught for PID %d", pid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->event_type = EVENT_SYS_EXIT;
    e->pid = pid;
    e->syscall_id = ctx->id;
    e->stack_trace_id = 0; // Default
    e->kernel_ts = bpf_ktime_get_ns();

    // Retrieve stored STACK ID
    u32 *stored_stack_id = bpf_map_lookup_elem(&temp_stack_ids, &pid);
    if (stored_stack_id) {
        e->stack_trace_id = *stored_stack_id;
        bpf_map_delete_elem(&temp_stack_ids, &pid);
    }

    // Retrieve stored EXEC PATH (goes into payload.exec_path).
    char *stored_path = bpf_map_lookup_elem(&temp_exec_paths, &pid);
    if (stored_path) {
        __builtin_memcpy(e->payload.exec_path, stored_path, PATH_SIZE);
        bpf_map_delete_elem(&temp_exec_paths, &pid);
    }

    bpf_ringbuf_submit(e, 0);        
    return 0;
}


/* example of sending a sigterm to the traced process
SEC("fentry/__x64_sys_execve")
int BPF_PROG(hook_sys_execve) {

    struct stack_trace_t {
        __u64 ip[10]; // Adjust size as needed
    } trace;
    int res = bpf_get_stack((struct pt_regs *)ctx, &trace, sizeof(trace), BPF_F_USER_STACK);
 
    bpf_send_signal(9);
    bpf_override_return((struct pt_regs *)ctx, -EPERM);
}
*/

