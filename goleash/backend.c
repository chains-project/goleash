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



// DETECT NEW TARGETS via Exec
SEC("tracepoint/sched/sched_process_exec")
int trace_exec_event(struct trace_event_raw_sched_process_exec *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[PROCESS_NAME_SIZE];

    // The kernel has already updated the process name to the new binary
    bpf_get_current_comm(&comm, sizeof(comm));

    // Heavy logic (Loop + String Compare) happens HERE, not in sys_enter
    #pragma unroll
    for (int i = 0; i < MAX_PROCESS_NAMES; i++) {
        if (strcmp(comm, target_process_names[i], sizeof(target_process_names[i])) == 0) {
            u32 dummy = 1;
            bpf_map_update_elem(&tracked_pids_map, &pid, &dummy, BPF_ANY);
            // bpf_printk("Tracking new process: %s (PID: %d)", comm, pid);
            return 0;
        }
    }
    return 0;
}

// DETECT WORKERS via Fork
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;

    char comm[PROCESS_NAME_SIZE];
    bpf_get_current_comm(&comm, sizeof(comm));

    // If parent is tracked, child is automatically tracked
    if (bpf_map_lookup_elem(&tracked_pids_map, &parent_pid)) {
        u32 dummy = 1;
        bpf_map_update_elem(&tracked_pids_map, &child_pid, &dummy, BPF_ANY);
        // bpf_printk("Fork Intercepted from the process %s. Parent was: %d, Child is: %d", comm, parent_pid, child_pid);
    }
    return 0;
}

// CLEANUP
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32; // This is the Main Process ID (PID in user view)
    u32 pid = id;        // This is the Thread ID (TID)

    // In Linux, threads are just processes that share memory. 
    // When a Go goroutine finishes, it triggers this probe.
    // If pid != tgid, it is just a worker thread exiting. 
    // We MUST NOT delete the map yet, or we lose track of the main app.
    if (pid != tgid) {
        return 0;
    }

    // If we are here, the Main Process is truly dying.
    if (bpf_map_lookup_elem(&tracked_pids_map, &tgid)) {
        // bpf_printk("CLEANUP: Main Process %d exited, stop tracking.", tgid);
        bpf_map_delete_elem(&tracked_pids_map, &tgid);
    }
    
    // Clean up temp maps
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

    // If not in map, return immediately.
    u32 *is_tracked = bpf_map_lookup_elem(&tracked_pids_map, &current_pid);
    if (!is_tracked) {
        return 0; 
    }
    
    // If we are here, we are definitely tracking this process.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;
    
    e->event_type = EVENT_SYS_ENTER;
    e->pid = current_pid;
    e->syscall_id = BPF_CORE_READ(ctx, id);
    bpf_get_current_comm(&e->process_name, PROCESS_NAME_SIZE);

    // Get stack trace
    int stack_id = bpf_get_stackid(ctx, &stacktraces, BPF_F_USER_STACK);
    e->stack_trace_id = (stack_id >= 0) ? stack_id : 0;


    // If a tracked process calls execve, we stash the path/stack
    // so we can retrieve it at sys_exit.
    long syscall_id = e->syscall_id; //
    if (syscall_id == SYS_execve || syscall_id == SYS_execveat) {
        
        // bpf_printk("DEBUG: Execve/at ENTER caught for PID %d", current_pid);

        // Stash Stack ID
        if (stack_id >= 0) {
            bpf_map_update_elem(&temp_stack_ids, &current_pid, &stack_id, BPF_ANY);
        }

        // Stash Exec Path (Argument 0 or 1)
        const char *filename_ptr = NULL;
        unsigned long args[2];
        
        bpf_probe_read_kernel(&args, sizeof(args), &ctx->args[0]);

        if (syscall_id == SYS_execve) {
            filename_ptr = (const char *)args[0];
        } else {
            filename_ptr = (const char *)args[1];
        }

        
        char exec_path[PATH_SIZE];
        long ret = bpf_probe_read_user_str(exec_path, sizeof(exec_path), filename_ptr);
        if (ret > 0) {
            // bpf_printk("DEBUG: Stashing path: %s for PID %d", exec_path, current_pid);
            bpf_map_update_elem(&temp_exec_paths, &current_pid, exec_path, BPF_ANY);
        } 
    }
      
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}




SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Fast check
    u32 *is_tracked = bpf_map_lookup_elem(&tracked_pids_map, &pid);
    if (!is_tracked) {
        return 0;
    }

    // We only care about exit events if they are EXECVE/EXECVEAT
    if (ctx->id != SYS_execve && ctx->id != SYS_execveat) {
        return 0;
    }

    // bpf_printk("DEBUG: Execve EXIT caught for PID %d", pid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->event_type = EVENT_SYS_EXIT;
    bpf_get_current_comm(&e->process_name, PROCESS_NAME_SIZE);
    e->pid = pid;
    e->syscall_id = ctx->id;
    e->stack_trace_id = 0; // Default

    // Retrieve stored STACK ID
    u32 *stored_stack_id = bpf_map_lookup_elem(&temp_stack_ids, &pid);
    if (stored_stack_id) {
        e->stack_trace_id = *stored_stack_id;
        bpf_map_delete_elem(&temp_stack_ids, &pid);
    }

    // Retrieve stored EXEC PATH
    char *stored_path = bpf_map_lookup_elem(&temp_exec_paths, &pid);
    if (stored_path) {
        __builtin_memcpy(e->exec_path, stored_path, PATH_SIZE);
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

