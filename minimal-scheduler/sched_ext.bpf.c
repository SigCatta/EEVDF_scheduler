#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define a shared Dispatch Queue (DSQ) ID
#define SHARED_DSQ_ID 0

#define BPF_STRUCT_OPS(name, args...)	\
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)	\
    SEC("struct_ops.s/"#name)							      \
    BPF_PROG(name, ##args)

// Define a BPF map to store virtual deadlines for tasks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Task PID
    __type(value, u64); // Virtual deadline
    __uint(max_entries, 1024);
} task_deadlines SEC(".maps");

// Function to calculate the virtual deadline for a task
static __always_inline u64 calculate_virtual_deadline(struct task_struct *p) {
    u64 now = bpf_ktime_get_ns(); // Current time in nanoseconds
    u64 runtime = p->se.sum_exec_runtime; // Task's runtime
    return now + runtime; // Example: deadline = now + runtime
}

// Initialize the scheduler by creating a shared dispatch queue (DSQ)
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

// Enqueue a task to the shared DSQ, dispatching it with a virtual deadline
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    u32 pid = p->pid;
    u64 deadline = calculate_virtual_deadline(p);

    // Store the virtual deadline in the BPF map
    bpf_map_update_elem(&task_deadlines, &pid, &deadline, BPF_ANY);
    
    // Calculate a time slice for the task
    u64 time_slice = 5000000; // fixed time slice of 5ms (in nanoseconds)

    // Enqueue the task with its virtual deadline
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, time_slice, deadline, enq_flags);
    return 0;
}

int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // DSQ iterator
    struct task_struct *p = NULL;     // Pointer to the task being dispatched

    bpf_iter_scx_dsq_new(&it__iter, SHARED_DSQ_ID, 0); // Initialize the DSQ iterator

    p = bpf_iter_scx_dsq_next(&it__iter); // Get the next task from the DSQ

    if(p == NULL) {
        bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
        return -1; // No task was dispatched (e.g., DSQ is empty)
    }

    // Attempt to dispatch the task with the earliest virtual deadline
    if (scx_bpf_dsq_move_vtime(&it__iter, p, SHARED_DSQ_ID, 0) == 0) {
        bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
        return 0; // Task successfully dispatched
    }

    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return -1; // No task was dispatched (e.g., DSQ is empty)
}

// Define the main scheduler operations structure (sched_ops)
SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue   = (void *)sched_enqueue,
    .dispatch  = (void *)sched_dispatch,
    .init      = (void *)sched_init,
    .flags     = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
    .name      = "eevdf_scheduler"
};

// License for the BPF program
char _license[] SEC("license") = "GPL";