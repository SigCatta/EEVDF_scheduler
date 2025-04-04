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

// returns the a task's virtual deadline
static __always_inline u64 get_task_deadline(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *deadline_ptr = bpf_map_lookup_elem(&task_deadlines, &pid);
    return deadline_ptr ? *deadline_ptr : -1;
}

// Function to calculate the virtual deadline for a task
static __always_inline u64 calculate_virtual_deadline(struct task_struct *p) {
    u64 now = bpf_ktime_get_ns(); // Current time in nanoseconds
    u64 runtime = p->se.sum_exec_runtime; // Task's runtime
    return now + runtime; // Example: deadline = now + runtime
}

// print the tasks in the shared DSQ, including their PIDs and virtual deadlines
static __always_inline void print_tasks() {
    struct task_struct *p = NULL;
    struct bpf_iter_scx_dsq it__iter; // DSQ iterator

    // Initialize the DSQ iterator
    if (bpf_iter_scx_dsq_new(&it__iter, SHARED_DSQ_ID, 0) < 0) {
        bpf_iter_scx_dsq_destroy(&it__iter);
        return;
    }

    // Loop through tasks in the DSQ
    int i = 1;
    while ((p = bpf_iter_scx_dsq_next(&it__iter)) != NULL) {
        u32 pid;
        u64 *deadline;

        // Copy the PID from the task_struct to a local variable
        bpf_core_read(&pid, sizeof(pid), &p->pid);

        // Get the virtual deadline from the BPF map
        deadline = bpf_map_lookup_elem(&task_deadlines, &pid);
        if (deadline) {
            bpf_printk("%d. Task: %d, vdeadline: %llu\n", i++, pid, *deadline);
        } else {
            bpf_printk("%d. Task: %d, no deadline found\n", i++, pid);
        }
    }

    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
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

// Check if a task is eligible for dispatch
static __always_inline bool is_task_eligible(struct task_struct *p, s32 cpu) {
    // Skip tasks that are not in TASK_RUNNING state
    if (p->__state != 0) {
        bpf_printk("Skipping task %d: not in TASK_RUNNING state (state=%ld)\n", p->pid, p->__state);
        return false;
    }

    // Skip idle tasks
    if (p->pid == 0) {
        bpf_printk("Skipping idle task on CPU %d\n", cpu);
        return false;
    }

    // Check if the task can be moved (on_cpu is basically a lock...)
    if (p->on_cpu != 0) {
        bpf_printk("Task %d cannot be moved on CPU %d\n", p->pid, cpu);
        return false;
    }

    // Check if the task's CPU affinity allows it to run on the specified CPU
    if (!(p->cpus_mask.bits[0] & (1 << cpu))) {
        bpf_printk("Task %d cannot run on CPU %d due to affinity\n", p->pid, cpu);
        return false;
    }

    return true; // Task is eligible for dispatch
}

/**
 * Dispatch a task from the user-defined global DSQ (user-defined as a priority queue on vdeadline) to the local cpu
 * Returns 1 if successful, 0 if no task was dispatched, negative error codes on failure
 */
int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // DSQ iterator
    struct task_struct *p = NULL;     // Pointer to the task being dispatched
    int dispatched;                   // return value

    // Initialize the DSQ iterator
    if ((dispatched = bpf_iter_scx_dsq_new(&it__iter, SHARED_DSQ_ID, 0)) < 0){
        bpf_printk("Failed to initialize DSQ iterator for CPU %d\n", cpu);  
        goto out;
    }

    // Loop to find a task to dispatch
    while ((p = bpf_iter_scx_dsq_next(&it__iter)) != NULL) {

        // Skip to the next task if not eligible
        if(!is_task_eligible(p, cpu)) continue;

        // Attempt to move the task
        if ((dispatched = scx_bpf_dsq_move_vtime(&it__iter, p, SCX_DSQ_LOCAL, 0))) {
            bpf_printk("Successfully dispatched task %d to CPU %d\n", p->pid, cpu);
            goto out;
        }
        else bpf_printk("Failed to move task %d to CPU %d\n", p->pid, cpu);
    }
    
out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return dispatched; // No task was dispatched
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

// .select_cpu		= (void *)simple_select_cpu,    // probably not needed for us
// .running			= (void *)simple_running,       // 
// .stopping		= (void *)simple_stopping,
// .enable			= (void *)simple_enable,
// .exit			= (void *)simple_exit,          // probably not needed for us

// License for the BPF program
char _license[] SEC("license") = "GPL";