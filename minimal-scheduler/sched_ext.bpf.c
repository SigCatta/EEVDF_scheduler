#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define a shared Dispatch Queue (DSQ) ID
#define VE_DSQ_ID 12345
#define VD_DSQ_ID 23456

#define BPF_STRUCT_OPS(name, args...)	\
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)	\
    SEC("struct_ops.s/"#name)							      \
    BPF_PROG(name, ##args)

// Define a BPF map to store virtual deadlines for tasks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Task PID
    __type(value, u64); // Eligible time
    __uint(max_entries, 1024);
} task_ves SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Task PID
    __type(value, u64); // Virtual deadline
    __uint(max_entries, 1024);
} task_vds SEC(".maps");

long vtime = 0; // still need to build the logic for updating vtime ~ WIP
long QUANTUMSIZE = 6000000; // default quantum size of 6 ms

// returns the a task's virtual deadline
static __always_inline u64 get_task_vd(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *vd_ptr = bpf_map_lookup_elem(&task_vds, &pid);
    return vd_ptr ? *vd_ptr : -1;
}

// returns the a task's virtual deadline
static __always_inline u64 get_task_ve(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *ve_ptr = bpf_map_lookup_elem(&task_ves, &pid);
    return ve_ptr ? *ve_ptr : -1;
}

// Function to calculate the virtual deadline for a task
static __always_inline u64 calculate_virtual_deadline(struct task_struct *p) {
    u64 now = bpf_ktime_get_ns(); // Current time in nanoseconds
    u64 runtime = p->se.sum_exec_runtime; // Task's runtime
    return now + runtime; // Example: deadline = now + runtime
}

// Initialize the scheduler by creating a shared dispatch queue (DSQ)
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
    return scx_bpf_create_dsq(VE_DSQ_ID, -1) | scx_bpf_create_dsq(VD_DSQ_ID, -1);
}

// Enqueue a task to the shared DSQ, dispatching it with a virtual deadline
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    u32 pid = p->pid;
    u64 deadline = calculate_virtual_deadline(p);
    u64 eligible = vtime;

    // Store the virtual deadline in the BPF map
    bpf_map_update_elem(&task_vds, &pid, &deadline, BPF_ANY);
    
    // Store the virtual deadline in the BPF map
    bpf_map_update_elem(&task_ves, &pid, &eligible, BPF_ANY);

    // Enqueue the task with on the DSQ, ordered by eligible time
    scx_bpf_dsq_insert_vtime(p, VE_DSQ_ID, QUANTUMSIZE, eligible, enq_flags);

    return 0;
}

/**
 * Checks if a task is can be dispatched on the current cpu
 */
static __always_inline bool is_task_allowed(struct task_struct *p, s32 cpu) {
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

    return true; // Task is allowed for dispatch on the current CPU
}

/**
 * Checks if the given task is eligible
 */
static bool is_task_eligible(struct task_struct *p){
    return get_task_ve(p) <= vtime;
}

/**
 * Iterates over the VE DSQ, checking if any tasks are eligible,
 * all eligible tasks are moved to the VD DSQ
 */
static void move_eligible_tasks_to_vd_dsq(s32 cpu){
    struct bpf_iter_scx_dsq it__iter; // iterator over the VE DSQ
    struct task_struct *p = NULL;     // current task_struct

    if (bpf_iter_scx_dsq_new(&it__iter, VE_DSQ_ID, 0)){
        bpf_printk("Failed to initialize VE DSQ iterator for CPU %d\n", cpu);  
        goto out;
    }

    // iterate over the VE DSQ
    while ((p = bpf_iter_scx_dsq_next(&it__iter))) {
        if(is_task_eligible(p)){
            u64 deadline = get_task_vd(p);
            
            // Override the vtime of the next task that will be moved from it__iter
            scx_bpf_dsq_move_set_vtime(&it__iter, deadline); 

            // Finally move the task, with updated vtime
            scx_bpf_dsq_move_vtime(&it__iter, p, VD_DSQ_ID, 0); 
            
            bpf_printk("Successfully moved task %d to VD_DSQ, vd: %ld\n", p->pid, deadline);
        }
        else break; // Since it's a priority queue, if this task is not eligible, others aren't either
    }

out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return;
}

static bool is_task_expired(struct task_struct *p){
    return get_task_vd(p) < vtime;
}

/**
 * Dispatch a task from the user-defined global DSQ (user-defined as a priority queue on vd) to the local cpu
 * Returns 1 if successful, 0 if no task was dispatched, negative error codes on failure
 */
int BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // iterator over the VD DSQ
    struct task_struct *p = NULL;     // Pointer to the task being dispatched
    int dispatched = 0;               // return value

    // Check if any tasks became eligible
    move_eligible_tasks_to_vd_dsq(cpu);

    // Initialize the DSQ iterator
    if (bpf_iter_scx_dsq_new(&it__iter, VD_DSQ_ID, 0)){
        bpf_printk("Failed to initialize VD DSQ iterator for CPU %d\n", cpu);  
        goto out;
    }

    // Loop to find a task to dispatch
    while ((p = bpf_iter_scx_dsq_next(&it__iter))) {

        // Skip to the next task if this cannot run on this cpu
        if(!is_task_allowed(p, cpu)) continue;

        if(is_task_expired(p)){
            bpf_printk("Task %d has expired! vd: %ld vt: %ld\n", p->pid, get_task_vd(p), vtime);
            continue;
        }

        // Attempt to move the task
        if ((dispatched = scx_bpf_dsq_move(&it__iter, p, SCX_DSQ_LOCAL, 0))) {
            bpf_printk("Successfully dispatched task %d to CPU %d, vd: %ld\n", p->pid, cpu, get_task_vd(p));
            goto out;
        }
        else bpf_printk("Failed to move task %d to CPU %d\n", p->pid, cpu);
    }
    
out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return dispatched; // No task was dispatched
}

/*
 * Architectures might want to move the poison pointer offset
 * into some well-recognized area such as 0xdead000000000000,
 * that is also not mappable by user-space exploits:
 */
#ifdef CONFIG_ILLEGAL_POINTER_VALUE
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)
#else
# define POISON_POINTER_DELTA 0
#endif
#define BPF_PTR_POISON ((void *)(0xeB9FUL + POISON_POINTER_DELTA)) // idfk


// Define the main scheduler operations structure (sched_ops)
SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue   = (void *)sched_enqueue,
    .dispatch  = (void *)sched_dispatch_dsq,
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