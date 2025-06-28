#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define shared Dispatch Queue (DSQ) IDs
#define VE_DSQ_ID 12345
#define VD_DSQ_ID 23456

#define BPF_STRUCT_OPS(name, args...) \
    SEC("struct_ops/"#name)	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name) \
    BPF_PROG(name, ##args)

// Define a BPF map to store virtual eligible times for tasks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Task PID
    __type(value, u64); // Eligible time
    __uint(max_entries, 1024);
} task_ves SEC(".maps");

// Define a BPF map to store virtual deadlines for tasks
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // Task PID
    __type(value, u64); // Virtual deadline
    __uint(max_entries, 1024);
} task_vds SEC(".maps");

u64 total_weight = 0;       // Sum of all weights of active tasks
u64 vtime = 0;             // Still need to build the logic for updating vtime ~ WIP
u64 QUANTUMSIZE = 6000000; // Default quantum size of 6 ms

/** 
 * Returns the a task's virtual deadline
 */
static __always_inline u64 get_task_vd(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *vd_ptr = bpf_map_lookup_elem(&task_vds, &pid);
    return vd_ptr ? *vd_ptr : -1;
}

/**
 * Returns the a task's virtual eligible time
 */
static __always_inline u64 get_task_ve(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *ve_ptr = bpf_map_lookup_elem(&task_ves, &pid);
    return ve_ptr ? *ve_ptr : -1;
}

/**
 * Weights directly depend on the nice value similarly to standard CFS priority
 * 
 * Relative distance between task weights is ~25% (from one nice value to the another)
 */
static __always_inline u32 get_task_weight(struct task_struct *p){
    return p->scx.weight;
}

/**
 * Returns the current virtual time
 */
static __always_inline u64 get_vtime(){
    return vtime;
}

/**
 * Atomically increments the virtual time by 1 / total_weight
 * 
 * ~ This function should be called when a task is dispatched
 */
static __always_inline void incr_vtime(){ 
    //TODO: have to figure out how much to increment, this seems to work, but the paper uses 1 / total_weight
    __sync_fetch_and_add(&vtime, QUANTUMSIZE / total_weight);
}

// Comptue and update a task's virtual deadline in the bpf map
static __always_inline void update_virtual_deadline(struct task_struct *p) {
    pid_t pid = p->pid;
    u64 ve = get_task_ve(p);

    u64 vd = ve + QUANTUMSIZE / get_task_vd(p);

    bpf_map_update_elem(&task_vds, &pid, &vd, BPF_ANY);
}

// Comptue and update a task's virtual eligible time in the bpf map
static __always_inline void update_virtual_eligible_time(struct task_struct *p){
    pid_t pid;
    u64 ve;

    bpf_core_read(&pid, sizeof(pid), &p->pid);

    if(!bpf_map_lookup_elem(&task_ves, &pid)) // if task is new
        ve = get_vtime();
    else
    // Should actually be ve += used / weight  --  but we cannot wait for the task to end!! So we assume the whole QUANTUM is used
        ve = get_task_ve(p) + QUANTUMSIZE / get_task_weight(p);

    bpf_map_update_elem(&task_ves, &pid, &ve, BPF_ANY);
}

/**
 * Initialize the scheduler by creating two shared dispatch queues (DSQ) ~ will be used as priority queues
 * 
 * VE_DSQ_ID contains tasks ordered by their virtual eligible time, all tasks here are not eligible
 * VD_DSQ_ID contains tasks ordered by their virtual deadline, all tasks here are eligible
 * 
 * By default, all tasks are put in the VE DSQ. When tasks become eligible, they are moved to the VD DSQ for dispatch
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
    return scx_bpf_create_dsq(VE_DSQ_ID, -1) | scx_bpf_create_dsq(VD_DSQ_ID, -1);
}

/**
 * Subtract the task's weight from the total
 */
static __always_inline void decr_tasks_weight(struct task_struct *p){
    u32 weight = get_task_weight(p);

    __sync_fetch_and_sub(&total_weight, weight);
}

/**
 * Add the task's weight to the total
 */
static __always_inline void incr_tasks_weight(struct task_struct *p){
    u32 weight = get_task_weight(p);

    __sync_fetch_and_add(&total_weight, weight);
}

/**
 * Enqueue new tasks in the VE DSQ
 * 
 * Virtual deadline and eligible time are also computed and stored in the bpf maps
 */
int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    u32 pid = p->pid;

    // Increa that total tasks weight
    incr_tasks_weight(p);

    // Store the virtual deadline and eligible time in the BPF maps ~ have to compute VE before VD !!!
    update_virtual_eligible_time(p);
    update_virtual_deadline(p);

    // Enqueue the task with on the DSQ, ordered by eligible time
    scx_bpf_dsq_insert_vtime(p, VE_DSQ_ID, QUANTUMSIZE, get_task_ve(p), enq_flags);

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
static __always_inline bool is_task_eligible(struct task_struct *p){
    return get_task_ve(p) <= get_vtime();
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

    // Iterate over the VE DSQ
    while ((p = bpf_iter_scx_dsq_next(&it__iter))) {
        if(is_task_eligible(p)){
            u64 vd = get_task_vd(p);
            
            // Override the vtime of the next task that will be moved from it__iter
            scx_bpf_dsq_move_set_vtime(&it__iter, vd); 

            // Finally move the task, with updated vtime
            scx_bpf_dsq_move_vtime(&it__iter, p, VD_DSQ_ID, 0); 
            
            bpf_printk("Successfully moved task %d to VD_DSQ, vd: %ld\n", p->pid, vd);
        }
        else break; // Since it's a priority queue, if this task is not eligible, the next aren't either
    }

out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return;
}

/**
 * Check if a task's deadline is expired (i.e., deadline has passed)
 */
static __always_inline bool is_task_expired(struct task_struct *p){
    return get_task_vd(p) < get_vtime();
}

/**
 * Move all eligible tasks from the VE to the VD DSQ, then iterate over the VD DSQ.
 * Dispatch a task from the VD DSQ (user-defined as a priority queue on vd) to the local cpu
 * 
 * Returns 1 if successful, 0 if no task was dispatched, negative error codes on failure
 */
int BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // iterator over the VD DSQ
    struct task_struct *p = NULL;     // Pointer to the task being dispatched
    int dispatched = 0;               // Return value

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

        // // Re-schedule task if expired
        // if(is_task_expired(p)){
        //     // Update virtual deadline and eligible time in the BPF maps ~ have to compute VE before VD !!!
        //     update_virtual_eligible_time(p);
        //     update_virtual_deadline(p);

        //     // Move ask back to VE DSQ
        //     scx_bpf_dsq_move_set_vtime(&it__iter, get_task_ve(p));
        //     scx_bpf_dsq_move_vtime(&it__iter, p, VE_DSQ_ID, 0);
        //     continue;
        // }

        // Attempt to move the task
        if ((dispatched = scx_bpf_dsq_move(&it__iter, p, SCX_DSQ_LOCAL, 0))) {
            incr_vtime();
            decr_tasks_weight(p);
            goto out;
        }
        else bpf_printk("Failed to move task %d to CPU %d\n", p->pid, cpu);
    }
    
out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return dispatched;
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