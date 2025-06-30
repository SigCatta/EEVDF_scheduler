#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define shared Dispatch Queue (DSQ) IDs
#define VE_DSQ_ID 12345
#define VD_DSQ_ID 23456

// Define kick throttle timeout (in nanoseconds) - 1ms
#define KICK_TIMEOUT 1000000ULL

// Define convenience macros for BPF struct_ops function definitions
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

// Define a per-CPU array to track last kick time for each CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32); // CPU ID
    __type(value, u64); // Last kick timestamp
    __uint(max_entries, 64); // Support up to 64 CPUs
} cpu_last_kick SEC(".maps");

u64 total_weight = 0;      // Sum of all weights of active tasks
u64 vtime = 0;             // Current virtual time
u64 QUANTUMSIZE = 6000000; // Default quantum size of 6 ms

/***** GETTERS *****/

/** 
 * Returns a task's virtual deadline
 */
static __always_inline u64 get_task_vd(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *vd_ptr = bpf_map_lookup_elem(&task_vds, &pid);
    return vd_ptr ? *vd_ptr : 0; // Return 0 if not found (new task)
}

/**
 * Returns a task's virtual eligible time
 */
static __always_inline u64 get_task_ve(struct task_struct *p) {
    u32 pid;

    // Copy the PID from the task_struct to a local variable ~ must do because of the BPF verifier
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    // Perform the map lookup
    u64 *ve_ptr = bpf_map_lookup_elem(&task_ves, &pid);
    return ve_ptr ? *ve_ptr : 0; // Return 0 if not found (new task)
}

/**
 * Weights directly depend on the nice value similarly to standard CFS priority
 * 
 * Relative distance between task weights is ~25% (from one nice value to the another)
 */
static __always_inline u32 get_task_weight(struct task_struct *p){
    return p->scx.weight ? p->scx.weight : 1; // Return 1 if scx.weight == 0 to prevent division by 0
}

/**
 * Returns the current virtual time
 */
static __always_inline u64 get_vtime(){
    return vtime;
}

/***** SHARED STATE *****/

/**
 * Atomically subtracts the task's weight from the total
 */
static __always_inline void decr_tasks_weight(struct task_struct *p){
    u32 weight = get_task_weight(p);

    __sync_fetch_and_sub(&total_weight, weight);
}

/**
 * Atomically adds the task's weight to the total
 */
static __always_inline void incr_tasks_weight(struct task_struct *p){
    u32 weight = get_task_weight(p);

    __sync_fetch_and_add(&total_weight, weight);
}

/**
 * Atomically increments the virtual time by QUANTUMSIZE / total_weight
 * 
 * ~ This function should be called when a task is dispatched
 */
static __always_inline void incr_vtime(){ 
    // Avoid division by zero - if no tasks are active, don't increment vtime
    if (total_weight > 0)
        __sync_fetch_and_add(&vtime, QUANTUMSIZE / total_weight);
}

/***** HELPERS *****/

/**
 * Compute and update a task's virtual deadline in the bpf map
 */
static __always_inline void update_virtual_deadline(struct task_struct *p) {
    pid_t pid = p->pid;
    u64 ve = get_task_ve(p);

    u64 vd = ve + QUANTUMSIZE / get_task_weight(p);

    bpf_map_update_elem(&task_vds, &pid, &vd, BPF_ANY);
}

/**
 * Compute and update a task's virtual eligible time in the bpf map
 */
static __always_inline void update_virtual_eligible_time(struct task_struct *p){
    pid_t pid;
    u64 ve;

    bpf_core_read(&pid, sizeof(pid), &p->pid);

    ve = get_vtime();

    bpf_map_update_elem(&task_ves, &pid, &ve, BPF_ANY);
}

/**
 * Checks if a task can be dispatched on the current cpu
 */
static __always_inline bool is_task_allowed(struct task_struct *p, s32 cpu) {

    // Check if the task's CPU affinity allows it to run on the specified CPU
    if (!(p->cpus_mask.bits[0] & (1 << cpu))) {
        
        // Kick the first available CPU (simple bit operation)
        u64 mask = p->cpus_mask.bits[0];
        if (mask) {
            s32 target_cpu = __builtin_ctzll(mask);  // Count trailing zeros = first set bit
            u64 now = bpf_ktime_get_ns();
            u64* last_kick = bpf_map_lookup_elem(&cpu_last_kick, &target_cpu);
            
            // Only kick if we haven't kicked this CPU recently
            if (!last_kick || (now - *last_kick) > KICK_TIMEOUT) {
                // Update the last kick timestamp
                bpf_map_update_elem(&cpu_last_kick, &target_cpu, &now, BPF_ANY);
                
                scx_bpf_kick_cpu(target_cpu, 0);
                bpf_printk("Task %d cannot run here due to affinity, kicking CPU %d\n", p->pid, target_cpu);
            }
        }

        return false;
    }

    // Check if the task can be moved (on_cpu is basically a lock...)
    if (p->on_cpu != 0) {
        bpf_printk("Task %d cannot be moved on CPU %d\n", p->pid, cpu);
        return false;
    }

    // Skip tasks that are not in TASK_RUNNING state
    if (p->__state != 0) {
        bpf_printk("Skipping task %d: not in TASK_RUNNING state (state=%ld)\n", p->pid, p->__state);
        return false;
    }

    // Skip idle tasks
    if (p->pid == 0)
        return false;

    return true; // Task is allowed for dispatch on the current CPU
}

/**
 * Checks if the given task is eligible
 */
static __always_inline bool is_task_eligible(struct task_struct *p){
    return get_task_ve(p) <= get_vtime();
}

/**
 * Check if a task's deadline is expired (i.e., deadline has passed)
 */
static __always_inline bool is_task_expired(struct task_struct *p){
    return get_task_vd(p) < get_vtime();
}

/**
 * Iterates over the VE DSQ, checking if any tasks are eligible,
 * all eligible tasks are moved to the VD DSQ
 */
static void move_eligible_tasks_to_vd_dsq(s32 cpu){
    struct bpf_iter_scx_dsq it__iter; // iterator over the VE DSQ
    struct task_struct *p = NULL;     // current task_struct

    if (bpf_iter_scx_dsq_new(&it__iter, VE_DSQ_ID, 0))
        goto out; // Quit if we fail to initialize the iterator

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

/***** SCHED OPS FUNCTIONS *****/

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
 * Enqueue a new task in the VE DSQ and add its weight to the shared state total variable
 * 
 * Virtual deadline and eligible time are also computed and stored in the bpf maps
 */
s32 BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    bpf_printk("Task %d enqueued\n", p->pid);

    // Increase the total tasks weight
    incr_tasks_weight(p);

    // Store the virtual deadline and eligible time in the BPF maps ~ have to compute VE before VD !!!
    update_virtual_eligible_time(p);
    update_virtual_deadline(p);

    // Enqueue the task on the DSQ, ordered by eligible time
    scx_bpf_dsq_insert_vtime(p, VE_DSQ_ID, QUANTUMSIZE, get_task_ve(p), enq_flags);

    return 0;
}

/**
 * Move all eligible tasks from the VE to the VD DSQ, then iterate over the VD DSQ.
 * Dispatch a task from the VD DSQ (user-defined as a priority queue on vd) to the local cpu
 * 
 * Returns 1 if successful, 0 if no task was dispatched, negative error codes on failure
 */
s32 BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // iterator over the VD DSQ
    struct task_struct *p = NULL;     // Pointer to the task being dispatched
    s32 dispatched = 0;               // Return value

    // Check if any tasks became eligible
    move_eligible_tasks_to_vd_dsq(cpu);

    // Initialize the DSQ iterator
    if (bpf_iter_scx_dsq_new(&it__iter, VD_DSQ_ID, 0))
        goto out; // Quit if we fail to initialize the iterator

    // Loop to find a task to dispatch
    while ((p = bpf_iter_scx_dsq_next(&it__iter))) {

        // Skip to the next task if this cannot run on this cpu
        if(!is_task_allowed(p, cpu)) continue;

        // Re-schedule task if expired
        if(is_task_expired(p)){
            bpf_printk("Task %d expired\n", p->pid);

            // Update virtual deadline and eligible time in the BPF maps ~ have to compute VE before VD !!!
            update_virtual_eligible_time(p);
            update_virtual_deadline(p);

            // Move task back to VE DSQ
            scx_bpf_dsq_move_set_vtime(&it__iter, get_task_ve(p));
            scx_bpf_dsq_move_vtime(&it__iter, p, VE_DSQ_ID, 0);
            continue;
        }

        // Attempt to move the task
        if ((dispatched = scx_bpf_dsq_move(&it__iter, p, SCX_DSQ_LOCAL, 0))) {
            pid_t pid;
            bpf_core_read(&pid, sizeof(pid), &p->pid);

            bpf_printk("Successfully dispatched task %d to CPU %d\n", pid, cpu);
            incr_vtime();
            decr_tasks_weight(p);
            
            // Clean up maps when task is dispatched (no longer enqueued)
            bpf_map_delete_elem(&task_ves, &pid);
            bpf_map_delete_elem(&task_vds, &pid);
            
            goto out;
        }
        else bpf_printk("Failed to move task %d to CPU %d\n", p->pid, cpu);
    }
    
out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return dispatched;
}

/**
 * Exit a previously-running task from the system. p is exiting or the BPF scheduler is being unloaded.
 * Remove p's data from the ve and vd maps, also decrement the total weight if exited between .enqueue and .dispatch
 */
s32 BPF_STRUCT_OPS(sched_exit_task, struct task_struct *p, struct scx_exit_task_args *args) {
    pid_t pid;
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    bpf_printk("Task %d exiting\n", pid);

    // Remove VE map entry
    u64 *existing_ve = bpf_map_lookup_elem(&task_ves, &pid);
    if(existing_ve)
        bpf_map_delete_elem(&task_ves, &pid);

    // Remove VD map entry
    u64 *existing_vd = bpf_map_lookup_elem(&task_vds, &pid);
    if(existing_vd)
        bpf_map_delete_elem(&task_vds, &pid);

    // If the task is present in either maps, it was in a DSQ. We have to remove its weight from the total
    // Note that sched_ext already handles the removal tasks from ALL DSQs to prevent dangling references (also from user-defined DSQs)
    if(existing_ve || existing_vd)
        decr_tasks_weight(p);

    return 0;
}


// Define the main scheduler operations structure (sched_ops)
SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue   = (void *)sched_enqueue,
    .dispatch  = (void *)sched_dispatch_dsq,
    .init      = (void *)sched_init,
    .exit_task = (void *)sched_exit_task,
    .flags     = SCX_OPS_KEEP_BUILTIN_IDLE // Keep built-in idle tracking
                | SCX_OPS_ENQ_LAST,        // The last task on a CPU, is not kept there after its slice ~ it's passed to .enqueue instead 
    .name      = "eevdf_scheduler"
};

// License for the BPF program
char _license[] SEC("license") = "GPL";