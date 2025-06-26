#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)
#define bpf_rbtree_add(head, node, less) bpf_rbtree_add_impl(head, node, less, NULL, 0) // last two args are always (NULL, 0)
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))

// Define a shared Dispatch Queue (DSQ) ID
#define SHARED_DSQ_ID 0
#define QUANTUMSIZE  1000000 // 1ms in nanoseconds

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

struct node_data {
    struct bpf_rb_node node;    // Must be first
    struct task_struct *task;
    long vd;                    // virtual deadline
    long ve;                    // virtual eligible time ~ don't think we actually need this variable, may be dynamically computed
};

static bool less_vd(struct bpf_rb_node *a, const struct bpf_rb_node *b){
    struct node_data *node_a; // node A is the node we want to add to tree
    struct node_data *node_b;

    node_a = container_of(a, struct node_data, node);
    node_b = container_of(b, struct node_data, node);
   
    return node_a->vd < node_b->vd;
}

static bool less_ve(struct bpf_rb_node *a, const struct bpf_rb_node *b){
    struct node_data *node_a; // node A is the node we want to add to tree
    struct node_data *node_b;

    node_a = container_of(a, struct node_data, node);
    node_b = container_of(b, struct node_data, node);
 
    return node_a->ve < node_b->ve;
}

long vtime = 0; // still need to build the logic for updating vtime ~ WIP
int Totweight = 0; // total weight of all requests

/** LOCK FOR BOTH TREES ~ have to use one because the BPF verifier complains... **/
private(A) struct bpf_spin_lock glock;

/** TREE ORDERED BY VE ~ used to store non-eligible tasks **/
private(A) struct bpf_rb_root groot_ve __contains(node_data, node);

/** TREE ORDERED BY VD ~ used to store eligible tasks **/
private(A) struct bpf_rb_root groot_vd __contains(node_data, node);

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

// Get current virtual time
static __always_inline long get_current_vt() {
    return vtime;
}

// Helper function to add a task to the rb tree, given its virtual deadline
static __always_inline int add_node_to_ve_tree(struct task_struct *task){
    struct node_data *n;

    // Allocate memory for a new node in the RB tree
    n = bpf_obj_new(typeof(*n));
    if (!n)
        return -1;

    // TODO: add something related to the weight since in theory it would have also - client_lag / Totweights
    n->ve = get_current_vt();
    n->vd = n->ve + QUANTUMSIZE;
    n->task = task;

    bpf_spin_lock(&glock);
    bpf_rbtree_add(&groot_ve, &n->node, less_ve);
    bpf_spin_unlock(&glock);

    return 0;
}

// If any tasks became eligible in the ve tree, move them to the vd tree
static __always_inline int move_eligible_tasks_to_vd_tree(){
    struct node_data *m;
    struct bpf_rb_node *res;

    while (true){
        bpf_spin_lock(&glock);
        res = bpf_rbtree_first(&groot_ve);
        if (!res)
            break;
        
        m = container_of(res, struct node_data, node);
        if(!m)
            break;

        // Copy node data
        long ve = m->ve;
        long vd = m->vd;
        struct task_struct *p = m->task;

        // Task is eligible! -> move it!
        if (ve < vtime){
            // Delete the copied node from the ve tree
            res = bpf_rbtree_remove(&groot_ve, res);
            bpf_spin_unlock(&glock);

            // Drop node
            m = container_of(res, struct node_data, node);
            if(!m)
                return 0;
            bpf_obj_drop(m); 

            /** START: create a copy of the node to move**/
            struct node_data *n;
            n = bpf_obj_new(typeof(*n));
            if(!n)
                return 0;
            
            n->ve = ve;
            n->vd = vd;
            n->task = p;
            /** END: create a copy of the node to move**/

            // Add copy to the vd tree
            bpf_spin_lock(&glock);
            bpf_rbtree_add(&groot_vd, &n->node, less_vd);
            bpf_spin_unlock(&glock);
        } else break;
    }
    
    bpf_spin_unlock(&glock);
    return 0;
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

    // Enqueue the task with its virtual deadline to the dsq ~ idk if we still need it after introducing rb trees
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, time_slice, deadline, enq_flags);

    // add node to the non-eligible tasks tree
    return add_node_to_ve_tree(p);
}

// Check if a task is eligible for dispatch (with respect to task contraints...)
static __always_inline bool is_task_allowed(struct task_struct *p, s32 cpu) {
    if(!p){
        bpf_printk("Invalid pointer");
        return false;
    }

    int pid;
    bpf_core_read(&pid, sizeof(pid), &p->pid);

    long state;
    bpf_core_read(&state, sizeof(state), &p->__state);

    // Skip tasks that are not in TASK_RUNNING state
    if (state != 0) {
        bpf_printk("Skipping task %d: not in TASK_RUNNING state (state=%ld)\n", pid, state);
        return false;
    }

    // Skip idle tasks
    if (pid == 0) {
        bpf_printk("Skipping idle task on CPU %d\n", cpu);
        return false;
    }

    int on_cpu;
    bpf_core_read(&on_cpu, sizeof(on_cpu), &p->on_cpu);

    // Check if the task can be moved (on_cpu is basically a lock...)
    if (on_cpu != 0) {
        bpf_printk("Task %d cannot be moved on CPU %d\n", pid, cpu);
        return false;
    }

    unsigned long cpus_mask_bits;
    bpf_core_read(&cpus_mask_bits, sizeof(cpus_mask_bits), &p->cpus_mask.bits[0]);

    // Check if the task's CPU affinity allows it to run on the specified CPU
    if (!(cpus_mask_bits & (1 << cpu))) {
        bpf_printk("Task %d cannot run on CPU %d due to affinity\n", pid, cpu);
        return false;
    }

    return true; // Task is eligible for dispatch
}

/**
 * Dispatch a task from the user-defined global DSQ (user-defined as a priority queue on vd) to the local cpu
 * Returns 1 if successful, 0 if no task was dispatched, negative error codes on failure

int BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev) {
    struct bpf_iter_scx_dsq it__iter; // DSQ iterator
    struct task_struct *p = NULL;     // Pointer to the task being dispatched
    int dispatched;                   // return value

    // Initialize the DSQ iterator
    if ((dispatched = bpf_iter_scx_dsq_new(&it__iter, SHARED_DSQ_ID, 0))){
        bpf_printk("Failed to initialize DSQ iterator for CPU %d\n", cpu);  
        goto out;
    }

    // Loop to find a task to dispatch
    while ((p = bpf_iter_scx_dsq_next(&it__iter))) {

        // Skip to the next task if this cannot run on this cpu
        if(!is_task_allowed(p, cpu)) continue;

        // Attempt to move the task
        if ((dispatched = scx_bpf_dsq_move(&it__iter, p, SCX_DSQ_LOCAL, 0))) {
            bpf_printk("Successfully dispatched task %d to CPU %d\n", p->pid, cpu);
            goto out;
        }
        else bpf_printk("Failed to move task %d to CPU %d\n", p->pid, cpu);
    }
    
out:
    bpf_iter_scx_dsq_destroy(&it__iter); // Destroy the DSQ iterator
    return dispatched; // No task was dispatched
}*/

// get_first from the vd tree, if it's not expired ~ all tasks in vd tree are eligible anyway...
static __always_inline struct task_struct *get_eligible_request(long virtualtime, s32 cpu) {
    struct node_data *m;
    struct bpf_rb_node *res;
    struct task_struct *p;
    long vd;

    // Fetch eligible node with the earliest deadline
    bpf_spin_lock(&glock);
    res = bpf_rbtree_first(&groot_vd);
    if (!res)
        goto err_unlk;

    m = container_of(res, struct node_data, node);
    if (!m)
        goto err_unlk;

    // Access all necessary fields
    p = m->task;            // task_struct pointer
    vd = m->vd;             // virtual deadline

    bpf_spin_unlock(&glock);

    // If the task cannot run on this cpu, we just return NULL, without removing the node from the tree
    // ~ has to be done without holding a lock...
    if (!is_task_allowed(p, cpu))
        goto err;

    bpf_spin_lock(&glock);

    // Remove the node from the tree
    // ~ have to re-fetch it because res is not a non-owning reference
    struct bpf_rb_node *ref = bpf_rbtree_first(&groot_vd);
    if (ref == res) // ensure consistency
        ref = bpf_rbtree_remove(&groot_vd, ref);
    else
        goto err_unlk;

    bpf_spin_unlock(&glock);

    if (!ref)
        goto err;

    // Get task pointer, to drop the node
    m = container_of(ref, struct node_data, node);
    if (!m)
        goto err;
    bpf_obj_drop(m);

    // Ensure the task is not expired. If it is, we can just return NULL since the node has been removed from the tree
    if (vd < virtualtime)
        goto err;

    // Return the task_struct pointer
    return p;

err_unlk:                           // jump here to return after an error, if we hold a lock
    bpf_spin_unlock(&glock);
err:                                // jump here to return after an error, if no lock is held
    return NULL;
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


int BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev){
    // check if any tasks became eligible. If so, move them to the vd tree 
    move_eligible_tasks_to_vd_tree();

    struct task_struct *next = get_eligible_request(get_current_vt(), cpu);
    if (!next) return 0;

    u64 runtime = QUANTUMSIZE; // O runtime effettivo
    vtime += runtime;

    // Add node to the ve tree ~ it may have become un-eligible...
    add_node_to_ve_tree(next);

    // Dispatch the task for execution
    scx_bpf_dsq_insert(next, SHARED_DSQ_ID, runtime, 0);

    bpf_obj_drop(next);
    return 0;
}

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