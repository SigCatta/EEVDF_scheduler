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
    long ve;                    // virtual eligible time ~ don't the we actually need this variable, may be dynamically computed
    long min_vd;                // minimum virtual deadline in the subtree
};

static bool less(struct bpf_rb_node *a, const struct bpf_rb_node *b){
    struct node_data *node_a; // node A is the node we want to add to tree
    struct node_data *node_b;

    node_a = container_of(a, struct node_data, node);
    node_b = container_of(b, struct node_data, node);

    // If this subtree has a min_vd bigger than the new node's vd
    // update the min_vd, because the new node joins this subtree
    if(node_b->min_vd > node_a->vd)
        node_b->min_vd = node_a->vd;
    
    return node_a->ve < node_b->ve;
}

long vtime = 0; // still need to build the logic for updating vtime ~ WIP
int Totweight = 0; // total weight of all requests
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_rb_root groot __contains(node_data, node);

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
static __always_inline int add_node_to_tree(struct task_struct *task){
    struct node_data *n;

    // Allocate memory for a new node in the RB tree
    n = bpf_obj_new(typeof(*n));
    if (!n)
        return -1;

    // TODO: add something related to the weight since in theory it would have also - client_lag / Totweights
    n->ve = get_current_vt();
    n->vd = n->ve + QUANTUMSIZE;
    n->min_vd = n->vd;
    n->task = task;

    bpf_spin_lock(&glock);
    bpf_rbtree_add(&groot, &n->node, less);
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

    return add_node_to_tree(p);
}

// Check if a task is eligible for dispatch
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

static __always_inline struct node_data *get_eligible_request(long virtualtime) {
    struct bpf_rb_node *node = NULL;
    struct node_data *path_req = NULL, *st_tree = NULL;
    struct bpf_rb_node *subtree_root = NULL;

    bpf_spin_lock(&glock);
    node = bpf_rbtree_first(&groot);

    // Prima ricerca: trova il miglior candidato lungo il percorso
    while (node) {
        struct node_data *current = container_of(node, struct node_data, node);

        if (current->ve <= virtualtime) {
            // Aggiorna il miglior candidato lungo il percorso
            if (!path_req || (path_req->vd > current->vd)) {
                path_req = current;
            }

            // Verifica i sottoalberi sinistri per min_vd
            if (current->node.left) {
                struct node_data *left = container_of(current->node.left, struct node_data, node);
                if (!st_tree || (st_tree->min_vd > left->min_vd)) {
                    st_tree = left;
                    subtree_root = current->node.left;
                }
            }
            node = current->node.right;
        } else {
            node = current->node.left;
        }
    }

    // Controlla se il miglior candidato è lungo il percorso
    if (!st_tree || (st_tree->min_vd >= path_req->vd)) {
        bpf_spin_unlock(&glock);
        return path_req;
    }

    // Seconda ricerca: esplora il sottoalbero promettente
    for (node = subtree_root; node; ) {
        struct node_data *current = container_of(node, struct node_data, node);

        if (current->vd == st_tree->min_vd) {
            bpf_spin_unlock(&glock);
            return current;
        }

        if (current->node.left) {
            struct node_data *left = container_of(current->node.left, struct node_data, node);
            if (left->min_vd == st_tree->min_vd) {
                node = current->node.left;
                continue;
            }
        }
        node = current->node.right;
    }

    bpf_spin_unlock(&glock);
    return NULL;
}

int BPF_STRUCT_OPS(sched_dispatch_dsq, s32 cpu, struct task_struct *prev){
    struct node_data *next = get_eligible_request(get_current_vt());
    if (!next) return 0;

    u64 runtime = QUANTUMSIZE; // O runtime effettivo
    VirtualTime += runtime ;

    // Rimuovi e reinserta con nuovi ve/vd
    bpf_rbtree_remove(&groot, &next->node);
    next->ve += runtime ;
    next->vd = next->ve + QUANTUMSIZE;
    bpf_rbtree_add(&groot, &next->node, less);

    scx_bpf_dispatch(next->task, SHARED_DSQ_ID, runtime, 0);
    return 0;
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

/**
 * Travels down the tree, leaving nodes with an expired vd on the left of the path
 */
static int rbtree_split(){
	struct rb_node **link = &((struct rb_root_cached *)&groot)->rb_root.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		parent = *link;
        
        struct node_data *node;
        node = container_of((struct bpf_rb_node *) parent, struct node_data, node);
        if (node->vd <= vtime)
            link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

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