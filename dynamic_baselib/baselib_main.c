#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/kref.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

#include "baselib_dyn_api.h"
#include "process_exit_hook.h"

/**
 * @brief VMA baseline (Data Node)
 *
 * Stores a single file path (vma_path) and its corresponding hash value.
 * This structure serves as a node within a Red-Black Tree.
 */
struct vma_baseline {
    struct rb_node node;
    char *vma_path;
    char *hash;
};

/**
 * @brief Process baseline
 *
 * Stores all VMA baselines related to a specific process (PID).
 * It contains a Red-Black Tree root to manage all associated vma_baseline nodes.
 */
struct process_baseline {
    struct rb_root vma_tree;      
    struct rw_semaphore tree_lock;
    struct kref refcount;
    pid_t pid;
};

static DEFINE_XARRAY(g_process_db);
static DEFINE_SPINLOCK(g_process_db_lock);
static struct dentry *debugfs_dir;

static void release_process_baseline(struct kref *kref);

static struct vma_baseline *__find_vma_in_tree(struct rb_root *root, const char *vma_path) {
    struct rb_node *node = root->rb_node;
    while (node) {
        struct vma_baseline *vma = container_of(node, struct vma_baseline, node);
        int cmp = strcmp(vma_path, vma->vma_path);
        if (cmp < 0) node = node->rb_left;
        else if (cmp > 0) node = node->rb_right;
        else return vma;
    }
    return NULL;
}

static int __insert_vma_into_tree(struct rb_root *root, struct vma_baseline *new_vma) {
    struct rb_node **new = &(root->rb_node), *parent = NULL;
    while (*new) {
        struct vma_baseline *this = container_of(*new, struct vma_baseline, node);
        int result = strcmp(new_vma->vma_path, this->vma_path);
        parent = *new;
        if (result < 0) new = &((*new)->rb_left);
        else if (result > 0) new = &((*new)->rb_right);
        else return -EEXIST;
    }
    rb_link_node(&new_vma->node, parent, new);
    rb_insert_color(&new_vma->node, root);
    return 0;
}

static void release_process_baseline(struct kref *kref) {
    struct process_baseline *proc_base = container_of(kref, struct process_baseline, refcount);
    struct rb_node *node;
    // pr_info("baseline_db: Releasing baseline object for PID %d\n", proc_base->pid);
    while ((node = rb_first(&proc_base->vma_tree))) {
        struct vma_baseline *vma = rb_entry(node, struct vma_baseline, node);
        rb_erase(node, &proc_base->vma_tree);
        kfree(vma->vma_path); 
        kfree(vma->hash); 
        kfree(vma);
    }
    kfree(proc_base);
}


int db_register_vma_baseline(pid_t pid, const char* vma_path, const char* hash) {
    struct process_baseline *proc_base;
    struct vma_baseline *new_vma;
    int ret = 0;

    spin_lock(&g_process_db_lock);
    proc_base = xa_load(&g_process_db, pid);
    if (!proc_base) {
        proc_base = kzalloc(sizeof(*proc_base), GFP_ATOMIC);
        if (!proc_base) {
            spin_unlock(&g_process_db_lock); 
            return -ENOMEM;
        }
        proc_base->pid = pid; 
        proc_base->vma_tree = RB_ROOT;

        init_rwsem(&proc_base->tree_lock); 
        kref_init(&proc_base->refcount);
        xa_store(&g_process_db, pid, proc_base, GFP_ATOMIC);
    }
    kref_get(&proc_base->refcount);
    spin_unlock(&g_process_db_lock);

    down_write(&proc_base->tree_lock);
    if (__find_vma_in_tree(&proc_base->vma_tree, vma_path)) {
        ret = -EEXIST;
        goto unlock_tree;
    }
    
    new_vma = kzalloc(sizeof(*new_vma), GFP_KERNEL);
    if (!new_vma) {
        ret = -ENOMEM;
        goto unlock_tree; 
    }
    new_vma->vma_path = kstrdup(vma_path, GFP_KERNEL);
    new_vma->hash = kstrdup(hash, GFP_KERNEL);
    if (!new_vma->vma_path || !new_vma->hash) {
        kfree(new_vma->vma_path); 
        kfree(new_vma->hash); 
        kfree(new_vma);
        ret = -ENOMEM; 
        goto unlock_tree;
    }
    __insert_vma_into_tree(&proc_base->vma_tree, new_vma);

unlock_tree:
    up_write(&proc_base->tree_lock);
    kref_put(&proc_base->refcount, release_process_baseline);
    return ret;
}
EXPORT_SYMBOL_GPL(db_register_vma_baseline);

int db_verify_vma_baseline(pid_t pid, const char* vma_path, const char* hash_to_verify) {
    struct process_baseline *proc_base;
    struct vma_baseline *vma;
    int ret = -ENOENT;

    spin_lock(&g_process_db_lock);
    proc_base = xa_load(&g_process_db, pid);
    if (proc_base) 
        kref_get(&proc_base->refcount);
    spin_unlock(&g_process_db_lock);
    if (!proc_base) 
        return -ENOENT;

    down_read(&proc_base->tree_lock);
    vma = __find_vma_in_tree(&proc_base->vma_tree, vma_path);
    if (!vma) {
        ret = -ENOENT; 
    } else {
        if (strcmp(vma->hash, hash_to_verify) == 0)
            ret = 0; 
        else
            ret = -EPERM;
    }
    up_read(&proc_base->tree_lock);
    kref_put(&proc_base->refcount, release_process_baseline);
    return ret;
}
EXPORT_SYMBOL_GPL(db_verify_vma_baseline);

void db_remove_process_baselines(pid_t pid) {
    struct process_baseline *proc_base;
    spin_lock(&g_process_db_lock);
    proc_base = xa_erase(&g_process_db, pid);
    spin_unlock(&g_process_db_lock);
    if (proc_base) {
        pr_debug("baseline_db: PID %d exited, queuing for cleanup.\n", pid);
        kref_put(&proc_base->refcount, release_process_baseline);
    }
}
EXPORT_SYMBOL_GPL(db_remove_process_baselines);

static int dump_show(struct seq_file *m, void *v) {
    unsigned long index; struct process_baseline *proc_base; struct vma_baseline *vma; struct rb_node *node;
    seq_puts(m, "--- Baseline DB Dump ---\n");
    xa_for_each(&g_process_db, index, proc_base) {
        down_read(&proc_base->tree_lock);
        seq_printf(m, "PID: %d (refcount: %d)\n", proc_base->pid, kref_read(&proc_base->refcount));
        for (node = rb_first(&proc_base->vma_tree); node; node = rb_next(node)) {
            vma = rb_entry(node, struct vma_baseline, node);
            seq_printf(m, "\t- VMA: %s, Hash: %s\n", vma->vma_path, vma->hash);
        }
        up_read(&proc_base->tree_lock);
    }
    seq_puts(m, "--- End of Dump ---\n");
    return 0;
}
static int dump_open(struct inode *inode, struct file *file) { return single_open(file, dump_show, NULL); }
static const struct file_operations dump_fops = {
    .owner = THIS_MODULE, .open = dump_open, .read = seq_read, .llseek = seq_lseek, .release = single_release,
};

static int __init baseline_db_init(void) {
    pr_info("baseline_db: Loading baseline database module...\n");
    if (init_exit_hook() != 0) { pr_err("baseline_db: Failed to initialize process exit hook\n"); return -1; }
    debugfs_dir = debugfs_create_dir("baseline_db", NULL);
    if (IS_ERR_OR_NULL(debugfs_dir)) {
        pr_err("baseline_db: Failed to create debugfs directory\n"); cleanup_exit_hook(); return -ENODEV;
    }
    debugfs_create_file("dump", 0444, debugfs_dir, NULL, &dump_fops);
    pr_info("baseline_db: Module loaded successfully.\n");
    return 0;
}
static void __exit baseline_db_exit(void) {
    unsigned long index; struct process_baseline *proc_base;
    pr_info("baseline_db: Unloading baseline database module...\n");
    debugfs_remove_recursive(debugfs_dir);
    cleanup_exit_hook();
    pr_info("baseline_db: Force cleaning up all remaining baselines...\n");
    pr_info("baseline_db: Clean Up All BaseValues\n");
    xa_for_each(&g_process_db, index, proc_base) {
        db_remove_process_baselines(proc_base->pid);
    }
    pr_info("baseline_db: Module unloaded.\n");
}

module_init(baseline_db_init);
module_exit(baseline_db_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dynamic_measure_baselib");