#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/sched/task.h>

#include "../dynamic_baselib/baselib_dyn_api.h"
#include "vma_hash_calculator.h"

static int scan_interval_sec = 30;
module_param(scan_interval_sec, int, 0644);
MODULE_PARM_DESC(scan_interval_sec, "Interval in seconds between periodic scans (default: 30)");

static struct task_struct *scanner_thread;

static int process_single_vma(struct task_struct *task_ref,
                             struct mm_struct *mm,
                             struct vm_area_struct *vma,
                             char *vma_path_buf,
                             char *hash_hex_buf,
                             int *process_had_error)
{
    char *path_str;
    int ret;

    if (!(vma->vm_flags & VM_EXEC) || !vma->vm_file) {
        return 0;
    }

    path_str = d_path(&vma->vm_file->f_path, vma_path_buf, PATH_MAX);
    if (IS_ERR(path_str)) {
        return 0;
    }

    ret = calculate_vma_hash(task_ref, mm, vma, hash_hex_buf);
    if (ret != 0) {
        pr_err("dynamic_measure: Failed to calculate hash for PID %d VMA %s (error %d) during scan.\n",
               task_ref->pid, path_str, ret);
        return 0;
    }

    ret = db_verify_vma_baseline(task_ref->pid, path_str, hash_hex_buf);

    if (ret == -EPERM) {
        pr_alert("\n"
                 "******************************************************************\n"
                 "!!!          INTEGRITY CHECK FAILED (THREAT DETECTED)          !!!\n"
                 "******************************************************************\n"
                 "* PID:      %d\n"
                 "* Process:  %s\n"
                 "* VMA Path: %s\n"
                 "* REASON:   HASH MISMATCH\n"
                 "* ACTION:   TERMINATING PROCESS (SIGKILL)\n"
                 "******************************************************************\n",
                 task_ref->pid, task_ref->comm, path_str);

        // send_sig(SIGKILL, task_ref, 1);
        *process_had_error = 1;
        return -1;
    } else if (ret == -ENOENT) {
        ret = db_register_vma_baseline(task_ref->pid, path_str, hash_hex_buf);
        if (ret != 0 && ret != -EEXIST) {
            pr_err("dynamic_measure: Failed to register TOFU baseline for PID %d, VMA %s (error %d)\n",
                   task_ref->pid, path_str, ret);
        }
    } else if (ret != 0) {
        pr_err("dynamic_measure: Error verifying baseline for PID %d, VMA %s (error %d)\n",
               task_ref->pid, path_str, ret);
    }
    return 0;
}

static int measure_process_vmas(struct task_struct *task_ref,
                               int *processes_with_errors)
{
    struct mm_struct *mm = NULL;
    struct vm_area_struct *vma;
    char *vma_path_buf = NULL;
    char hash_hex_buf[SM3_HEX_DIGEST_BUF_SIZE];
    int process_had_error = 0;
    int ret = 0;

    vma_path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!vma_path_buf) {
        pr_err("dynamic_measure: Failed to allocate path buffer for PID %d.\n", task_ref->pid);
        return -ENOMEM;
    }

    mm = get_task_mm(task_ref);
    if (!mm) {
        kfree(vma_path_buf);
        return -ESRCH;
    }

    mmap_read_lock(mm);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        struct vma_iterator vmi;
        vma_iter_init(&vmi, mm, 0);
        for_each_vma(vmi, vma) {
    #else
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
    #endif
        ret = process_single_vma(task_ref, mm, vma, vma_path_buf, hash_hex_buf, &process_had_error);
        if (ret == -1) {
            break;
        }
    }
    mmap_read_unlock(mm);

    if (process_had_error) {
        (*processes_with_errors)++;
    }

    mmput(mm);
    kfree(vma_path_buf);

    return 0;
}

static int handle_initial_process_scan(struct task_struct *task_ref,
                                      int *initial_scan_errors)
{
    if (task_ref->mm) {
        if (establish_baseline_for_task(task_ref) != 0) {
            (*initial_scan_errors)++;
        }
        return 1;
    }
    return 0;
}

static int perform_initial_scan(int *initial_scan_errors)
{
    struct task_struct *p;
    struct task_struct *task_ref;

    pr_info("dynamic_measure: Starting initial scan...\n");
    rcu_read_lock();

    for_each_process(p) {
        get_task_struct(p);
        task_ref = p;
        if (!task_ref) continue;

        if (strstr(task_ref->comm, "postgres") == NULL && strstr(task_ref->comm, "mysqld") == NULL) { 
            put_task_struct(task_ref);
            continue;
        }

        if (handle_initial_process_scan(task_ref, initial_scan_errors)) {
            rcu_read_unlock();

            put_task_struct(task_ref);

            if (msleep_interruptible(1)) {
                pr_info("dynamic_measure: Initial scan interrupted.\n");
                if (kthread_should_stop()) {
                    rcu_read_lock();
                    return -1;
                }
            }
            rcu_read_lock();
        } else {
            put_task_struct(task_ref);
        }
    }
    rcu_read_unlock();

    return 0;
}

static int handle_periodic_process_scan(struct task_struct *task_ref,
                                       int *total_processes_measured_in_cycle,
                                       int *processes_with_errors)
{
    struct mm_struct *mm = NULL;

    mm = get_task_mm(task_ref);
    if (!mm) {
        put_task_struct(task_ref);
        return -1;
    }

    (*total_processes_measured_in_cycle)++;
    measure_process_vmas(task_ref, processes_with_errors);

    mmput(mm);
    return 0;
}

static int perform_periodic_scan(int *total_processes_measured_in_cycle,
                                int *processes_with_errors)
{
    struct task_struct *p;

    rcu_read_lock();
    for_each_process(p) {
        struct task_struct *task_ref;

        // task_ref = find_task_by_vpid(p->pid);
        get_task_struct(p);
        task_ref = p;
        if (!task_ref) continue;

        if (strstr(task_ref->comm, "postgres") == NULL) {
            put_task_struct(task_ref);
            continue;
        }

        rcu_read_unlock();
        if (handle_periodic_process_scan(task_ref, total_processes_measured_in_cycle, processes_with_errors) == -1) {
            rcu_read_lock();
            continue;
        }
        put_task_struct(task_ref);

        if (msleep_interruptible(1)) {
             pr_info("dynamic_measure: Periodic scan interrupted during process loop.\n");
             if (kthread_should_stop()) {
                 return -1;
             }
        }

        rcu_read_lock();
    }
    rcu_read_unlock();

    return 0;
}

static int scanner_thread_func(void *data)
{
    int initial_scan_errors = 0;
    int total_processes_measured_in_cycle = 0;
    int processes_with_errors_in_cycle = 0;
    int ret;

    pr_info("dynamic_measure: Scanner thread started (PID %d).\n", current->pid);

    ret = perform_initial_scan(&initial_scan_errors);
    if (ret == -1) {
        goto exit_scan;
    }

    pr_info("dynamic_measure: Initial scan complete. %d process(es) encountered errors during baseline registration.\n",
            initial_scan_errors);
    pr_info("dynamic_measure: Starting periodic scan loop (interval %d seconds).\n", scan_interval_sec);

    while (!kthread_should_stop()) {
        if (msleep_interruptible(scan_interval_sec * 1000)) {
            if (kthread_should_stop()) {
                break;
            }
        }

        total_processes_measured_in_cycle = 0;
        processes_with_errors_in_cycle = 0;

        ret = perform_periodic_scan(&total_processes_measured_in_cycle, &processes_with_errors_in_cycle);
        if (ret == -1) {
            goto exit_scan;
        }

        pr_info("dynamic_measure: Periodic scan cycle complete. Measured %d processes, %d process(es) had integrity errors.\n",
                total_processes_measured_in_cycle, processes_with_errors_in_cycle);
    }

exit_scan:
    pr_info("dynamic_measure: Scanner thread stopping.\n");
    return 0;
}

static int __init dynamic_measure_init(void)
{
    int ret = 0;

    pr_alert("!!!!!!!!!! DYNAMIC MEASURE INIT ENTRY !!!!!!!!!!\n");
    pr_info("dynamic_measure: Loading module...\n");

    scanner_thread = kthread_run(scanner_thread_func, NULL, "kmeasure_scanner");
    if (IS_ERR(scanner_thread)) {
        pr_err("dynamic_measure: Failed to create scanner thread. Error code: %ld\n", PTR_ERR(scanner_thread));
        pr_alert("!!!!!!!!!! KTHREAD_RUN FAILED !!!!!!!!!!\n");
        ret = PTR_ERR(scanner_thread);
    } else {
         pr_info("dynamic_measure: Scanner thread created successfully.\n");
    }

    if (ret == 0) {
         pr_info("dynamic_measure: Module loaded successfully.\n");
    } else {
         pr_alert("!!!!!!!!!! MODULE INIT FAILED (ret=%d) !!!!!!!!!!\n", ret);
    }

    return ret;
}

static void __exit dynamic_measure_exit(void)
{
    if (scanner_thread) {
        kthread_stop(scanner_thread);
        pr_info("dynamic_measure: Scanner thread stopped.\n");
    }
    pr_info("dynamic_measure: Module unloaded.\n");
}

module_init(dynamic_measure_init);
module_exit(dynamic_measure_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dynamic_measure");