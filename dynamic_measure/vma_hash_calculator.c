#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/highmem.h>

#include "../dynamic_baselib/baselib_dyn_api.h"
#include "../include/sm3.h"
#include "vma_hash_calculator.h"
#include <linux/module.h>

#define BATCH_SIZE 256

static void sm3_hash_to_hex(unsigned int *hash, char *hex_out)
{
    int i;
    for (i = 0; i < 8; i++) {
        snprintf(hex_out + (i * 8), 9, "%08x", hash[i]);
    }
    hex_out[SM3_HEX_DIGEST_STRLEN] = '\0';
}

int calculate_vma_hash(struct task_struct *task, struct mm_struct *mm, struct vm_area_struct *vma, char *out_hash_hex)
{
    unsigned long addr = vma->vm_start;
    unsigned long end_addr = vma->vm_end;
    unsigned long total_pages;
    unsigned long vma_size;
    sm3_context sm3_ctx;
    unsigned int final_hash[8];

    struct page *pages[BATCH_SIZE];
    int batch_pages;
    int ret;
    int i;
    int total_processed = 0;

    if (addr >= end_addr) return 0;
    
    vma_size = end_addr - addr;
    total_pages = (vma_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if (total_pages == 0) return 0;

    pr_debug("vma_hash_calc: Processing VMA 0x%lx-0x%lx (%lu pages, %lu bytes)\n", 
             addr, end_addr, total_pages, vma_size);

    SM3_init(&sm3_ctx);


    while (addr < end_addr) {
        unsigned long remaining_size = end_addr - addr;
        unsigned long remaining_pages = (remaining_size + PAGE_SIZE - 1) / PAGE_SIZE;
        batch_pages = (int)min((unsigned long)BATCH_SIZE, remaining_pages);
        
        pr_debug("vma_hash_calc: Processing batch at 0x%lx, %d pages\n", addr, batch_pages);
        
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
            ret = get_user_pages_remote(mm, addr, batch_pages, 0, pages, NULL);
        #else
            ret = get_user_pages_remote(task, mm, addr, batch_pages, 0, pages, NULL, NULL);
        #endif

        if (ret < 0) {
            pr_err("vma_hash_calc: get_user_pages_remote failed at 0x%lx with error %d\n", 
                   addr, ret);
            return ret;
        }

        if (ret < batch_pages) {
            pr_warn("vma_hash_calc: Could not get all pages for VMA 0x%lx (got %d, expected %d)\n", 
                    addr, ret, batch_pages);
            for (i = 0; i < ret; i++) {
                put_page(pages[i]);
            }
            return -EFAULT;
        }

        for (i = 0; i < batch_pages; i++) {
            void *page_addr;
            size_t bytes_to_hash = PAGE_SIZE;
            unsigned long current_addr = addr + (i * PAGE_SIZE);
            
            if (current_addr + PAGE_SIZE > end_addr) {
                bytes_to_hash = end_addr - current_addr;
                pr_debug("vma_hash_calc: Last page at 0x%lx, only hashing %zu bytes\n", 
                        current_addr, bytes_to_hash);
            }
            
            page_addr = kmap(pages[i]);
            if (!page_addr) {
                pr_err("vma_hash_calc: kmap failed for page at 0x%lx\n", current_addr);
                put_page(pages[i]);
                while (++i < batch_pages) {
                    put_page(pages[i]);
                }
                return -EFAULT;
            }
            
            SM3_update(&sm3_ctx, page_addr, bytes_to_hash);
            
            kunmap(pages[i]);
            put_page(pages[i]);
            
            total_processed++;
        }
        
        addr += batch_pages * PAGE_SIZE;
        
        cond_resched();
    }

    SM3_final(&sm3_ctx, final_hash);
    sm3_hash_to_hex(final_hash, out_hash_hex);

    return 0;
}

int establish_baseline_for_task(struct task_struct *task)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char *vma_path_buf = NULL;
    char hash_hex_buf[SM3_HEX_DIGEST_BUF_SIZE];
    int ret = 0;
    int registration_errors = 0;

    if (!task) return -EINVAL;
    
    mm = get_task_mm(task);
    if (!mm) {
        return -ESRCH;
    }

    vma_path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!vma_path_buf) {
        mmput(mm); 
        return -ENOMEM;
    }
    
    pr_info("baseline: Establishing baseline for PID %d (%s)\n", task->pid, task->comm);

    mmap_read_lock(mm);
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        struct vma_iterator vmi;
        vma_iter_init(&vmi, mm, 0);
        for_each_vma(vmi, vma) {
    #else
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
    #endif
        char *path_str;

        if (!(vma->vm_flags & VM_EXEC) || !vma->vm_file) {
            continue;
        }
        
        path_str = d_path(&vma->vm_file->f_path, vma_path_buf, PATH_MAX);
        if (IS_ERR(path_str)) {
            continue;
        }
        
        ret = calculate_vma_hash(task, mm, vma, hash_hex_buf);
        if (ret == 0) {
            // pr_info("  -> VMA Path: %s, Hash: %s\n", path_str, hash_hex_buf);
            
            ret = db_register_vma_baseline(task->pid, path_str, hash_hex_buf);
            if (ret == -EEXIST) {
                pr_debug("baseline: Baseline for PID %d, VMA %s already exists. Skipping.\n", task->pid, path_str);
            } else if (ret != 0) {
                pr_err("baseline: Failed to register baseline for PID %d, VMA %s (error %d)\n", task->pid, path_str, ret);
                registration_errors++;
            }
        } else {
            pr_err("baseline: Failed to calculate hash for VMA %s (error %d)\n", path_str, ret);
            registration_errors++;
        }
    }
    mmap_read_unlock(mm);

    kfree(vma_path_buf);
    mmput(mm); 
    
    return registration_errors > 0 ? -EIO : 0;
}
MODULE_LICENSE("GPL");