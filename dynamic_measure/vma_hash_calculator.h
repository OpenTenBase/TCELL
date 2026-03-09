#ifndef __VMA_HASH_CALCULATOR_H__
#define __VMA_HASH_CALCULATOR_H__

#define SM3_HEX_DIGEST_STRLEN 64
#define SM3_HEX_DIGEST_BUF_SIZE (SM3_HEX_DIGEST_STRLEN + 1)
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#ifndef mmap_read_lock
#define mmap_read_lock(mm)      down_read(&(mm)->mmap_sem)
#define mmap_read_unlock(mm)    up_read(&(mm)->mmap_sem)
#define mmap_write_lock(mm)     down_write(&(mm)->mmap_sem)
#define mmap_write_unlock(mm)   up_write(&(mm)->mmap_sem)
#endif
#endif
/**
 * @brief Calculates the SM3 hash value of a single VMA.
 * @param task The target process task_struct.
 * @param mm The mm_struct of the target process.
 * @param vma The VMA for which the hash is to be calculated.
 * @param out_hash_hex Buffer to store the resulting hex string of the hash.
 * @return 0 on success, or a negative error code on failure.
 */
int calculate_vma_hash(struct task_struct *task, struct mm_struct *mm, struct vm_area_struct *vma, char *out_hash_hex);

/**
 * @brief Establishes a complete initial baseline for a given task.
 * Calculates the hash value for each VMA and registers them into the baseline library by calling the module's API.
 * @param task The target process task_struct.
 * @return 0 on success, or a negative error code on failure.
 */
int establish_baseline_for_task(struct task_struct *task);

#endif // __VMA_HASH_CALCULATOR_H__