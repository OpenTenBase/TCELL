#ifndef __BASELIB_DYN_API_H__
#define __BASELIB_DYN_API_H__

#include <linux/types.h>

/**
 * @brief Registers a new VMA baseline.
 * If the baseline already exists, this function returns -EEXIST and does not modify the existing baseline.
 *
 * @param pid The PID of the target process.
 * @param vma_path The file path corresponding to the VMA.
 * @param hash The baseline hash value to be registered.
 * @return 0 on success, or -EEXIST if the baseline already exists.
 */
int db_register_vma_baseline(pid_t pid, const char* vma_path, const char* hash);

/**
 * @brief Verifies whether the current hash of a VMA matches its baseline.
 * This is the core calling interface of the dynamic measurement module.
 *
 * @param pid The PID of the target process.
 * @param vma_path The file path corresponding to the VMA.
 * @param hash_to_verify The currently calculated hash value to be verified.
 * @return 0 on successful verification, -EPERM if verification fails, or -ENOENT if the baseline does not exist.
 */
int db_verify_vma_baseline(pid_t pid, const char* vma_path, const char* hash_to_verify);

/**
 * @brief Removes all baselines associated with a process.
 *
 * @param pid The PID of the target process.
 */
void db_remove_process_baselines(pid_t pid);

#endif // __BASELIB_DYN_API_H__
