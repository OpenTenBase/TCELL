#ifndef __PROCESS_EXIT_HOOK_H__
#define __PROCESS_EXIT_HOOK_H__

/**
 * @brief Initializes the process exit hook.
 * @return 0 on success, or a negative error code on failure.
 */
int init_exit_hook(void);

/**
 * @brief Cleans up the process exit hook.
 */
void cleanup_exit_hook(void);

#endif // __PROCESS_EXIT_HOOK_H__