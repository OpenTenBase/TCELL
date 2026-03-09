#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/err.h>

#include "baselib_dyn_api.h"
#include "process_exit_hook.h"

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    db_remove_process_baselines(current->pid);
    return 0;
}

static struct kprobe kp = {
    .symbol_name    = "do_exit",
    .pre_handler    = handler_pre,
};

int init_exit_hook(void)
{
    int ret;
    pr_info("process_exit_hook: Registering kprobe on do_exit...\n");
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("process_exit_hook: register_kprobe failed, ret %d\n", ret);
        return ret;
    }
    pr_info("process_exit_hook: Kprobe registered successfully.\n");
    return 0;
}

void cleanup_exit_hook(void)
{
    unregister_kprobe(&kp);
    // pr_info("process_exit_hook: Kprobe unregistered.\n");
}