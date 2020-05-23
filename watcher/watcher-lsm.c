#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include "ksyms.h"
#include "watcher-lsm.h"

typedef void (*security_add_hooks_t)(struct security_hook_list *hooks, int count, char *lsm);

static unsigned long long count = 0;

int on_bprm_check_security(struct linux_binprm *bprm)
{
    printk("[]  call bprm_check_security(). count=%llu\n", ++count);    
    return 0;
}

static struct security_hook_list hooks[] = {
    LSM_HOOK_INIT(bprm_check_security, on_bprm_check_security),
};

int watcher_lsm_hook(void)
{
    security_add_hooks_t *add_hooks = find_kernel_entry("security_add_hooks");
    if (!add_hooks) {
        return 1;
    }
    (*add_hooks)(hooks, ARRAY_SIZE(hooks), "kEIPM");
    return 0;
}
