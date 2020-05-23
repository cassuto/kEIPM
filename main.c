#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "keipm.h"

MODULE_AUTHOR ("cassuto <diyer175@hotmail.com>");
MODULE_DESCRIPTION ("kernel ELF Integrity Protection Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

static int __init keipm_init(void)
{
    printk(KERN_INFO KEIPM "%s\n", __func__);
    return 0;
}

static void __exit keipm_exit(void)
{
    printk(KERN_INFO KEIPM "%s\n", __func__);
}

module_init(keipm_init);
module_exit(keipm_exit);
