#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "keipm.h"
#include "watcher.h"
#include "cert-validator.h"
#include "data/ca.h"

MODULE_AUTHOR ("cassuto <diyer175@hotmail.com>");
MODULE_DESCRIPTION ("kernel ELF Integrity Protection Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

struct cert g_cert;

static int __init keipm_init(void)
{
    keipm_err_t err;
    printk(KERN_INFO KEIPM "%s\n", __func__);
    
    /*err = watcher_init();
    if (err.errno != kEIPM_OK) {
        return 1;
    }*/
    cert_init(&g_cert);

    // Add root cert
    err = cert_add_ca(&g_cert, g_ca, g_cbca);
    if (err.errno != kEIPM_OK) {
        return 1;
    }

    return 0;
}

static void __exit keipm_exit(void)
{
    printk(KERN_INFO KEIPM "%s\n", __func__);
    /*watcher_uninit();*/
}

module_init(keipm_init);
module_exit(keipm_exit);
