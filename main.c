#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "keipm.h"
#include "watcher.h"
#include "validator.h"
#include "builtin/ca.h"
#include "builtin/private_pkcs1.h"

MODULE_AUTHOR ("cassuto <diyer175@hotmail.com>");
MODULE_DESCRIPTION ("kernel ELF Integrity Protection Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

static int __init keipm_init(void)
{
#define FAIL_ON_ERROR(_x) do { \
    keipm_err_t _ret = (_x); \
    if(_ret.errno != kEIPM_OK) { \
        printk(KERN_ERR kEIPM "%s", _ret.reason); \
        return 1; \
    } \
}while(0)

    printk(KERN_INFO kEIPM "%s\n", __func__);
    
    // FAIL_ON_ERROR(watcher_init());

    validator_init();

    // Add root cert
    FAIL_ON_ERROR(validator_add_root_cert("kEIPM", g_ca, g_cbca));
    // Set built-in private key
    FAIL_ON_ERROR(validator_add_pubkey("kEIPM", g_private_pkcs1, g_cbprivate_pkcs1));

    return 0;
}

static void __exit keipm_exit(void)
{
    printk(KERN_INFO kEIPM "%s\n", __func__);
    /*watcher_uninit();*/
}

module_init(keipm_init);
module_exit(keipm_exit);
