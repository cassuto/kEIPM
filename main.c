/*
 *  kEIPM (kerenl ELF Integrity Protection Module)
 *  Copyright (C) 2020 cassuto <diyer175@hotmail.com> & KingOfSmail
 * 
 *  This project is free edition; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public             
 *  License(GPL) as published by the Free Software Foundation; either      
 *  version 2.1 of the License, or (at your option) any later version.     
 *                                                                         
 *  This project is distributed in the hope that it will be useful,        
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      
 *  Lesser General Public License for more details.                        
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "keipm.h"
#include "watcher.h"
#include "validator.h"
#include "builtin/ca.h"
#include "builtin/public_pkcs1.h"

MODULE_AUTHOR ("cassuto <diyer175@hotmail.com>");
MODULE_DESCRIPTION ("kernel ELF Integrity Protection Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

static int __init keipm_init(void)
{
#define TRACE_ERROR(_x) do { \
    keipm_err_t _ret = (_x); \
    if(_ret.errno != kEIPM_OK) { \
        printk(KERN_ERR kEIPM "%s", _ret.reason); \
    } \
}while(0)

    printk(KERN_INFO kEIPM "%s\n", __func__);
    
    validator_init();

    /* Add root cert */
    TRACE_ERROR(validator_add_root_cert("kEIPM", g_ca, g_cbca));
    /* Set built-in private key */
    TRACE_ERROR(validator_add_pubkey("kEIPM", g_public_pkcs1, g_cbpublic_pkcs1));

    validator_analysis_binary("/home/ain/test");

    //TRACE_ERROR(watcher_init());
    return 0;
}

static void __exit keipm_exit(void)
{
    printk(KERN_INFO kEIPM "%s\n", __func__);
    //watcher_uninit();
}

module_init(keipm_init);
module_exit(keipm_exit);
