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
#include "builtin/builtin.h"

MODULE_AUTHOR ("cassuto <diyer175@hotmail.com>");
MODULE_DESCRIPTION ("kernel ELF Integrity Protection Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

static void trace_error(keipm_err_t err);

static int __init keipm_init(void)
{
    size_t i;

    /* banner */
    printk(KERN_INFO kEIPM "module loaded.\n");
    
    validator_init();

    /*
     * Load built-in certificates or RSA public keys
     */
    for(i=0;i<builtin_num; ++i) {
        keipm_err_t err;
        const char *typestr = "unknown";
        switch (builtin_list[i].type) {
            case BUILTIN_RSA_PUBKEY:
                typestr = "RSA pubkey";
                err = validator_add_pubkey(builtin_list[i].issuer, builtin_list[i].data, builtin_list[i].length);
                break;
            case BUILTIN_CERT:
                typestr = "certificate";
                err = validator_add_root_cert(builtin_list[i].issuer, builtin_list[i].data, builtin_list[i].length);
                break;
            default:
                continue;
        }
        if (err.errno == kEIPM_OK) {
            printk(KERN_INFO kEIPM "Loaded built-in: %s - %s\n", typestr, builtin_list[i].issuer);
        } else {
            trace_error(err);
        }
    }

    trace_error(watcher_init());
    return 0;
}

static void __exit keipm_exit(void)
{
    printk(KERN_INFO kEIPM "%s\n", __func__);
    watcher_uninit();
}

module_init(keipm_init);
module_exit(keipm_exit);

static void trace_error(keipm_err_t err)
{
    if(err.errno != kEIPM_OK) {
        printk(KERN_ERR kEIPM "%s", err.reason);
    }
}

