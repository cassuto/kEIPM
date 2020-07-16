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
#include <linux/binfmts.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm/page.h>
#include "ksyms.h"
#include "validator.h"
#include "keipm.h"
#include "watcher.h"

static uintptr_t p_load_elf_binary;
static uintptr_t p_load_elf_library;
static uintptr_t *pp_elf_format_load_elf_binary, *pp_elf_format_load_elf_library;
static char pathname[PATH_MAX];
static bool watcher_hooked = false;

typedef int (*pfn_load_elf_binary)(struct linux_binprm *bprm);
typedef int (*pfn_load_elf_library)(struct file *file);

/**
 * @brief Trying to copy pathname from the kernel
 * @param ptr Potential address of pathname
 * @param buf Where to store the result.
 * @retval 0 if it may be a pathname string.
 * @retval otherwise, impossible to be a pathname.
 */
static int copy_path_from_kernel(uintptr_t ptr, char buf[PATH_MAX])
{
    char *dst = buf;
    const char *s = (const char *)ptr;
    int count = 0;
    if(ptr < PAGE_OFFSET) { /* check if a kernel pointer */
        return -EFAULT;
    }
    if(*s!='/') { /* check if is a pathname */
        return -EFAULT;
    }
    while(*s && count<PATH_MAX) {
        *dst++ = *s++;
        ++count;
    }
    buf[count] = '\0';
    return 0;
}

/**
 * @brief Hooker handler of kernel load_elf_binary()
 */
static int on_load_elf_binary(struct linux_binprm *bprm)
{
    size_t num_traced_pathname = 0;
    const char *traced_file;
    pfn_load_elf_binary org = (pfn_load_elf_binary)p_load_elf_binary;
    size_t i;
    struct file *file;

    /* pointers in linux_binprm are aligned at 8 bytes boundary */
    uintptr_t *s = (uintptr_t *)bprm;

    for(i=0;i<sizeof(struct linux_binprm)/sizeof(uintptr_t);++i) {
        if(!copy_path_from_kernel(s[i], pathname)) {
            /*
             * Check whether this pathname has been already processed.
             * This is because linux_binprm takes two fields to hold 
             * the pathname of executables: 'filename' and 'interp'.
             * Most of the time interp is same as filename, but could be different
             * for binfmt_{misc,script}.
             */
            if (++num_traced_pathname > 1) {
                if(strcmp(pathname,traced_file) == 0) {
                    break;
                }
            }
            traced_file = pathname;
            if (verify_fs(pathname).errno ==kEIPM_OK) {
                /*
                * Parse the traced file
                * that file indicated by pathname may be not an ELF.
                */
                file = filp_open(pathname, O_LARGEFILE | O_RDONLY, S_IRUSR);
                if (IS_ERR(file)) {
                    return 0;
                }
                if(validator_analysis_binary(file)) {
                    filp_close(file, NULL);
                    printk("%s signature invalid", pathname);
                    return -EPERM;
                }
                filp_close(file, NULL);
            }
        }
    }

    /* normally load */
    return (*org)(bprm);
}

/**
 * @brief Hooker handler of kernel load_elf_library()
 */
static int on_load_elf_library(struct file *file)
{
    pfn_load_elf_library org = (pfn_load_elf_library)p_load_elf_library;
    return (*org)(file);
}

keipm_err_t watcher_init(void)
{
    int i=0;
    uintptr_t *pointers;
    uintptr_t p_elf_format;
    
    if (watcher_hooked) {
        return ERROR(kEIPM_OK, NULL);
    }

    p_elf_format = (uintptr_t)find_kernel_entry("elf_format");
    p_load_elf_binary = (uintptr_t)find_kernel_entry("load_elf_binary");
    p_load_elf_library = (uintptr_t)find_kernel_entry("load_elf_library");
    
    if(!p_elf_format || !p_load_elf_binary) {
        return ERROR(kEIPM_ERR_UNSUPPORTED, "Unrecognized kernel version");
    }

    pointers = (uintptr_t *)p_elf_format;
    
    for(i=0;i<sizeof(struct linux_binfmt)/sizeof(uintptr_t);++i) {
        if (pointers[i] == p_load_elf_binary) {

            /* hook load_elf_binary() */
            pp_elf_format_load_elf_binary = &pointers[i];
            pointers[i] = (uintptr_t)on_load_elf_binary;
        }
        if (pointers[i] == p_load_elf_library) {
            
            /* hook load_elf_library() */
            pp_elf_format_load_elf_library = &pointers[i];
            pointers[i] = (uintptr_t)on_load_elf_library;
        }
    }

    watcher_hooked = true;
    return ERROR(kEIPM_OK, NULL);
}

void watcher_uninit(void)
{
    if (watcher_hooked) {
        /* unhook load_elf_binary */
        *pp_elf_format_load_elf_binary = p_load_elf_binary;
        *pp_elf_format_load_elf_library = p_load_elf_library;
        watcher_hooked = false;
    }
}
