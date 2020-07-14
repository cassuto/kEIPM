#include <linux/binfmts.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/string.h>
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
 * @brief Called when kernel start to call load_elf_binary
 */
static int on_load_elf_binary(struct linux_binprm *bprm)
{
    pfn_load_elf_binary org = (pfn_load_elf_binary)p_load_elf_binary;

    int i;
    /* pointers in linux_binprm are aligned at 8 bytes boundary */
    uintptr_t *s = (uintptr_t *)bprm;

    for(i=0;i<sizeof(struct linux_binprm)/sizeof(uintptr_t);++i) {
        if(!copy_path_from_kernel(s[i], pathname)) {
            printk("tracing %s\n", pathname);
            if(strcmp(pathname, "/home/ain/tet")==0) {
                if(validator_analysis_binary(pathname)) {
                    return -ENOEXEC;
                }
            }
        }
    }

    /* normally load */
    return (*org)(bprm);
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

    printk("size=%lu\n", sizeof(struct linux_binfmt));

    pointers  =(uintptr_t *)p_elf_format;
    
    for(i=0;i<sizeof(struct linux_binfmt)/sizeof(uintptr_t);++i) {
        if (pointers[i] == p_load_elf_binary) {
            printk("found %lx at offset %x!\n", p_load_elf_binary, i);

            /* hook load_elf_binary */
            pp_elf_format_load_elf_binary = &pointers[i];
            pointers[i] = (uintptr_t)on_load_elf_binary;
        }
        if (pointers[i] == p_load_elf_library) {
            printk("found %lx at offset %x!\n", p_load_elf_library, i);
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
        watcher_hooked = false;
    }
}
