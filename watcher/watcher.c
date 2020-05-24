#include <linux/binfmts.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <asm/page.h>
#include "ksyms.h"
#include "keipm.h"
#include "watcher.h"

static uintptr_t p_load_elf_binary;
static uintptr_t p_load_elf_library;
static uintptr_t *pp_elf_format_load_elf_binary, *pp_elf_format_load_elf_library;

static char pathname[PATH_MAX];

typedef int (*pfn_load_elf_binary)(struct linux_binprm *bprm);

static int analysis_binary(const char *pathname)
{
    char buf[32];
    loff_t pos = 0;
    int retval;
    struct file *file = filp_open(pathname, O_LARGEFILE | O_RDONLY, S_IRUSR);
    if (IS_ERR(file)) {
        return 0;
    }
    retval = kernel_read(file, buf, sizeof(buf), &pos);
	if (retval != sizeof(buf)) {
        printk("kernel_read failed.\n");
        return 0;
	}
    if (memcmp(buf, ELFMAG, SELFMAG) == 0) {
        printk("Tracing ELF %s\n", pathname);
    }
    filp_close(file, NULL);
    return 0;
}

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
    uintptr_t *s = (uintptr_t *)bprm;

    for(i=0;i<sizeof(struct linux_binprm)/sizeof(uintptr_t);++i) {
        if(!copy_path_from_kernel(s[i], pathname)) {
            if(analysis_binary(pathname)) {
                return -ENOEXEC;
            }
        }
    }

    return (*org)(bprm);
}

int watcher_init(void)
{
    int i=0;
    uintptr_t *pointers;
    uintptr_t p_elf_format = (uintptr_t)find_kernel_entry("elf_format");
    p_load_elf_binary = (uintptr_t)find_kernel_entry("load_elf_binary");
    p_load_elf_library = (uintptr_t)find_kernel_entry("load_elf_library");
    
    if(!p_elf_format || !p_load_elf_binary) {
        printk("Unrecognized kernel version!\n");
        return 0;
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

    return 0;
}

void watcher_uninit(void)
{
    /* unhook load_elf_binary */
    *pp_elf_format_load_elf_binary = p_load_elf_binary;
}
