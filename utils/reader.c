#include "utils.h"
#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <stdio.h>
#endif

ssize_t util_read(util_fp_t fp, void *buf, size_t size, util_off_t *pos)
{
#ifdef __KERNEL__
    return kernel_read(fp, buf, size, pos);
#else
    fseek(fp, *pos, SEEK_SET);
    ssize_t len = fread(buf, 1, size, fp);
    *pos = ftell(fp);
    return len;
#endif
}

#ifndef __KERNEL__
extern ssize_t util_write(util_fp_t fp, const void *buf, size_t size, util_off_t *pos)
{
    fseek(fp, *pos, SEEK_SET);
    ssize_t len = fwrite(buf, 1, size, fp);
    *pos = ftell(fp);
    return len;
}
#endif
