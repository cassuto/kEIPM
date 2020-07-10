#include "utils.h"
#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <stdio.h>
#endif

size_t util_read(util_fp_t fp, void *buf, size_t size, util_off_t *pos)
{
#ifdef __KERNEL__
    return kernel_read(fp, buf, size, pos);
#else
    fseek(fp, *pos, SEEK_SET);
    size_t len = fread(buf, 1, size, fp);
    *pos = ftell(fp);
    return len;
#endif
}
