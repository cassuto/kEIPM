#ifndef UTILS_H_
#define UTILS_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * reader.c
 */
typedef void * util_fp_t;
#ifdef __KERNEL__
typedef long long util_off_t;
#else
typedef long util_off_t;
#endif

extern util_fp_t util_open_rd(const char *filename);
extern size_t util_read(util_fp_t fp, void *buf, size_t size, util_off_t *pos);

#ifdef __KERNEL__
# include <linux/slab.h>
# define util_new(_s) kmalloc(_s, GFP_KERNEL)
# define util_delete(_ptr) kfree(_ptr)
#else
# define util_new(_s) malloc(_s)
# define util_delete(_ptr) free(_ptr)
#endif

#endif // UTILS_H_
