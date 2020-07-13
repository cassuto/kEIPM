#ifndef UTILS_H_
#define UTILS_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <string.h>
#endif

#define ALIGN_TO(addr,size) (((addr)+(size)-1)&(~((size)-1)))

/*
 * reader.c
 */
#ifdef __KERNEL__
#include <linux/fs.h>
typedef struct file * util_fp_t;
typedef loff_t util_off_t;
#else
#include <stdio.h>
typedef FILE * util_fp_t;
typedef long int util_off_t;
#endif

extern ssize_t util_read(util_fp_t fp, void *buf, size_t size, util_off_t *pos);
#ifndef __KERNEL__
extern ssize_t util_write(util_fp_t fp, const void *buf, size_t size, util_off_t *pos);
#endif

#ifdef __KERNEL__
# include <linux/slab.h>
# define util_new(_s) kmalloc(_s, GFP_KERNEL)
# define util_delete(_ptr) kfree(_ptr)
#else
# include <stdlib.h>
# define util_new(_s) malloc(_s)
# define util_delete(_ptr) do { if(_ptr) free(_ptr); } while(0)
#endif

/* IMPORTANT! it is danger to pass non-variable arguments to MAX/MIN*/
#ifndef MAX
#define MAX(a, b) (((a) < (b)) ? b : a)
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? a : b)
#endif

#endif // UTILS_H_
