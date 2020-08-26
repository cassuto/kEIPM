#ifndef UTILS_H_
#define UTILS_H_

#include <linux/types.h>

#ifdef __KERNEL__
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
extern size_t util_filesize(util_fp_t fp);
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


#ifndef __KERNEL__
    typedef uint8_t u8;
    typedef uint16_t u16;
    typedef uint32_t u32;
    typedef uint64_t u64;
    typedef int8_t s8;
    typedef int16_t s16;
    typedef int32_t s32;
    typedef int64_t s64;

#   ifndef EPERM
#   define EPERM 1
#   endif

#   ifndef unlikely
#   define unlikely(_x) (_x)
#   endif

#endif

#endif // UTILS_H_
