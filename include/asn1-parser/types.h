#pragma once

#ifdef __KERNEL__
# include <linux/kernel.h>
# include <linux/types.h>
# include <linux/string.h>
# undef assert
# define assert(_x) (void)(_x)
#else
# include <stdint.h>
# include <stdarg.h>
# include <stdbool.h>
# include <stdio.h>
# include <string.h>
#endif