#ifndef ERRORS_H_
#define ERRORS_H_

#include <errno.h>

#define EEFAULT 100
#define EENOTCLASS64 (EEFAULT+1) /* Not a 64 bit ELF file */

#endif /* ERRORS_H_ */