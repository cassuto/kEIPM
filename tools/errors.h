#ifndef ERRORS_H_
#define ERRORS_H_

#include <errno.h>

#define EEELFOP 100
#define EENOTCLASS64 (EEELFOP+1) /* Not a 64 bit ELF file */
#define EESECTION_EXISTED (EEELFOP+2) /* Section is Existed */

#endif /* ERRORS_H_ */