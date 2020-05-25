#ifndef ELFOP_H_
#define ELFOP_H_

#include <stdio.h>
#include "elf.h"

struct elfop_context
{
    struct elf64_hdr hdr;
};

extern int elfop_open(FILE *fp, struct elfop_context **out);
extern void elfop_close(struct elfop_context **ep);

#endif /* ELFOP_H_ */