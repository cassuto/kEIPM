#ifndef ELFOP_H_
#define ELFOP_H_

#include <stdio.h>
#include "elf.h"

struct elfop_context
{
    struct elf64_hdr hdr;
    struct elf64_phdr *phdrs;
    struct elf64_shdr *shdrs;
    FILE *fp;
};

extern int elfop_open(FILE *fp, struct elfop_context **out);
extern void elfop_close(struct elfop_context **ep);
extern int elfop_read_phdr(struct elfop_context *ep);
extern int elfop_find_section(struct elfop_context *ep, const char *name, Elf64_Off type, Elf64_Off *out);
extern int elfop_add_section(struct elfop_context *ep, const char *name, Elf64_Off type, const void *data, size_t dsize);

/*
 * elf-reader.c
 */
extern int elfop_read(struct elfop_context *ep, void *buf, size_t size);
extern void elfop_seek(struct elfop_context *ep, long offset);
extern long elfop_size(struct elfop_context *ep);

#define elfop_new(_s) malloc(_s)
#define elfop_delete(_ptr) free(_ptr)

#define ELFOP_SECTION_NAME_MAX 32

#endif /* ELFOP_H_ */