#ifndef KEIPM_ELF_OP_H_
#define KEIPM_ELF_OP_H_

#include "elf.h"
#include "errors.h"
#include "utils.h"

#define ELF64_FILE_ALIGN 8 /* byte */

struct elf_parser {
    struct elf64_hdr hdr;
    util_fp_t fp;
#ifndef __KERNEL__
    struct elf64_shdr *shdrs;
#endif
};

extern void elf_setfile(struct elf_parser *parser, util_fp_t fp);
extern keipm_err_t elf_parse(struct elf_parser *parser);
extern keipm_err_t elf_find_section(struct elf_parser *ep, const char *name, Elf64_Off type, Elf64_Off *offset, Elf64_Xword *size);
extern void elf_exit(struct elf_parser *parser);

#ifndef __KERNEL__
extern keipm_err_t elf_write_signature_section(struct elf_parser *ep, util_fp_t wfp, const char *name, const void *sig, size_t sig_len);
#endif // __KERNEL__

#define ELFOP_SECTION_NAME_MAX 32

#endif /* KEIPM_ELF_OP_H_ */
