#ifndef KEIPM_ELF_OP_H_
#define KEIPM_ELF_OP_H_

#include "elf.h"
#include "errors.h"
#include "utils.h"

#define ELF64_FILE_ALIGN 8 /* byte */

struct elf_op {
    struct elf64_hdr hdr;
    util_fp_t fp;
#ifndef __KERNEL__
    struct elf64_shdr *shdrs;
#endif
};

typedef keipm_err_t (*pfn_on_segment)(Elf64_Off foffset, Elf64_Xword len, void *opaque);

extern void elf_setfile(struct elf_op *parser, util_fp_t fp);
extern keipm_err_t elf_parse(struct elf_op *parser);
extern keipm_err_t elf_find_section(struct elf_op *ep, const char *name, Elf64_Off type, Elf64_Off *offset, Elf64_Xword *size);
extern keipm_err_t elf_foreach_segment(struct elf_op *ep, Elf64_Word target_type, pfn_on_segment callback, void *opaque);
extern void elf_exit(struct elf_op *parser);

#ifndef __KERNEL__
extern keipm_err_t elf_write_signature_section(struct elf_op *ep, util_fp_t wfp, const char *name, const void *sig, size_t sig_len);
#endif // __KERNEL__

#define ELFOP_SECTION_NAME_MAX 32

#endif /* KEIPM_ELF_OP_H_ */
