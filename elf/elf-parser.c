/*
 *  kEIPM (kerenl ELF Integrity Protection Module)
 *  Copyright (C) 2020 cassuto <diyer175@hotmail.com> & KingOfSmail
 * 
 *  This project is free edition; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public             
 *  License(GPL) as published by the Free Software Foundation; either      
 *  version 2.1 of the License, or (at your option) any later version.     
 *                                                                         
 *  This project is distributed in the hope that it will be useful,        
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      
 *  Lesser General Public License for more details.                        
 */
#include "utils.h"
#include "elf-op.h"

keipm_err_t elf_parse(struct elf_op *parser)
{
    ssize_t len;
    util_off_t pos;
    /* Read out the header */
    pos = 0;
    len = util_read(parser->fp, &parser->hdr, sizeof(parser->hdr), &pos);
	if (len != sizeof(parser->hdr)) {
        return ERROR(kEIPM_ERR_MALFORMED, "elf: can not read.");
	}
    if (memcmp(parser->hdr.e_ident, ELFMAG, SELFMAG)) {
        return ERROR(kEIPM_ERR_INVALID, "elf: invalid format");
    }
    /* Check if a ELF64 file is presented. ELFCLASS32 is not supported! */
    if ( (parser->hdr.e_ident[4]==ELFCLASSNONE && parser->hdr.e_ehsize != sizeof(parser->hdr)) ||
            (parser->hdr.e_ident[4]!=ELFCLASSNONE && parser->hdr.e_ident[4]!=ELFCLASS64) ) {
        return ERROR(kEIPM_ERR_INVALID, "elf: not 64bit elf");
    }
    return ERROR(kEIPM_OK, NULL);
}

keipm_err_t elf_find_section(struct elf_op *ep, const char *name, Elf64_Off type, Elf64_Off *offset, Elf64_Xword *size)
{
    ssize_t len;
    Elf64_Sword i;
    struct elf64_shdr shstr, shcur;
    char buf[ELFOP_SECTION_NAME_MAX]; /* >= strlen(SIG_ELF_SECTION_NAME) */
    util_off_t pos;

    pos = ep->hdr.e_shoff + ep->hdr.e_shstrndx*ep->hdr.e_shentsize;
    len = util_read(ep->fp, &shstr, sizeof(struct elf64_shdr), &pos);
    if (len != sizeof(struct elf64_shdr)) {
        return ERROR(kEIPM_ERR_MALFORMED, "elf: can not read file");
    }

    /* find from the last section header to speed up */
    for (i=ep->hdr.e_shnum-1; i>0; i--) {
        pos = ep->hdr.e_shoff + i*ep->hdr.e_shentsize;
        len = util_read(ep->fp, &shcur, sizeof(struct elf64_shdr), &pos);
        if (len != sizeof(struct elf64_shdr)) {
            return ERROR(kEIPM_ERR_MALFORMED, "elf: can not read file");
        }

        if (shcur.sh_type == type) {
            pos = shstr.sh_offset + shcur.sh_name;
            len = util_read(ep->fp, buf, sizeof(buf), &pos);
            if (len != sizeof(buf)) {
                return ERROR(kEIPM_ERR_MALFORMED, "elf: can not read file");
            }
    
            if (strcmp(buf,name)==0) {
                *offset = shcur.sh_offset;
                *size = shcur.sh_size;
                return ERROR(kEIPM_OK, NULL);
            }
        }
    }

    return ERROR(kEIPM_ERR_INVALID, "elf: section not found");
}

keipm_err_t elf_foreach_segment(struct elf_op *ep, Elf64_Word target_type, pfn_on_segment callback, void *opaque)
{
    ssize_t len;
    Elf64_Sword i;
    struct elf64_phdr phdr;
    util_off_t pos;

    for(i=0;i<ep->hdr.e_phnum;++i) {
        /* read out the program header */
        pos = ep->hdr.e_phoff + i * ep->hdr.e_phentsize;
        len = util_read(ep->fp, &phdr, sizeof(phdr), &pos);
        if (len != sizeof(phdr)) {
            return ERROR(kEIPM_ERR_MALFORMED, "elf: can not read file");
        }

        if (phdr.p_type == target_type) {
            RETURN_ON_ERROR((*callback)(phdr.p_offset, phdr.p_filesz, opaque));
        }
    }
    return ERROR(kEIPM_OK, NULL);
}

void elf_setfile(struct elf_op *parser, util_fp_t fp)
{
    parser->fp = fp;
}

void elf_exit(struct elf_op *parser)
{
    parser->fp = NULL;
}
