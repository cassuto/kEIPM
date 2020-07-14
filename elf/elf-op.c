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

/*
 * The following code is not for kernel module
 */
#ifndef __KERNEL__

#include <stdio.h>
#include <assert.h>

static long filesize(util_fp_t fp)
{
    long pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    return size;
}

static keipm_err_t elf_read_shdr(struct elf_op *ep)
{
    Elf64_Off i;
    ssize_t len;
    loff_t pos;
    if (!ep->hdr.e_shnum) {
        /* no section headers */
        ep->shdrs = NULL;
        return ERROR(kEIPM_OK, NULL);
    }
    ep->shdrs = (struct elf64_shdr *)util_new(ep->hdr.e_shnum*sizeof(struct elf64_shdr));

    pos = ep->hdr.e_shoff;
    for(i=0; i<ep->hdr.e_shnum; ++i) {
        len = util_read(ep->fp, &ep->shdrs[i], sizeof(struct elf64_shdr), &pos);
        if (len != sizeof(struct elf64_shdr)) {
            return ERROR(kEIPM_ERR_MALFORMED, "can not read file");
        }
    }
    return ERROR(kEIPM_OK, NULL);
}

keipm_err_t copy_section(util_fp_t fp, size_t src_foff,size_t total, util_fp_t wfp, size_t dst_foff)
{
    char chunk[512];
    size_t rlen, wlen;
    ssize_t remain = total;
    fseek(fp, src_foff, SEEK_SET);
    fseek(wfp, dst_foff, SEEK_SET);
    while(remain > 0) {
        rlen = fread(chunk, 1,sizeof(chunk), fp);
        if (ferror(fp) || rlen == 0) {
            break;
        }
        wlen = fwrite(chunk, 1,rlen, wfp);
        if (wlen != rlen) {
            return ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
        }
        remain -= rlen;
    }
    return remain ==0 ? ERROR(kEIPM_OK, NULL) : ERROR(kEIPM_ERR_MALFORMED, "elf: can not read file");
}

keipm_err_t elf_write_signature_section(struct elf_op *ep, util_fp_t wfp, const char *name, const void *sig, size_t sig_len, Elf64_Off *foff)
{
    keipm_err_t res;
    ssize_t len;
    long file_size;
    util_off_t pos;
    Elf64_Off shstr_upperbound, sh_upperbound, section_upperbound, sh_off;
    Elf64_Xword sh_size;
    Elf64_Sword i;
    struct elf64_shdr tshstr;
    struct elf64_hdr thdr;
    struct elf64_shdr tshdr;
    const size_t name_size = strlen(name);
    int shstr_write_through_sht;

    /* Construct a section header for signature */
    tshdr.sh_addr = 0;
    tshdr.sh_addralign = 0;
    tshdr.sh_entsize = 0;
    tshdr.sh_flags = 0;
    tshdr.sh_info = 0;
    tshdr.sh_type = SHT_PROGBITS;
    tshdr.sh_link = SHN_UNDEF;

    /* check if target section is existed */
    res = elf_find_section(ep,name,tshdr.sh_type,&sh_off,&sh_size);
    if (res.errno == kEIPM_OK) {
        return ERROR(kEIPM_ERR_MALFORMED, "elf: section is existed");
    }

    file_size = filesize(ep->fp);

    RETURN_ON_ERROR(copy_section(ep->fp, 0,file_size, wfp,0));

    ep->shdrs = NULL;
    res = elf_read_shdr(ep);
    if (res.errno != kEIPM_OK) {
        goto out;
    }

    /* Create a copy for ELF header and shstr section header from the original */
    thdr = ep->hdr;
    tshstr = ep->shdrs[ep->hdr.e_shstrndx];

    shstr_upperbound = tshstr.sh_offset + tshstr.sh_size;
    sh_upperbound = ep->hdr.e_shoff + ep->hdr.e_shnum * ep->hdr.e_shentsize;

    if (sh_upperbound > file_size) {
        res = ERROR(kEIPM_ERR_MALFORMED, "elf: invalid size of section header");
        goto out;
    }

    section_upperbound = 0;
    for(i=0; i<ep->hdr.e_shnum;++i) {
        section_upperbound = MAX(section_upperbound, ep->shdrs[i].sh_offset + ep->shdrs[i].sh_size);
    }

    /*
     * see if we could simply append the section name on the original shstrtab
     * and overwrite section headers.
     */
    shstr_write_through_sht = (
        /* see if shstrtab was the last section of file */
        (shstr_upperbound == section_upperbound) && 
        /* see if section header tab came after shstrtab (or just non-existent) */
        (ep->hdr.e_shoff == ALIGN_TO(shstr_upperbound, ELF64_FILE_ALIGN)) &&
        /* see if the size of section header tab was enough to bear shstr string */
        (name_size < ep->hdr.e_shnum*ep->hdr.e_shentsize)
    );
    if (shstr_write_through_sht) {
        tshdr.sh_name = tshstr.sh_size;
        tshstr.sh_size += name_size;
    } else {
        /* locate shstrtab to the end of file */
        pos = ALIGN_TO(file_size, ELF64_FILE_ALIGN);

        /* copy the original shstrtab to new offset */
        res = copy_section(ep->fp, tshstr.sh_offset, tshstr.sh_size, wfp, pos);
        if (res.errno != kEIPM_OK) {
            goto out;
        }

        tshstr.sh_offset = pos;
        tshdr.sh_name = tshstr.sh_size; /* get the original size of .shstrtab */
        tshstr.sh_size += name_size;
    }
    /* append section name of signature to shstrtab */
    pos = tshstr.sh_offset + tshdr.sh_name;
    len = util_write(wfp, name, name_size, &pos);
    if (len != name_size) {
        res = ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
        goto out;
    }

    /* locate section header tab */
    if (shstr_write_through_sht) {
        if (sh_upperbound == file_size) {
            /* there is no data below section header tab
             * so it's safe to write through.
             */
            thdr.e_shoff = ALIGN_TO(tshstr.sh_offset + tshstr.sh_size, ELF64_FILE_ALIGN);
        } else {
            /* there may be some data below section header tab.
             * to preserve it, we should write from the end of file.
             */
            thdr.e_shoff = ALIGN_TO(file_size, ELF64_FILE_ALIGN);
            assert(ALIGN_TO(tshstr.sh_offset + tshstr.sh_size, ELF64_FILE_ALIGN) < thdr.e_shoff);
        }
    } else {
        /* in this case shstrtab is inevitable to be written at end of file.
         * so just follow tirh shstrtab
         */
        thdr.e_shoff = ALIGN_TO(tshstr.sh_offset + tshstr.sh_size, ELF64_FILE_ALIGN);
    }

    /*
     * Copy original section headers to the new offset,
     * with shstr section updated
     */
    for(i=0;i<ep->hdr.e_shnum;++i) {
        const struct elf64_shdr *src_shdr;
        if (i != ep->hdr.e_shstrndx) {
            /* merely copy from the original ELF */
            src_shdr = &ep->shdrs[i];
        } else {
            /* be consistent with what we have updated */
            src_shdr = &tshstr;
        }
        pos = thdr.e_shoff + i * thdr.e_shentsize;
        len = util_write(wfp, src_shdr, sizeof(*src_shdr), &pos);
        if (len != sizeof(*src_shdr)) {
            res = ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
            goto out;
        }
    }

    /* locate the signature section (following with section header tab) */
    {
        Elf64_Off new_sh_upperbound = thdr.e_shoff + (thdr.e_shnum+1) * thdr.e_shentsize;
        tshdr.sh_offset = ALIGN_TO(new_sh_upperbound, ELF64_FILE_ALIGN);
    }
    tshdr.sh_size = sig_len;

    /* now we can append the new section header */
    pos = thdr.e_shoff + thdr.e_shnum * thdr.e_shentsize;
    len = util_write(wfp, &tshdr, sizeof(tshdr), &pos);
    if (len != sizeof(tshdr)) {
        res = ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
        goto out;
    }

    /*
     * Append signature section
     */
    pos = tshdr.sh_offset;
    len = util_write(wfp, sig, tshdr.sh_size, &pos);
    if (len != tshdr.sh_size) {
        res = ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
        goto out;
    }
    thdr.e_shnum++;

    /* pass out the file offset for refilling data later */
    if (foff) {
        *foff = tshdr.sh_offset;
    }

    /* write ELF header back */
    pos = 0;
    len = util_write(wfp, &thdr, sizeof(thdr), &pos);
    if (len != sizeof(thdr)) {
        res = ERROR(kEIPM_ERR_MALFORMED, "elf: can not write file");
        goto out;
    }

    res = ERROR(kEIPM_OK, NULL);
out:
    util_delete(ep->shdrs);
    return res;
}

#endif
