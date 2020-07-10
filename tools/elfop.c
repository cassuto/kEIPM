#include <stdlib.h>
#include <string.h>
#include "errors.h"
#include "elf.h"
#include "elfop.h"

int elfop_open(FILE *fp, struct elfop_context **out)
{
    int retval = 0;
    struct elfop_context *ep = (struct elfop_context *)elfop_new(sizeof(*ep));
    memset(ep, 0, sizeof(*ep));
    ep->fp = fp;
    /* read out the header */
    elfop_seek(ep, 0);
    retval = elfop_read(ep, &ep->hdr, sizeof(ep->hdr));
    if (retval) {
        goto err;
    }
    if (memcmp(ep->hdr.e_ident, ELFMAG, SELFMAG)) {
        retval = -ENOEXEC;
        goto err;
    }
    /* check if a ELF64 file is presented. ELFCLASS32 is not supported! */
    if ( (ep->hdr.e_ident[4]==ELFCLASSNONE && ep->hdr.e_ehsize != sizeof(ep->hdr)) ||
            (ep-ep->hdr.e_ident[4]!=ELFCLASSNONE && ep->hdr.e_ident[4]!=ELFCLASS64) ) {
        retval = EENOTCLASS64;
        goto err;
    }
    *out = ep;
    return 0;
err:
    free(ep);
    *out = NULL;
    return retval;
}

/**
 * @brief Read Program Header.
 * @param ep elfop Context
 * @return status code
 */
int elfop_read_phdr(struct elfop_context *ep)
{
    Elf64_Off i;
    int retval;
    if (!ep->hdr.e_phnum) {
        return -EFAULT; /* no program header */
    }
    if (ep->phdrs) {
        elfop_delete(ep->phdrs);
    }
    ep->phdrs = (struct elf64_phdr *)elfop_new(ep->hdr.e_phnum*sizeof(struct elf64_phdr));

    elfop_seek(ep, ep->hdr.e_phoff);
    for(i=0; i<ep->hdr.e_phnum; ++i) {
        retval = elfop_read(ep, &ep->phdrs[i], sizeof(struct elf64_phdr));
        if (retval) {
            goto err;
        }
    }
err:
    return retval;
}


/**
 * @brief Read Section Header.
 * @param ep elfop Context
 * @return status code
 */
int elfop_read_shdr(struct elfop_context *ep)
{
    Elf64_Off i;
    int retval;
    if (!ep->hdr.e_shnum) {
        return -EFAULT; /* no program header */
    }
    if (ep->shdrs) {
        elfop_delete(ep->shdrs);
    }
    ep->shdrs = (struct elf64_shdr *)elfop_new(ep->hdr.e_shnum*sizeof(struct elf64_shdr));

    elfop_seek(ep, ep->hdr.e_shoff);
    for(i=0; i<ep->hdr.e_shnum; ++i) {
        retval = elfop_read(ep, &ep->shdrs[i], sizeof(struct elf64_shdr));
        if (retval) {
            goto err;
        }
    }
err:
    return retval;
}

int elfop_find_section(struct elfop_context *ep, const char *name, Elf64_Off type, Elf64_Off *out)
{
    int retval = 1;
    Elf64_Off i;
    struct elf64_shdr shstr, shcur;
    char buf[ELFOP_SECTION_NAME_MAX];

    elfop_seek(ep, ep->hdr.e_shoff + ep->hdr.e_shstrndx*ep->hdr.e_shentsize);
    retval = elfop_read(ep, &shstr, sizeof(struct elf64_shdr));
    if (retval) {
        goto err;
    }

    for (i=0; i<ep->hdr.e_shnum; i++) {
        elfop_seek(ep, ep->hdr.e_shoff + i*ep->hdr.e_shentsize);
        retval = elfop_read(ep, &shcur, sizeof(struct elf64_shdr));
        if (retval) {
            goto err;
        }

        if (shcur.sh_type == type) {
            elfop_seek(ep, shstr.sh_offset + shcur.sh_name);
            elfop_read(ep, buf, sizeof(buf)); // TODO
    
            if (strcmp(buf,name)==0) {
                *out = i;
                return 0;
            }
        }
    }

err:
    return retval;
}

#ifdef ELF_WRITER

#include <stdio.h>

static long elfop_size(struct elfop_context *ep)
{
    long pos = ftell(ep->fp);
    fseek(ep->fp, 0, SEEK_END);
    long size = ftell(ep->fp);
    fseek(ep->fp, pos, SEEK_SET);
    return size;
}

int elfop_add_section(struct elfop_context *ep, const char *name, Elf64_Off type, const void *data, size_t dsize)
{
    int retval = 0;
    Elf64_Off i;
    Elf64_Off shdr_upperbound, sizeof_file;
    Elf64_Off write_file_off;

    if (!ep->shdrs) {
        retval = elfop_read_shdr(ep);
        if (retval) {
            goto err;
        }
    }

    /* check if target section is existed */
    retval = elfop_find_section(ep,name,type,&i);
    if (retval) {
        return EESECTION_EXISTED;
    }

    shdr_upperbound = ep->hdr.e_shoff + ep->hdr.e_shentsize * ep->hdr.e_shnum;
    sizeof_file = elfop_size(ep);
    write_file_off = sizeof_file;
    /*
     * See if we can overwrite the original Section Header Table and
     * append a new one to the file;
     */
    if (sizeof_file == shdr_upperbound) {
        write_file_off = ep->hdr.e_shoff;
    }
    

err:
    return retval;
}

#endif

void elfop_close(struct elfop_context **ep)
{
    if (*ep) {
        if ((*ep)->phdrs) {
            elfop_delete((*ep)->phdrs);
        }
        elfop_delete(*ep);
        *ep = NULL;
    }
}
