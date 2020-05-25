#include <stdlib.h>
#include <string.h>
#include "errors.h"
#include "elf.h"
#include "elfop.h"

int elfop_open(FILE *fp, struct elfop_context **out)
{
    int retval = 0;
    struct elfop_context *ep = (struct elfop_context *)malloc(sizeof(*ep));
    fseek(fp, 0, SEEK_SET);
    size_t len = fread(&ep->hdr, 1, sizeof(ep->hdr), fp);
    if (len != sizeof(ep->hdr)) {
        retval = -ENOENT;
        goto err;
    }
    if (memcmp(ep->hdr.e_ident, ELFMAG, SELFMAG)) {
        retval = -ENOEXEC;
        goto err;
    }
    /* check if a ELF64 file. ELFCLASS32 is not supported! */
    if ( (ep-ep->hdr.e_ident[4]==ELFCLASSNONE && ep->hdr.e_ehsize != sizeof(ep->hdr)) ||
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

void elfop_close(struct elfop_context **ep)
{
    if (*ep) {
        free(*ep);
        *ep = NULL;
    }
}
