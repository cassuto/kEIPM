#include "elf-op.h"
#include "validator.h"

static int validate_elf(struct elf_parser *parser)
{
    return 0;
}

int analysis_binary(const char *pathname)
{
    int retval;
    keipm_err_t err;
    struct elf_parser ep;
    struct file *file = filp_open(pathname, O_LARGEFILE | O_RDONLY, S_IRUSR);
    if (IS_ERR(file)) {
        return 0;
    }
    elf_setfile(&ep, file);
    err = elf_parse(&ep);
    if (err.errno != kEIPM_OK) { /* If not a valid ELF file */
        retval = 0;
        goto out;
    }
    retval = validate_elf(&ep);
out:
    elf_exit(&ep);
    filp_close(file, NULL);
    return retval;
}