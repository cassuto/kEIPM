#include <stdio.h>
#include <string.h>
#include "errors.h"
#include "api.h"
#include "elf-op.h"

int main(int argc, char *argv[])
{
    keipm_err_t err;
    FILE *wfp;
    const char *secdata = "hello world";
    FILE *fp = fopen(argv[1],"rb+");

    err = gen_rsa_pri_key("prikey.pem");
    printf("%d\n", err.errno);
    err = gen_rsa_pub_key("prikey.pem", "pubkey.pem");
    printf("%d\n", err.errno);
    return 0;

    if(!fp) {
        perror("fopen");
        return 1;
    }
    struct elf_op ep;
    elf_setfile(&ep, fp);
    err = elf_parse(&ep);
    if (err.errno != kEIPM_OK) {
        perror(err.reason);
        return 1;
    }
    wfp = fopen("tet", "wb");
    err = elf_write_signature_section(&ep, wfp, ".signature", secdata, strlen(secdata)+1);
    if (err.errno != kEIPM_OK) {
        perror(err.reason);
        return 1;
    }
    elf_exit(&ep);
    fclose(fp);
    fclose(wfp);
    printf("done.\n");
    return 0;
}
