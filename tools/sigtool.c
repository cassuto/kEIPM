#include <stdio.h>
#include <string.h>
#include "errors.h"
#include "api.h"
#include "elf-op.h"

int main(int argc, char *argv[])
{
    keipm_err_t err;

    err = sign_elf_rsa("/home/ain/test", "prikey.pem");
    printf("%s\n", err.reason ? err.reason : "OK");
    return 0;

    err = gen_rsa_pri_key("prikey.pem");
    printf("%d\n", err.errno);
    err = gen_rsa_pub_key("prikey.pem", "pubkey.pem");
    printf("%d\n", err.errno);
    return 0;

    return 0;
}
