#include <stdio.h>
#include <string.h>
#include "elfop.h"

int main(int argc, char *argv[])
{
    int retval;
    const char *secdata = "hello world";
    FILE *fp = fopen(argv[1],"rb+");
    if(!fp) {
        perror("fopen");
        return 1;
    }
    struct elfop_context *ep = NULL;
    retval = elfop_open(fp, &ep);
    if (retval) {
        perror("elfop_open");
        return 1;
    }
    retval = elfop_add_section(ep, ".signature", SHT_PROGBITS, secdata, strlen(secdata)+1);
    if (retval) {
        perror("elfop_add_section");
        return 1;
    }
    elfop_close(&ep);
    fclose(fp);
    printf("done.\n");
    return 0;
}
