#include <stdio.h>
#include "elfop.h"

int main(int argc, char *argv[])
{
    int retval;
    FILE *fp = fopen(argv[1],"rb");
    if(!fp) {
        perror("");
        return 1;
    }
    struct elfop_context *ep = NULL;
    retval = elfop_open(fp, &ep);
    if (retval) {
        perror("");
        return 1;
    }
    elfop_close(&ep);
    fclose(fp);
    return 0;
}
