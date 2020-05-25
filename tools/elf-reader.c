#include <errno.h>
#include "elfop.h"

int elfop_read(struct elfop_context *ep, void *buf, size_t size)
{
    size_t len = fread(buf, 1, size, ep->fp);
    if (len==0) {
        return -EFAULT; /* maybe EOF */
    }
    return len != size ? -EACCES : 0;
}
void elfop_seek(struct elfop_context *ep, long offset)
{
    fseek(ep->fp, offset, SEEK_SET);
}
long elfop_size(struct elfop_context *ep)
{
    long pos = ftell(ep->fp);
    fseek(ep->fp, 0, SEEK_END);
    long size = ftell(ep->fp);
    fseek(ep->fp, pos, SEEK_SET);
    return size;
}
