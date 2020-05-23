#include "watcher-lsm.h"
#include "watcher.h"

int watcher_init(void)
{
    int rc;
    if ((rc = watcher_lsm_hook())) {
        return rc;
    }
    return 0;
}

void watcher_uninit(void)
{
}
