#include <linux/kallsyms.h>
#include "string.h"
#include "ksyms.h"

struct opaque {
    const char *name;
    long addr;
};

static int kallsyms_on_symbol(void *data, const char *name, void *module, long addr)
{
    struct opaque *target = (struct opaque *)data;
    if (addr && !module) { /* don't find in modules */
        if (0==strcmp_slow(target->name, name)) {
            target->addr = addr;
            return 1;
        }
    }
    return 0;
}

void *find_kernel_entry(const char *symbol)
{
    struct opaque data = {symbol, 0};
	kallsyms_on_each_symbol((void *)kallsyms_on_symbol, &data);
	return (void *)data.addr;
}
