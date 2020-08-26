#ifndef BUILTIN_H_
#define BUILTIN_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdlib.h>
#include <stdint.h>
#endif

typedef enum builtin_type {
    BUILTIN_RSA_PUBKEY = 0,
    BUILTIN_CERT
} builtin_type_t;

struct builtin_node {
    builtin_type_t type;
    const char *issuer;
    const unsigned char *data;
    size_t length;
};

extern const struct builtin_node *builtin_list;
extern size_t builtin_num;

#endif /* BUILTIN_H_ */