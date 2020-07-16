#include "ca.h"
#include "public_pkcs1.h"

#include "builtin.h"

static struct builtin_node list[] = {
    {
        BUILTIN_CERT,           /** type */
        "builtin/ca.der",       /** issuer */
        g_ca,                   /** data */
        g_cbca                  /** length */
    },
    {
        BUILTIN_RSA_PUBKEY,
        "builtin/public_pkcs1.pem",
        g_public_pkcs1,
        g_cbpublic_pkcs1
    },
};

const struct builtin_node *builtin_list = list;
size_t builtin_num = sizeof(list)/sizeof(*list);
