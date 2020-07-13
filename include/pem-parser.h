#ifndef PEM_PARSER_H
#define PEM_PARSER_H

#include <linux/types.h>
#include "errors.h"

struct pem_key {
    uint8_t *buffer;
    size_t buffer_size;
    const uint8_t *modulus;
    size_t modulus_len;
    const uint8_t *public_exponent;
    size_t public_exponent_len;
    const uint8_t *private_exponent;
    size_t private_exponent_len;
};

extern keipm_err_t pem_parse_private_key(struct pem_key *pem, const uint8_t *dat, size_t dat_len);
extern void pem_exit(struct pem_key *pem);

#endif // PEM_PARSER_H