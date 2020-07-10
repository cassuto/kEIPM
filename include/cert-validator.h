#ifndef CERT_VALIDATOR_H_
#define CERT_VALIDATOR_H_

#include "errors.h"

#define MAX_CA 5

struct cert_ca {
    const uint8_t *trust;
    size_t trust_length;
};

struct cert {
    struct cert_ca cas[MAX_CA];
    size_t n_cas;
};

extern void cert_init(struct cert *cts);
extern keipm_err_t cert_add_ca(struct cert *cts, const uint8_t *trust, size_t trust_length);
extern keipm_err_t cert_validate(struct cert *cts, const uint8_t *content, size_t contentlength);

/* main.c */
extern struct cert g_cert;

#endif // CERT_VALIDATOR_H_
