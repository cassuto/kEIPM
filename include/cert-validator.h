#ifndef CERT_VALIDATOR_H_
#define CERT_VALIDATOR_H_

#include "errors.h"

extern keipm_err_t cert_validate(const uint8_t *trust, size_t trust_length,
    const uint8_t *contents, size_t contents_length);

#endif // CERT_VALIDATOR_H_
