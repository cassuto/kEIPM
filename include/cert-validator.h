#ifndef CERT_VALIDATOR_H_
#define CERT_VALIDATOR_H_

#include "errors.h"
#include "asn1-parser/x509.h"

extern keipm_err_t cert_validate(const uint8_t *trust, size_t trust_length,
    asn1_parser_t *parser, x509_cert_t *cert);

#endif // CERT_VALIDATOR_H_
