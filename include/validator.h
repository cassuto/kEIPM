#ifndef VALIDATOR_H_
#define VALIDATOR_H_

#include "errors.h"

extern void validator_init(void);
extern int validator_analysis_binary(struct file *file);
extern keipm_err_t verify_fs(const char *pathname);
extern keipm_err_t validator_add_pubkey(const char *issuer, const uint8_t *pubkey, size_t pubkey_len);
extern keipm_err_t validator_add_root_cert(const char *issuer, const uint8_t *cert, size_t cert_len);

#endif // VALIDATOR_H_
