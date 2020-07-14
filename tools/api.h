#ifndef API_H_
#define API_H_

#include "errors.h"

extern keipm_err_t gen_rsa_pri_key(const char *out_pri_key);
extern keipm_err_t gen_rsa_pub_key(const char *in_pri_key, const char *out_pub_key);

extern keipm_err_t sign_elf_rsa(const char *target_elf, const char *in_pri_key);

#endif // API_H_