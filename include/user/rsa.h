/*****************************************************************************
Filename: rsa.h
Author  : Chuck Li (lch0821@foxmail.com)
Date    : 2018-01-19 18:29:32
Description:
*****************************************************************************/
#ifndef __RSA_H__
#define __RSA_H__

#ifdef __KERNEL__
#error FAULT
#endif

#include <stdint.h>

// RSA key lengths
#define RSA_MIN_MODULUS_BITS                508
#define RSA_MAX_MODULUS_BITS                2048
#define RSA_MAX_MODULUS_LEN                 ((RSA_MAX_MODULUS_BITS + 7) / 8)
#define RSA_MAX_PRIME_BITS                  ((RSA_MAX_MODULUS_BITS + 1) / 2)
#define RSA_MAX_PRIME_LEN                   ((RSA_MAX_PRIME_BITS + 7) / 8)

// Error codes
#define ERR_WRONG_DATA                      0x1001
#define ERR_WRONG_LEN                       0x1002

typedef struct {
    uint32_t bits;
    uint8_t  modulus[RSA_MAX_MODULUS_LEN];
    uint8_t  exponent[RSA_MAX_MODULUS_LEN];
} rsa_pk_t;

int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, const uint8_t *in, uint32_t in_len, rsa_pk_t *pk);
int rsa_get_bits(uint32_t modulus_len);

#endif  // __RSA_H__
