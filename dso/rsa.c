/*****************************************************************************
Filename: rsa.c
Author  : Chuck Li (lch0821@foxmail.com)
Date    : 2018-01-19 18:56:09
Description:
*****************************************************************************/
#include <string.h>
#include <stdio.h>

#include "user/rsa.h"
#include "bignum.h"

static int public_block_operation(uint8_t *out, uint32_t *out_len, const uint8_t *in, uint32_t in_len, rsa_pk_t *pk);

int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, const uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint32_t modulus_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = public_block_operation(out, out_len, in, in_len, pk);
    if(status != 0)
        return status;

    if(*out_len != modulus_len)
        return ERR_WRONG_LEN;

    return status;
}

static int public_block_operation(uint8_t *out, uint32_t *out_len, const uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    uint32_t edigits, ndigits;
    bn_t c[BN_MAX_DIGITS], e[BN_MAX_DIGITS], m[BN_MAX_DIGITS], n[BN_MAX_DIGITS];

    bn_decode(m, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(e, BN_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);

    ndigits = bn_digits(n, BN_MAX_DIGITS);
    edigits = bn_digits(e, BN_MAX_DIGITS);

    if(bn_cmp(m, n, ndigits) >= 0) {
        return ERR_WRONG_DATA;
    }

    bn_mod_exp(c, m, e, edigits, n, ndigits);

    *out_len = (pk->bits + 7) / 8;
    bn_encode(out, *out_len, c, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)m, 0, sizeof(m));

    return 0;
}

int rsa_get_bits(uint32_t modulus_len)
{
    return modulus_len*8;
}