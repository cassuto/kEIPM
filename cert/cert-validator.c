/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "errors.h"
#include "asn1-parser/dsl.h"
#include "asn1-parser/x509.h"
#include "asn1-parser/internal/macros.h"
#include "sha.h"
#include "rsa.h"
#include "pkcs1.h"

#ifdef __KERNEL__
#include <linux/time.h>
#include <linux/rtc.h>
#endif

#include "cert-validator.h"

static void get_current_time(asn1_time_t *now) {
#ifdef __KERNEL__
    struct timeval tv;
    struct rtc_time tm, *utc = &tm;
    do_gettimeofday(&tv);
    rtc_time_to_tm(tv.tv_sec,&tm);
#else
    time_t t = time(NULL);
    struct tm *utc = gmtime(&t);
#endif
    now->year   = (int32_t)utc->tm_year + 1900;
    now->month  = (uint8_t)utc->tm_mon + 1;
    now->day    = (uint8_t)utc->tm_mday;
    now->hour   = (uint8_t)utc->tm_hour;
    now->minute = (uint8_t)utc->tm_min;
    now->second = (uint8_t)utc->tm_sec;
}

static keipm_err_t validate_rsa_signature(const x509_pubkey_t *pubkey, x509_pubkey_params_t params,
    const x509_signature_t *sig, const uint8_t *hash, size_t hash_len,
    const uint8_t *oid, size_t oid_len)
{
    keipm_err_t res;
    struct rsa_req rsa;
    struct rsa_key raw_key;
    unsigned int maxsize;

    (void)params;

    rsa_init_req(&rsa);
    rsa.dst = NULL;

    raw_key.n = pubkey->key.rsa.n;
    raw_key.n_sz = pubkey->key.rsa.n_num;
    raw_key.e = pubkey->key.rsa.e;
    raw_key.e_sz = pubkey->key.rsa.e_num;
    if (rsa_set_pub_key(&rsa, &raw_key)) {
        res = ERROR(ASININE_ERR_UNTRUSTED, "rsa: signature public key not valid");
        goto error;
    }

    /* Find out new modulus size from rsa implementation */
    maxsize = rsa_max_size(&rsa);
    if (maxsize > PAGE_SIZE) {
        res = ERROR(kEIPM_ERR_MALFORMED, "rsa: size of modulus is out of PAGE_SIZE");
        goto error;
    }

    rsa.src = sig->data;
    rsa.src_len = sig->num;
    rsa.dst_len = maxsize;
    rsa.dst = kmalloc(rsa.dst_len, GFP_KERNEL);
    if (rsa_verify(&rsa)) {
        res = ERROR(kEIPM_ERR_MALFORMED, "rsa: unexpected error");
        goto error;
    }

	if (pkcs1_verify(rsa.dst, rsa.dst_len, oid, oid_len, hash, hash_len)) {
		res = ERROR(ASININE_ERR_UNTRUSTED, "rsa: signature not valid");
		goto error;
	}

	res = ERROR(ASININE_OK, NULL);
error:
    kfree(rsa.dst);
	rsa_exit_req(&rsa);
	return res;
}

static struct sha256_state sha256_sst;
/*
 * Note that this is not reenterable
 */
keipm_err_t validate_signature(const x509_pubkey_t *pubkey, x509_pubkey_params_t params,
    const x509_signature_t *sig, const uint8_t *raw, size_t raw_num,
    void *ctx)
{
    uint8_t hash[64] = {0};
    size_t hash_len;
    const unsigned char *oid = NULL;
    size_t oid_size;

	(void)ctx;

	switch (sig->algorithm) {
	case X509_SIGNATURE_INVALID:
		return ERROR(kEIPM_ERR_INVALID, "signature: invalid algorithm");
		break;
	case X509_SIGNATURE_SHA256_RSA:
	case X509_SIGNATURE_SHA256_ECDSA:
	case X509_SIGNATURE_SHA256_DSA: {
        sha256_init(&sha256_sst);
        sha256_update(&sha256_sst, raw,raw_num, sha256_block);
        sha256_finalize(&sha256_sst, sha256_block);
        sha256_fill_digest(&sha256_sst, hash);
        hash_len = SHA256_DIGEST_SIZE;
        oid = OID_DIGEST_ALG_SHA256;
        oid_size = sizeof(OID_DIGEST_ALG_SHA256) - 1;
		break;
    }
	case X509_SIGNATURE_SHA384_RSA:
	case X509_SIGNATURE_SHA384_ECDSA:
		return ERROR(kEIPM_ERR_UNSUPPORTED, "signature: sha384 not supported");
		break;
	case X509_SIGNATURE_SHA512_RSA:
	case X509_SIGNATURE_SHA512_ECDSA:
		return ERROR(kEIPM_ERR_UNSUPPORTED, "signature: sha512 not supported");
		break;
	case X509_SIGNATURE_MD2_RSA:
	case X509_SIGNATURE_MD5_RSA:
	case X509_SIGNATURE_SHA1_RSA:
		return ERROR(kEIPM_ERR_DEPRECATED, "signature: uses MD2/MD5/SHA1");
	}

    if (!oid) {
        return ERROR(kEIPM_ERR_INVALID, "signature: unknown algorithm");
    }

	switch (sig->algorithm) {
	case X509_SIGNATURE_INVALID:
		return ERROR(kEIPM_ERR_INVALID, "signature: invalid algorithm");
		break;
	case X509_SIGNATURE_SHA256_RSA:
	case X509_SIGNATURE_SHA384_RSA:
	case X509_SIGNATURE_SHA512_RSA:
		return validate_rsa_signature(pubkey, params, sig, hash, hash_len, oid, oid_size);
	case X509_SIGNATURE_SHA256_ECDSA:
	case X509_SIGNATURE_SHA384_ECDSA:
	case X509_SIGNATURE_SHA512_ECDSA:
        return ERROR(kEIPM_ERR_UNSUPPORTED, "signature: ECDSA not supported");
	case X509_SIGNATURE_MD2_RSA:
	case X509_SIGNATURE_MD5_RSA:
	case X509_SIGNATURE_SHA1_RSA:
		return ERROR(kEIPM_ERR_DEPRECATED, "signature: uses MD2/MD5/SHA1");
	case X509_SIGNATURE_SHA256_DSA:
		return ERROR(kEIPM_ERR_UNSUPPORTED, "signature: DSA is not supported");
	}
    return ERROR(kEIPM_OK, NULL);
}

static keipm_err_t find_issuer(const uint8_t *buf, size_t length, const x509_cert_t *cert, x509_cert_t *issuer) {
	asn1_parser_t parser;
	asn1_init(&parser, buf, length);
	return x509_find_issuer(&parser, cert, issuer);
}

static x509_cert_t issuer, cert;
static x509_path_t path;
static asn1_parser_t parser;
/**
 * @brief Validate a cert
 * Note that this is not reenterable
 */
keipm_err_t cert_validate(const uint8_t *trust, size_t trust_length,
    const uint8_t *contents, size_t contents_length)
{
    keipm_err_t err;
    static asn1_time_t now;

    get_current_time(&now);
    
    asn1_init(&parser, contents, contents_length);

    RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));

    if (trust != NULL) {
        err = find_issuer(trust, trust_length, &cert, &issuer);
        if (err.errno != kEIPM_OK) {
            return err;
        }
    } else {
        issuer = cert;
        RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));
    }

    x509_path_init(&path, &issuer, &now, validate_signature, NULL);

    while (!asn1_end(&parser)) {
        err = x509_path_add(&path, &cert);
        if (err.errno != kEIPM_OK) {
            return err;
        }

        RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));
    }

    err = x509_path_end(&path, &cert);
    if (err.errno != kEIPM_OK) {
        return err;
    }

    return ERROR(kEIPM_OK, NULL);
}
