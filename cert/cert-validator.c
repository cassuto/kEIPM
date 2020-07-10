/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "errors.h"
#include "asn1-parser/dsl.h"
#include "asn1-parser/x509.h"
#include "asn1-parser/internal/macros.h"
#include "sha.h"

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
    mbedtls_md_type_t digest)
{
	(void)params;
	(void)hash_len;

	mbedtls_rsa_context rsa;
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
	rsa.len = pubkey->key.rsa.n_num;

	keipm_err_t res;
	if (mbedtls_mpi_read_binary(
	        &rsa.N, pubkey->key.rsa.n, pubkey->key.rsa.n_num) != 0) {
		res = ERROR(ASININE_ERR_MALFORMED, "rsa: invalid public modulus");
		goto error;
	}

	if (mbedtls_mpi_read_binary(
	        &rsa.E, pubkey->key.rsa.e, pubkey->key.rsa.e_num) != 0) {
		res = ERROR(ASININE_ERR_MALFORMED, "rsa: invalid exponent");
		goto error;
	}

	if (mbedtls_rsa_check_pubkey(&rsa) != 0) {
		res = ERROR(ASININE_ERR_INVALID, "rsa: public key check failed");
		goto error;
	}

	if (mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, digest,
	        0, hash, sig->data) != 0) {
		res = ERROR(ASININE_ERR_UNTRUSTED, "rsa: signature not valid");
		goto error;
	}

	res = ERROR(ASININE_OK, NULL);
error:
	mbedtls_rsa_free(&rsa);
	return res;
}

static struct sha256_state sha256_sst;

keipm_err_t validate_signature(const x509_pubkey_t *pubkey, x509_pubkey_params_t params,
    const x509_signature_t *sig, const uint8_t *raw, size_t raw_num,
    void *ctx)
{
    uint8_t hash[64] = {0};
    size_t hash_len;

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

	switch (sig->algorithm) {
	case X509_SIGNATURE_INVALID:
		return ERROR(kEIPM_ERR_INVALID, "signature: invalid algorithm");
		break;
	case X509_SIGNATURE_SHA256_RSA:
	case X509_SIGNATURE_SHA384_RSA:
	case X509_SIGNATURE_SHA512_RSA:
		return validate_rsa_signature(pubkey, params, sig, hash, hash_len, digest);
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
static asn1_time_t now;
static asn1_parser_t parser;
/*
 * Note that this is not reenterable
 */
static keipm_err_t validate_path(const uint8_t *trust, size_t trust_length,
    const uint8_t *contents, size_t length)
{
    keipm_err_t err;

    get_current_time(&now);
    
    asn1_init(&parser, contents, length);

    RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));
    
    if (trust != NULL) {
        err = find_issuer(trust, trust_length, &cert, &issuer);
        if (err.errno != kEIPM_OK) {
            //dump_name(stderr, &cert.issuer);
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
            //dump_name(stderr, &cert.subject);
            return err;
        }

        RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));
    }

    err = x509_path_end(&path, &cert);
    if (err.errno != kEIPM_OK) {
        //dump_name(stderr, &cert.subject);
        return err;
    }

    return ERROR(kEIPM_OK, NULL);
}

void cert_init(struct cert *cts) {
    cts->n_cas = 0;
}

/**
 * @brief Add a root cert to the chain. 
 * Note that this would NOT copy the buffer of trust pointer.
 */
keipm_err_t cert_add_ca(struct cert *cts, const uint8_t *trust, size_t trust_length) {
    if (cts->n_cas +1 > MAX_CA) {
        return ERROR(kEIPM_ERR_MEMORY, "cert: out of root CA number limit.");
    }
    cts->cas[cts->n_cas].trust = trust;
    cts->cas[cts->n_cas].trust_length = trust_length;
    ++cts->n_cas;
    return ERROR(kEIPM_OK, NULL);
}

/**
 * @brief Validate a cert
 * Note that this is not reenterable
 */
keipm_err_t cert_validate(struct cert *cts, const uint8_t *content, size_t content_length) {
    keipm_err_t error;
    size_t i;
    for(i=0;i<cts->n_cas;++i) {
        error = validate_path(cts->cas[cts->n_cas].trust, cts->cas[cts->n_cas].trust_length,
            content, content_length);
        if (error.errno == kEIPM_OK) {
            return ERROR(kEIPM_OK, NULL);
        }
    }
    return error;
}
