/*
 *  kEIPM (kerenl ELF Integrity Protection Module)
 *  Copyright (C) 2020 cassuto <diyer175@hotmail.com> & KingOfSmail
 * 
 *  This project is free edition; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public             
 *  License(GPL) as published by the Free Software Foundation; either      
 *  version 2.1 of the License, or (at your option) any later version.     
 *                                                                         
 *  This project is distributed in the hope that it will be useful,        
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      
 *  Lesser General Public License for more details.                        
 */
#include "cert-validator.h"
#include "asn1-parser/dsl.h"
#include "asn1-parser/x509.h"
#include "asn1-parser/internal/macros.h"
#include "elf-op.h"
#include "rsa.h"
#include "sha.h"
#include "signature.h"
#include "pem-parser.h"
#include <linux/string.h>

#include "validator.h"

/** Define max number of public keys built-in this module */
#define MAX_N_PUBKEY 5
/** Define max number of root CA certificates built-in this module */
#define MAX_N_CA 5
/** Define max size of certificate in bytes */
#define MAX_CERT_BUFFER 65536
/** Define max size of signature data in bytes */
#define MAX_ENC_DIGEST_BUFFER 65536
/** Define size of file chunk for SHA */
#define SHA_FILE_CHUNK_SIZE 8192

typedef struct pubkey_info {
    char *              issuer;
    struct pem_key      key;
} pubkey_info_t;
typedef struct cert_info {
    char *              issuer;
    const uint8_t *     data;
    size_t              length;
} cert_info_t;

static struct validator {
    uint8_t             cert_buff[MAX_CERT_BUFFER];
    uint8_t             edigest_buff[MAX_ENC_DIGEST_BUFFER];
    uint8_t             hash[SHA256_DIGEST_SIZE];
    struct sha256_state sha_state;
    uint8_t             sha_filechunk[SHA_FILE_CHUNK_SIZE];
    pubkey_info_t       pubkeys[MAX_N_PUBKEY];
    size_t              num_pubkey;
    cert_info_t         certs[MAX_N_CA];
    size_t              num_cert;
} vld;

/**
 * @brief Callback for elf_foreach_segment(). 
 * Hash each LOAD segment of the ELF
 */
static keipm_err_t on_elf_segment(Elf64_Off foffset, Elf64_Xword flen, void *opaque)
{
    ssize_t len, remain;
    struct elf_op * elfop = (struct elf_op *)opaque;
    util_off_t pos;

    remain = flen;
    pos = foffset;
    while(remain > 0) {
        size_t to_read = MIN(remain, sizeof(vld.sha_filechunk));
        len = util_read(elfop->fp, vld.sha_filechunk, to_read, &pos);
        if (len <= 0) {
            break;
        }
        sha256_update(&vld.sha_state, vld.sha_filechunk, len, sha256_block);
        remain -= len;
    }
    return ERROR(kEIPM_OK, NULL);
}

/**
 * @brief Inner. Compute hash of all LOAD segments
 */
static keipm_err_t hash_elf(struct elf_op *parser)
{
    sha256_init(&vld.sha_state);
    RETURN_ON_ERROR(elf_foreach_segment(parser, PT_LOAD, on_elf_segment, parser));
    sha256_finalize(&vld.sha_state, sha256_block);
    sha256_fill_digest(&vld.sha_state, vld.hash);
    return ERROR(kEIPM_OK, NULL);
}

static keipm_err_t verify_rsa_sign_(
    const uint8_t *edigest, size_t edigest_len,
    const uint8_t *modulus, size_t modulus_len,
    const uint8_t *public_exponent, size_t public_exponent_len)
{
    keipm_err_t res;
    struct rsa_req rsa;
    struct rsa_key raw_key;
    unsigned int maxsize;
    rsa_init_req(&rsa);
    rsa.dst = NULL;

    raw_key.n = modulus;
    raw_key.n_sz = modulus_len;
    raw_key.e = public_exponent;
    raw_key.e_sz = public_exponent_len;
    if (rsa_set_pub_key(&rsa, &raw_key)) {
        res = ERROR(kEIPM_ERR_UNTRUSTED, "rsa: signature public key not valid");
        goto out;
    }

    /* Find out new modulus size from rsa implementation */
    maxsize = rsa_max_size(&rsa);
    if (maxsize > PAGE_SIZE) {
        res = ERROR(kEIPM_ERR_MALFORMED, "rsa: size of modulus is out of PAGE_SIZE");
        goto out;
    }
    rsa.src = edigest;
    rsa.src_len = edigest_len;
    rsa.dst_len = maxsize;
    rsa.dst = kmalloc(rsa.dst_len, GFP_KERNEL);
    if (rsa_verify(&rsa)) {
        res = ERROR(kEIPM_ERR_MALFORMED, "rsa: unexpected error");
        goto out;
    }

    /* anti leading ZERO padding */
    if ((rsa.dst_len >= sizeof(vld.hash))
            && (memcmp(rsa.dst+(rsa.dst_len-sizeof(vld.hash)), vld.hash, sizeof(vld.hash)) == 0)) {
        res = ERROR(kEIPM_OK, NULL);
        goto out;
    } else {
        res = ERROR(kEIPM_ERR_UNTRUSTED, "signature not valid");
    }

out:
    kfree(rsa.dst);
    rsa.dst = NULL;
    rsa_exit_req(&rsa);

    return res;
}

static keipm_err_t verify_rsa_signature(const uint8_t *edigest, size_t edigest_len)
{
    keipm_err_t err;
    size_t i;
    /* Try for each built-in pubkey */
    for(i=0; i<vld.num_pubkey; ++i) {
        err = verify_rsa_sign_(
                edigest, edigest_len,
                vld.pubkeys[i].key.modulus,
                vld.pubkeys[i].key.modulus_len,
                vld.pubkeys[i].key.public_exponent,
                vld.pubkeys[i].key.public_exponent_len);
        if (err.errno == kEIPM_OK) {
            return err;
        }
    }
    return err;
}

static keipm_err_t verify_cert_signature(const uint8_t *cert_data, size_t cert_len,
                                    const uint8_t *edigest, size_t edigest_len)
{
    keipm_err_t err;
    size_t i;
    static x509_cert_t cert;
    asn1_parser_t parser;

    asn1_init(&parser, cert_data, cert_len);

    RETURN_ON_ERROR(x509_parse_cert(&parser, &cert));

    /* check public key algorithm */
    switch (cert.pubkey.algorithm) {
        case X509_PUBKEY_RSA:
            break;
        default:
            return ERROR(kEIPM_ERR_INVALID, "certificate: unsupported pubkey algorithm");
    }

    /* Try for each root CA */
    for(i=0; i<vld.num_cert;++i) {
        err = cert_validate(vld.certs[i].data, vld.certs[i].length,
                        &parser, &cert);
        if (err.errno == kEIPM_OK) {
            return verify_rsa_sign_(
                edigest, edigest_len,
                cert.pubkey.key.rsa.n, cert.pubkey.key.rsa.n_num,
                cert.pubkey.key.rsa.e, cert.pubkey.key.rsa.e_num
            );
        }
    }
    return ERROR(kEIPM_ERR_INVALID, "elf: certificate is invalid");
}

static keipm_err_t validate_elf(struct elf_op *parser)
{
    keipm_err_t err;
    Elf64_Off sig_section_off;
    Elf64_Xword sig_section_size;
    uint8_t sig_hdr[2];
    uint8_t sig_hdr_cert_len[2];
    size_t sig_hdr_size;
    size_t cert_size = 0;
    size_t edigest_size;
    util_off_t pos;
    ssize_t len;

    err = elf_find_section(parser, SIG_ELF_SECTION_NAME, SHT_PROGBITS, &sig_section_off, &sig_section_size);
    if (err.errno != kEIPM_OK) {
        return ERROR(kEIPM_ERR_INVALID, "elf: no signature");
    }
    if (sig_section_size < sizeof(sig_hdr)) {
        return ERROR(kEIPM_ERR_INVALID, "elf: no signature");
    }

    /* read out signature header */
    pos = sig_section_off;
    len = util_read(parser->fp, sig_hdr, sizeof(sig_hdr), &pos);
    if (len != sizeof(sig_hdr)) {
        return ERROR(kEIPM_ERR_INVALID, "elf: can't not read file");
    }

    if (sig_hdr[0] != SIG_HDR_MAGIC) {
        return ERROR(kEIPM_ERR_INVALID, "elf: signature was broken");
    }

    switch (sig_hdr[1]) {
        case SIG_HDR_TYPE_RSA_KEY: {
            sig_hdr_size = sizeof(sig_hdr);
            break;
        }
        case SIG_HDR_TYPE_CERT: {
            /* read out length of cert */
            len = util_read(parser->fp, sig_hdr_cert_len, sizeof(sig_hdr_cert_len), &pos);
            if (len <= 0) {
                return ERROR(kEIPM_ERR_INVALID, "elf: can't not read file");
            }
            /* read out certificate data */
            cert_size = ((sig_hdr_cert_len[1] << 8) | sig_hdr_cert_len[0]);
            cert_size = MIN(cert_size, sizeof(vld.cert_buff));
            len = util_read(parser->fp, vld.cert_buff, cert_size, &pos);
            if (len != cert_size) {
                return ERROR(kEIPM_ERR_INVALID, "elf: invalid size of signature");
            }
            sig_hdr_size = sizeof(sig_hdr) + sizeof(sig_hdr_cert_len) + cert_size;
            break;
        }
        default: {
            return ERROR(kEIPM_ERR_INVALID, "elf: signature was broken");
        }
    }

    /* read out encrypted digest from signature section */
    edigest_size = MIN(sig_section_size-sig_hdr_size, sizeof(vld.edigest_buff));
    len = util_read(parser->fp, vld.edigest_buff, edigest_size, &pos);
    if (len != edigest_size) {
        return ERROR(kEIPM_ERR_INVALID, "elf: can't not read file");
    }

    RETURN_ON_ERROR(hash_elf(parser));

    switch (sig_hdr[1]) {
        case SIG_HDR_TYPE_RSA_KEY: {
            RETURN_ON_ERROR(verify_rsa_signature(vld.edigest_buff, edigest_size));
            break;
        }
        case SIG_HDR_TYPE_CERT: {
            RETURN_ON_ERROR(verify_cert_signature(vld.cert_buff, cert_size, vld.edigest_buff, edigest_size));
            break;
        }
    }

    return ERROR(kEIPM_OK, NULL);
}

int validator_analysis_binary(const char *pathname)
{
    int retval;
    keipm_err_t err;
    struct elf_op ep;
    struct file *file = filp_open(pathname, O_LARGEFILE | O_RDONLY, S_IRUSR);
    if (IS_ERR(file)) {
        return 0;
    }
    elf_setfile(&ep, file);
    err = elf_parse(&ep);
    if (err.errno != kEIPM_OK) { /* If not a valid ELF file */
        retval = 0;
        goto out;
    }
    err = validate_elf(&ep);
    printk("valid=%d %s\n", err.errno, err.reason);
    retval = (err.errno == kEIPM_OK) ? 0 : -ENOEXEC;
out:
    elf_exit(&ep);
    filp_close(file, NULL);
    return retval;
}

void validator_init(void) {
    vld.num_pubkey = 0;
    vld.num_cert = 0;
}

/**
 * @brief Add a RSA public key
 */
keipm_err_t validator_add_pubkey(const char *issuer, const uint8_t *pubkey, size_t pubkey_len)
{
    if (vld.num_pubkey + 1 > MAX_N_PUBKEY) {
        return ERROR(kEIPM_ERR_MEMORY, "the number of built-in pubkey is out of limit");
    }
    vld.pubkeys[vld.num_pubkey].issuer = util_new(strlen(issuer)+1);
    strcpy(vld.pubkeys[vld.num_pubkey].issuer, issuer);

    RETURN_ON_ERROR(pem_key_parse(&vld.pubkeys[vld.num_pubkey].key, false, pubkey, pubkey_len));

    vld.num_pubkey++;
    return ERROR(kEIPM_OK, NULL);
}

/**
 * @brief Add a root cert to the CA list. 
 * IMPORTANT! this would NOT copy the buffer of cert pointer.
 */
keipm_err_t validator_add_root_cert(const char *issuer, const uint8_t *cert, size_t cert_len)
{
    if (vld.num_cert +1 > MAX_N_CA) {
        return ERROR(kEIPM_ERR_MEMORY, "the number of CA is out of limit.");
    }
    vld.pubkeys[vld.num_pubkey].issuer = util_new(strlen(issuer)+1);
    strcpy(vld.pubkeys[vld.num_pubkey].issuer, issuer);

    /* IMPORTANT! reference buffer without copying */
    vld.certs[vld.num_cert].data = cert;
    vld.certs[vld.num_cert].length = cert_len;
    ++vld.num_cert;
    return ERROR(kEIPM_OK, NULL);
}
