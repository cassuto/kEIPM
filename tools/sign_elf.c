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
#include <stdint.h>
#include <limits.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include "signature.h"
#include "elf-op.h"

#include "api.h"

#define SHA_FILE_CHUNK_SIZE 8192

struct hash_elf_params {
    /** ELF parser & writer */
    struct elf_op * elfop;
    /** SHA context state */
    SHA256_CTX      sha;
    uint8_t         sha_filechunk[SHA_FILE_CHUNK_SIZE];
};

/**
 * @brief Inner. Callback of elf_foreach_segment(). 
 * To hash each LOAD segment of the ELF
 */
static keipm_err_t on_elf_segment(Elf64_Off foffset, Elf64_Xword flen, void *opaque)
{
    ssize_t len, remain;
    struct hash_elf_params *params = (struct hash_elf_params *)opaque;
    util_off_t pos;

    remain = flen;
    pos = foffset;
    while(remain > 0) {
        size_t to_read = MIN(remain, sizeof(params->sha_filechunk));
        len = util_read(params->elfop->fp, params->sha_filechunk, to_read, &pos);
        if (len <= 0) {
            break;
        }
        SHA256_Update(&params->sha, params->sha_filechunk, len);
        remain -= len;
    }
    return ERROR(kEIPM_OK, NULL);
}

/**
 * @brief Inner. Compute hash of all LOAD segments
 */
static keipm_err_t hash_elf(struct elf_op *parser, uint8_t digest[SHA256_DIGEST_LENGTH])
{
    struct hash_elf_params params;
    params.elfop = parser;
    SHA256_Init(&params.sha);
    RETURN_ON_ERROR(elf_foreach_segment(parser, PT_LOAD, on_elf_segment, &params));
    SHA256_Final(digest, &params.sha);
    return ERROR(kEIPM_OK, NULL);
}

/**
 * @brief Copy file indicated by src to dst
 * This don't care about file permissions
 */
static keipm_err_t copy_file(const char *src, const char *dst)
{
    uint8_t cant_write = 0;
    util_fp_t fp_src = NULL, fp_dst = NULL;
    char chunk[512];
    size_t rlen, wlen;

    fp_src = fopen(src, "rb");
    fp_dst = fopen(dst, "wb");
    if (!fp_src || !fp_dst) {
       cant_write = 1;
       goto out;
    }
    
    for(;;) {
        rlen = fread(chunk, 1,sizeof(chunk), fp_src);
        if (ferror(fp_src) || rlen == 0) {
            break;
        }
        wlen = fwrite(chunk, 1,rlen, fp_dst);
        if (wlen != rlen) {
            cant_write = 1;
            goto out;
        }
    }

out:
    if (fp_src) fclose(fp_src);
    if (fp_dst) fclose(fp_dst);

    if (cant_write) {
        return ERROR(kEIPM_ERR_MALFORMED, "Can not write file. Please check your permission.");
    }
    return ERROR(kEIPM_OK, NULL);
}

static keipm_err_t sign_elf(const char *target_elf, uint8_t by_rsa, const char *in_key)
{
    keipm_err_t err;
    int ret;
    char backup_pathname[PATH_MAX];
    char private_key_pathname[PATH_MAX];
    BIO *keybio = NULL;
    RSA *rsa = NULL;
    FILE *fp_cert = NULL;
    size_t cert_size;
    uint8_t elf_digest[SHA256_DIGEST_LENGTH];
    uint8_t *elf_sign = NULL;
    size_t elf_sign_size;
    struct elf_op elfop;
    util_fp_t fp_elf_rd = NULL;
    util_fp_t fp_elf_wb = NULL;
    util_off_t pos;
    ssize_t len;
    uint8_t *rsa_in = NULL;
    uint8_t sig_hdr[2];
    size_t sig_hdr_ext_size;
    uint8_t *sig_section_buff = NULL;
    size_t sig_section_size;
    Elf64_Off sig_section_foff;

    /*
     * Create backup of the target file
     */
    snprintf(backup_pathname, sizeof(backup_pathname), "%s.bak", target_elf);
    err = copy_file(target_elf, backup_pathname);
    if (err.errno != kEIPM_OK) {
        goto out;
    }

    /*
     * Read the original ELF file
     */
    fp_elf_rd = fopen(backup_pathname, "rb");
    if (!fp_elf_rd) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not read ELF file. Please check your path and permission.");
        goto out;
    }
    elf_setfile(&elfop, fp_elf_rd);
    err = elf_parse(&elfop);
    if (err.errno != kEIPM_OK) {
        goto out;
    }

    if (by_rsa) {
        strcpy(private_key_pathname, in_key);
        sig_hdr_ext_size = 0;
    } else {
        snprintf(private_key_pathname, sizeof(private_key_pathname), "%s.key", in_key);
        
        /* Open user certificate file */
        fp_cert = fopen(in_key, "rb");
        if (!fp_cert) {
            err = ERROR(kEIPM_ERR_MALFORMED, "Can not read certificate file. Please check your path and permission.");
            goto out;
        }
        cert_size = util_filesize(fp_cert);
        sig_hdr_ext_size = SIZEOF_SIG_HDR_CERT_LEN + cert_size;
    }

    /*
     * Load RSA private key
     */
    keybio = BIO_new_file(private_key_pathname, "r");
    if (!keybio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not read private key file");
        goto out;
    }

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL); 
    if (!rsa) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not load private key file");
        goto out;
    }

    elf_sign_size = SIG_RSA_BITS / 8;
    sig_section_size = sizeof(sig_hdr) + sig_hdr_ext_size + elf_sign_size;

    elf_sign = (uint8_t *)malloc(elf_sign_size);
    sig_section_buff = (uint8_t*)malloc(sig_section_size);

    /*
     * Pass #1: temporarily fill zeros with signature section,
     * so we can create target ELF
     */
    memset(sig_section_buff, 0, sig_section_size);

    /*
     * Open target ELF file to write
     */
    fp_elf_wb = fopen(target_elf, "rb+");
    if (!fp_elf_wb) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write file. Please check your permission.");
        goto out;
    }

    /* create new ELF file based on the original */
    err = elf_write_signature_section(&elfop, fp_elf_wb, SIG_ELF_SECTION_NAME, sig_section_buff, sig_section_size, &sig_section_foff);
    if (err.errno != kEIPM_OK) {
        goto out;
    }

    /*
     * Pass #2: Compute hash digest of created target ELF
     */
    elf_exit(&elfop);
    elf_setfile(&elfop, fp_elf_wb);
    err = elf_parse(&elfop);
    if (err.errno != kEIPM_OK) {
        goto out;
    }
    err = hash_elf(&elfop, elf_digest);
    if (err.errno != kEIPM_OK) {
        goto out;
    }

    /*
     * Compute RSA signature of digest now
     */
    rsa_in = (uint8_t *)malloc(elf_sign_size);
    memset(rsa_in, 0, elf_sign_size);
    /* leading zero padding */
    memcpy(rsa_in+(elf_sign_size-sizeof(elf_digest)), elf_digest, sizeof(elf_digest));
    
    ret = RSA_private_encrypt(elf_sign_size, rsa_in,
                                elf_sign, rsa, RSA_NO_PADDING);
    if (ret != elf_sign_size) {
        err = ERROR(kEIPM_ERR_MALFORMED, "failed on RSA encrypt");
        goto out;
    }

    /*
     * Construct signature section
     */
    sig_hdr[0] = SIG_HDR_MAGIC;
    sig_hdr[1] = by_rsa ? SIG_HDR_TYPE_RSA_KEY : SIG_HDR_TYPE_CERT;
    memcpy(sig_section_buff, sig_hdr, sizeof(sig_hdr));
    
    if (by_rsa) {
        /* Write RSA signature */
        memcpy(sig_section_buff+sizeof(sig_hdr), elf_sign, elf_sign_size);
    } else {
        uint8_t *buf_ptr = sig_section_buff+sizeof(sig_hdr);
        /* Write certificate length */
        *buf_ptr++ = (cert_size) & 0xff;
        *buf_ptr++ = (cert_size>>8) & 0xff;
        /* Write certificate body */
        pos = 0;
        len = util_read(fp_cert, buf_ptr, cert_size, &pos);
        if (len != cert_size) {
            err = ERROR(kEIPM_ERR_MALFORMED, "Can not read certificate file");
            goto out;
        }
        /* Write RSA signature */
        memcpy(buf_ptr+cert_size, elf_sign, elf_sign_size);
    }

    /*
     * Write back signature to target ELF
     */
    pos = sig_section_foff;
    len = util_write(fp_elf_wb, sig_section_buff, sig_section_size, &pos);
    if (len != sig_section_size) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not write elf");
        goto out;
    }


    err = ERROR(kEIPM_OK, NULL);
out:
    if (keybio)
        BIO_free(keybio);
    if (rsa)
        RSA_free(rsa);
    if (rsa_in)
        free(rsa_in);
    if (fp_cert)
        fclose(fp_cert);
    if (fp_elf_rd)
        fclose(fp_elf_rd);
    if (fp_elf_wb)
        fclose(fp_elf_wb);
    if (elf_sign)
        free(elf_sign);
    if (sig_section_buff)
        free(sig_section_buff);
    elf_exit(&elfop);
    return err;
}

keipm_err_t keipm_set_Key(const char* prikey_path,const char* elf_path)
{
    return sign_elf(elf_path, 1, prikey_path);
}

keipm_err_t keipm_set_UserCA(const char* UserCA_Path,const char* elf_Path)
{
    return sign_elf(elf_Path, 0, UserCA_Path);
}