#include <stdint.h>
#include <limits.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include "signature.h"
#include "elf-op.h"

#include "api.h"

#define SHA_CHUNK_SIZE 1024

struct hash_elf_params {
    /** ELF parser & writer */
    struct elf_op * elfop;
    /** SHA context state */
    SHA256_CTX      sha;
    uint8_t         sha_filechunk[/*SHA_CHUNK_SIZE*/64];
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
        len = util_read(params->elfop->fp, params->sha_filechunk, sizeof(params->sha_filechunk), &pos);
        if (len <= 0) {
            break;
        }
        printf("r%x ", params->sha_filechunk[0]);
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

keipm_err_t sign_elf_rsa(const char *target_elf, const char *in_pri_key)
{
    keipm_err_t err;
    int ret;
    char backup_pathname[PATH_MAX];
    BIO *keybio = NULL;
    RSA *rsa = NULL;
    uint8_t elf_digest[SHA256_DIGEST_LENGTH];
    uint8_t elf_signature[SIG_RSA_BITS/8];
    struct elf_op elfop;
    util_fp_t fp_elf_rd = NULL;
    util_fp_t fp_elf_wb = NULL;
    util_off_t pos;
    ssize_t len;
    uint8_t sig_hdr[2];
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
        err = ERROR(kEIPM_ERR_MALFORMED, "can not read ELF file");
        goto out;
    }
    elf_setfile(&elfop, fp_elf_rd);
    err = elf_parse(&elfop);
    if (err.errno != kEIPM_OK) {
        goto out;
    }

    /*
     * Load private key
     */
    keybio = BIO_new_file(in_pri_key, "r");
    if (!keybio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not read private key file");
        goto out;
    }

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL); 
    if (!rsa) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not load private key file");
        goto out;
    }

    /*
     * Pass #1: temporarily fill zeros with signature section,
     * so we can create target ELF
     */
    sig_section_size = sizeof(sig_hdr) + sizeof(elf_signature);
    sig_section_buff = (uint8_t*)malloc(sig_section_size);
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
    memset(elf_signature, 0, sizeof(elf_signature));
    ret = RSA_private_encrypt(sizeof(elf_signature),
                                elf_digest,
                                elf_signature, rsa, RSA_NO_PADDING);
    if (ret != sizeof(elf_signature)) {
        err = ERROR(kEIPM_ERR_MALFORMED, "failed on RSA encrypt");
        goto out;
    }

    /*
     * Construct signature header
     */
    sig_hdr[0] = SIG_HDR_MAGIC;
    sig_hdr[1] = SIG_HDR_TYPE_RSA_KEY;
    memcpy(sig_section_buff, sig_hdr, sizeof(sig_hdr));
    memcpy(sig_section_buff+sizeof(sig_hdr), elf_signature, sizeof(elf_signature));

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
    if (keybio) BIO_free(keybio);
    if (rsa) RSA_free(rsa);
    if (fp_elf_rd) fclose(fp_elf_rd);
    if (fp_elf_wb) fclose(fp_elf_wb);
    if (sig_section_buff) free(sig_section_buff);
    elf_exit(&elfop);
    return err;
}
