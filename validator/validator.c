#include <linux/string.h>
#include "elf-op.h"
#include "rsa.h"
#include "sha.h"
#include "signature.h"
#include "pem-parser.h"
#include "cert-validator.h"

#include "validator.h"

/** Define max number of public keys built-in this module */
#define MAX_N_PUBKEY 5
/** Define max number of root CA certificates built-in this module */
#define MAX_N_CA 5
/** Define max size of signature data in bytes */
#define MAX_ENCDATA_BUFFER 1024*1024L

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
    uint8_t             edat_buff[MAX_ENCDATA_BUFFER];
    uint8_t             hash[SHA256_DIGEST_SIZE];
    struct sha256_state sha_state;
    uint8_t             sha_filechunk[SHA256_BLOCK_SIZE];
    pubkey_info_t       pubkeys[MAX_N_PUBKEY];
    size_t              num_pubkey;
    cert_info_t         certs[MAX_N_CA];
    size_t              num_cert;
} vld;

/**
 * @brief Inner. Callback of elf_foreach_segment(). 
 * To hash each LOAD segment of the ELF
 */
static keipm_err_t on_elf_segment(Elf64_Off foffset, Elf64_Xword flen, void *opaque)
{
    ssize_t len, remain;
    struct elf_op * elfop = (struct elf_op *)opaque;
    util_off_t pos;

    remain = flen;
    pos = foffset;
    while(remain > 0) {
        len = util_read(elfop->fp, vld.sha_filechunk, sizeof(vld.sha_filechunk), &pos);
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
};

/**
 * @brief Inner. Validate signature by means of RSA
 */
static keipm_err_t vld_rsa_signature(const uint8_t *edat, size_t edat_len)
{
    keipm_err_t res;
    struct rsa_req rsa;
    struct rsa_key raw_key;
    unsigned int maxsize;
    size_t i;

    rsa_init_req(&rsa);

    /*
     * Try foreach pubkeys
     */
    for(i=0; i<vld.num_pubkey; ++i) {
        rsa.dst = NULL;

        raw_key.n = vld.pubkeys[i].key.modulus;
        raw_key.n_sz = vld.pubkeys[i].key.modulus_len;
        raw_key.e = vld.pubkeys[i].key.public_exponent;
        raw_key.e_sz = vld.pubkeys[i].key.public_exponent_len;
        if (rsa_set_pub_key(&rsa, &raw_key)) {
            res = ERROR(kEIPM_ERR_UNTRUSTED, "rsa: signature public key not valid");
            goto error;
        }

        /* Find out new modulus size from rsa implementation */
        maxsize = rsa_max_size(&rsa);
        if (maxsize > PAGE_SIZE) {
            res = ERROR(kEIPM_ERR_MALFORMED, "rsa: size of modulus is out of PAGE_SIZE");
            goto error;
        }

        rsa.src = edat;
        rsa.src_len = edat_len;
        rsa.dst_len = maxsize;
        rsa.dst = kmalloc(rsa.dst_len, GFP_KERNEL);
        if (rsa_verify(&rsa)) {
            res = ERROR(kEIPM_ERR_MALFORMED, "rsa: unexpected error");
            goto error;
        }

        if ((rsa.dst_len == sizeof(vld.hash)) && (memcpy(rsa.dst, vld.hash, rsa.dst_len) == 0)) {
            res = ERROR(kEIPM_OK, NULL);
            goto error;
        } else {
            res = ERROR(kEIPM_ERR_UNTRUSTED, "signature not valid");
        }

    error:
        kfree(rsa.dst);
        rsa.dst = NULL;
        rsa_exit_req(&rsa);

        if (res.errno == kEIPM_OK) {
            break;
        }
    }

    return res;
}

static keipm_err_t validate_elf(struct elf_op *parser)
{
    keipm_err_t err;
    Elf64_Off sig_section_off;
    Elf64_Xword sig_section_size;
    util_off_t edat_pos;
    size_t edat_size;
    uint8_t sig_hdr[2];
    util_off_t pos;
    ssize_t len;

    err = elf_find_section(parser, SIG_ELF_SECTION_NAME, SHT_PROGBITS, &sig_section_off, &sig_section_size);
    if (err.errno != kEIPM_OK) {
        return ERROR(kEIPM_ERR_INVALID, "elf: no signature");
    }
    if (sig_section_size < sizeof(sig_hdr)) {
        return ERROR(kEIPM_ERR_INVALID, "elf: no signature");
    }

    pos = sig_section_off;
    len = util_read(parser->fp, sig_hdr, sizeof(sig_hdr), &pos);
    if (len != sizeof(sig_hdr)) {
        return ERROR(kEIPM_ERR_INVALID, "elf: can't not read file");
    }

    if (sig_hdr[0] != SIG_HDR_MAGIC) {
        return ERROR(kEIPM_ERR_INVALID, "elf: signature was broken");
    }

    RETURN_ON_ERROR(hash_elf(parser));

    /* read out encrypted digest from signature section */
    edat_pos = pos;
    edat_size = MIN(sig_section_size-edat_pos-1, sizeof(vld.edat_buff));
    len = util_read(parser->fp, vld.edat_buff, edat_size, &edat_pos);
    if (len <= 0) {
        return ERROR(kEIPM_ERR_INVALID, "elf: can't not read file");
    }

    switch (sig_hdr[1]) {
        case SIG_HDR_TYPE_RSA_KEY: {
            RETURN_ON_ERROR(vld_rsa_signature(vld.edat_buff, edat_size));
            break;
        }
        case SIG_HDR_TYPE_CERT:
            break;
        default:
            return ERROR(kEIPM_ERR_INVALID, "elf: signature was broken");
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
