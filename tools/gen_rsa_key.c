#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "signature.h"
#include "api.h"

#define BUG_CHECK "Internal error of libssl. Please check your OpenSSL library and then retry"

keipm_err_t gen_rsa_pri_key(const char *out_pri_key)
{
    keipm_err_t err;
    int ret;
    size_t pri_len = 0;
    char* pri_key = NULL;
    BIGNUM *bne = NULL;
    RSA *rsa = NULL;
    BIO* pri = NULL;
    FILE *fp = NULL;
    size_t len;
    
    bne = BN_new();
	ret = BN_set_word(bne, RSA_3);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, BUG_CHECK);
        goto out;
    }
	rsa = RSA_new();
	ret = RSA_generate_key_ex(rsa, SIG_RSA_BITS, bne, NULL);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, BUG_CHECK);
        goto out;
    }
    pri = BIO_new(BIO_s_mem());

    ret = PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, BUG_CHECK);
        goto out;
    }

    /*
     * Write private key with format of PEM PKCS#1 to file
     */
    pri_len = BIO_pending(pri);
    pri_key = (char*)malloc(pri_len + 1);
    ret = BIO_read(pri, pri_key, pri_len);
    if (ret != pri_len) {
        err = ERROR(kEIPM_ERR_MALFORMED, BUG_CHECK);
        goto out;
    }

    fp = fopen(out_pri_key, "wb");
    if (!fp) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not write target file");
        goto out;
    }
    len = fwrite(pri_key, 1,pri_len, fp);
    if (len!=pri_len) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not write target file");
        goto out;
    }

    err = ERROR(kEIPM_OK, NULL);
out:
    if (fp) fclose(fp);
    if (bne) BN_free(bne);
    if (rsa) RSA_free(rsa);
    if (pri) BIO_free_all(pri);
    if (pri_key) free(pri_key);

    return err;
}

keipm_err_t gen_rsa_pub_key(const char *in_pri_key, const char *out_pub_key)
{
    keipm_err_t err;
    int ret;
    RSA *rsa = NULL;
    BIO *keybio = NULL;
    BIO *outbio = NULL;

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

    outbio = BIO_new_file(out_pub_key, "w");
    if (!keybio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not write public key file");
        goto out;
    }

    ret = PEM_write_bio_RSAPublicKey(outbio, rsa);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, "no info of pubilc key in private key file");
        goto out;
    }

    err = ERROR(kEIPM_OK, NULL);
out:
    if (keybio) BIO_free(keybio);
    if (outbio) BIO_free(outbio);
    if (rsa) RSA_free(rsa);
    return err;
}
