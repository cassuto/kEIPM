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
#include <limits.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "signature.h"
#include "api.h"

#define BUG_CHECK " Please check your libssl"

static RSA *gen_key_pair() {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    int ret;

    bne = BN_new();
	ret = BN_set_word(bne, RSA_F4);
    if (ret != 1) {
        goto error;
    }
	rsa = RSA_new();
	ret = RSA_generate_key_ex(rsa, SIG_RSA_BITS, bne, NULL);
    if (ret != 1) {
        goto error;
    }

    goto out;
error:
    if (rsa) {
        RSA_free(rsa);
    }
    rsa = NULL;
out:
    if (bne)
        BN_free(bne);
    return rsa;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */
static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}	

/*
 * Format: DER
 * Hash: SHA256
 */
static keipm_err_t make_cert(const char *out_pathname,
    RSA **ca_key, /* when ca_key==public_key we suppose we're making CA*/
    RSA **public_key,
    const char *field_C,
    const char *field_S,
    const char *field_L,
    const char *field_O,
    const char *field_CN,
    int days)
{
    keipm_err_t err;
    int ret;
	X509 *x = NULL;
	EVP_PKEY *pk = NULL, *pk_priv = NULL;
	X509_NAME *name=NULL;
    BIO *bio=NULL;
    uint8_t gen_root = 1;
	
    if (*ca_key == *public_key) {
        gen_root = 1;
        if ((pk=EVP_PKEY_new()) == NULL) {
            err = ERROR(kEIPM_ERR_MEMORY, "out of memory");
            goto out;
        }
        if (!EVP_PKEY_assign_RSA(pk,*ca_key)) {
            err = ERROR(kEIPM_ERR_MEMORY, "Can not load RSA key." BUG_CHECK);
            goto out;
        }
        *ca_key = NULL;
    } else {
        gen_root = 0;
        if (((pk=EVP_PKEY_new()) == NULL) || ((pk_priv=EVP_PKEY_new()) == NULL)) {
            err = ERROR(kEIPM_ERR_MEMORY, "out of memory");
            goto out;
        }
        if (!EVP_PKEY_assign_RSA(pk_priv,*ca_key)) {
            err = ERROR(kEIPM_ERR_MEMORY, "Can not load RSA key." BUG_CHECK);
            goto out;
        }
        *ca_key = NULL;
        if (!EVP_PKEY_assign_RSA(pk,*public_key)) {
            err = ERROR(kEIPM_ERR_MEMORY, "Can not load RSA key." BUG_CHECK);
            goto out;
        }
        *public_key = NULL;
    }
    if ((x=X509_new()) == NULL) {
        err = ERROR(kEIPM_ERR_MEMORY, "out of memory");
        goto out;
    }

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), /* SERIAL */ 1);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

    name = X509_get_subject_name(x);
    if (!gen_root) {
	    
    }

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, (const unsigned char*)field_C, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"S",
				MBSTRING_ASC, (const unsigned char*)field_S, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"L",
				MBSTRING_ASC, (const unsigned char*)field_L, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"O",
				MBSTRING_ASC, (const unsigned char*)field_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, (const unsigned char*)field_CN, -1, -1, 0);

	/* Its self signed so set the issuer name to be the same as the
 	 * subject.
	 */
	X509_set_issuer_name(x,name);

    /* Add various extensions: standard extensions */
	add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(x, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, "sslCA");

	add_ext(x, NID_netscape_comment, "none");

	if (!X509_sign(x, gen_root ? pk : pk_priv, EVP_sha256())) {
        err = ERROR(kEIPM_ERR_MEMORY, "Can not sign cert." BUG_CHECK);
		goto out;
    }

    bio = BIO_new_file(out_pathname, "w");
    if (!bio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write certificate file. Please check your path and permission.");
        goto out;
    }

    ret = i2d_X509_bio(bio, x);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write certificate file. Please check your path and permission.");
        goto out;
    }

	err = ERROR(kEIPM_OK, NULL);
out:
    if (pk) {
        EVP_PKEY_free(pk);
    }
    if (pk_priv) {
        EVP_PKEY_free(pk_priv);
    }
    if (x) {
        X509_free(x);
    }
    if (bio) {
        BIO_free(bio);
    }
	return err;
}

keipm_err_t keipm_create_rootCA(const char *rootCA_Path, const RootCa *rootca)
{
    keipm_err_t err;
    char private_key_pathname[PATH_MAX];
    BIO *keybio;
    int ret;
    RSA *private_key = gen_key_pair();
    if (!private_key) {
        return ERROR(kEIPM_ERR_MEMORY, "Can not generate RSA key pair." BUG_CHECK);
    }

    /*
     * Save CA private key
     */
    snprintf(private_key_pathname, sizeof(private_key_pathname), "%s.key", rootCA_Path);
    keybio = BIO_new_file(private_key_pathname, "w");
    if (!keybio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write private key file. Please check your path and permission.");
        goto out;
    }

    ret = PEM_write_bio_RSAPrivateKey(keybio, private_key, NULL, NULL, 0, NULL, NULL);
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write private key file. Please check your path and permission.");
        goto out;
    }

    err = make_cert(rootCA_Path,
        &private_key,
        &private_key,
        rootca->Root_Country,
        rootca->Root_State,
        rootca->Root_Local,
        rootca->Root_Org_name,
        rootca->Root_Common_name,
        rootca->days);
out:
    if (keybio) {
        BIO_free(keybio);
    }
    if (private_key) {
        RSA_free(private_key);
    }
    return err;
}

keipm_err_t keipm_create_userCA(const char *out_cert_path, const UserCa *userca)
{
    keipm_err_t err;
    int ret;
    char private_key_pathname[PATH_MAX];
    RSA *CA_key = NULL;
    RSA *public_key = NULL;
    BIO *keybio = NULL, *outbio = NULL;

    /*
     * Load CA private key for signing user cert
     */
    keybio = BIO_new_file(userca->User_input_RootCA_Path, "r");
    if (!keybio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not read private key file. Please check your path and permission.");
        goto out;
    }

    CA_key = PEM_read_bio_RSAPrivateKey(keybio, &CA_key, NULL, NULL); 
    if (!CA_key) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not load private key file. Please check your path and permission.");
        goto out;
    }

    /*
     * Generate user private key
     */
    public_key = gen_key_pair();
    if (!public_key) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not generate private key." BUG_CHECK);
    }

    snprintf(private_key_pathname, sizeof(private_key_pathname), "%s.key", out_cert_path);
    outbio = BIO_new_file(private_key_pathname, "w");
    if (!outbio) {
        err = ERROR(kEIPM_ERR_MALFORMED, "Can not write private key file. Please check your path and permission.");
        goto out;
    }

    ret = PEM_write_bio_RSAPrivateKey(outbio, public_key, NULL, NULL, 0, NULL, NULL); 
    if (ret != 1) {
        err = ERROR(kEIPM_ERR_MALFORMED, "can not load private key file");
        goto out;
    }

    err = make_cert(out_cert_path,
        &CA_key,
        &public_key,
        userca->User_Country,
        userca->User_State,
        userca->User_Local,
        userca->User_Org_name,
        userca->User_Common_name,
        userca->days);
out:
    if (keybio) {
        BIO_free(keybio);
    }
    if (outbio) {
        BIO_free(outbio);
    }
    if (CA_key) {
        RSA_free(CA_key);
    }
    if (public_key) {
        RSA_free(public_key);
    }
    return err;
}