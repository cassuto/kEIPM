#include "asn1-parser/asn1.h"
#include "utils.h"
#include "base64.h"
#include "pem-parser.h"

#define PRIVATE_KEY_HDR "-----BEGIN RSA PRIVATE KEY-----"
#define PRIVATE_KEY_FOOTER "-----END RSA PRIVATE KEY-----"
#define PUBLIC_KEY_HDR "-----BEGIN RSA PUBLIC KEY-----"
#define PUBLIC_KEY_FOOTER "-----END RSA PUBLIC KEY-----"

keipm_err_t pem_key_parse(struct pem_key *pem, bool private, const uint8_t *dat, size_t dat_len)
{
    asn1_parser_t parser;
    const asn1_token_t *token = &parser.token;
    size_t i;
    const char *header, *footer;
    size_t header_size, footer_size;
    size_t base64_len;

    pem->buffer = util_new(dat_len);
    if (!pem->buffer) {
        return ERROR(kEIPM_ERR_MEMORY, "no memory");
    }
    if (private) {
        header = PRIVATE_KEY_HDR;
        header_size = sizeof(PRIVATE_KEY_HDR)-1;
        footer = PRIVATE_KEY_FOOTER;
        footer_size = sizeof(PRIVATE_KEY_FOOTER)-1;
    } else {
        header = PUBLIC_KEY_HDR;
        header_size = sizeof(PUBLIC_KEY_HDR)-1;
        footer = PUBLIC_KEY_FOOTER;
        footer_size = sizeof(PUBLIC_KEY_FOOTER)-1;
    }

    if (memcmp(dat, header, header_size)) {
        return ERROR(kEIPM_ERR_INVALID, private ? "pem: not a private key"
            : "pem: not a public key");
    }
    /* skip pem footer */
    base64_len = 0;
    for(i=header_size;i<dat_len-footer_size;++i) {
        if (strncmp(dat+i, footer, footer_size)==0) {
            base64_len = i-header_size;
            break;
        }
    }
    if (!base64_len) {
        return ERROR(kEIPM_ERR_INVALID, "pem: invalid footer of file");
    }

    pem->buffer_size = base64_decode(dat+header_size, base64_len, pem->buffer);
    if (!pem->buffer_size) {
        return ERROR(kEIPM_ERR_INVALID, "pem: not base64 encoded");
    }

    asn1_init(&parser, pem->buffer, pem->buffer_size);

    /* RSAPrivateKey */
    RETURN_ON_ERROR(asn1_push_seq(&parser));

    if (private) {
        /* version */
        RETURN_ON_ERROR(asn1_next(&parser));

        /* modulus INTEGER */
        RETURN_ON_ERROR(asn1_next(&parser));
        if (!asn1_is_int(token)) {
            return ERROR(kEIPM_ERR_INVALID, "pem: invalid format");
        }
        pem->modulus = token->data;
        pem->modulus_len = token->length;

        /* publicExponent INTEGER */
        RETURN_ON_ERROR(asn1_next(&parser));
        if (!asn1_is_int(token)) {
            return ERROR(kEIPM_ERR_INVALID, "pem: invalid format");
        }
        pem->public_exponent = token->data;
        pem->public_exponent_len = token->length;

        /* privateExponent INTEGER */
        RETURN_ON_ERROR(asn1_next(&parser));
        if (!asn1_is_int(token)) {
            return ERROR(kEIPM_ERR_INVALID, "pem: invalid format");
        }
        pem->private_exponent = token->data;
        pem->private_exponent_len = token->length;

    } else { /* public key */

    }

    return ERROR(kEIPM_OK, NULL);
}

void pem_exit(struct pem_key *pem)
{
    if (pem->buffer) {
        util_delete(pem->buffer);
        pem->buffer = NULL;
    }
}