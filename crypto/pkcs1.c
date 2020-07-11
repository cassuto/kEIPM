#include <linux/string.h>
#include "pkcs1.h"

#define ASN1_SEQUENCE 0x10
#define ASN1_CONSTRUCTED 0x20
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06

int pkcs1_verify(const uint8_t *dec, size_t dec_lenght,
				const unsigned char *oid, size_t oid_size,
				const uint8_t *digest, size_t digest_length)
{
	int err = -EINVAL;
	unsigned int pos;
	const uint8_t *out_buf = dec;
    size_t dst_len = dec_lenght;

    if (out_buf[0] != 0x00)
        /* Decrypted value had no leading 0 byte */
        goto done;
    dst_len--;
    out_buf++;

	if (out_buf[0] != 0x01)
		goto done;
	for (pos = 1; pos < dst_len; pos++)
		if (out_buf[pos] != 0xff)
			break;

	if (pos < 9 || pos == dst_len || out_buf[pos] != 0x00)
		goto done;
	pos++;

	if (out_buf[pos] != (ASN1_SEQUENCE | ASN1_CONSTRUCTED))
		goto done;
	pos++;
	if (out_buf[pos] != (unsigned char)( 0x08 + oid_size + digest_length ))
		goto done;
	pos++;
	if (out_buf[pos] != (ASN1_SEQUENCE | ASN1_CONSTRUCTED))
		goto done;
	pos++;
	if (out_buf[pos] != (unsigned char)( 0x04 + oid_size ))
		goto done;
	pos++;
    if (out_buf[pos] != ASN1_OID)
		goto done;
	pos++;
    if (out_buf[pos] != (unsigned char) oid_size)
		goto done;
	pos++;
	if (memcmp(out_buf + pos, oid, oid_size))
		goto done;
    pos += oid_size;
    if (out_buf[pos] != ASN1_NULL)
		goto done;
	pos++;
    if (out_buf[pos] != 0x00)
		goto done;
	pos++;
    if (out_buf[pos] != ASN1_OCTET_STRING)
		goto done;
	pos++;
    if (out_buf[pos] != (unsigned char) digest_length)
		goto done;
	pos++;

	if (memcmp(out_buf + pos, digest, digest_length))
		goto done;
	pos += digest_length;

	if (dec_lenght < dst_len - pos)
		err = -EOVERFLOW;
	err = 0;
done:
	return err;
}
