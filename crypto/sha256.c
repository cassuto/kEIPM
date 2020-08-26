/*
 * Cryptographic API.
 *
 * SHA-256, as specified in
 * http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 *
 * SHA-256 code by Jean-Luc Cooke <jlcooke@certainkey.com>.
 *
 * Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * SHA224 Support Copyright 2007 Intel Corporation <jonathan.lynch@intel.com>
 *
 * This program is free software; you can redistribute _it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */
#include "utils.h"
#ifdef __KERNEL__
#include <asm/unaligned.h>
#include <linux/kernel.h>
#else
#	ifdef FEATURE_BIG_ENDIAN
#		include <linux/byteorder/big_endian.h>
#	else
#		include <linux/byteorder/little_endian.h>
#	endif
#endif
#include "sha.h"

const u8 sha224_zero_message_hash[SHA224_DIGEST_SIZE] = {
	0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47,
	0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2,
	0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4,
	0x2f
};

const u8 sha256_zero_message_hash[SHA256_DIGEST_SIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static inline u32 Ch(u32 x, u32 y, u32 z)
{
	return z ^ (x & (y ^ z));
}

static inline u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) | (z & (x | y));
}

/*
 * User space compact
 */
#ifndef __KERNEL__
struct __una_u32 { u32 x; } __packed;
static inline u32 __get_unaligned_cpu32(const void *p)
{
    const struct __una_u32 *ptr = (const struct __una_u32 *)p;
    return ptr->x;
}
static inline u32 get_unaligned_be32(const void *p)
{
    return __get_unaligned_cpu32((const u8 *)p);
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 ror32(__u32 word, unsigned int shift)
{
	return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

#define cpu_to_be64 __cpu_to_be64

#define memzero_explicit(_dst, _len) memset(_dst,0,_len)
#endif

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static inline void LOAD_OP(int I, u32 *W, const u8 *input)
{
	W[I] = get_unaligned_be32((u32 *)input + I);
}

static inline void BLEND_OP(int I, u32 *W)
{
	W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];
}

static void sha256_transform(u32 *state, const u8 *input)
{
	u32 a, b, c, d, e, f, g, h, t1, t2;
	u32 W[64];
	int i;

	/* load the input */
	for (i = 0; i < 16; i++)
		LOAD_OP(i, W, input);

	/* now blend */
	for (i = 16; i < 64; i++)
		BLEND_OP(i, W);

	/* load the state into our registers */
	a=state[0];  b=state[1];  c=state[2];  d=state[3];
	e=state[4];  f=state[5];  g=state[6];  h=state[7];

	/* now iterate */
	t1 = h + e1(e) + Ch(e,f,g) + 0x428a2f98 + W[ 0];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x71374491 + W[ 1];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb5c0fbcf + W[ 2];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xe9b5dba5 + W[ 3];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x3956c25b + W[ 4];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x59f111f1 + W[ 5];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x923f82a4 + W[ 6];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xab1c5ed5 + W[ 7];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xd807aa98 + W[ 8];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x12835b01 + W[ 9];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x243185be + W[10];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x550c7dc3 + W[11];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x72be5d74 + W[12];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x80deb1fe + W[13];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x9bdc06a7 + W[14];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc19bf174 + W[15];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xe49b69c1 + W[16];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xefbe4786 + W[17];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x0fc19dc6 + W[18];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x240ca1cc + W[19];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x2de92c6f + W[20];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4a7484aa + W[21];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5cb0a9dc + W[22];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x76f988da + W[23];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x983e5152 + W[24];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa831c66d + W[25];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb00327c8 + W[26];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xbf597fc7 + W[27];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xc6e00bf3 + W[28];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd5a79147 + W[29];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x06ca6351 + W[30];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x14292967 + W[31];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x27b70a85 + W[32];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x2e1b2138 + W[33];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x4d2c6dfc + W[34];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x53380d13 + W[35];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x650a7354 + W[36];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x766a0abb + W[37];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x81c2c92e + W[38];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x92722c85 + W[39];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xa2bfe8a1 + W[40];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa81a664b + W[41];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xc24b8b70 + W[42];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xc76c51a3 + W[43];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xd192e819 + W[44];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd6990624 + W[45];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xf40e3585 + W[46];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x106aa070 + W[47];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x19a4c116 + W[48];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x1e376c08 + W[49];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x2748774c + W[50];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x34b0bcb5 + W[51];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x391c0cb3 + W[52];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4ed8aa4a + W[53];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5b9cca4f + W[54];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x682e6ff3 + W[55];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x748f82ee + W[56];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x78a5636f + W[57];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x84c87814 + W[58];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x8cc70208 + W[59];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x90befffa + W[60];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xa4506ceb + W[61];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xbef9a3f7 + W[62];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc67178f2 + W[63];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;

	/* clear any sensitive info... */
	a = b = c = d = e = f = g = h = t1 = t2 = 0;
	memzero_explicit(W, 64 * sizeof(u32));
}

void sha256_block(struct sha256_state *sst, u8 const *src, int blocks)
{
	while (blocks--) {
		sha256_transform(sst->state, src);
		src += SHA256_BLOCK_SIZE;
	}
}

void sha256_fill_digest(struct sha256_state *sst, u8 dst[64])
{
	size_t i;
	for(i=0;i<SHA256_DIGEST_SIZE/4;++i) {
		*dst++ = (sst->state[i]>>24) & 0xff;
		*dst++ = (sst->state[i]>>16) & 0xff;
		*dst++ = (sst->state[i]>>8) & 0xff;
		*dst++ = sst->state[i] & 0xff;
	}
}

void sha224_init(struct sha256_state *sst)
{
	sst->state[0] = SHA224_H0;
	sst->state[1] = SHA224_H1;
	sst->state[2] = SHA224_H2;
	sst->state[3] = SHA224_H3;
	sst->state[4] = SHA224_H4;
	sst->state[5] = SHA224_H5;
	sst->state[6] = SHA224_H6;
	sst->state[7] = SHA224_H7;
	sst->count = 0;
}

void sha256_init(struct sha256_state *sst)
{
	sst->state[0] = SHA256_H0;
	sst->state[1] = SHA256_H1;
	sst->state[2] = SHA256_H2;
	sst->state[3] = SHA256_H3;
	sst->state[4] = SHA256_H4;
	sst->state[5] = SHA256_H5;
	sst->state[6] = SHA256_H6;
	sst->state[7] = SHA256_H7;
	sst->count = 0;
}

void sha256_update(struct sha256_state *sctx,
					const u8 *data,
					unsigned int len,
					sha256_block_fn *block_fn)
{
	unsigned int partial = sctx->count % SHA256_BLOCK_SIZE;

	sctx->count += len;

	if (unlikely((partial + len) >= SHA256_BLOCK_SIZE)) {
		int blocks;

		if (partial) {
			int p = SHA256_BLOCK_SIZE - partial;

			memcpy(sctx->buf + partial, data, p);
			data += p;
			len -= p;

			block_fn(sctx, sctx->buf, 1);
		}

		blocks = len / SHA256_BLOCK_SIZE;
		len %= SHA256_BLOCK_SIZE;

		if (blocks) {
			block_fn(sctx, data, blocks);
			data += blocks * SHA256_BLOCK_SIZE;
		}
		partial = 0;
	}
	if (len)
		memcpy(sctx->buf + partial, data, len);
}

void sha256_finalize(struct sha256_state *sctx,
					  sha256_block_fn *block_fn)
{
	const int bit_offset = SHA256_BLOCK_SIZE - sizeof(__be64);
	__be64 *bits = (__be64 *)(sctx->buf + bit_offset);
	unsigned int partial = sctx->count % SHA256_BLOCK_SIZE;

	sctx->buf[partial++] = 0x80;
	if (partial > bit_offset) {
		memset(sctx->buf + partial, 0x0, SHA256_BLOCK_SIZE - partial);
		partial = 0;

		block_fn(sctx, sctx->buf, 1);
	}

	memset(sctx->buf + partial, 0x0, bit_offset - partial);
	*bits = cpu_to_be64(sctx->count << 3);
	block_fn(sctx, sctx->buf, 1);
}
