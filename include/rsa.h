#ifndef RSA_H_
#define RSA_H_

#include <linux/types.h>
#include <linux/mpi.h>
#include <linux/errno.h>

struct rsa_mpi_key {
	MPI n;
	MPI e;
	MPI d;
};

struct rsa_req {
    u8 *src;
	u8 *dst;
	unsigned int src_len;
	unsigned int dst_len;
    struct rsa_mpi_key key;
};

/**
 * rsa_key - RSA key structure
 * @n           : RSA modulus raw byte stream
 * @e           : RSA public exponent raw byte stream
 * @d           : RSA private exponent raw byte stream
 * @p           : RSA prime factor p of n raw byte stream
 * @q           : RSA prime factor q of n raw byte stream
 * @dp          : RSA exponent d mod (p - 1) raw byte stream
 * @dq          : RSA exponent d mod (q - 1) raw byte stream
 * @qinv        : RSA CRT coefficient q^(-1) mod p raw byte stream
 * @n_sz        : length in bytes of RSA modulus n
 * @e_sz        : length in bytes of RSA public exponent
 * @d_sz        : length in bytes of RSA private exponent
 * @p_sz        : length in bytes of p field
 * @q_sz        : length in bytes of q field
 * @dp_sz       : length in bytes of dp field
 * @dq_sz       : length in bytes of dq field
 * @qinv_sz     : length in bytes of qinv field
 */
struct rsa_key {
	const u8 *n;
	const u8 *e;
	const u8 *d;
	const u8 *p;
	const u8 *q;
	const u8 *dp;
	const u8 *dq;
	const u8 *qinv;
	size_t n_sz;
	size_t e_sz;
	size_t d_sz;
	size_t p_sz;
	size_t q_sz;
	size_t dp_sz;
	size_t dq_sz;
	size_t qinv_sz;
};

extern int rsa_enc(struct rsa_req *req);
extern int rsa_dec(struct rsa_req *req);
extern int rsa_sign(struct rsa_req *req);
extern int rsa_verify(struct rsa_req *req);
extern int rsa_set_pub_key(struct rsa_req *req, struct rsa_key *raw_key);
extern int rsa_set_priv_key(struct rsa_req *req, struct rsa_key *raw_key);
extern unsigned int rsa_max_size(struct rsa_req *req);
extern void rsa_exit_req(struct rsa_req *req);

#endif // RSA_H_