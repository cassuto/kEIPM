/* RSA asymmetric public-key algorithm [RFC3447]
 *
 * Copyright (c) 2015, Intel Corporation
 * Authors: Tadeusz Struk <tadeusz.struk@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include "rsa.h"

/*
 * RSAEP function [RFC3447 sec 5.1.1]
 * c = m^e mod n;
 */
static int _rsa_enc(const struct rsa_mpi_key *key, MPI c, MPI m)
{
	/* (1) Validate 0 <= m < n */
	if (mpi_cmp_ui(m, 0) < 0 || mpi_cmp(m, key->n) >= 0)
		return -EINVAL;

	/* (2) c = m^e mod n */
	return mpi_powm(c, m, key->e, key->n);
}

/*
 * RSADP function [RFC3447 sec 5.1.2]
 * m = c^d mod n;
 */
static int _rsa_dec(const struct rsa_mpi_key *key, MPI m, MPI c)
{
	/* (1) Validate 0 <= c < n */
	if (mpi_cmp_ui(c, 0) < 0 || mpi_cmp(c, key->n) >= 0)
		return -EINVAL;

	/* (2) m = c^d mod n */
	return mpi_powm(m, c, key->d, key->n);
}

/*
 * RSASP1 function [RFC3447 sec 5.2.1]
 * s = m^d mod n
 */
static int _rsa_sign(const struct rsa_mpi_key *key, MPI s, MPI m)
{
	/* (1) Validate 0 <= m < n */
	if (mpi_cmp_ui(m, 0) < 0 || mpi_cmp(m, key->n) >= 0)
		return -EINVAL;

	/* (2) s = m^d mod n */
	return mpi_powm(s, m, key->d, key->n);
}

/*
 * RSAVP1 function [RFC3447 sec 5.2.2]
 * m = s^e mod n;
 */
static int _rsa_verify(const struct rsa_mpi_key *key, MPI m, MPI s)
{
	/* (1) Validate 0 <= s < n */
	if (mpi_cmp_ui(s, 0) < 0 || mpi_cmp(s, key->n) >= 0)
		return -EINVAL;

	/* (2) m = s^e mod n */
	return mpi_powm(m, s, key->e, key->n);
}

static inline struct rsa_mpi_key *rsa_get_key(struct rsa_req *req)
{
	return &req->key;
}

int rsa_enc(struct rsa_req *req)
{
	const struct rsa_mpi_key *pkey = rsa_get_key(req);
	MPI m, c = mpi_alloc(0);
	int ret = 0;
	int sign;
	unsigned int nbytes = req->dst_len;

	if (!c)
		return -ENOMEM;

	if (unlikely(!pkey->n || !pkey->e)) {
		ret = -EINVAL;
		goto err_free_c;
	}

	ret = -ENOMEM;
	m = mpi_read_raw_data(req->src, req->src_len);
	if (!m)
		goto err_free_c;

	ret = _rsa_enc(pkey, c, m);
	if (ret)
		goto err_free_m;

	ret = mpi_read_buffer(c, req->dst, req->dst_len, &nbytes, &sign);
	if (ret)
		goto err_free_m;

	if (sign < 0)
		ret = -EBADMSG;

err_free_m:
	mpi_free(m);
err_free_c:
	mpi_free(c);
	return ret;
}

int rsa_dec(struct rsa_req *req)
{
	const struct rsa_mpi_key *pkey = rsa_get_key(req);
	MPI c, m = mpi_alloc(0);
	int ret = 0;
	int sign;
	unsigned int nbytes = req->dst_len;

	if (!m)
		return -ENOMEM;

	if (unlikely(!pkey->n || !pkey->d)) {
		ret = -EINVAL;
		goto err_free_m;
	}

	ret = -ENOMEM;
	c = mpi_read_raw_data(req->src, req->src_len);
	if (!c)
		goto err_free_m;

	ret = _rsa_dec(pkey, m, c);
	if (ret)
		goto err_free_c;

	ret = mpi_read_buffer(m, req->dst, req->dst_len, &nbytes, &sign);
	if (ret)
		goto err_free_c;

	if (sign < 0)
		ret = -EBADMSG;
err_free_c:
	mpi_free(c);
err_free_m:
	mpi_free(m);
	return ret;
}

int rsa_sign(struct rsa_req *req)
{
	const struct rsa_mpi_key *pkey = rsa_get_key(req);
	MPI m, s = mpi_alloc(0);
	int ret = 0;
	int sign;
	unsigned int nbytes = req->dst_len;

	if (!s)
		return -ENOMEM;

	if (unlikely(!pkey->n || !pkey->d)) {
		ret = -EINVAL;
		goto err_free_s;
	}

	ret = -ENOMEM;
	m = mpi_read_raw_data(req->src, req->src_len);
	if (!m)
		goto err_free_s;

	ret = _rsa_sign(pkey, s, m);
	if (ret)
		goto err_free_m;

	ret = mpi_read_buffer(s, req->dst, req->dst_len, &nbytes, &sign);
	if (ret)
		goto err_free_m;

	if (sign < 0)
		ret = -EBADMSG;

err_free_m:
	mpi_free(m);
err_free_s:
	mpi_free(s);
	return ret;
}

int rsa_verify(struct rsa_req *req)
{
	const struct rsa_mpi_key *pkey = rsa_get_key(req);
	MPI s, m = mpi_alloc(0);
	int ret = 0;
	int sign;
	unsigned int nbytes = req->dst_len;

	if (!m)
		return -ENOMEM;

	if (unlikely(!pkey->n || !pkey->e)) {
		ret = -EINVAL;
		goto err_free_m;
	}

	s = mpi_read_raw_data(req->src, req->src_len);
	if (!s) {
		ret = -ENOMEM;
		goto err_free_m;
	}

	ret = _rsa_verify(pkey, m, s);
	if (ret)
		goto err_free_s;

	ret = mpi_read_buffer(m, req->dst, req->dst_len, &nbytes, &sign);
	if (ret)
		goto err_free_s;

	if (sign < 0)
		ret = -EBADMSG;

err_free_s:
	mpi_free(s);
err_free_m:
	mpi_free(m);
	return ret;
}

static void rsa_free_mpi_key(struct rsa_mpi_key *key)
{
	mpi_free(key->d);
	mpi_free(key->e);
	mpi_free(key->n);
	key->d = NULL;
	key->e = NULL;
	key->n = NULL;
}

static int rsa_check_key_length(unsigned int len)
{
	switch (len) {
	case 512:
	case 1024:
	case 1536:
	case 2048:
	case 3072:
	case 4096:
		return 0;
	}

	return -EINVAL;
}

int rsa_set_pub_key(struct rsa_req *req, struct rsa_key *raw_key)
{
	struct rsa_mpi_key *mpi_key = rsa_get_key(req);

	/* Free the old MPI key if any */
	rsa_free_mpi_key(mpi_key);

	mpi_key->e = mpi_read_raw_data(raw_key->e, raw_key->e_sz);
	if (!mpi_key->e)
		goto err;

	mpi_key->n = mpi_read_raw_data(raw_key->n, raw_key->n_sz);
	if (!mpi_key->n)
		goto err;

	if (rsa_check_key_length(mpi_get_size(mpi_key->n) << 3)) {
		rsa_free_mpi_key(mpi_key);
		return -EINVAL;
	}

	return 0;

err:
	rsa_free_mpi_key(mpi_key);
	return -ENOMEM;
}

int rsa_set_priv_key(struct rsa_req *req, struct rsa_key *raw_key)
{
	struct rsa_mpi_key *mpi_key = rsa_get_key(req);

	/* Free the old MPI key if any */
	rsa_free_mpi_key(mpi_key);

	mpi_key->d = mpi_read_raw_data(raw_key->d, raw_key->d_sz);
	if (!mpi_key->d)
		goto err;

	mpi_key->e = mpi_read_raw_data(raw_key->e, raw_key->e_sz);
	if (!mpi_key->e)
		goto err;

	mpi_key->n = mpi_read_raw_data(raw_key->n, raw_key->n_sz);
	if (!mpi_key->n)
		goto err;

	if (rsa_check_key_length(mpi_get_size(mpi_key->n) << 3)) {
		rsa_free_mpi_key(mpi_key);
		return -EINVAL;
	}

	return 0;

err:
	rsa_free_mpi_key(mpi_key);
	return -ENOMEM;
}

unsigned int rsa_max_size(struct rsa_req *req)
{
	struct rsa_mpi_key *pkey = rsa_get_key(req);

	return mpi_get_size(pkey->n);
}

void rsa_exit_req(struct rsa_req *req)
{
	struct rsa_mpi_key *pkey = rsa_get_key(req);

	rsa_free_mpi_key(pkey);
}
