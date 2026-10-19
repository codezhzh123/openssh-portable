/* $OpenBSD$ */
/*
 * Copyright (c) 2023 Huawei Technologies Co., Ltd
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#endif /* WITH_OPENSSL */

#if defined(WITH_OPENSSL) && defined(NID_sm2)

#include <sys/types.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

/* Reuse some ECDSA internals */
extern const struct sshkey_impl_funcs sshkey_ecdsa_funcs;

/* Z value computation lives in kexsm2.c */
int	sm2_compute_z_digest(u_char *, const EVP_MD *, const u_char *,
    size_t, const EC_KEY *);

/*
 * Default user identity for SM2 signatures, from GM/T 0003.2-2012:
 * "1234567812345678".
 */
static const u_char sm2_id[] = "1234567812345678";
#define SM2_ID_LEN	(sizeof(sm2_id) - 1)

/*
 * Convert an EVP_PKEY holding an SM2 key into a legacy EC_KEY.  OpenSSL 3
 * stores SM2 keys as provider-backed keys that cannot be retrieved with
 * EVP_PKEY_get1_EC_KEY(), so extract the curve and the key material via the
 * generic parameter interface in that case.
 */
EC_KEY *
sshkey_sm2_pkey_to_ec_key(EVP_PKEY *pkey)
{
	EC_KEY *ec_key = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	char curve_name[64];
	u_char pubkey[256];
	size_t pubkey_len = sizeof(pubkey);
	BIGNUM *priv_bn = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *pub_point = NULL;
	int nid;

	if (pkey == NULL)
		return NULL;
	/* Some builds/versions can still bridge this directly */
	if ((ec_key = EVP_PKEY_get1_EC_KEY(pkey)) != NULL)
		return ec_key;
	if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
	    curve_name, sizeof(curve_name), NULL))
		return NULL;
	if ((nid = OBJ_txt2nid(curve_name)) == NID_undef)
		return NULL;
	if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL)
		goto out;
	if ((ec_key = EC_KEY_new()) == NULL)
		goto out;
	if (EC_KEY_set_group(ec_key, group) != 1)
		goto out;
	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
	    pubkey, sizeof(pubkey), &pubkey_len)) {
		if ((pub_point = EC_POINT_new(group)) == NULL)
			goto out;
		if (EC_POINT_oct2point(group, pub_point, pubkey,
		    pubkey_len, NULL) != 1)
			goto out;
		if (EC_KEY_set_public_key(ec_key, pub_point) != 1)
			goto out;
	}
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
	    &priv_bn) && priv_bn != NULL) {
		if (EC_KEY_set_private_key(ec_key, priv_bn) != 1)
			goto out;
	}
	if (EC_KEY_get0_public_key(ec_key) != NULL &&
	    EC_KEY_check_key(ec_key) != 1)
		goto out;
	EC_GROUP_free(group);
	EC_POINT_free(pub_point);
	BN_clear_free(priv_bn);
	return ec_key;
 out:
	EC_KEY_free(ec_key);
	EC_GROUP_free(group);
	EC_POINT_free(pub_point);
	BN_clear_free(priv_bn);
	return NULL;
#else
	/* In pre-3.0 OpenSSL, SM2 keys share the EC_KEY representation */
	if (pkey == NULL || EVP_PKEY_set_alias_type(pkey, EVP_PKEY_EC) != 1)
		return NULL;
	ec_key = EVP_PKEY_get1_EC_KEY(pkey);
	EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	return ec_key;
#endif
}

/* Return a legacy EC_KEY for "src", accepting either EC- or SM2-typed keys */
static EC_KEY *
ssh_sm2_get_ec_key(EVP_PKEY *src)
{
	EC_KEY *ec = NULL;

	if (src == NULL)
		return NULL;
	if ((ec = EVP_PKEY_get1_EC_KEY(src)) != NULL)
		return ec;
	return sshkey_sm2_pkey_to_ec_key(src);
}

/* Compute the SM2 message digest e = SM3(Z_A || M) */
static int
ssh_sm2_compute_e(const EC_KEY *key, const u_char *data, size_t dlen,
    BIGNUM *e)
{
	u_char z[32], dgst[32];
	EVP_MD_CTX *ctx = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (!sm2_compute_z_digest(z, EVP_sm3(), sm2_id, SM2_ID_LEN, key)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!EVP_DigestInit(ctx, EVP_sm3()) ||
	    !EVP_DigestUpdate(ctx, z, sizeof(z)) ||
	    !EVP_DigestUpdate(ctx, data, dlen) ||
	    !EVP_DigestFinal(ctx, dgst, NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_bin2bn(dgst, sizeof(dgst), e) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ret = 0;
 out:
	explicit_bzero(z, sizeof(z));
	explicit_bzero(dgst, sizeof(dgst));
	EVP_MD_CTX_free(ctx);
	return ret;
}

static void
ssh_sm2_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_sm2_equal(const struct sshkey *a, const struct sshkey *b)
{
	EC_KEY *ec_a = NULL, *ec_b = NULL;
	int ret = 0;

	if ((ec_a = ssh_sm2_get_ec_key(a->pkey)) == NULL ||
	    (ec_b = ssh_sm2_get_ec_key(b->pkey)) == NULL)
		goto out;
	if (a->ecdsa_nid != b->ecdsa_nid)
		goto out;
	if (EC_POINT_cmp(EC_KEY_get0_group(ec_a),
	    EC_KEY_get0_public_key(ec_a), EC_KEY_get0_public_key(ec_b),
	    NULL) != 0)
		goto out;
	ret = 1;
 out:
	EC_KEY_free(ec_a);
	EC_KEY_free(ec_b);
	return ret;
}

static int
ssh_sm2_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	return sshkey_ecdsa_funcs.serialize_public(key, b, opts);
}

static int
ssh_sm2_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	return sshkey_ecdsa_funcs.deserialize_public(ktype, b, key);
}

static int
ssh_sm2_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	return sshkey_ecdsa_funcs.serialize_private(key, b, opts);
}

static int
ssh_sm2_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	return sshkey_ecdsa_funcs.deserialize_private(ktype, b, key);
}

static int
ssh_sm2_generate(struct sshkey *k, int bits)
{
	EC_KEY *ec = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (bits != 256)
		return SSH_ERR_KEY_LENGTH;
	k->ecdsa_nid = NID_sm2;
	if ((ec = EC_KEY_new_by_curve_name(k->ecdsa_nid)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EC_KEY_generate_key(ec) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);
	if ((pkey = EVP_PKEY_new()) == NULL ||
	    EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	k->pkey = pkey;
	pkey = NULL;
	ret = 0;
 out:
	EC_KEY_free(ec);
	EVP_PKEY_free(pkey);
	return ret;
}

static int
ssh_sm2_copy_public(const struct sshkey *from, struct sshkey *to)
{
	return sshkey_ecdsa_funcs.copy_public(from, to);
}

static int
ssh_sm2_sign(struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen, const char *alg,
    const char *sk_provider, const char *sk_pin, u_int compat)
{
	EC_KEY *ec = NULL;
	BN_CTX *bnctx = NULL;
	const EC_GROUP *group;
	const BIGNUM *d;
	BIGNUM *e = NULL, *k = NULL, *r = NULL, *s = NULL;
	BIGNUM *x1 = NULL, *tmp = NULL, *order = NULL, *one = NULL;
	EC_POINT *pt = NULL;
	ECDSA_SIG *esig = NULL;
	struct sshbuf *b = NULL;
	u_char *der = NULL, *cp;
	int derlen = 0, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_SM2)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((ec = ssh_sm2_get_ec_key(key->pkey)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(ec);
	if ((d = EC_KEY_get0_private_key(ec)) == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((bnctx = BN_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_CTX_start(bnctx);
	e = BN_CTX_get(bnctx);
	k = BN_CTX_get(bnctx);
	r = BN_CTX_get(bnctx);
	s = BN_CTX_get(bnctx);
	x1 = BN_CTX_get(bnctx);
	tmp = BN_CTX_get(bnctx);
	order = BN_CTX_get(bnctx);
	one = BN_CTX_get(bnctx);
	if (one == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_one(one);
	if (EC_GROUP_get_order(group, order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((pt = EC_POINT_new(group)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = ssh_sm2_compute_e(ec, data, dlen, e)) != 0)
		goto out;

	for (;;) {
		/* k = random in [1, n-1] */
		do {
			if (BN_rand_range(k, order) != 1) {
				ret = SSH_ERR_LIBCRYPTO_ERROR;
				goto out;
			}
		} while (BN_is_zero(k));
		if (EC_POINT_mul(group, pt, k, NULL, NULL, bnctx) != 1 ||
		    EC_POINT_get_affine_coordinates(group, pt, x1, NULL,
		    bnctx) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		/* r = (e + x1) mod n; reject if r == 0 or r + k == n */
		if (BN_mod_add(r, e, x1, order, bnctx) != 1 ||
		    BN_mod_add(tmp, r, k, order, bnctx) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (BN_is_zero(r) || BN_is_zero(tmp))
			continue;
		/* s = (1 + d)^-1 * (k - r*d) mod n */
		if (BN_mod_mul(tmp, r, d, order, bnctx) != 1 ||
		    BN_mod_sub(tmp, k, tmp, order, bnctx) != 1 ||
		    BN_mod_add(s, d, one, order, bnctx) != 1 ||
		    BN_mod_inverse(s, s, order, bnctx) == NULL ||
		    BN_mod_mul(s, s, tmp, order, bnctx) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (BN_is_zero(s))
			continue;
		break;
	}

	if ((esig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	{
		BIGNUM *rr = BN_dup(r), *ss = BN_dup(s);

		if (rr == NULL || ss == NULL || ECDSA_SIG_set0(esig, rr, ss) != 1) {
			BN_free(rr);
			BN_free(ss);
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}
	if ((derlen = i2d_ECDSA_SIG(esig, NULL)) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((der = malloc(derlen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	cp = der;
	if (i2d_ECDSA_SIG(esig, &cp) != derlen) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_string(b, der, derlen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	if (bnctx != NULL)
		BN_CTX_end(bnctx);
	freezero(der, derlen > 0 ? (size_t)derlen : 0);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	EC_POINT_free(pt);
	BN_CTX_free(bnctx);
	EC_KEY_free(ec);
	return ret;
}

static int
ssh_sm2_verify(const struct sshkey *key, const u_char *signature,
    size_t signaturelen, const u_char *data, size_t dlen, const char *alg,
    u_int compat, struct sshkey_sig_details **detailsp)
{
	EC_KEY *ec = NULL;
	BN_CTX *bnctx = NULL;
	const EC_GROUP *group;
	const EC_POINT *pa;
	const unsigned char *psig;
	ECDSA_SIG *esig = NULL;
	const BIGNUM *r, *s;
	BIGNUM *e = NULL, *t = NULL, *x1 = NULL, *R = NULL, *order = NULL;
	EC_POINT *pt = NULL;
	struct sshbuf *b = NULL;
	const u_char *sig = NULL;
	char *ktype = NULL;
	size_t slen = 0;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_SM2 ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string_direct(b, &sig, &slen) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	psig = sig;
	if ((esig = d2i_ECDSA_SIG(NULL, &psig, slen)) == NULL) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ECDSA_SIG_get0(esig, &r, &s);
	if ((ec = ssh_sm2_get_ec_key(key->pkey)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(ec);
	if ((pa = EC_KEY_get0_public_key(ec)) == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((bnctx = BN_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_CTX_start(bnctx);
	e = BN_CTX_get(bnctx);
	t = BN_CTX_get(bnctx);
	x1 = BN_CTX_get(bnctx);
	R = BN_CTX_get(bnctx);
	order = BN_CTX_get(bnctx);
	if (order == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_GROUP_get_order(group, order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_is_zero(r) || BN_is_negative(r) || BN_cmp(r, order) >= 0 ||
	    BN_is_zero(s) || BN_is_negative(s) || BN_cmp(s, order) >= 0) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((ret = ssh_sm2_compute_e(ec, data, dlen, e)) != 0)
		goto out;
	/* t = (r + s) mod n; reject if t == 0 */
	if (BN_mod_add(t, r, s, order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (BN_is_zero(t)) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	if ((pt = EC_POINT_new(group)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* pt = [s]G + [t]PA */
	if (EC_POINT_mul(group, pt, s, pa, t, bnctx) != 1 ||
	    EC_POINT_get_affine_coordinates(group, pt, x1, NULL, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* R = (e + x1) mod n; accept iff R == r */
	if (BN_mod_add(R, e, x1, order, bnctx) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = BN_cmp(R, r) == 0 ? 0 : SSH_ERR_SIGNATURE_INVALID;
 out:
	if (bnctx != NULL)
		BN_CTX_end(bnctx);
	free(ktype);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	EC_POINT_free(pt);
	BN_CTX_free(bnctx);
	EC_KEY_free(ec);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_sm2_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_sm2_cleanup,
	/* .equal = */		ssh_sm2_equal,
	/* .ssh_serialize_public = */	ssh_sm2_serialize_public,
	/* .ssh_deserialize_public = */	ssh_sm2_deserialize_public,
	/* .ssh_serialize_private = */	ssh_sm2_serialize_private,
	/* .ssh_deserialize_private = */ssh_sm2_deserialize_private,
	/* .generate = */	ssh_sm2_generate,
	/* .copy_public = */	ssh_sm2_copy_public,
	/* .sign = */		ssh_sm2_sign,
	/* .verify = */		ssh_sm2_verify,
};

const struct sshkey_impl sshkey_sm2_impl = {
	/* .name = */		"sm2",
	/* .shortname = */	"SM2",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SM2,
	/* .nid = */		NID_sm2,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sm2_funcs,
};

const struct sshkey_impl sshkey_sm2_cert_impl = {
	/* .name = */		"sm2-cert",
	/* .shortname = */	"SM2-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SM2_CERT,
	/* .nid = */		NID_sm2,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sm2_funcs,
};

#endif /* WITH_OPENSSL && NID_sm2 */
