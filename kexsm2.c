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
 *
 * SM2 key agreement (GM/T 0003.3-2012) for the sm2-sm3 key exchange.
 */

#include "includes.h"

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#endif /* WITH_OPENSSL */

#if defined(WITH_OPENSSL) && defined(NID_sm2)

#include <sys/types.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "kex.h"
#include "log.h"

/* Also used by ssh-sm2.c for SM2 signature generation/verification. */
int	sm2_compute_z_digest(u_char *, const EVP_MD *, const u_char *,
    size_t, const EC_KEY *);

/*
 * Compute the SM2 Z value, i.e.
 *   Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 */
int
sm2_compute_z_digest(u_char *out, const EVP_MD *digest, const u_char *id,
    size_t id_len, const EC_KEY *key)
{
	int rc = 0;
	const EC_GROUP *group = EC_KEY_get0_group(key);
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *hash = NULL;
	int bn_started = 0;
	BIGNUM *p = NULL, *a = NULL, *b = NULL;
	BIGNUM *xG = NULL, *yG = NULL, *xA = NULL, *yA = NULL;
	int p_bytes = 0;
	u_char *buf = NULL;
	uint16_t entl = 0;
	uint8_t e_byte = 0;

	hash = EVP_MD_CTX_new();
	ctx = BN_CTX_new();
	if (hash == NULL || ctx == NULL)
		goto done;
	BN_CTX_start(ctx);
	bn_started = 1;

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	xG = BN_CTX_get(ctx);
	yG = BN_CTX_get(ctx);
	xA = BN_CTX_get(ctx);
	yA = BN_CTX_get(ctx);
	if (yA == NULL)
		goto done;

	if (!EVP_DigestInit(hash, digest))
		goto done;

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	if (id_len >= (UINT16_MAX / 8)) {
		/* too large */
		goto done;
	}
	entl = (uint16_t)(8 * id_len);

	e_byte = entl >> 8;
	if (!EVP_DigestUpdate(hash, &e_byte, 1))
		goto done;
	e_byte = entl & 0xFF;
	if (!EVP_DigestUpdate(hash, &e_byte, 1))
		goto done;

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len))
		goto done;

	if (!EC_GROUP_get_curve(group, p, a, b, ctx))
		goto done;

	p_bytes = BN_num_bytes(p);
	buf = OPENSSL_zalloc(p_bytes);
	if (buf == NULL)
		goto done;

	if (BN_bn2binpad(a, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(b, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EC_POINT_get_affine_coordinates(group,
	        EC_GROUP_get0_generator(group), xG, yG, ctx)
	    || BN_bn2binpad(xG, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(yG, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EC_POINT_get_affine_coordinates(group,
	        EC_KEY_get0_public_key(key), xA, yA, ctx)
	    || BN_bn2binpad(xA, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(yA, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EVP_DigestFinal(hash, out, NULL))
		goto done;

	rc = 1;

 done:
	if (bn_started)
		BN_CTX_end(ctx);
	OPENSSL_free(buf);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(hash);
	return rc;
}

/* GM/T 0003.3-2012 key derivation function */
static int
kdf_gmt003_2012(u_char *out, size_t outlen, const u_char *Z, size_t Zlen,
    const u_char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
	EVP_MD_CTX *mctx = NULL;
	unsigned int counter;
	u_char ctr[4];
	size_t mdlen;
	int retval = 0;
	u_char dgst[EVP_MAX_MD_SIZE];

	if (!out || !outlen)
		return retval;
	if (md == NULL)
		md = EVP_sm3();
	if ((mdlen = EVP_MD_size(md)) == 0)
		return retval;
	if ((mctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	for (counter = 1;; counter++) {
		if (counter == 0) {
			error_f("SM2 KDF counter overflow");
			goto err;
		}
		if (!EVP_DigestInit(mctx, md))
			goto err;
		ctr[0] = (u_char)((counter >> 24) & 0xFF);
		ctr[1] = (u_char)((counter >> 16) & 0xFF);
		ctr[2] = (u_char)((counter >> 8) & 0xFF);
		ctr[3] = (u_char)(counter & 0xFF);
		if (!EVP_DigestUpdate(mctx, Z, Zlen) ||
		    !EVP_DigestUpdate(mctx, ctr, sizeof(ctr)) ||
		    !EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen) ||
		    !EVP_DigestFinal(mctx, dgst, NULL))
			goto err;

		if (outlen > mdlen) {
			memcpy(out, dgst, mdlen);
			out += mdlen;
			outlen -= mdlen;
		} else {
			memcpy(out, dgst, outlen);
			explicit_bzero(dgst, sizeof(dgst));
			break;
		}
	}
	retval = 1;
err:
	explicit_bzero(dgst, sizeof(dgst));
	EVP_MD_CTX_free(mctx);
	return retval;
}

static int
sm2_kap_compute_key(void *out, size_t outlen, int server,
    const u_char *peer_uid, int peer_uid_len,
    const u_char *self_uid, int self_uid_len,
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key,
    const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, const EVP_MD *md)
{
	BN_CTX *ctx = NULL;
	EC_POINT *UorV = NULL;
	const EC_POINT *Rs, *Rp;
	BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL;
	BIGNUM *two_power_w = NULL, *order = NULL;
	const BIGNUM *priv_key, *r;
	const EC_GROUP *group;
	int w, ret = -1;
	size_t buflen, len, elemet_len, idx;
	u_char *buf = NULL;

	if (outlen > INT_MAX)
		goto err;
	if (!peer_pub_key || !self_eckey)
		goto err;
	if ((priv_key = EC_KEY_get0_private_key(self_eckey)) == NULL)
		goto err;
	if (!peer_ecdhe_key || !self_ecdhe_key)
		goto err;

	Rs = EC_KEY_get0_public_key(self_ecdhe_key);
	Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
	r = EC_KEY_get0_private_key(self_ecdhe_key);
	if (!Rs || !Rp || !r)
		goto err;

	ctx = BN_CTX_new();
	Xs = BN_new();
	Xp = BN_new();
	h = BN_new();
	t = BN_new();
	two_power_w = BN_new();
	order = BN_new();
	if (!ctx || !Xs || !Xp || !h || !t || !two_power_w || !order)
		goto err;

	group = EC_KEY_get0_group(self_eckey);

	/* Second: calculate w */
	if (!EC_GROUP_get_order(group, order, ctx) ||
	    !EC_GROUP_get_cofactor(group, h, ctx))
		goto err;
	w = (BN_num_bits(order) + 1) / 2 - 1;
	if (!BN_lshift(two_power_w, BN_value_one(), w))
		goto err;

	/* Third: X = 2^w + (x mod 2^w) */
	if ((UorV = EC_POINT_new(group)) == NULL)
		goto err;

	/* Test peer public key is on curve */
	if (!EC_POINT_is_on_curve(group, Rp, ctx))
		goto err;

	/* Get x coordinates of self and peer ephemeral keys */
	if (!EC_POINT_get_affine_coordinates(group, Rs, Xs, NULL, ctx) ||
	    !EC_POINT_get_affine_coordinates(group, Rp, Xp, NULL, ctx))
		goto err;

	/* self: x mod 2^w + 2^w */
	if (!BN_nnmod(Xs, Xs, two_power_w, ctx) ||
	    !BN_add(Xs, Xs, two_power_w))
		goto err;
	/* peer: x mod 2^w + 2^w */
	if (!BN_nnmod(Xp, Xp, two_power_w, ctx) ||
	    !BN_add(Xp, Xp, two_power_w))
		goto err;

	/* Fourth: t = (Xs * r + d) * h */
	if (!BN_mod_mul(t, Xs, r, order, ctx) ||
	    !BN_mod_add(t, t, priv_key, order, ctx) ||
	    !BN_mul(t, t, h, ctx))
		goto err;

	/* Fifth: V (or U) = h * t * (Pp + [Xp]Rp) */
	if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx) ||
	    !EC_POINT_add(group, UorV, UorV,
	        EC_KEY_get0_public_key(peer_pub_key), ctx) ||
	    !EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
		goto err;
	if (EC_POINT_is_at_infinity(group, UorV))
		goto err;

	/* Sixth: derive the key from xU||yU||Z_A||Z_B */
	elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
	buflen = elemet_len * 2 + 32 * 2 + 1;    /* add 1 byte tag */
	buf = OPENSSL_malloc(buflen);
	if (buf == NULL)
		goto err;
	memset(buf, 0, buflen);
	/* first byte is the (unused) point tag, not valid key material */
	idx = EC_POINT_point2oct(group, UorV, POINT_CONVERSION_UNCOMPRESSED,
	    buf, buflen, ctx);
	if (idx == 0)
		goto err;

	if (!server) {
		/* side A: self Z first */
		if (!sm2_compute_z_digest(buf + idx, md, self_uid,
		    self_uid_len, self_eckey))
			goto err;
		idx += 32;
	}
	/* peer Z */
	if (!sm2_compute_z_digest(buf + idx, md, peer_uid, peer_uid_len,
	    peer_pub_key))
		goto err;
	idx += 32;
	if (server) {
		/* side B: self Z last */
		if (!sm2_compute_z_digest(buf + idx, md, self_uid,
		    self_uid_len, self_eckey))
			goto err;
		idx += 32;
	}

	/* Skip the leading point tag byte */
	len = outlen;
	if (!kdf_gmt003_2012(out, len, buf + 1, idx - 1, NULL, 0, md))
		goto err;

	ret = (int)outlen;

err:
	BN_free(Xs);
	BN_free(Xp);
	BN_free(h);
	BN_free(t);
	BN_free(two_power_w);
	BN_free(order);
	EC_POINT_free(UorV);
	if (buf != NULL) {
		explicit_bzero(buf, buflen);
		OPENSSL_free(buf);
	}
	BN_CTX_free(ctx);
	return ret;
}

/*
 * Derive the SM2 KAP user identity from the SSH session.  During the
 * initial key exchange the session ID has not been established yet (it is
 * set from the exchange hash once the shared secret is known), so bind the
 * identity to the KEXINIT exchange instead.  Both peers compute the same
 * value: client version, server version, client KEXINIT and server KEXINIT,
 * in that order.
 */
#define SM2_KAP_UID_LABEL	"SM2-KAP-UID"
#define SM2_KAP_UID_LEN		32

static int
sm2_kap_uid(u_char *uid, size_t uidlen, const struct kex *kex)
{
	EVP_MD_CTX *ctx = NULL;
	const struct sshbuf *ic, *is;
	u_char dgst[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	int ret = -1;

	if (uid == NULL || uidlen == 0 || kex == NULL ||
	    kex->my == NULL || kex->peer == NULL)
		return -1;
	if ((ctx = EVP_MD_CTX_new()) == NULL)
		return -1;
	if (!EVP_DigestInit(ctx, EVP_sm3()) ||
	    !EVP_DigestUpdate(ctx, SM2_KAP_UID_LABEL,
	    sizeof(SM2_KAP_UID_LABEL) - 1))
		goto out;
	if (kex->session_id != NULL && sshbuf_len(kex->session_id) != 0) {
		/* Rekey: both peers already share the initial session ID. */
		if (!EVP_DigestUpdate(ctx, sshbuf_ptr(kex->session_id),
		    sshbuf_len(kex->session_id)))
			goto out;
	} else {
		/*
		 * Initial KEX: session_id is still empty.  Bind to the
		 * KEXINIT exchange in a direction-independent order.
		 */
		ic = kex->server ? kex->peer : kex->my;
		is = kex->server ? kex->my : kex->peer;
		if (kex->client_version == NULL || kex->server_version == NULL ||
		    !EVP_DigestUpdate(ctx, sshbuf_ptr(kex->client_version),
		    sshbuf_len(kex->client_version)) ||
		    !EVP_DigestUpdate(ctx, sshbuf_ptr(kex->server_version),
		    sshbuf_len(kex->server_version)) ||
		    !EVP_DigestUpdate(ctx, sshbuf_ptr(ic), sshbuf_len(ic)) ||
		    !EVP_DigestUpdate(ctx, sshbuf_ptr(is), sshbuf_len(is)))
			goto out;
	}
	if (!EVP_DigestFinal(ctx, dgst, &dlen) || dlen < uidlen)
		goto out;
	memcpy(uid, dgst, uidlen);
	ret = 0;
 out:
	explicit_bzero(dgst, sizeof(dgst));
	EVP_MD_CTX_free(ctx);
	return ret;
}

int
SM2KAP_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
    const EC_KEY *eckey, int server, const struct kex *kex)
{
	int ret = 0;
	EC_KEY *pubkey = NULL;
	u_char id[SM2_KAP_UID_LEN] = { 0 };

	if (sm2_kap_uid(id, sizeof(id), kex) != 0)
		return 0;
	if ((pubkey = EC_KEY_new_by_curve_name(NID_sm2)) == NULL)
		goto out;
	if (EC_KEY_set_public_key(pubkey, pub_key) != 1)
		goto out;

	ret = sm2_kap_compute_key(out, outlen, server, id, (int)sizeof(id), id,
	    (int)sizeof(id), pubkey, eckey, pubkey, eckey, EVP_sm3());

out:
	explicit_bzero(id, sizeof(id));
	EC_KEY_free(pubkey);
	return ret;
}

#endif /* WITH_OPENSSL && NID_sm2 */
