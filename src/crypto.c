#include "crypto.h"
#include "storage.h"
#include "tls.h"

#include <unistd.h>  /* unlink() for selftest cleanup */

/* OpenSSL 3.0 deprecates the EC_KEY API in favor of OSSL_PARAM-based
 * EVP_PKEY. For a research driver the old API is clearer and still
 * works; suppress the warnings here rather than ifdef'ing two paths. */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>

int fp_crypto_rand(void *buf, size_t len)
{
	return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

int fp_crypto_sha256(const void *data, size_t len, uint8_t out[FP_SHA256_LEN])
{
	return EVP_Digest(data, len, out, NULL, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

int fp_crypto_sha384(const void *data, size_t len, uint8_t out[FP_SHA384_LEN])
{
	return EVP_Digest(data, len, out, NULL, EVP_sha384(), NULL) == 1 ? 0 : -1;
}

int fp_crypto_hmac_sha256(const void *key, size_t key_len,
                          const void *data, size_t data_len,
                          uint8_t out[FP_SHA256_LEN])
{
	unsigned int outlen = FP_SHA256_LEN;
	return HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &outlen)
	       ? 0 : -1;
}

int fp_crypto_hmac_sha384(const void *key, size_t key_len,
                          const void *data, size_t data_len,
                          uint8_t out[FP_SHA384_LEN])
{
	unsigned int outlen = FP_SHA384_LEN;
	return HMAC(EVP_sha384(), key, (int)key_len, data, data_len, out, &outlen)
	       ? 0 : -1;
}

static int aes256_cbc(const uint8_t key[FP_AES256_KEY_LEN],
                      const uint8_t iv[FP_AES_BLOCK_LEN],
                      const void *in, void *out, size_t data_len,
                      int encrypt)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	int ok = 1;
	if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt) != 1) ok = 0;
	if (ok) EVP_CIPHER_CTX_set_padding(ctx, 0);

	int outlen = 0, finlen = 0;
	if (ok && EVP_CipherUpdate(ctx, out, &outlen, in, (int)data_len) != 1) ok = 0;
	if (ok && EVP_CipherFinal_ex(ctx, (unsigned char *)out + outlen, &finlen) != 1) ok = 0;

	EVP_CIPHER_CTX_free(ctx);
	if (!ok) return -1;
	if ((size_t)(outlen + finlen) != data_len) return -1;
	return 0;
}

int fp_crypto_aes256_cbc_encrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t iv[FP_AES_BLOCK_LEN],
                                 const void *in, void *out, size_t data_len)
{
	return aes256_cbc(key, iv, in, out, data_len, 1);
}

int fp_crypto_aes256_cbc_decrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t iv[FP_AES_BLOCK_LEN],
                                 const void *in, void *out, size_t data_len)
{
	return aes256_cbc(key, iv, in, out, data_len, 0);
}

/* AES-256-GCM encrypt: takes 12-byte nonce, encrypts pt → ct (same length),
 * appends 16-byte auth tag. Optional aad (additional authenticated data,
 * e.g., TLS record header + seq_num) is authenticated but not encrypted.
 * Output buffer must hold pt_len + 16 bytes. */
int fp_crypto_aes256_gcm_encrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t nonce[12],
                                 const void *aad, size_t aad_len,
                                 const void *pt,  size_t pt_len,
                                 void *out_ct_plus_tag)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;
	int ok = 1;
	int outl = 0;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
	if (ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
	if (ok && aad && aad_len > 0) {
		int dummy = 0;
		if (EVP_EncryptUpdate(ctx, NULL, &dummy, (const unsigned char*)aad, (int)aad_len) != 1) ok = 0;
	}
	if (ok && pt_len > 0) {
		if (EVP_EncryptUpdate(ctx, (unsigned char*)out_ct_plus_tag, &outl,
		                      (const unsigned char*)pt, (int)pt_len) != 1) ok = 0;
	}
	int final_out = 0;
	if (ok && EVP_EncryptFinal_ex(ctx, (unsigned char*)out_ct_plus_tag + outl, &final_out) != 1) ok = 0;
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
	                              (unsigned char*)out_ct_plus_tag + pt_len) != 1) ok = 0;
	EVP_CIPHER_CTX_free(ctx);
	return ok ? 0 : -1;
}

/* AES-256-GCM decrypt: input is ct (pt_len bytes) || tag (16 bytes).
 * Returns 0 on success (tag verified), -1 on failure. */
int fp_crypto_aes256_gcm_decrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t nonce[12],
                                 const void *aad, size_t aad_len,
                                 const void *ct, size_t ct_len,
                                 const void *tag,
                                 void *out_pt)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;
	int ok = 1;
	int outl = 0;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) ok = 0;
	if (ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
	if (ok && aad && aad_len > 0) {
		int dummy = 0;
		if (EVP_DecryptUpdate(ctx, NULL, &dummy, (const unsigned char*)aad, (int)aad_len) != 1) ok = 0;
	}
	if (ok && ct_len > 0) {
		if (EVP_DecryptUpdate(ctx, (unsigned char*)out_pt, &outl,
		                      (const unsigned char*)ct, (int)ct_len) != 1) ok = 0;
	}
	if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) ok = 0;
	int final_out = 0;
	if (ok && EVP_DecryptFinal_ex(ctx, (unsigned char*)out_pt + outl, &final_out) != 1) ok = 0;
	EVP_CIPHER_CTX_free(ctx);
	return ok ? 0 : -1;
}

/* Build an EVP_PKEY for P-256 from raw private/public bytes. The caller
 * gets back something usable for EVP_PKEY_derive (ECDH) and friends. */
static EVP_PKEY *make_p256_priv(const uint8_t priv[FP_P256_PRIV_LEN])
{
	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ec) return NULL;

	BIGNUM *priv_bn = BN_bin2bn(priv, FP_P256_PRIV_LEN, NULL);
	if (!priv_bn) { EC_KEY_free(ec); return NULL; }

	if (EC_KEY_set_private_key(ec, priv_bn) != 1) {
		BN_free(priv_bn);
		EC_KEY_free(ec);
		return NULL;
	}
	BN_free(priv_bn);

	/* Derive the public point from the private scalar so signatures work. */
	const EC_GROUP *grp = EC_KEY_get0_group(ec);
	EC_POINT *pub = EC_POINT_new(grp);
	BN_CTX *bnctx = BN_CTX_new();
	BIGNUM *priv2 = BN_bin2bn(priv, FP_P256_PRIV_LEN, NULL);
	int ok = pub && bnctx && priv2 &&
	         EC_POINT_mul(grp, pub, priv2, NULL, NULL, bnctx) == 1 &&
	         EC_KEY_set_public_key(ec, pub) == 1;
	EC_POINT_free(pub);
	BN_CTX_free(bnctx);
	BN_free(priv2);
	if (!ok) { EC_KEY_free(ec); return NULL; }

	EVP_PKEY *pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
		EC_KEY_free(ec);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

static EVP_PKEY *make_p256_pub(const uint8_t pub_xy[FP_P256_PUB_LEN])
{
	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ec) return NULL;

	uint8_t uncompressed[1 + FP_P256_PUB_LEN];
	uncompressed[0] = 0x04;
	memcpy(uncompressed + 1, pub_xy, FP_P256_PUB_LEN);

	const EC_GROUP *grp = EC_KEY_get0_group(ec);
	EC_POINT *pt = EC_POINT_new(grp);
	BN_CTX *bnctx = BN_CTX_new();
	int ok = pt && bnctx &&
	         EC_POINT_oct2point(grp, pt, uncompressed, sizeof(uncompressed), bnctx) == 1 &&
	         EC_KEY_set_public_key(ec, pt) == 1;
	EC_POINT_free(pt);
	BN_CTX_free(bnctx);
	if (!ok) { EC_KEY_free(ec); return NULL; }

	EVP_PKEY *pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
		EC_KEY_free(ec);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return pkey;
}

int fp_crypto_p256_keygen(uint8_t priv_out[FP_P256_PRIV_LEN],
                          uint8_t pub_out[FP_P256_PUB_LEN])
{
	EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!ec) return -1;
	if (EC_KEY_generate_key(ec) != 1) { EC_KEY_free(ec); return -1; }

	const BIGNUM *priv = EC_KEY_get0_private_key(ec);
	if (BN_bn2binpad(priv, priv_out, FP_P256_PRIV_LEN) != FP_P256_PRIV_LEN) {
		EC_KEY_free(ec);
		return -1;
	}

	const EC_POINT *pt = EC_KEY_get0_public_key(ec);
	const EC_GROUP *grp = EC_KEY_get0_group(ec);
	BN_CTX *bnctx = BN_CTX_new();
	uint8_t uncompressed[1 + FP_P256_PUB_LEN];
	size_t ulen = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
	                                 uncompressed, sizeof(uncompressed), bnctx);
	BN_CTX_free(bnctx);
	EC_KEY_free(ec);
	if (ulen != sizeof(uncompressed) || uncompressed[0] != 0x04) return -1;
	memcpy(pub_out, uncompressed + 1, FP_P256_PUB_LEN);
	return 0;
}

const uint8_t fp_sensor_fw_pubkey[FP_P256_PUB_LEN] = {
	/* X = be4b906e 24fca153 c8a73c70 e897cd1b 31e49591 7a58a286 a870f609 3077993d */
	0xbe, 0x4b, 0x90, 0x6e, 0x24, 0xfc, 0xa1, 0x53,
	0xc8, 0xa7, 0x3c, 0x70, 0xe8, 0x97, 0xcd, 0x1b,
	0x31, 0xe4, 0x95, 0x91, 0x7a, 0x58, 0xa2, 0x86,
	0xa8, 0x70, 0xf6, 0x09, 0x30, 0x77, 0x99, 0x3d,
	/* Y = 10dff795 0f6883e6 a4117cda 82e70b8b f29d6b5b f53e77b4 c10e4900 83ba94f8 */
	0x10, 0xdf, 0xf7, 0x95, 0x0f, 0x68, 0x83, 0xe6,
	0xa4, 0x11, 0x7c, 0xda, 0x82, 0xe7, 0x0b, 0x8b,
	0xf2, 0x9d, 0x6b, 0x5b, 0xf5, 0x3e, 0x77, 0xb4,
	0xc1, 0x0e, 0x49, 0x00, 0x83, 0xba, 0x94, 0xf8,
};

int fp_crypto_p256_keygen_canonical_y(uint8_t priv_out[FP_P256_PRIV_LEN],
                                      uint8_t pub_xy_out[FP_P256_PUB_LEN])
{
	uint8_t pub_recovered[FP_P256_PUB_LEN];
	if (fp_crypto_p256_keygen(priv_out, pub_xy_out) != 0) return -1;
	/* Captured Windows fresh-pair hash2/cert Y bytes have ODD parity
	 * (LSB=1) — see clean-install frame 252 (`02fdee71...55608611`
	 * ends in 0x11, odd).  Force our Y to match. */
	if (fp_crypto_p256_point_from_x(pub_xy_out, 1, pub_recovered) != 0) return -1;
	if (memcmp(pub_recovered + 32, pub_xy_out + 32, 32) == 0)
		return 0;  /* Already on odd-Y path */

	/* We're on the -sqrt path. Negate the private scalar — that flips Y
	 * to -Y mod p, putting us on the +sqrt path. */
	BIGNUM *priv = BN_bin2bn(priv_out, FP_P256_PRIV_LEN, NULL);
	if (!priv) return -1;
	EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!grp) { BN_free(priv); return -1; }
	BIGNUM *order = BN_new();
	BN_CTX *bnctx = BN_CTX_new();
	int rc = -1;
	if (!order || !bnctx) goto out;
	if (EC_GROUP_get_order(grp, order, bnctx) != 1) goto out;
	BIGNUM *neg = BN_new();
	if (!neg || BN_sub(neg, order, priv) != 1) goto out;
	if (BN_bn2binpad(neg, priv_out, FP_P256_PRIV_LEN) != FP_P256_PRIV_LEN) goto out;
	BN_free(neg);
	/* Now flip Y in pub_xy_out to (p - Y) mod p. */
	memcpy(pub_xy_out + 32, pub_recovered + 32, 32);
	rc = 0;
out:
	BN_free(priv); BN_free(order);
	BN_CTX_free(bnctx); EC_GROUP_free(grp);
	return rc;
}

int fp_crypto_p256_point_from_x(const uint8_t x_be[32], int y_parity,
                                uint8_t pub_out[FP_P256_PUB_LEN])
{
	int rc = -1;
	EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM *x = NULL;
	EC_POINT *pt = NULL;
	BN_CTX *bnctx = BN_CTX_new();
	if (!grp || !bnctx) goto out;

	x = BN_bin2bn(x_be, 32, NULL);
	if (!x) goto out;
	pt = EC_POINT_new(grp);
	if (!pt) goto out;

	if (EC_POINT_set_compressed_coordinates(grp, pt, x, y_parity & 1, bnctx) != 1)
		goto out;

	uint8_t buf[1 + 64];
	size_t got = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
	                                buf, sizeof(buf), bnctx);
	if (got != sizeof(buf) || buf[0] != 0x04) goto out;
	memcpy(pub_out, buf + 1, FP_P256_PUB_LEN);
	rc = 0;
out:
	if (pt) EC_POINT_free(pt);
	if (x)  BN_free(x);
	if (bnctx) BN_CTX_free(bnctx);
	if (grp) EC_GROUP_free(grp);
	return rc;
}

int fp_crypto_p256_ecdh(const uint8_t priv[FP_P256_PRIV_LEN],
                        const uint8_t peer_pub[FP_P256_PUB_LEN],
                        uint8_t shared_out[FP_SHA256_LEN])
{
	EVP_PKEY *mine = make_p256_priv(priv);
	EVP_PKEY *peer = make_p256_pub(peer_pub);
	int rc = -1;
	if (!mine || !peer) goto out;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(mine, NULL);
	if (!ctx) goto out;
	if (EVP_PKEY_derive_init(ctx) != 1) { EVP_PKEY_CTX_free(ctx); goto out; }
	if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) { EVP_PKEY_CTX_free(ctx); goto out; }

	size_t shared_len = FP_SHA256_LEN;
	if (EVP_PKEY_derive(ctx, shared_out, &shared_len) != 1 || shared_len != FP_SHA256_LEN) {
		EVP_PKEY_CTX_free(ctx);
		goto out;
	}
	EVP_PKEY_CTX_free(ctx);
	rc = 0;
out:
	EVP_PKEY_free(mine);
	EVP_PKEY_free(peer);
	return rc;
}

int fp_crypto_p256_ecdsa_sign(const uint8_t priv[FP_P256_PRIV_LEN],
                              const uint8_t hash[FP_SHA256_LEN],
                              uint8_t *sig_out, size_t *sig_len_out)
{
	EVP_PKEY *mine = make_p256_priv(priv);
	if (!mine) return -1;
	EC_KEY *ec = (EC_KEY *)EVP_PKEY_get0_EC_KEY(mine);
	int rc = -1;
	if (!ec) goto out;

	unsigned int siglen = (unsigned int)*sig_len_out;
	if (ECDSA_sign(0, hash, FP_SHA256_LEN, sig_out, &siglen, ec) != 1) goto out;
	*sig_len_out = siglen;
	rc = 0;
out:
	EVP_PKEY_free(mine);
	return rc;
}

int fp_crypto_p256_ecdsa_verify(const uint8_t pub[FP_P256_PUB_LEN],
                                const uint8_t hash[FP_SHA256_LEN],
                                const uint8_t *sig, size_t sig_len)
{
	EVP_PKEY *peer = make_p256_pub(pub);
	if (!peer) return -1;
	EC_KEY *ec = (EC_KEY *)EVP_PKEY_get0_EC_KEY(peer);
	int rc = -1;
	if (!ec) goto out;
	if (ECDSA_verify(0, hash, FP_SHA256_LEN, sig, (int)sig_len, ec) != 1) goto out;
	rc = 0;
out:
	EVP_PKEY_free(peer);
	return rc;
}

/* ---- Known-answer self-test ---- */

static int memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

static int rec_cb_selftest(uint8_t ct, const uint8_t *b, int blen, void *c)
{
	(void)b;
	struct { uint8_t ct; int len; } *seen = c;
	seen->ct = ct;
	seen->len = blen;
	return 0;
}

static int hs_cb_selftest(uint8_t type, const uint8_t *b, int blen, void *c)
{
	(void)b; (void)blen;
	struct { uint8_t types[8]; int n; } *seen = c;
	if (seen->n < 8) seen->types[seen->n++] = type;
	return 0;
}

static uint8_t captured_body[256];
static int captured_len;
static int rt_cb_selftest(uint8_t ct, const uint8_t *body, int body_len, void *c)
{
	(void)ct; (void)c;
	captured_len = body_len;
	if (body_len > 0 && body_len <= (int)sizeof(captured_body))
		memcpy(captured_body, body, (size_t)body_len);
	return 0;
}

int fp_crypto_selftest(void)
{
	/* SHA-256 of "abc" — RFC 6234 test vector. */
	static const uint8_t sha256_abc[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	uint8_t h[FP_SHA384_LEN];
	if (fp_crypto_sha256("abc", 3, h) != 0) { fprintf(stderr, "sha256 fail\n"); return -1; }
	if (!memeq(h, sha256_abc, 32)) { fprintf(stderr, "sha256 KAT mismatch\n"); return -1; }
	printf("  sha256 KAT      OK\n");

	/* SHA-384 of "abc" — RFC 6234. */
	static const uint8_t sha384_abc[] = {
		0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
		0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
		0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
		0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
		0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
		0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
	};
	if (fp_crypto_sha384("abc", 3, h) != 0) { fprintf(stderr, "sha384 fail\n"); return -1; }
	if (!memeq(h, sha384_abc, 48)) { fprintf(stderr, "sha384 KAT mismatch\n"); return -1; }
	printf("  sha384 KAT      OK\n");

	/* HMAC-SHA384 — RFC 4231 test case 1: key=0x0b×20, data="Hi There". */
	static const uint8_t hmac_key[20] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b,
	};
	static const uint8_t hmac_expected[FP_SHA384_LEN] = {
		0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
		0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
		0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
		0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
		0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
		0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
	};
	if (fp_crypto_hmac_sha384(hmac_key, 20, "Hi There", 8, h) != 0) {
		fprintf(stderr, "hmac fail\n"); return -1;
	}
	if (!memeq(h, hmac_expected, 48)) { fprintf(stderr, "hmac KAT mismatch\n"); return -1; }
	printf("  hmac-sha384 KAT OK\n");

	/* AES-256-CBC round trip with a random key/iv/plaintext. */
	uint8_t key[FP_AES256_KEY_LEN], iv[FP_AES_BLOCK_LEN];
	uint8_t pt[64], ct[64], pt2[64];
	if (fp_crypto_rand(key, sizeof(key)) != 0
	 || fp_crypto_rand(iv, sizeof(iv)) != 0
	 || fp_crypto_rand(pt, sizeof(pt)) != 0) {
		fprintf(stderr, "rand fail\n"); return -1;
	}
	if (fp_crypto_aes256_cbc_encrypt(key, iv, pt, ct, sizeof(pt)) != 0
	 || fp_crypto_aes256_cbc_decrypt(key, iv, ct, pt2, sizeof(pt)) != 0) {
		fprintf(stderr, "aes round-trip fail\n"); return -1;
	}
	if (!memeq(pt, pt2, sizeof(pt))) {
		fprintf(stderr, "aes round-trip mismatch\n"); return -1;
	}
	printf("  aes256-cbc      OK (round trip)\n");

	/* ECDSA sign/verify round trip on a random P-256 keypair. */
	uint8_t priv[FP_P256_PRIV_LEN], pub[FP_P256_PUB_LEN];
	if (fp_crypto_p256_keygen(priv, pub) != 0) {
		fprintf(stderr, "p256 keygen fail\n"); return -1;
	}
	uint8_t msg_hash[FP_SHA256_LEN];
	if (fp_crypto_sha256("test message", 12, msg_hash) != 0) return -1;
	uint8_t sig[FP_P256_SIG_MAX];
	size_t sig_len = sizeof(sig);
	if (fp_crypto_p256_ecdsa_sign(priv, msg_hash, sig, &sig_len) != 0) {
		fprintf(stderr, "ecdsa sign fail\n"); return -1;
	}
	if (fp_crypto_p256_ecdsa_verify(pub, msg_hash, sig, sig_len) != 0) {
		fprintf(stderr, "ecdsa verify fail\n"); return -1;
	}
	printf("  p256 ECDSA      OK (sign+verify round trip, sig=%zu B)\n", sig_len);

	/* ECDH round trip: both sides should agree on the shared secret. */
	uint8_t priv_a[FP_P256_PRIV_LEN], pub_a[FP_P256_PUB_LEN];
	uint8_t priv_b[FP_P256_PRIV_LEN], pub_b[FP_P256_PUB_LEN];
	uint8_t s_a[FP_SHA256_LEN], s_b[FP_SHA256_LEN];
	if (fp_crypto_p256_keygen(priv_a, pub_a) != 0
	 || fp_crypto_p256_keygen(priv_b, pub_b) != 0) {
		fprintf(stderr, "ecdh keygen fail\n"); return -1;
	}
	if (fp_crypto_p256_ecdh(priv_a, pub_b, s_a) != 0
	 || fp_crypto_p256_ecdh(priv_b, pub_a, s_b) != 0) {
		fprintf(stderr, "ecdh derive fail\n"); return -1;
	}
	if (!memeq(s_a, s_b, FP_SHA256_LEN)) {
		fprintf(stderr, "ecdh disagreement\n"); return -1;
	}
	printf("  p256 ECDH       OK (both sides derive same secret)\n");

	/* TLS-PRF KAT — reference output produced by python-validity's prf()
	 * (which is byte-identical to what our DLL's palPRF computes).
	 * Input: secret = 0x0b*20, seed = "prf-test-seed".
	 * See [[project-python-validity-rosetta]] for the protocol family. */
	uint8_t prf_out[100];
	static const uint8_t prf_secret[20] = {
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
		0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
	};
	static const char prf_seed[] = "prf-test-seed";
	static const uint8_t prf_expected_100[100] = {
		0x68,0x4e,0x7e,0x0c,0x11,0xf1,0x6a,0x0f,0xef,0x71,0xaa,0xbb,0x32,0x3d,0x4a,0x6f,
		0xb0,0xbe,0x50,0x4e,0x36,0x7b,0x10,0x44,0x98,0xe3,0xaa,0xcc,0x9c,0xe5,0xfc,0x38,
		0x4c,0x35,0x66,0xdd,0xa4,0x16,0xc2,0x59,0x27,0xda,0x4e,0x62,0x9c,0x73,0xc2,0xde,
		0x63,0x58,0x05,0x91,0xb3,0x68,0xf7,0xf9,0x27,0x0c,0x85,0xd4,0xe5,0xd8,0x94,0xef,
		0x21,0x60,0xc0,0x91,0x55,0xfe,0x42,0xb7,0xba,0x57,0x71,0xf2,0x93,0x8d,0x3b,0xa9,
		0x13,0x7f,0xe8,0x72,0xa6,0x54,0x79,0x03,0x5d,0x5c,0xf2,0x96,0xdd,0x56,0xc7,0xec,
		0x54,0x44,0x4c,0x94,
	};
	if (fp_tls_prf(prf_secret, sizeof(prf_secret),
	               prf_seed, sizeof(prf_seed) - 1,
	               prf_out, sizeof(prf_out)) != 0) {
		fprintf(stderr, "tls_prf fail\n"); return -1;
	}
	if (memcmp(prf_out, prf_expected_100, sizeof(prf_expected_100)) != 0) {
		fprintf(stderr, "tls_prf KAT mismatch\n");
		fprintf(stderr, "  expected first 32: ");
		for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", prf_expected_100[i]);
		fprintf(stderr, "\n  got              : ");
		for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", prf_out[i]);
		fprintf(stderr, "\n");
		return -1;
	}
	printf("  tls_prf KAT     OK (matches python-validity output, 100 B)\n");

	/* TLS record framing KAT — parse captured try-3 ClientHello bytes.
	 * The captured frame 180 was 82 bytes: `44 00 00 00` Synaptics prefix
	 * + a single TLS record (handshake / ClientHello, length 0x49 = 73). */
	static const uint8_t client_hello_record[] = {
		/* TLS record header */
		0x16, 0x03, 0x03, 0x00, 0x49,
		/* Handshake (ClientHello) body — 73 B */
		0x01, 0x00, 0x00, 0x45, 0x03, 0x03,
		0x0b, 0x2c, 0x3f, 0x25, 0xd6, 0xb7, 0xd7, 0x6f,
		0xad, 0x71, 0x88, 0x24, 0xc6, 0xbc, 0xf0, 0x66,
		0x16, 0xdf, 0x1e, 0x53, 0x6b, 0xc3, 0x51, 0xc8,
		0xa1, 0x6b, 0x8c, 0x07, 0x3e, 0x71, 0x4b, 0xf0,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0xc0, 0x05, 0xc0, 0x2e, 0x00, 0x3d,
		0x00, 0x8d, 0x00, 0xa8, 0x00, 0x00, 0x0a, 0x00,
		0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00,
		0x02, 0x01, 0x00,
	};
	struct fp_tls_state st;
	if (fp_tls_state_init(&st) != 0) { fprintf(stderr, "tls init fail\n"); return -1; }

	struct { uint8_t ct; int len; } seen = { 0xff, -1 };
	int n = fp_tls_parse_records(&st, client_hello_record, sizeof(client_hello_record),
	                             rec_cb_selftest, &seen);
	fp_tls_state_destroy(&st);
	if (n != 1 || seen.ct != FP_TLS_CT_HANDSHAKE || seen.len != 0x49) {
		fprintf(stderr, "tls record-parse KAT mismatch (n=%d ct=0x%02x len=%d)\n",
			n, seen.ct, seen.len);
		return -1;
	}
	printf("  tls record KAT  OK (parsed captured ClientHello: 1 record, ct=0x16, len=73)\n");

	/* TLS ClientHello byte-output KAT — when our builder uses try-3's
	 * captured client_random, the output should match the captured
	 * handshake-message body byte-for-byte. */
	struct fp_tls_state st2;
	if (fp_tls_state_init(&st2) != 0) return -1;
	static const uint8_t try3_random[32] = {
		0x0b, 0x2c, 0x3f, 0x25, 0xd6, 0xb7, 0xd7, 0x6f,
		0xad, 0x71, 0x88, 0x24, 0xc6, 0xbc, 0xf0, 0x66,
		0x16, 0xdf, 0x1e, 0x53, 0x6b, 0xc3, 0x51, 0xc8,
		0xa1, 0x6b, 0x8c, 0x07, 0x3e, 0x71, 0x4b, 0xf0,
	};
	memcpy(st2.client_random, try3_random, 32);
	uint8_t ch_msg[128];
	int ch_len = fp_tls_make_client_hello(&st2, ch_msg, sizeof(ch_msg));
	/* Captured frame 180 had: 16 03 03 00 49 | <body>.
	 * Body is the inner handshake message starting at 01 00 00 45. */
	static const uint8_t expected_ch[] = {
		0x01, 0x00, 0x00, 0x45, 0x03, 0x03,
		0x0b, 0x2c, 0x3f, 0x25, 0xd6, 0xb7, 0xd7, 0x6f,
		0xad, 0x71, 0x88, 0x24, 0xc6, 0xbc, 0xf0, 0x66,
		0x16, 0xdf, 0x1e, 0x53, 0x6b, 0xc3, 0x51, 0xc8,
		0xa1, 0x6b, 0x8c, 0x07, 0x3e, 0x71, 0x4b, 0xf0,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0xc0, 0x05, 0xc0, 0x2e, 0x00, 0x3d,
		0x00, 0x8d, 0x00, 0xa8, 0x00, 0x00, 0x0a, 0x00,
		0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00,
		0x02, 0x01, 0x00,
	};
	if (ch_len != (int)sizeof(expected_ch) || memcmp(ch_msg, expected_ch, sizeof(expected_ch)) != 0) {
		fprintf(stderr, "tls ClientHello build mismatch (got %d B, expected %zu B)\n",
			ch_len, sizeof(expected_ch));
		fprintf(stderr, "  got     : ");
		for (int i = 0; i < ch_len; i++) fprintf(stderr, "%02x", ch_msg[i]);
		fprintf(stderr, "\n  expected: ");
		for (size_t i = 0; i < sizeof(expected_ch); i++) fprintf(stderr, "%02x", expected_ch[i]);
		fprintf(stderr, "\n");
		fp_tls_state_destroy(&st2);
		return -1;
	}
	printf("  tls ClHello KAT OK (build matches captured try-3 frame 180 byte-for-byte)\n");

	/* TLS handshake splitter KAT — captured frame 183 carries 3 messages
	 * concatenated: ServerHello (45 B) + CertificateRequest (4 B) +
	 * ServerHelloDone (0 B), with 4-byte headers each. */
	static const uint8_t frame183_body[] = {
		/* msg 1: ServerHello, len 0x2d = 45 */
		0x02, 0x00, 0x00, 0x2d,
		0x03, 0x83,
		0x00, 0x05, 0x2e, 0xd9, 0x57, 0xb8, 0xcc, 0xbf,
		0x64, 0x11, 0xaf, 0x8f, 0x24, 0x66, 0xf4, 0x06,
		0xf1, 0x1e, 0x85, 0xd3, 0x74, 0x99, 0x3d, 0x57,
		0xb6, 0xad, 0x8d, 0xb9, 0x01, 0xad, 0x14, 0x96,
		0x07, 0x54, 0x4c, 0x53, 0x57, 0xb8, 0xcc, 0xbf,
		0xc0, 0x2e,
		0x00,
		/* msg 2: CertificateRequest, len 4 */
		0x0d, 0x00, 0x00, 0x04, 0x01, 0x40, 0x00, 0x00,
		/* msg 3: ServerHelloDone, len 0 */
		0x0e, 0x00, 0x00, 0x00,
	};
	struct sh_seen { uint8_t types[8]; int n; uint16_t cipher; };
	struct sh_seen sh_seen = { .n = 0 };
	int split_rc = fp_tls_split_handshake(frame183_body, sizeof(frame183_body),
	                                       hs_cb_selftest, &sh_seen);
	if (split_rc != 3 || sh_seen.types[0] != FP_TLS_HS_SERVER_HELLO
	    || sh_seen.types[1] != FP_TLS_HS_CERTIFICATE_REQUEST
	    || sh_seen.types[2] != FP_TLS_HS_SERVER_HELLO_DONE) {
		fprintf(stderr, "tls splitter KAT mismatch (rc=%d types=%02x %02x %02x)\n",
			split_rc, sh_seen.types[0], sh_seen.types[1], sh_seen.types[2]);
		fp_tls_state_destroy(&st2);
		return -1;
	}
	printf("  tls splitter    OK (frame 183: ServerHello + CertReq + SrvHelloDone)\n");

	/* ServerHello parse KAT — feed just the SH body (post-4-byte-hdr). */
	uint16_t parsed_cipher = 0;
	int sh_rc = fp_tls_parse_server_hello(&st2,
		frame183_body + 4, 0x2d, &parsed_cipher);
	if (sh_rc != 0 || parsed_cipher != FP_TLS_CIPHER_ECDHE_PSK_AES256_CBC_SHA384) {
		fprintf(stderr, "tls SrvHello parse fail (rc=%d cipher=%04x)\n",
			sh_rc, parsed_cipher);
		fp_tls_state_destroy(&st2);
		return -1;
	}
	printf("  tls SrvHello KAT OK (cipher=0xc02e ECDHE_PSK_AES256_CBC_SHA384)\n");

	/* TLS key derivation determinism — same inputs → same outputs.
	 * Uses fixed test vectors (not the real sensor PSK). */
	uint8_t mock_ecdh[32], mock_psk[64];
	memset(mock_ecdh, 0xaa, sizeof(mock_ecdh));
	memset(mock_psk,  0xbb, sizeof(mock_psk));
	memcpy(st2.client_random, "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
	                          "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00", 32);
	memcpy(st2.server_random, "\x88\x77\x66\x55\x44\x33\x22\x11\xff\xee\xdd\xcc\xbb\xaa\x99\x00"
	                          "\x88\x77\x66\x55\x44\x33\x22\x11\xff\xee\xdd\xcc\xbb\xaa\x99\x00", 32);
	if (fp_tls_derive_session_keys(&st2, mock_ecdh, 32, mock_psk, 64) != 0) {
		fprintf(stderr, "tls keys derive fail\n"); return -1;
	}
	/* Save first 8 bytes of each key, derive again, ensure identical. */
	uint8_t snap_ms[8], snap_ek_c[8], snap_iv_c[4];
	memcpy(snap_ms, st2.master_secret, 8);
	memcpy(snap_ek_c, st2.enc_key_client, 8);
	memcpy(snap_iv_c, st2.iv_client, FP_TLS_GCM_IV_LEN);
	memset(st2.master_secret, 0, sizeof(st2.master_secret));
	memset(st2.enc_key_client, 0, sizeof(st2.enc_key_client));
	if (fp_tls_derive_session_keys(&st2, mock_ecdh, 32, mock_psk, 64) != 0) return -1;
	if (memcmp(snap_ms, st2.master_secret, 8) != 0
	 || memcmp(snap_ek_c, st2.enc_key_client, 8) != 0
	 || memcmp(snap_iv_c, st2.iv_client, FP_TLS_GCM_IV_LEN) != 0) {
		fprintf(stderr, "tls keys non-deterministic\n");
		return -1;
	}
	/* Sanity: keys are non-zero and distinct. */
	int all_zero_ms = 1;
	for (int i = 0; i < FP_TLS_MASTER_SECRET; i++) if (st2.master_secret[i]) { all_zero_ms = 0; break; }
	if (all_zero_ms) { fprintf(stderr, "tls master_secret all zero\n"); return -1; }
	if (memcmp(st2.enc_key_client, st2.enc_key_server, 8) == 0) {
		fprintf(stderr, "tls client/server enc keys identical (should differ)\n");
		return -1;
	}
	printf("  tls keys derive OK (deterministic, master+keys non-zero, c/s keys distinct)\n");

	/* TLS record encrypt/decrypt round trip — needs both sides to share
	 * keys. Simulate by pointing server-side keys at client-side keys. */
	memcpy(st2.enc_key_server, st2.enc_key_client, FP_TLS_ENC_KEY_LEN);
	memcpy(st2.iv_server,      st2.iv_client,      FP_TLS_GCM_IV_LEN);
	st2.secure_tx = 1;
	st2.secure_rx = 1;
	st2.seq_send = 0;
	st2.seq_recv = 0;

	static const uint8_t cleartext[] =
		"Hello sensor! This is a TLS application_data payload that "
		"must round-trip through encrypt-then-MAC and back.";
	uint8_t enc_record[512];
	int enc_len = fp_tls_record_build(&st2, FP_TLS_CT_APPLICATION_DATA,
	                                  cleartext, (int)sizeof(cleartext) - 1,
	                                  enc_record, sizeof(enc_record));
	if (enc_len < 5 + 16 + FP_SHA384_LEN) {
		fprintf(stderr, "tls enc build fail (returned %d)\n", enc_len);
		fp_tls_state_destroy(&st2);
		return -1;
	}

	/* Now parse it back. Use a callback that captures the body. */
	captured_len = -1;
	int n_records = fp_tls_parse_records(&st2, enc_record, enc_len,
	                                     rt_cb_selftest, NULL);
	if (n_records != 1 || captured_len != (int)sizeof(cleartext) - 1
	    || memcmp(captured_body, cleartext, sizeof(cleartext) - 1) != 0) {
		fprintf(stderr, "tls enc/dec round-trip FAIL (n=%d, len=%d)\n",
			n_records, captured_len);
		fp_tls_state_destroy(&st2);
		return -1;
	}
	printf("  tls enc/dec rt  OK (AES-256-GCM, %d B round-tripped)\n",
		(int)sizeof(cleartext) - 1);

	/* Finished round-trip. The server-finished computation must match
	 * what the client built, given the same transcript state. We can't
	 * verify a CLIENT-finished against itself (the labels differ), so
	 * instead we build a client-finished, then craft a synthetic
	 * server-finished using the same PRF with the "server finished"
	 * label, and verify it. This exercises both make and verify. */
	struct fp_tls_state ft_st;
	if (fp_tls_state_init(&ft_st) != 0) return -1;
	memcpy(ft_st.master_secret, "\x00\x01\x02\x03\x04\x05\x06\x07"
	                            "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	                            "\x10\x11\x12\x13\x14\x15\x16\x17"
	                            "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	                            "\x20\x21\x22\x23\x24\x25\x26\x27"
	                            "\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f", 48);
	/* Mix some bytes into the transcript to get a non-empty hash. */
	fp_tls_handshake_hash_update(&ft_st, "ClientHello + ServerHello transcript", 36);

	/* Build client-finished — also adds its body to the transcript. */
	uint8_t cf_buf[64];
	int cf_len = fp_tls_make_finished(&ft_st, cf_buf, sizeof(cf_buf));
	if (cf_len != 16 || cf_buf[0] != 0x14) {
		fprintf(stderr, "make_finished build error (len=%d hdr=0x%02x)\n",
			cf_len, cf_buf[0]);
		fp_tls_state_destroy(&ft_st);
		return -1;
	}

	/* For verify-server-finished: do PRF over CURRENT transcript (which
	 * already includes client's Finished) with "server finished" label,
	 * then feed those bytes into our verify function. Should accept. */
	uint8_t hs_hash[48], sf_seed[15 + 48], sf_verify_data[12];
	if (fp_tls_handshake_hash_snapshot(&ft_st, hs_hash) != 0) return -1;
	memcpy(sf_seed, "server finished", 15);
	memcpy(sf_seed + 15, hs_hash, 48);
	if (fp_tls_prf_sha384(ft_st.master_secret, 48, sf_seed, sizeof(sf_seed),
	                      sf_verify_data, 12) != 0) return -1;
	if (fp_tls_verify_server_finished(&ft_st, sf_verify_data, 12) != 0) {
		fprintf(stderr, "verify_server_finished rejected its own PRF output\n");
		fp_tls_state_destroy(&ft_st);
		return -1;
	}
	/* And confirm we REJECT a tampered one. */
	sf_verify_data[5] ^= 0x01;
	if (fp_tls_verify_server_finished(&ft_st, sf_verify_data, 12) == 0) {
		fprintf(stderr, "verify_server_finished accepted tampered MAC\n");
		fp_tls_state_destroy(&ft_st);
		return -1;
	}
	printf("  tls Finished    OK (make+verify; rejects tampered)\n");

	/* Certificate + ClientKeyExchange + CertificateVerify build KAT. */
	uint8_t cert_blob[100];
	memset(cert_blob, 0xab, sizeof(cert_blob));
	uint8_t out[1024];
	int total = 0;

	int n_cert = fp_tls_make_certificate(&ft_st, cert_blob, sizeof(cert_blob),
	                                     out + total, sizeof(out) - total);
	if (n_cert != 4 + 6 + 100) {
		fprintf(stderr, "Certificate build wrong size %d (expected %d)\n",
			n_cert, 4 + 6 + 100);
		fp_tls_state_destroy(&ft_st); return -1;
	}
	total += n_cert;

	uint8_t pub_xy[64];
	for (int i = 0; i < 64; i++) pub_xy[i] = (uint8_t)(i ^ 0x5a);
	int n_kex = fp_tls_make_client_key_exchange(&ft_st, pub_xy,
	                                            out + total, sizeof(out) - total);
	if (n_kex != 4 + 65) {
		fprintf(stderr, "ClientKex build wrong size %d\n", n_kex);
		fp_tls_state_destroy(&ft_st); return -1;
	}
	total += n_kex;

	uint8_t test_priv[32];
	for (int i = 0; i < 32; i++) test_priv[i] = (uint8_t)(i + 1);
	int n_cv = fp_tls_make_certificate_verify(&ft_st, test_priv,
	                                          out + total, sizeof(out) - total);
	if (n_cv < 4 + 70 || n_cv > 4 + 72) {
		fprintf(stderr, "CertificateVerify build wrong size %d (expected 4 + 70-72)\n", n_cv);
		fp_tls_state_destroy(&ft_st); return -1;
	}
	total += n_cv;

	if (out[0] != FP_TLS_HS_CERTIFICATE
	 || out[n_cert] != FP_TLS_HS_CLIENT_KEY_EXCHANGE
	 || out[n_cert + n_kex] != FP_TLS_HS_CERTIFICATE_VERIFY) {
		fprintf(stderr, "TLS message types not in expected order\n");
		fp_tls_state_destroy(&ft_st); return -1;
	}
	printf("  tls cert3       OK (Cert + ClientKex + CertVerify; total %d B)\n", total);

	/* P-256 point-from-X KAT — captured try-3 ServerHello.random is
	 * verified to be a valid P-256 X-coord (big-endian). Recovery
	 * should succeed for at least one y parity. */
	static const uint8_t try3_sh_random[32] = {
		0x00, 0x05, 0x2e, 0xd9, 0x57, 0xb8, 0xcc, 0xbf,
		0x64, 0x11, 0xaf, 0x8f, 0x24, 0x66, 0xf4, 0x06,
		0xf1, 0x1e, 0x85, 0xd3, 0x74, 0x99, 0x3d, 0x57,
		0xb6, 0xad, 0x8d, 0xb9, 0x01, 0xad, 0x14, 0x96,
	};
	uint8_t sensor_pub[64];
	if (fp_crypto_p256_point_from_x(try3_sh_random, 0, sensor_pub) != 0) {
		fprintf(stderr, "p256 point recovery failed for try-3 SH.random\n");
		fp_tls_state_destroy(&ft_st);
		fp_tls_state_destroy(&st2);
		return -1;
	}
	if (memcmp(sensor_pub, try3_sh_random, 32) != 0) {
		fprintf(stderr, "p256 recovery: X-coord mismatch (recovery corrupted X)\n");
		return -1;
	}
	printf("  tls sensor pub  OK (recovered P-256 (X,Y) from try-3 ServerHello.random)\n");

	/* Verify the hardcoded sensor-firmware verification key is a valid
	 * P-256 point — guards against a typo when transcribing. */
	uint8_t fw_recovered[FP_P256_PUB_LEN];
	if (fp_crypto_p256_point_from_x(fp_sensor_fw_pubkey, 0, fw_recovered) != 0
	 && fp_crypto_p256_point_from_x(fp_sensor_fw_pubkey, 1, fw_recovered) != 0) {
		fprintf(stderr, "fp_sensor_fw_pubkey X is NOT on curve!\n");
		fp_tls_state_destroy(&ft_st); fp_tls_state_destroy(&st2);
		return -1;
	}
	/* And confirm the Y stored in the constant matches one of the two
	 * possible y values for the X. */
	if (memcmp(fp_sensor_fw_pubkey + 32, fw_recovered + 32, 32) != 0) {
		/* Try the other parity. */
		fp_crypto_p256_point_from_x(fp_sensor_fw_pubkey, 1, fw_recovered);
		if (memcmp(fp_sensor_fw_pubkey + 32, fw_recovered + 32, 32) != 0) {
			fprintf(stderr, "fp_sensor_fw_pubkey Y doesn't match recovered Y\n");
			fp_tls_state_destroy(&ft_st); fp_tls_state_destroy(&st2);
			return -1;
		}
	}
	printf("  fw pubkey       OK (sensor fw verification key is on P-256)\n");

	/* Storage save/load round trip — uses a tmp file so the user's real
	 * pair-data isn't touched. */
	const char *tmp_path = "/tmp/fpdrv-selftest-pairdata";
	struct fp_pairdata pd1, pd2;
	if (fp_storage_generate_fresh(&pd1) != 0) {
		fprintf(stderr, "storage: generate fresh failed\n"); return -1;
	}
	if (fp_storage_save(&pd1, tmp_path) != 0) {
		fprintf(stderr, "storage: save failed\n"); return -1;
	}
	if (fp_storage_load(&pd2, tmp_path) != 0) {
		fprintf(stderr, "storage: load failed\n"); return -1;
	}
	if (memcmp(&pd1, &pd2, sizeof(struct fp_pairdata)) != 0) {
		fprintf(stderr, "storage: save+load mismatch\n"); return -1;
	}
	unlink(tmp_path);
	printf("  storage rt      OK (pair-data save+load round trip)\n");

	fp_tls_state_destroy(&ft_st);
	fp_tls_state_destroy(&st2);

	return 0;
}
