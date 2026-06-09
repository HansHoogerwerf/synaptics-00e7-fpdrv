#include "tls.h"
#include "crypto.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TLS-PRF (TLS 1.2) using HMAC-SHA256. python-validity's `prf()`:
 *
 *   def prf(secret, seed, length):
 *       n = (length + 0x20 - 1) // 0x20
 *       a = HMAC-SHA256(secret, seed)
 *       res = b''
 *       while n > 0:
 *           res += HMAC-SHA256(secret, a + seed)
 *           a    = HMAC-SHA256(secret, a)
 *           n   -= 1
 *       return res[:length]
 *
 * That's the standard P_SHA256(secret, seed) construction. */
int fp_tls_prf(const void *secret, size_t secret_len,
               const void *seed,   size_t seed_len,
               uint8_t *out, size_t out_len)
{
	uint8_t a[FP_SHA256_LEN];
	if (fp_crypto_hmac_sha256(secret, secret_len, seed, seed_len, a) != 0)
		return -1;

	size_t produced = 0;
	while (produced < out_len) {
		/* HMAC(secret, A || seed) */
		uint8_t buf[FP_SHA256_LEN + 4096];   /* seed + A; 4 KB is plenty for our seeds */
		if (FP_SHA256_LEN + seed_len > sizeof(buf)) return -1;
		memcpy(buf, a, FP_SHA256_LEN);
		memcpy(buf + FP_SHA256_LEN, seed, seed_len);

		uint8_t block[FP_SHA256_LEN];
		if (fp_crypto_hmac_sha256(secret, secret_len, buf, FP_SHA256_LEN + seed_len, block) != 0)
			return -1;

		size_t take = out_len - produced;
		if (take > FP_SHA256_LEN) take = FP_SHA256_LEN;
		memcpy(out + produced, block, take);
		produced += take;

		/* A_{i+1} = HMAC(secret, A_i) */
		if (fp_crypto_hmac_sha256(secret, secret_len, a, FP_SHA256_LEN, a) != 0)
			return -1;
	}

	return 0;
}

int fp_tls_prf_sha384(const void *secret, size_t secret_len,
                      const void *seed,   size_t seed_len,
                      uint8_t *out, size_t out_len)
{
	uint8_t a[FP_SHA384_LEN];
	if (fp_crypto_hmac_sha384(secret, secret_len, seed, seed_len, a) != 0)
		return -1;

	size_t produced = 0;
	while (produced < out_len) {
		uint8_t buf[FP_SHA384_LEN + 4096];
		if (FP_SHA384_LEN + seed_len > sizeof(buf)) return -1;
		memcpy(buf, a, FP_SHA384_LEN);
		memcpy(buf + FP_SHA384_LEN, seed, seed_len);

		uint8_t block[FP_SHA384_LEN];
		if (fp_crypto_hmac_sha384(secret, secret_len,
		                          buf, FP_SHA384_LEN + seed_len, block) != 0)
			return -1;

		size_t take = out_len - produced;
		if (take > FP_SHA384_LEN) take = FP_SHA384_LEN;
		memcpy(out + produced, block, take);
		produced += take;

		if (fp_crypto_hmac_sha384(secret, secret_len, a, FP_SHA384_LEN, a) != 0)
			return -1;
	}
	return 0;
}

int fp_tls_derive_session_keys(struct fp_tls_state *st,
                               const uint8_t *ecdh, size_t ecdh_len,
                               const uint8_t *psk,  size_t psk_len)
{
	if (!ecdh || ecdh_len == 0) return -1;
	if (ecdh_len > 0xffff) return -1;
	(void)psk; (void)psk_len;

	/* SYNAPTICS QUIRK (verified live from libtudor BCryptDeriveKey trace
	 * 2026-05-19): Despite cipher 0xc02e=TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
	 * the sensor's TLS_PRF takes ONLY the ECDH shared as the secret.
	 * No PSK is mixed in. RFC 4279's pre_master_secret PSK-concat
	 * scheme is NOT used. */
	const uint8_t *pms = ecdh;
	int pms_len = (int)ecdh_len;

	/* master_secret = PRF-SHA384(pms, "master secret" | client_random | server_random, 48). */
	uint8_t seed_ms[13 + FP_TLS_RANDOM_LEN * 2];
	memcpy(seed_ms, "master secret", 13);
	memcpy(seed_ms + 13, st->client_random, FP_TLS_RANDOM_LEN);
	memcpy(seed_ms + 13 + FP_TLS_RANDOM_LEN, st->server_random, FP_TLS_RANDOM_LEN);
	if (fp_tls_prf_sha384(pms, pms_len, seed_ms, sizeof(seed_ms),
	                      st->master_secret, FP_TLS_MASTER_SECRET) != 0) return -1;

	/* key_block layout for AES-256-GCM (TLS 1.2 AEAD, RFC 5288):
	 *   client_write_key (32) | server_write_key (32)
	 *   client_write_IV  (4)  | server_write_IV  (4)
	 * Total = 72 bytes. No MAC keys (GCM is AEAD).
	 *
	 * SYNAPTICS QUIRK (2026-05-21): standard RFC says seed =
	 * "key expansion" || server_random || client_random. Synaptics SWAPS
	 * the randoms: seed = "key expansion" || client_random || server_random.
	 * Confirmed by offline decryption of captured libtudor Finished
	 * record — only the swapped order successfully decrypts. */
	uint8_t seed_kb[13 + FP_TLS_RANDOM_LEN * 2];
	memcpy(seed_kb, "key expansion", 13);
	memcpy(seed_kb + 13, st->client_random, FP_TLS_RANDOM_LEN);
	memcpy(seed_kb + 13 + FP_TLS_RANDOM_LEN, st->server_random, FP_TLS_RANDOM_LEN);

	uint8_t key_block[FP_TLS_ENC_KEY_LEN * 2 + FP_TLS_GCM_IV_LEN * 2];
	if (fp_tls_prf_sha384(st->master_secret, FP_TLS_MASTER_SECRET,
	                      seed_kb, sizeof(seed_kb),
	                      key_block, sizeof(key_block)) != 0) return -1;

	int kb = 0;
	memcpy(st->enc_key_client, key_block + kb, FP_TLS_ENC_KEY_LEN); kb += FP_TLS_ENC_KEY_LEN;
	memcpy(st->enc_key_server, key_block + kb, FP_TLS_ENC_KEY_LEN); kb += FP_TLS_ENC_KEY_LEN;
	memcpy(st->iv_client,      key_block + kb, FP_TLS_GCM_IV_LEN);  kb += FP_TLS_GCM_IV_LEN;
	memcpy(st->iv_server,      key_block + kb, FP_TLS_GCM_IV_LEN);  kb += FP_TLS_GCM_IV_LEN;

	return 0;
}

/* Read u16 LE without alignment assumptions. */
static uint16_t rd_u16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

/* Forward decl. */
static int try_walk(const uint8_t *buf, int len, int start,
                    fp_tls_flash_visit visit, void *ctx);

int fp_tls_flash_walk(const uint8_t *buf, int len,
                      fp_tls_flash_visit visit, void *ctx)
{
	if (!buf || len < 36) return -1;

	/* Captured blobs from `GET_CERTIFICATE_EX` carry an 8-byte envelope
	 * before the flash blocks proper (the first 4 bytes look like a
	 * small big-endian integer; the next 4 are zero). Try offset 0
	 * first; if it produces no validating blocks but offset 8 does,
	 * prefer offset 8. */
	int n0 = try_walk(buf, len, 0, NULL, NULL);
	int n8 = try_walk(buf, len, 8, NULL, NULL);
	int start = (n8 > n0) ? 8 : 0;

	return try_walk(buf, len, start, visit, ctx);
}

/* Internal walker shared between the auto-detect probe and the
 * caller-facing fp_tls_flash_walk. When `visit` is NULL we just count
 * blocks (used by the start-offset probe). */
static int try_walk(const uint8_t *buf, int len, int start,
                    fp_tls_flash_visit visit, void *ctx)
{
	int n = 0;
	int cursor = start;
	while (cursor + 36 <= len) {
		uint16_t id   = rd_u16le(buf + cursor + 0);
		uint16_t size = rd_u16le(buf + cursor + 2);

		/* Terminator: when we hit 0xffff for id (high padding) or size=0. */
		if (id == 0xffff || size == 0) break;
		/* Sanity. */
		if ((int)size > len - cursor - 36) break;

		const uint8_t *sha = buf + cursor + 4;
		const uint8_t *body = buf + cursor + 4 + 32;

		uint8_t computed[FP_SHA256_LEN];
		fp_crypto_sha256(body, size, computed);
		int ok = (memcmp(computed, sha, FP_SHA256_LEN) == 0);

		/* If we're probing without a callback, only count blocks whose
		 * SHA-256 matches — a wrong start offset will fail this check. */
		if (!visit && !ok) break;

		struct fp_tls_flash_block blk = {
			.offset = cursor,
			.id = id,
			.size = size,
			.body = body,
			.sha256_ok = ok,
		};
		if (visit && visit(&blk, ctx) != 0) return n + 1;
		n++;

		cursor += 4 + 32 + size;
	}
	return n;
}

static int dump_visitor(const struct fp_tls_flash_block *blk, void *ctx)
{
	int *idxp = (int *)ctx;
	printf("  [%d] off=%5d  id=%-4u  size=%4u  sha=%s  body[0..7]=",
	       (*idxp)++, blk->offset, blk->id, blk->size,
	       blk->sha256_ok ? "OK  " : "BAD!");
	int show = blk->size < 8 ? blk->size : 8;
	for (int i = 0; i < show; i++) printf("%02x", blk->body[i]);
	if (blk->size > show) printf("...");
	printf("\n");
	return 0;
}

int fp_tls_flash_dump(const uint8_t *buf, int len)
{
	if (len < 8) {
		printf("  (buffer too short: %d bytes)\n", len);
		return -1;
	}
	printf("  envelope (first 8 B): %02x %02x %02x %02x %02x %02x %02x %02x\n",
	       buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

	int idx = 0;
	int n = fp_tls_flash_walk(buf, len, dump_visitor, &idx);
	if (n < 0) {
		printf("  (parse error)\n");
		return -1;
	}
	printf("  %d blocks total\n", n);
	return n;
}


/* ----------- TLS state + record framing ----------- */

int fp_tls_state_init(struct fp_tls_state *st)
{
	memset(st, 0, sizeof(*st));
	EVP_MD_CTX *c384 = EVP_MD_CTX_new();
	EVP_MD_CTX *c256 = EVP_MD_CTX_new();
	if (!c384 || !c256 ||
	    EVP_DigestInit_ex(c384, EVP_sha384(), NULL) != 1 ||
	    EVP_DigestInit_ex(c256, EVP_sha256(), NULL) != 1) {
		if (c384) EVP_MD_CTX_free(c384);
		if (c256) EVP_MD_CTX_free(c256);
		return -1;
	}
	st->hh_sha384 = c384;
	st->hh_sha256 = c256;
	return 0;
}

void fp_tls_state_destroy(struct fp_tls_state *st)
{
	if (st->hh_sha384) { EVP_MD_CTX_free((EVP_MD_CTX *)st->hh_sha384); st->hh_sha384 = NULL; }
	if (st->hh_sha256) { EVP_MD_CTX_free((EVP_MD_CTX *)st->hh_sha256); st->hh_sha256 = NULL; }
}

int fp_tls_handshake_hash_update(struct fp_tls_state *st,
                                 const void *data, size_t len)
{
	EVP_MD_CTX *c384 = (EVP_MD_CTX *)st->hh_sha384;
	EVP_MD_CTX *c256 = (EVP_MD_CTX *)st->hh_sha256;
	if (!c384 || !c256) return -1;
	if (EVP_DigestUpdate(c384, data, len) != 1) return -1;
	if (EVP_DigestUpdate(c256, data, len) != 1) return -1;
	return 0;
}

static int snapshot_hash(EVP_MD_CTX *ctx, uint8_t *out, unsigned int expected)
{
	EVP_MD_CTX *dup = EVP_MD_CTX_new();
	if (!dup) return -1;
	int rc = -1;
	if (EVP_MD_CTX_copy_ex(dup, ctx) != 1) goto out;
	unsigned int outlen = expected;
	if (EVP_DigestFinal_ex(dup, out, &outlen) != 1) goto out;
	if (outlen != expected) goto out;
	rc = 0;
out:
	EVP_MD_CTX_free(dup);
	return rc;
}

int fp_tls_handshake_hash_snapshot(struct fp_tls_state *st, uint8_t out[48])
{
	if (!st->hh_sha384) return -1;
	return snapshot_hash((EVP_MD_CTX *)st->hh_sha384, out, 48);
}

int fp_tls_handshake_hash_snapshot_sha256(struct fp_tls_state *st, uint8_t out[32])
{
	if (!st->hh_sha256) return -1;
	return snapshot_hash((EVP_MD_CTX *)st->hh_sha256, out, 32);
}

int fp_tls_record_build(struct fp_tls_state *st,
                        uint8_t content_type,
                        const void *body, int body_len,
                        uint8_t *out, int out_cap)
{
	if (body_len < 0 || body_len > 0xffff) return -1;

	if (!st->secure_tx) {
		/* Cleartext record. */
		if (out_cap < body_len + 5) return -1;
		out[0] = content_type;
		out[1] = 0x03;
		out[2] = 0x03;
		out[3] = (uint8_t)((body_len >> 8) & 0xff);
		out[4] = (uint8_t)(body_len & 0xff);
		memcpy(out + 5, body, (size_t)body_len);
		return body_len + 5;
	}

	/* Encrypted record, AES-256-GCM (TLS 1.2 AEAD, RFC 5288).
	 *   wire body = <explicit_iv 8 B><ciphertext body_len B><auth_tag 16 B>
	 *   nonce      = <iv_client (4 B)><explicit_iv (8 B = seq_send BE)>
	 *   AAD        = <seq_send 8 B BE><ctype 1><ver 2><body_len 2 B BE>
	 *
	 * Verified against synaTudor trace 2026-05-19: 40-B Finished record
	 * for 16-B plaintext = 8 + 16 + 16. */
	int record_body_len = 8 + body_len + 16;
	if (out_cap < 5 + record_body_len) return -1;

	/* Explicit IV: Synaptics uses RANDOM 8 bytes (verified from libtudor
	 * trace which calls palCryptoRng before each palCryptoEncryptAuth).
	 * Per RFC 5288 §3, either seq_num or random is acceptable for AES-GCM. */
	uint8_t explicit_iv[8];
	if (fp_crypto_rand(explicit_iv, 8) != 0) return -1;

	uint8_t nonce[12];
	memcpy(nonce, st->iv_client, 4);
	memcpy(nonce + 4, explicit_iv, 8);

	/* AAD (RFC 5288 standard for TLS 1.2 GCM): seq_num(8 BE) || ctype || ver || pt_len. */
	uint8_t aad[13];
	for (int i = 0; i < 8; i++)
		aad[i] = (uint8_t)(st->seq_send >> (56 - 8*i));
	aad[8]  = content_type;
	aad[9]  = 0x03; aad[10] = 0x03;
	aad[11] = (uint8_t)((body_len >> 8) & 0xff);
	aad[12] = (uint8_t)(body_len & 0xff);

	/* Write record header + explicit IV. */
	out[0] = content_type;
	out[1] = 0x03; out[2] = 0x03;
	out[3] = (uint8_t)((record_body_len >> 8) & 0xff);
	out[4] = (uint8_t)(record_body_len & 0xff);
	memcpy(out + 5, explicit_iv, 8);

	/* GCM encrypt body into [explicit_iv(8) .. end]: ciphertext then tag. */
	if (fp_crypto_aes256_gcm_encrypt(st->enc_key_client, nonce,
	                                 aad, sizeof(aad),
	                                 body, (size_t)body_len,
	                                 out + 5 + 8) != 0) return -1;

	st->seq_send++;
	return 5 + record_body_len;
}

/* Inverse of compute_tls_mac for a server-side body: decrypt the record
 * body (IV-prefixed AES-CBC), strip padding + MAC, verify MAC against
 * the cleartext using the server's MAC key. Returns the cleartext
 * length on success, or -1 on failure (bad pad, bad MAC, etc).
 *
 * On success, the cleartext is written in place into rec_body, replacing
 * the IV+ciphertext bytes; the caller can read [0..returned_len). */
static int decrypt_record_body(struct fp_tls_state *st,
                               uint8_t content_type,
                               uint8_t *rec_body, int rec_body_len)
{
	/* AES-256-GCM record body: explicit_iv(8) || ciphertext(plain_len) || tag(16).
	 * Min size = 8 + 0 + 16 = 24. */
	if (rec_body_len < 24) return -1;

	int plain_len = rec_body_len - 8 - 16;
	if (plain_len < 0) return -1;

	uint8_t nonce[12];
	memcpy(nonce,     st->iv_server,    4);   /* implicit salt */
	memcpy(nonce + 4, rec_body,         8);   /* explicit IV from wire */

	/* AAD (TLS 1.2 standard): seq_recv(8 BE) || ctype || ver || plain_len. */
	uint8_t aad[13];
	for (int i = 0; i < 8; i++) aad[i] = (uint8_t)(st->seq_recv >> (56 - 8*i));
	aad[8]  = content_type;
	aad[9]  = 0x03; aad[10] = 0x03;
	aad[11] = (uint8_t)((plain_len >> 8) & 0xff);
	aad[12] = (uint8_t)(plain_len & 0xff);

	const uint8_t *ct  = rec_body + 8;
	const uint8_t *tag = rec_body + 8 + plain_len;

	uint8_t plain[0x4000];
	if (plain_len > (int)sizeof(plain)) return -1;

	if (fp_crypto_aes256_gcm_decrypt(st->enc_key_server, nonce,
	                                 aad, sizeof(aad),
	                                 ct, (size_t)plain_len,
	                                 tag, plain) != 0) return -1;

	memcpy(rec_body, plain, (size_t)plain_len);
	st->seq_recv++;
	return plain_len;
}

/* ---- Handshake message builders / parsers ---- */

/* Append a Handshake message header (type + 24-bit length) followed by
 * the body. Returns the total bytes written, or -1 if out_cap is too
 * small. The transcript hash is automatically updated with `hdr+body`
 * (every handshake message — both sent and received — must contribute
 * to the running hash, except HelloRequest which we don't send/receive). */
static int build_hs_message(struct fp_tls_state *st, uint8_t type,
                            const void *body, int body_len,
                            uint8_t *out, int out_cap)
{
	if (body_len < 0 || body_len > 0xffffff) return -1;
	if (out_cap < body_len + 4) return -1;
	out[0] = type;
	out[1] = (uint8_t)((body_len >> 16) & 0xff);
	out[2] = (uint8_t)((body_len >> 8) & 0xff);
	out[3] = (uint8_t)(body_len & 0xff);
	memcpy(out + 4, body, (size_t)body_len);
	fp_tls_handshake_hash_update(st, out, body_len + 4);
	return body_len + 4;
}

int fp_tls_make_client_hello(struct fp_tls_state *st,
                             uint8_t *out, int out_cap)
{
	/* Ensure client_random is set. */
	int zero = 1;
	for (int i = 0; i < FP_TLS_RANDOM_LEN; i++)
		if (st->client_random[i]) { zero = 0; break; }
	if (zero) {
		if (fp_crypto_rand(st->client_random, FP_TLS_RANDOM_LEN) != 0) return -1;
	}

	/* Assemble the body. */
	uint8_t body[128];
	int p = 0;

	/* legacy_version = 03 03 */
	body[p++] = 0x03; body[p++] = 0x03;
	/* random[32] */
	memcpy(body + p, st->client_random, FP_TLS_RANDOM_LEN); p += FP_TLS_RANDOM_LEN;
	/* session_id: 7 bytes of zeros (mirrors what the DLL sends). */
	body[p++] = 0x07;
	memset(body + p, 0, 7); p += 7;
	/* cipher_suites: 5 suites, 10 bytes. Same list as the DLL. */
	body[p++] = 0x00; body[p++] = 0x0a;
	uint16_t suites[5] = { 0xc005, 0xc02e, 0x003d, 0x008d, 0x00a8 };
	for (int i = 0; i < 5; i++) {
		body[p++] = (uint8_t)(suites[i] >> 8);
		body[p++] = (uint8_t)(suites[i] & 0xff);
	}
	/* compression_methods: empty list. */
	body[p++] = 0x00;
	/* Extensions: truncated_hmac (id=4, value=0x0017),
	 *             ec_point_formats (id=11, value="00"=uncompressed only).
	 * Length field encoded as (real_len - 2), matching the Synaptics
	 * quirk (python-validity: `pack('>H', len(exts) - 2)`). */
	uint8_t exts[16];
	int ep = 0;
	/* truncated_hmac: ext_id=0x0004, ext_data_len=2, data=0x0017 */
	exts[ep++] = 0x00; exts[ep++] = 0x04;
	exts[ep++] = 0x00; exts[ep++] = 0x02;
	exts[ep++] = 0x00; exts[ep++] = 0x17;
	/* ec_point_formats: ext_id=0x000b, ext_data_len=2, data=01 00 */
	exts[ep++] = 0x00; exts[ep++] = 0x0b;
	exts[ep++] = 0x00; exts[ep++] = 0x02;
	exts[ep++] = 0x01; exts[ep++] = 0x00;
	int real_len = ep;             /* 12 */
	uint16_t encoded_len = (uint16_t)(real_len - 2);
	body[p++] = (uint8_t)(encoded_len >> 8);
	body[p++] = (uint8_t)(encoded_len & 0xff);
	memcpy(body + p, exts, real_len); p += real_len;

	return build_hs_message(st, FP_TLS_HS_CLIENT_HELLO, body, p, out, out_cap);
}

int fp_tls_parse_server_hello(struct fp_tls_state *st,
                              const uint8_t *body, int body_len,
                              uint16_t *cipher_out)
{
	if (body_len < 2 + 32 + 1 + 2 + 1) return -1;
	int p = 0;
	/* The version field is the first 2 bytes. RFC standard is 0x0303,
	 * but our Synaptics sensor sends 0x0383 (a firmware-specific marker).
	 * Accept anything with major byte 0x03 — the cipher selection is
	 * what actually matters for security. */
	if (body[p] != 0x03) return -1;
	p += 2;
	memcpy(st->server_random, body + p, FP_TLS_RANDOM_LEN);
	p += FP_TLS_RANDOM_LEN;
	int sid_len = body[p++];
	if (p + sid_len + 3 > body_len) return -1;
	p += sid_len;     /* skip session id (we don't store it) */
	uint16_t cipher = (uint16_t)((body[p] << 8) | body[p + 1]);
	p += 2;
	if (cipher_out) *cipher_out = cipher;
	/* compression method (1 byte), then optional extensions. We don't
	 * parse those for now — sensor doesn't send any that affect us. */
	return 0;
}

int fp_tls_make_change_cipher_spec(uint8_t *out, int out_cap)
{
	if (out_cap < 6) return -1;
	out[0] = 0x14; out[1] = 0x03; out[2] = 0x03;
	out[3] = 0x00; out[4] = 0x01; out[5] = 0x01;
	return 6;
}

/* Synaptics quirks for Finished, verified empirically 2026-05-25:
 *   - Transcript hash is SHA-256 (rev.txt 1294), even though cipher PRF
 *     is SHA-384 (RFC 5289).
 *   - PRF used to compute verify_data is SHA-384 (cipher's PRF).
 *   - Sensor's server_finished uses the SAME transcript snapshot that
 *     verifies client_finished — i.e. WITHOUT our client_finished
 *     message added to the running hash. Standard TLS includes
 *     client_finished in the hash; Synaptics does not. We cache the
 *     pre-client-finished snapshot here and reuse it in
 *     verify_server_finished. */
int fp_tls_make_finished(struct fp_tls_state *st, uint8_t *out, int out_cap)
{
	if (out_cap < 16) return -1;

	uint8_t hs_hash[32];
	if (fp_tls_handshake_hash_snapshot_sha256(st, hs_hash) != 0) return -1;

	memcpy(st->saved_transcript_sha256, hs_hash, 32);
	st->saved_transcript_valid = 1;

	uint8_t seed[15 + 32];
	memcpy(seed, "client finished", 15);
	memcpy(seed + 15, hs_hash, 32);

	uint8_t verify_data[12];
	if (fp_tls_prf_sha384(st->master_secret, FP_TLS_MASTER_SECRET,
	                      seed, sizeof(seed),
	                      verify_data, 12) != 0) return -1;

	return build_hs_message(st, FP_TLS_HS_FINISHED, verify_data, 12, out, out_cap);
}

int fp_tls_verify_server_finished(struct fp_tls_state *st,
                                  const uint8_t *body, int body_len)
{
	if (body_len != 12) return -1;
	if (!st->saved_transcript_valid) return -1;

	uint8_t seed[15 + 32];
	memcpy(seed, "server finished", 15);
	memcpy(seed + 15, st->saved_transcript_sha256, 32);

	uint8_t expected[12];
	if (fp_tls_prf_sha384(st->master_secret, FP_TLS_MASTER_SECRET,
	                      seed, sizeof(seed),
	                      expected, 12) != 0) return -1;

	return memcmp(expected, body, 12) == 0 ? 0 : -1;
}

int fp_tls_make_certificate(struct fp_tls_state *st,
                            const uint8_t *cert_bytes, int cert_len,
                            uint8_t *out, int out_cap)
{
	if (cert_len < 0 || cert_len > 0xffffff) return -1;
	/* Synaptics 06cb:00e7 cert wrap format (derived from synaTudor trace
	 * 2026-05-18, refined 2026-05-21 via byte-diff of multiple sessions):
	 *   <0:1><cert_len:2 BE>     (outer length wrap)
	 *   <0:1><cert_len:2 BE>     (inner length wrap — same value, non-standard)
	 *   <client_random[4:6]>     (NOT a fixed magic — two bytes pulled from
	 *                             the ClientHello.random. Confirmed across
	 *                             3 separate sessions.)
	 *   <cert_bytes>
	 * Both length fields refer to ORIGINAL cert_len. */
	uint8_t body[3 + 3 + 2 + 0x2000];
	if (cert_len + 8 > (int)sizeof(body)) return -1;

	body[0] = 0;
	body[1] = (uint8_t)((cert_len >> 8) & 0xff);
	body[2] = (uint8_t)(cert_len & 0xff);
	body[3] = 0;
	body[4] = (uint8_t)((cert_len >> 8) & 0xff);
	body[5] = (uint8_t)(cert_len & 0xff);
	body[6] = st->client_random[4];
	body[7] = st->client_random[5];
	memcpy(body + 8, cert_bytes, (size_t)cert_len);

	return build_hs_message(st, FP_TLS_HS_CERTIFICATE, body, 8 + cert_len,
	                        out, out_cap);
}

int fp_tls_make_client_key_exchange(struct fp_tls_state *st,
                                    const uint8_t pub_xy[64],
                                    uint8_t *out, int out_cap)
{
	/* TLS ECDH ClientKeyExchange body for Synaptics 06cb:00e7:
	 *   <04><X_BE><Y_BE> (65 B), NO leading point-length byte.
	 * Verified from libtudor trace where X_BE forms a valid P-256 point
	 * (LE interpretation fails curve check). python-validity uses LE for
	 * the older 138a Validity sensors — this is a family difference. */
	uint8_t body[65];
	body[0] = 0x04;
	memcpy(body + 1, pub_xy, 64);
	return build_hs_message(st, FP_TLS_HS_CLIENT_KEY_EXCHANGE, body, 65,
	                        out, out_cap);
}

int fp_tls_make_certificate_verify(struct fp_tls_state *st,
                                   const uint8_t priv_d[32],
                                   uint8_t *out, int out_cap)
{
	/* Signs SHA-256 of the running transcript with the host's P-256
	 * private key. Matches python-validity's `make_cert_verify`. */
	uint8_t hash[FP_SHA256_LEN];
	if (fp_tls_handshake_hash_snapshot_sha256(st, hash) != 0) return -1;

	uint8_t sig[FP_P256_SIG_MAX];
	size_t sig_len = sizeof(sig);
	if (fp_crypto_p256_ecdsa_sign(priv_d, hash, sig, &sig_len) != 0) return -1;

	return build_hs_message(st, FP_TLS_HS_CERTIFICATE_VERIFY,
	                        sig, (int)sig_len, out, out_cap);
}

int fp_tls_split_handshake(const uint8_t *body, int len,
                           fp_tls_hs_cb cb, void *ctx)
{
	int cursor = 0;
	int n = 0;
	while (cursor + 4 <= len) {
		uint8_t type = body[cursor];
		int msg_len = ((int)body[cursor + 1] << 16)
		            | ((int)body[cursor + 2] << 8)
		            | (int)body[cursor + 3];
		if (cursor + 4 + msg_len > len) return -1;
		if (cb && cb(type, body + cursor + 4, msg_len, ctx) != 0)
			return n + 1;
		cursor += 4 + msg_len;
		n++;
	}
	return n;
}


int fp_tls_parse_records(struct fp_tls_state *st,
                         const uint8_t *buf, int len,
                         fp_tls_record_cb cb, void *ctx)
{
	int cursor = 0;
	int n = 0;

	while (cursor + 5 <= len) {
		uint8_t  ct  = buf[cursor];
		uint8_t  vmj = buf[cursor + 1];
		uint8_t  vmn = buf[cursor + 2];
		uint16_t bl  = (uint16_t)((buf[cursor + 3] << 8) | buf[cursor + 4]);

		if (vmj != 0x03 || vmn != 0x03) {
			fprintf(stderr, "tls parse: unexpected version %02x %02x at offset %d\n",
				vmj, vmn, cursor);
			return -1;
		}
		if (cursor + 5 + bl > len) {
			fprintf(stderr, "tls parse: truncated record at offset %d (need %d, have %d)\n",
				cursor, bl, len - cursor - 5);
			return -1;
		}
		const uint8_t *body = buf + cursor + 5;

		/* If we're in secure_rx, decrypt the record body into a stack
		 * buffer before delivering it to the callback. CCS itself is
		 * NOT encrypted in TLS 1.2 even when secure_rx is set (CCS
		 * is its own content type and ends the cleartext phase
		 * inbound — but ours is set true on receipt of CCS). */
		uint8_t plain_buf[0x4000];
		int effective_len = bl;
		const uint8_t *effective_body = body;
		if (st->secure_rx && ct != FP_TLS_CT_CHANGE_CIPHER_SPEC) {
			if (bl > (int)sizeof(plain_buf)) {
				fprintf(stderr, "tls parse: record too large to decrypt (%d B)\n", bl);
				return -1;
			}
			memcpy(plain_buf, body, (size_t)bl);
			int pt_len = decrypt_record_body(st, ct, plain_buf, bl);
			if (pt_len < 0) {
				fprintf(stderr, "tls parse: decrypt+MAC verify failed at offset %d\n", cursor);
				return -1;
			}
			effective_body = plain_buf;
			effective_len = pt_len;
		}

		if (cb && cb(ct, effective_body, effective_len, ctx) != 0) return n + 1;

		/* Side effects: state updates after callback dispatch. */
		if (ct == FP_TLS_CT_CHANGE_CIPHER_SPEC) {
			if (bl != 1 || body[0] != 0x01) {
				fprintf(stderr, "tls parse: invalid ChangeCipherSpec body\n");
				return -1;
			}
			st->secure_rx = 1;
		} else if (ct == FP_TLS_CT_HANDSHAKE) {
			/* Mix the body (cleartext if pre-CCS, decrypted otherwise)
			 * into the running transcript hash. */
			fp_tls_handshake_hash_update(st, effective_body, effective_len);
		}

		cursor += 5 + bl;
		n++;
	}

	if (cursor != len) {
		fprintf(stderr, "tls parse: %d trailing bytes after last record\n",
			len - cursor);
	}
	return n;
}


/* ---- Handshake orchestrator ---- */

/* Synaptics outbound prefix: every host->sensor bulk transfer carrying
 * TLS records is prefixed with `44 00 00 00`. Inbound replies have no
 * such prefix. */
static const uint8_t SYNAPTICS_PREFIX[4] = { 0x44, 0x00, 0x00, 0x00 };

/* Inner state for handshake-message dispatch callbacks during
 * fp_tls_open(). */
struct hs_ctx {
	struct fp_tls_state *st;
	uint16_t cipher;
	int got_server_hello;
	int got_server_hello_done;
	int got_server_finished;
};

static int dispatch_handshake(uint8_t type, const uint8_t *body, int len, void *ctx)
{
	struct hs_ctx *c = ctx;
	switch (type) {
	case FP_TLS_HS_SERVER_HELLO:
		if (fp_tls_parse_server_hello(c->st, body, len, &c->cipher) != 0) {
			fprintf(stderr, "fp_tls_open: ServerHello parse failed\n");
			return -1;
		}
		c->got_server_hello = 1;
		break;
	case FP_TLS_HS_CERTIFICATE_REQUEST:
		/* Synaptics sends sig_and_hash_algo = 0x0140 (ECDSA-SHA256).
		 * No further parsing needed; we already know what to sign with. */
		break;
	case FP_TLS_HS_SERVER_HELLO_DONE:
		c->got_server_hello_done = 1;
		break;
	case FP_TLS_HS_FINISHED:
		if (fp_tls_verify_server_finished(c->st, body, len) != 0) {
			fprintf(stderr, "fp_tls_open: server Finished MAC mismatch\n");
			return -1;
		}
		c->got_server_finished = 1;
		break;
	default:
		fprintf(stderr, "fp_tls_open: unexpected handshake type 0x%02x\n", type);
		return -1;
	}
	return 0;
}

static int record_cb(uint8_t ct, const uint8_t *body, int len, void *ctx)
{
	if (ct == FP_TLS_CT_HANDSHAKE) {
		int r = fp_tls_split_handshake(body, len, dispatch_handshake, ctx);
		return (r < 0) ? -1 : 0;  /* split returns count on success, <0 on error */
	}
	if (ct == FP_TLS_CT_CHANGE_CIPHER_SPEC)
		return 0;  /* fp_tls_parse_records flips secure_rx for us */
	if (ct == FP_TLS_CT_ALERT) {
		fprintf(stderr, "fp_tls_open: TLS Alert level=%u desc=%u\n",
			body[0], len > 1 ? body[1] : 0);
		return -1;
	}
	fprintf(stderr, "fp_tls_open: unexpected content type 0x%02x\n", ct);
	return -1;
}

int fp_tls_open(struct fp_tls_state *st,
                const struct fp_tls_handshake_inputs *in,
                const struct fp_tls_transport *xport)
{
	if (!st || !in || !xport) return -1;
	if (!in->cert_blob || !in->priv_d || !in->psk) return -1;

	/* Generate or accept the ephemeral ECDHE keypair. */
	uint8_t eph_priv[FP_P256_PRIV_LEN], eph_pub[FP_P256_PUB_LEN];
	if (in->eph_priv) {
		memcpy(eph_priv, in->eph_priv, FP_P256_PRIV_LEN);
		/* Derive the public point from priv. */
		uint8_t dummy_pub[FP_P256_PUB_LEN];
		if (fp_crypto_p256_keygen(dummy_pub, dummy_pub) != 0) return -1;
		/* We don't have a derive-pub-from-priv helper; just skip and
		 * fail loudly if the caller supplied a priv without a way to
		 * compute the pub. Future: add fp_crypto_p256_pub_from_priv. */
		(void)dummy_pub;
		fprintf(stderr, "fp_tls_open: TODO: supplied eph_priv path not implemented; use NULL\n");
		return -1;
	}
	if (fp_crypto_p256_keygen(eph_priv, eph_pub) != 0) return -1;
	if (in->eph_pub_out) memcpy(in->eph_pub_out, eph_pub, FP_P256_PUB_LEN);

	/* --- Round trip 1: ClientHello → server hello flight --- */
	uint8_t ch_msg[128];
	int ch_msg_len = fp_tls_make_client_hello(st, ch_msg, sizeof(ch_msg));
	if (ch_msg_len < 0) return -1;

	uint8_t rec_buf[256];
	int rec_len = fp_tls_record_build(st, FP_TLS_CT_HANDSHAKE,
	                                  ch_msg, ch_msg_len, rec_buf, sizeof(rec_buf));
	if (rec_len < 0) return -1;

	uint8_t out1[4 + 256];
	memcpy(out1, SYNAPTICS_PREFIX, 4);
	memcpy(out1 + 4, rec_buf, rec_len);
	if (xport->send(xport->ctx, out1, 4 + rec_len) < 0) return -1;

	uint8_t in_buf[2048];
	int n_in = xport->recv(xport->ctx, in_buf, sizeof(in_buf));
	if (n_in <= 0) return -1;

	struct hs_ctx hc = { .st = st };
	if (fp_tls_parse_records(st, in_buf, n_in, record_cb, &hc) < 0) return -1;
	if (!hc.got_server_hello) {
		fprintf(stderr, "fp_tls_open: ServerHello not received (got %d bytes)\n", n_in);
		return -1;
	}
	/* Synaptics doesn't always send a standalone ServerHelloDone — the
	 * post-ServerHello bytes can be trailing data we don't fully parse.
	 * We proceed once we have ServerHello + recognized cipher. */
	if (!hc.got_server_hello_done) {
		fprintf(stderr, "fp_tls_open: note: no ServerHelloDone — proceeding anyway\n");
	}
	if (hc.cipher != FP_TLS_CIPHER_ECDHE_PSK_AES256_CBC_SHA384) {
		fprintf(stderr, "fp_tls_open: unexpected cipher 0x%04x\n", hc.cipher);
		return -1;
	}

	/* --- Compute ECDH shared secret + derive session keys --- */
	const uint8_t *sensor_pub = in->sensor_pub_xy;
	uint8_t recovered_sensor_pub[FP_P256_PUB_LEN];
	if (!sensor_pub) {
		/* Hypothesis: the sensor packs its ECDH X-coordinate into
		 * SYNAPTICS QUIRK (2026-05-19): the sensor uses a STATIC ECDH
		 * pubkey, NOT an ephemeral one — same value across all sessions.
		 * No ServerKeyExchange msg is sent. ServerHello.random is just
		 * a random nonce (used only in PRF seed).
		 *
		 * The static sensor ECDH pubkey was extracted from
		 * BCryptImportKeyPair trace of libtudor's TLS handshake. */
		static const uint8_t SENSOR_STATIC_ECDH_PUB[64] = {
			/* X (BE) */
			0xf2, 0x98, 0x48, 0x61, 0x28, 0xb3, 0xa9, 0x6d,
			0x07, 0x74, 0xc4, 0xc3, 0x5b, 0x90, 0x2e, 0x3f,
			0x30, 0xb3, 0x73, 0x76, 0x1d, 0xe2, 0xa3, 0xac,
			0x51, 0xe5, 0x56, 0xb0, 0x13, 0xee, 0xc5, 0xd8,
			/* Y (BE) */
			0xc6, 0xbc, 0x5e, 0xd8, 0x1d, 0xc5, 0xbe, 0x07,
			0x79, 0x39, 0x4d, 0x93, 0x66, 0xe0, 0x36, 0x6b,
			0x11, 0x2d, 0x24, 0x36, 0x5e, 0xe7, 0xf1, 0x1e,
			0x9f, 0x4f, 0x0d, 0x81, 0x69, 0xaf, 0x7a, 0xac,
		};
		memcpy(recovered_sensor_pub, SENSOR_STATIC_ECDH_PUB, 64);
		sensor_pub = recovered_sensor_pub;
	}

	uint8_t shared[FP_SHA256_LEN];
	if (fp_crypto_p256_ecdh(eph_priv, sensor_pub, shared) != 0) return -1;
	if (fp_tls_derive_session_keys(st, shared, sizeof(shared),
	                               in->psk, (size_t)in->psk_len) != 0) return -1;

	/* --- Round trip 2: Cert + ClientKex + CertVerify + CCS + Finished
	 *                   → server CCS + Finished --- */
	uint8_t out2[4 + 1024];
	int o = 0;
	memcpy(out2, SYNAPTICS_PREFIX, 4); o = 4;

	/* Build a Handshake record containing Cert + ClientKex + CertVerify. */
	uint8_t hs_body[800];
	int h = 0;
	int n_cert = fp_tls_make_certificate(st, in->cert_blob, in->cert_blob_len,
	                                     hs_body + h, sizeof(hs_body) - h);
	if (n_cert < 0) return -1;
	h += n_cert;
	int n_kex = fp_tls_make_client_key_exchange(st, eph_pub,
	                                            hs_body + h, sizeof(hs_body) - h);
	if (n_kex < 0) return -1;
	h += n_kex;
	int n_cv = fp_tls_make_certificate_verify(st, in->priv_d,
	                                          hs_body + h, sizeof(hs_body) - h);
	if (n_cv < 0) return -1;
	h += n_cv;

	int n_hsrec = fp_tls_record_build(st, FP_TLS_CT_HANDSHAKE, hs_body, h,
	                                  out2 + o, sizeof(out2) - o);
	if (n_hsrec < 0) return -1;
	o += n_hsrec;

	/* ChangeCipherSpec record (always cleartext). */
	int n_ccs = fp_tls_make_change_cipher_spec(out2 + o, sizeof(out2) - o);
	if (n_ccs < 0) return -1;
	o += n_ccs;

	/* Flip secure_tx so Finished gets encrypted. */
	st->secure_tx = 1;

	/* Build the Finished handshake message and wrap in a Handshake record
	 * (which is now encrypted). */
	uint8_t fin_msg[16];
	int n_fin = fp_tls_make_finished(st, fin_msg, sizeof(fin_msg));
	if (n_fin < 0) return -1;
	int n_finrec = fp_tls_record_build(st, FP_TLS_CT_HANDSHAKE, fin_msg, n_fin,
	                                   out2 + o, sizeof(out2) - o);
	if (n_finrec < 0) return -1;
	o += n_finrec;

	fprintf(stderr, "fp_tls_open: sending 2nd flight (%d B), secure_tx=%d, seq_send=%llu\n",
	        o, st->secure_tx, (unsigned long long)st->seq_send);
	if (xport->send(xport->ctx, out2, o) < 0) return -1;

	/* Receive server CCS + encrypted Finished. */
	uint8_t in2_buf[512];
	int n_in2 = xport->recv(xport->ctx, in2_buf, sizeof(in2_buf));
	if (n_in2 <= 0) return -1;
	fprintf(stderr, "fp_tls_open: got 2nd-flight response (%d B), secure_rx=%d\n",
	        n_in2, st->secure_rx);

	hc.got_server_finished = 0;
	if (fp_tls_parse_records(st, in2_buf, n_in2, record_cb, &hc) < 0) return -1;
	if (!hc.got_server_finished) {
		fprintf(stderr, "fp_tls_open: server Finished not received\n");
		return -1;
	}

	return 0;
}

struct app_capture {
	uint8_t *out;
	int cap;
	int len;
};

static int app_capture_cb(uint8_t ct, const uint8_t *body, int len, void *ctx)
{
	struct app_capture *a = ctx;
	if (ct == FP_TLS_CT_ALERT) {
		fprintf(stderr, "fp_tls_app_send_recv: TLS Alert level=%u desc=%u\n",
			body[0], len > 1 ? body[1] : 0);
		return -1;
	}
	if (ct != FP_TLS_CT_APPLICATION_DATA) {
		fprintf(stderr, "fp_tls_app_send_recv: unexpected ct 0x%02x\n", ct);
		return -1;
	}
	if (a->len + len > a->cap) {
		fprintf(stderr, "fp_tls_app_send_recv: response buffer overflow "
			"(have %d, +%d would exceed cap %d)\n", a->len, len, a->cap);
		return -1;
	}
	memcpy(a->out + a->len, body, (size_t)len);
	a->len += len;
	return 0;
}

int fp_tls_app_send_recv(struct fp_tls_state *st,
                         const struct fp_tls_transport *xport,
                         const void *cmd, int cmd_len,
                         uint8_t *resp, int resp_cap)
{
	if (!st->secure_tx || !st->secure_rx) return -1;
	if (cmd_len < 1 || cmd_len > 0x4000) return -1;

	/* Application data records are sent WITHOUT the `44 00 00 00` prefix —
	 * per python-validity tls.py line 134 vs 370-376, only handshake
	 * records use the 0x44 wrapper command. App data is delivered as
	 * raw TLS records over the bulk pipe. */
	uint8_t out[5 + 0x4000 + 8 + 16];
	int rec_len = fp_tls_record_build(st, FP_TLS_CT_APPLICATION_DATA,
	                                  cmd, cmd_len,
	                                  out, sizeof(out));
	if (rec_len < 0) return -1;
	if (xport->send(xport->ctx, out, rec_len) < 0) return -1;

	uint8_t in_buf[0x4000];
	int n_in = xport->recv(xport->ctx, in_buf, sizeof(in_buf));
	if (n_in <= 0) return -1;

	struct app_capture cap = { .out = resp, .cap = resp_cap, .len = 0 };
	if (fp_tls_parse_records(st, in_buf, n_in, app_capture_cb, &cap) < 0)
		return -1;
	return cap.len;
}


/* ---- Dryrun: drive the orchestrator with captured try-3 server bytes ---- */

/* Try-3 frame 183: ServerHello + CertReq + ServerHelloDone in one record. */
static const uint8_t TRY3_FRAME_183[] = {
	0x16, 0x03, 0x03, 0x00, 0x3d, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x83,
	0x00, 0x05, 0x2e, 0xd9, 0x57, 0xb8, 0xcc, 0xbf, 0x64, 0x11, 0xaf, 0x8f,
	0x24, 0x66, 0xf4, 0x06, 0xf1, 0x1e, 0x85, 0xd3, 0x74, 0x99, 0x3d, 0x57,
	0xb6, 0xad, 0x8d, 0xb9, 0x01, 0xad, 0x14, 0x96, 0x07, 0x54, 0x4c, 0x53,
	0x57, 0xb8, 0xcc, 0xbf, 0xc0, 0x2e, 0x00, 0x0d, 0x00, 0x00, 0x04, 0x01,
	0x40, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
};

/* Try-3 frame 187: server ChangeCipherSpec + encrypted Finished. Note
 * the encrypted Finished payload won't validate against our placeholder
 * keys, so the dryrun will hit a Finished-MAC error at the very end.
 * That's expected — we're testing the state machine flow, not the MAC. */
static const uint8_t TRY3_FRAME_187[] = {
	0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
	0x16, 0x03, 0x03, 0x00, 0x28, 0x64, 0xd2, 0xc8, 0x4c, 0x17, 0x24, 0x94,
	0x65, 0x92, 0xab, 0xd0, 0x42, 0xbf, 0x59, 0x12, 0xf1, 0xbb, 0x7c, 0x27,
	0xe8, 0x85, 0x4d, 0xc9, 0x37, 0x97, 0xa9, 0xe3, 0xfd, 0x66, 0xac, 0x17,
	0x17, 0x66, 0xfb, 0x23, 0xab, 0x12, 0xd2, 0xfb, 0xd0,
};

struct mock_xport {
	int round;                 /* 0 = before first recv, 1 = after */
	uint8_t sent[8192];
	int sent_total;
};

static int mock_send(void *ctx, const void *buf, int len)
{
	struct mock_xport *m = ctx;
	if (m->sent_total + len > (int)sizeof(m->sent)) return -1;
	memcpy(m->sent + m->sent_total, buf, (size_t)len);
	m->sent_total += len;
	printf("  [mock] sent %d B (round %d)\n", len, m->round);
	return 0;
}

static int mock_recv(void *ctx, void *buf, int cap)
{
	struct mock_xport *m = ctx;
	const uint8_t *src;
	int len;
	if (m->round == 0) {
		src = TRY3_FRAME_183; len = sizeof(TRY3_FRAME_183);
	} else if (m->round == 1) {
		src = TRY3_FRAME_187; len = sizeof(TRY3_FRAME_187);
	} else {
		return -1;
	}
	m->round++;
	if (len > cap) return -1;
	memcpy(buf, src, (size_t)len);
	printf("  [mock] recv %d B (replay try-3 frame %d)\n", len,
	       m->round == 1 ? 183 : 187);
	return len;
}

int fp_tls_dryrun(void)
{
	printf("=== fp_tls_dryrun: drive orchestrator with captured try-3 server bytes ===\n");

	struct fp_tls_state st;
	if (fp_tls_state_init(&st) != 0) {
		fprintf(stderr, "state init failed\n");
		return 1;
	}

	/* Placeholder inputs. */
	uint8_t cert_blob[100];
	memset(cert_blob, 0xab, sizeof(cert_blob));
	uint8_t priv_d[32];
	for (int i = 0; i < 32; i++) priv_d[i] = (uint8_t)(i + 1);
	uint8_t psk[64];
	memset(psk, 0x55, sizeof(psk));
	uint8_t my_eph_pub[64];

	struct fp_tls_handshake_inputs in = {
		.cert_blob = cert_blob,
		.cert_blob_len = sizeof(cert_blob),
		.priv_d = priv_d,
		.psk = psk,
		.psk_len = sizeof(psk),
		.sensor_pub_xy = NULL,           /* trigger fake-pubkey path */
		.eph_priv = NULL,                /* let the orchestrator generate */
		.eph_pub_out = my_eph_pub,
	};

	struct mock_xport mock = { .round = 0 };
	struct fp_tls_transport xport = {
		.send = mock_send,
		.recv = mock_recv,
		.ctx  = &mock,
	};

	int rc = fp_tls_open(&st, &in, &xport);
	printf("\nfp_tls_open returned %d\n", rc);
	printf("  secure_tx = %d, secure_rx = %d\n", st.secure_tx, st.secure_rx);
	printf("  client_random[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.client_random[i]);
	printf("\n  server_random[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.server_random[i]);
	printf("\n  master_secret[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.master_secret[i]);
	printf("\n  total sent: %d B\n", mock.sent_total);

	printf("\nExpected outcome: orchestrator runs through Phase 1 (ClientHello → ServerHello+\n"
	       "CertReq+ServerHelloDone), computes session keys using FAKE sensor pubkey + FAKE PSK,\n"
	       "builds Cert+Kex+CV+CCS+Finished and 'sends' them, then fails at server-Finished MAC\n"
	       "verification (because the real sensor's Finished was MAC'd with REAL keys we don't have).\n"
	       "  → A non-zero return code from fp_tls_open is the SUCCESS condition for a dryrun.\n");

	fp_tls_state_destroy(&st);
	return 0;
}
