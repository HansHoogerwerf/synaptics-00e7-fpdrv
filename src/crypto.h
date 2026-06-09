#ifndef FPDRV_CRYPTO_H
#define FPDRV_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Thin OpenSSL wrappers tailored to what the Synaptics 06cb:00e7 protocol
 * needs:
 *   - SHA-256 (32-byte digest) for handshake context hashes in `0x93`
 *   - SHA-384 (48-byte digest) for the TLS 1.2 SHA384-PRF
 *   - HMAC-SHA384 for TLS record MAC and the PRF
 *   - AES-256-CBC for TLS bulk cipher
 *   - P-256 (secp256r1) ECDH for TLS_ECDHE_PSK_*
 *   - P-256 ECDSA for the host-attestation signature in `0x93`
 *   - Cryptographic RNG for nonces and ephemeral keys
 *
 * All functions return 0 on success and -1 on failure. Crypto-internal
 * errors are pushed onto the OpenSSL error queue; call ERR_print_errors_fp
 * if you need to debug.
 *
 * Buffer sizes are explicit (no opaque types) so the wire layer can hand
 * raw bytes back and forth without ever touching EVP_PKEY. */

#define FP_SHA256_LEN 32
#define FP_SHA384_LEN 48
#define FP_AES256_KEY_LEN 32
#define FP_AES_BLOCK_LEN 16

/* Random bytes. */
int fp_crypto_rand(void *buf, size_t len);

/* One-shot hashes. */
int fp_crypto_sha256(const void *data, size_t len, uint8_t out[FP_SHA256_LEN]);
int fp_crypto_sha384(const void *data, size_t len, uint8_t out[FP_SHA384_LEN]);

/* HMAC-SHA256. */
int fp_crypto_hmac_sha256(const void *key, size_t key_len,
                          const void *data, size_t data_len,
                          uint8_t out[FP_SHA256_LEN]);

/* HMAC-SHA384. */
int fp_crypto_hmac_sha384(const void *key, size_t key_len,
                          const void *data, size_t data_len,
                          uint8_t out[FP_SHA384_LEN]);

/* AES-256-CBC. data_len must be a multiple of FP_AES_BLOCK_LEN.
 * For decrypt, no padding is added or stripped — the TLS framing wraps
 * encrypted-then-MAC records with explicit IVs, so callers manage padding. */
int fp_crypto_aes256_cbc_encrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t iv[FP_AES_BLOCK_LEN],
                                 const void *in, void *out, size_t data_len);
int fp_crypto_aes256_cbc_decrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t iv[FP_AES_BLOCK_LEN],
                                 const void *in, void *out, size_t data_len);

/* AES-256-GCM. The Synaptics 06cb:00e7 sensor uses GCM for TLS records
 * despite negotiating cipher 0xc02e (CBC+HMAC) — verified 2026-05-19
 * from libtudor BCrypt trace. Nonce is 12 bytes (4-B implicit IV salt +
 * 8-B explicit IV per TLS 1.2). out_ct_plus_tag must hold pt_len + 16 B.
 * Returns 0 on success. Decrypt verifies the 16-byte auth tag. */
int fp_crypto_aes256_gcm_encrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t nonce[12],
                                 const void *aad, size_t aad_len,
                                 const void *pt,  size_t pt_len,
                                 void *out_ct_plus_tag);
int fp_crypto_aes256_gcm_decrypt(const uint8_t key[FP_AES256_KEY_LEN],
                                 const uint8_t nonce[12],
                                 const void *aad, size_t aad_len,
                                 const void *ct, size_t ct_len,
                                 const void *tag,
                                 void *out_pt);

/* P-256 keypair. The private key is 32 bytes; the public key is 64 bytes
 * (X || Y, uncompressed without the 0x04 prefix). */
#define FP_P256_PRIV_LEN 32
#define FP_P256_PUB_LEN  64

int fp_crypto_p256_keygen(uint8_t priv_out[FP_P256_PRIV_LEN],
                          uint8_t pub_out[FP_P256_PUB_LEN]);

/* ECDH on P-256: derive a 32-byte shared secret from our private key
 * and the peer's public key. */
int fp_crypto_p256_ecdh(const uint8_t priv[FP_P256_PRIV_LEN],
                        const uint8_t peer_pub[FP_P256_PUB_LEN],
                        uint8_t shared_out[FP_SHA256_LEN]);

/* Recover a P-256 point from its X-coordinate alone, using the curve
 * equation y² = x³ + ax + b (mod p). Writes X || Y (64 bytes) into pub_out.
 * `y_parity` selects which of the two possible y values is used (0 picks
 * the even y, 1 picks the odd y). Returns 0 on success or -1 if the
 * given X doesn't lie on the curve. */
int fp_crypto_p256_point_from_x(const uint8_t x[32], int y_parity,
                                uint8_t pub_out[FP_P256_PUB_LEN]);

/* Sensor firmware verification public key — a P-256 (X || Y, 64 bytes,
 * big-endian) embedded in synaWudfBioUsb104.dll at VA 0x1801345df,
 * inside an X.509 SubjectPublicKeyInfo blob. This is the analog of
 * python-validity's hardcoded `0xf727653b…, 0xa85538f8…` for the
 * Validity sensors. Used to verify signatures on the sensor's per-device
 * certificate and on the sensor-side ECDH parameters during the pair
 * handshake.
 *
 * Extracted 2026-05-17 by brute-force scanning .rdata + .data for the
 * UNIQUE 64-byte block where both halves form a point on P-256. */
extern const uint8_t fp_sensor_fw_pubkey[FP_P256_PUB_LEN];

/* Generate a P-256 keypair where the public Y satisfies Y == +sqrt(rhs)
 * (i.e., the "positive" root chosen by the curve-equation recovery path).
 * This matters because the Synaptics 0x93 protocol sends only X and the
 * sensor recovers Y via +sqrt — so the signer's Y must match for ECDSA
 * verification to work. On average, half the keypairs already satisfy this;
 * if not, we negate the private scalar (priv' = n - priv) which flips Y to
 * its negation, putting us on the +sqrt path. Returns 0 on success. */
int fp_crypto_p256_keygen_canonical_y(uint8_t priv_out[FP_P256_PRIV_LEN],
                                      uint8_t pub_xy_out[FP_P256_PUB_LEN]);

/* ECDSA on P-256 with SHA-256 digest, DER-encoded signature output.
 * The signature is variable length (typically ~70-72 bytes). Caller
 * provides a buffer of size FP_P256_SIG_MAX. Sets *sig_len_out to the
 * actual signature length. */
#define FP_P256_SIG_MAX 80

int fp_crypto_p256_ecdsa_sign(const uint8_t priv[FP_P256_PRIV_LEN],
                              const uint8_t hash[FP_SHA256_LEN],
                              uint8_t *sig_out, size_t *sig_len_out);
int fp_crypto_p256_ecdsa_verify(const uint8_t pub[FP_P256_PUB_LEN],
                                const uint8_t hash[FP_SHA256_LEN],
                                const uint8_t *sig, size_t sig_len);

/* Self-test: runs known-answer tests for each operation. Returns 0 if
 * all pass. Designed to be wired up under `fpdrv selftest`. */
int fp_crypto_selftest(void);

#endif
