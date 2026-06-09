#ifndef FPDRV_TLS_H
#define FPDRV_TLS_H

#include <stddef.h>
#include <stdint.h>

/* TLS layer for the Synaptics 06cb:00e7 fingerprint sensor.
 *
 * Direct C port of the relevant parts of python-validity's
 * `validitysensor/tls.py`. See `[[project-python-validity-rosetta]]` in
 * memory for the full cross-walk; the TL;DR is that our 06cb:00e7
 * protocol is the same family as the Validity 138a:00xx sensors and the
 * python-validity logic ports almost line-for-line, with these
 * differences:
 *   - cipher suite is `0xc02e = TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384`
 *     (Validity uses `0xc005 = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA`)
 *   - the host's private key wrap inside the flash blob uses Windows
 *     DPAPI rather than GWK-derived AES-CBC. We don't try to decrypt
 *     existing Windows-written blobs; our own fresh pair will store
 *     under a different scheme.
 *
 * Two utility surfaces here are independent of the live sensor and are
 * testable against captured blobs:
 *
 *   fp_tls_prf       — the TLS-PRF used to derive every keyed value
 *                      (HMAC-SHA256-based per python-validity's `prf()`)
 *   fp_tls_flash_*   — parser for the 4 KB pair-data blob format
 *                      `<id:u16 LE><size:u16 LE><sha256:32 B><body>`
 *                      padded to 4 KB with 0xff. Captured blobs at
 *                      `captures/try-N-decoded/sensor_cert.bin` have a
 *                      leading 8-byte envelope (probably a wrap header
 *                      written by the WBIO IOCTL framing) and the
 *                      flash blocks begin at offset 8.
 */

/* TLS-PRF as defined in RFC 5246 §5, parameterised by hash:
 *   fp_tls_prf       — P_SHA256 (matches python-validity exactly)
 *   fp_tls_prf_sha384 — P_SHA384 (required by our cipher 0xc02e per RFC 5289)
 *
 * Note the canonical TLS 1.2 PRF takes `(secret, label, seed)` and runs
 * P_hash(secret, label || seed). python-validity (and our DLL's analog
 * via palSymKeyGen) inline the label into the seed argument, so we
 * mirror that interface: caller is responsible for concatenating the
 * label and the per-derivation salt into one seed buffer.
 *
 * out_len can be any length; the PRF expands by repeated HMAC chaining
 * until enough bytes are produced. Returns 0 on success. */
int fp_tls_prf(const void *secret, size_t secret_len,
               const void *seed,   size_t seed_len,
               uint8_t *out, size_t out_len);
int fp_tls_prf_sha384(const void *secret, size_t secret_len,
                      const void *seed,   size_t seed_len,
                      uint8_t *out, size_t out_len);

/* One walked block from the flash format. */
struct fp_tls_flash_block {
	int         offset;          /* file offset within the input buffer */
	uint16_t    id;
	uint16_t    size;
	const uint8_t *body;         /* pointer into caller's buffer */
	int         sha256_ok;       /* 1 if integrity hash matched, 0 if not */
};

/* Walk the flash blocks in `buf`. The walker auto-detects the 8-byte
 * leading envelope (`00 00 00 10 00 00 00 00` in our captures) and skips
 * it before parsing blocks. Stops at the first `0xffffffff` block id
 * (= start of padding) or at the end of the buffer. Calls `visit` for
 * each block; if it returns non-zero, the walk stops.
 *
 * Returns the number of blocks visited on success, -1 on parse error. */
typedef int (*fp_tls_flash_visit)(const struct fp_tls_flash_block *blk, void *ctx);
int fp_tls_flash_walk(const uint8_t *buf, int len,
                      fp_tls_flash_visit visit, void *ctx);

/* Convenience: print all blocks to stdout. Useful for `fpdrv flash`. */
int fp_tls_flash_dump(const uint8_t *buf, int len);


/* TLS state + record framing.
 *
 * Mirrors python-validity's `Tls` class. Holds the in-progress
 * handshake state (transcript hash, client/server randoms, eventual
 * session keys) and the secure_rx/secure_tx flags that gate encrypted
 * record handling. Encryption isn't wired up yet — the record
 * builder/parser handles cleartext records and will be extended once
 * we have keys.
 *
 * For our cipher suite TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
 *   - MAC is HMAC-SHA384 (48 B key, 48 B output)
 *   - Bulk cipher is AES-256-CBC (32 B key, 16 B IV per record)
 *   - PRF hash is SHA-384, but python-validity uses SHA-256 PRF for the
 *     Validity sensors (cipher 0xc005). We'll need both — TLS-PRF is
 *     SHA-256 for the GWK/HS_KEY paths and SHA-384 for the TLS handshake
 *     keys themselves. */

#define FP_TLS_RANDOM_LEN     32
#define FP_TLS_MASTER_SECRET  48   /* TLS 1.2 master secret is always 48 B */
#define FP_TLS_ENC_KEY_LEN    32   /* AES-256 key */
#define FP_TLS_GCM_IV_LEN     4    /* implicit IV (salt) for AES-GCM nonce */

struct fp_tls_state {
	uint8_t  client_random[FP_TLS_RANDOM_LEN];
	uint8_t  server_random[FP_TLS_RANDOM_LEN];
	uint8_t  master_secret[FP_TLS_MASTER_SECRET];
	/* AES-256-GCM key schedule (Synaptics quirk: cipher 0xc02e is named
	 * CBC+SHA384, but the actual record layer is GCM — verified 2026-05-19
	 * via libtudor BCrypt trace). No MAC keys; the GCM auth tag IS the MAC. */
	uint8_t  enc_key_client[FP_TLS_ENC_KEY_LEN];
	uint8_t  enc_key_server[FP_TLS_ENC_KEY_LEN];
	uint8_t  iv_client[FP_TLS_GCM_IV_LEN];   /* implicit IV salt for outbound */
	uint8_t  iv_server[FP_TLS_GCM_IV_LEN];   /* implicit IV salt for inbound */
	uint64_t seq_send;     /* TLS write sequence number — also the explicit nonce part */
	uint64_t seq_recv;     /* TLS read sequence number */
	int      secure_tx;    /* 1 once we send ChangeCipherSpec */
	int      secure_rx;    /* 1 once we receive ChangeCipherSpec */
	/* Two parallel running hashes over the handshake transcript. Both
	 * see every handshake-message body that flows through the record
	 * layer; we finalise whichever one a given operation needs.
	 *   - hh_sha384 feeds Finished verify_data (cipher 0xc02e uses
	 *     SHA-384 PRF per RFC 5289).
	 *   - hh_sha256 feeds CertificateVerify (signature hash per the
	 *     CertificateRequest field 0x0140 = ECDSA+SHA-256).
	 * Both are EVP_MD_CTX* opaque to non-tls.c callers. */
	void    *hh_sha384;
	void    *hh_sha256;
	/* Synaptics quirk: server_finished verify_data is computed against the
	 * transcript hash snapshot taken AT CLIENT_FINISHED TIME — i.e. the
	 * sensor does NOT include our client_finished message in their
	 * transcript before computing their own server_finished. We cache the
	 * snapshot in make_finished so verify_server_finished can use it. */
	uint8_t  saved_transcript_sha256[32];
	int      saved_transcript_valid;
};

/* TLS content types. */
#define FP_TLS_CT_CHANGE_CIPHER_SPEC  0x14
#define FP_TLS_CT_ALERT               0x15
#define FP_TLS_CT_HANDSHAKE           0x16
#define FP_TLS_CT_APPLICATION_DATA    0x17

int  fp_tls_state_init(struct fp_tls_state *st);
void fp_tls_state_destroy(struct fp_tls_state *st);

/* Update the running handshake transcript with the given bytes. The
 * transcript covers every Handshake-content-type record's body
 * (everything after the 5-byte TLS record header), and is used by
 * Finished verification and the CertificateVerify message. */
int fp_tls_handshake_hash_update(struct fp_tls_state *st,
                                 const void *data, size_t len);

/* Snapshot the current transcript hash without finalizing it. Two
 * variants: SHA-384 for Finished, SHA-256 for CertificateVerify. */
int fp_tls_handshake_hash_snapshot(struct fp_tls_state *st,
                                   uint8_t out[48]);
int fp_tls_handshake_hash_snapshot_sha256(struct fp_tls_state *st,
                                          uint8_t out[32]);

/* Build a single TLS record. body+body_len is the cleartext body; the
 * function prepends the 5-byte TLS record header (`type|0x0303|len:u16
 * BE|body`). Encryption + MAC are NOT yet applied — caller must keep
 * secure_tx==0 for now. Out must have at least body_len + 5 bytes.
 *
 * Returns the total record length written (body_len + 5) or -1. */
int fp_tls_record_build(struct fp_tls_state *st,
                        uint8_t content_type,
                        const void *body, int body_len,
                        uint8_t *out, int out_cap);

/* Parse a buffer of one or more concatenated TLS records. For each
 * record, the callback is invoked with the content type and (decrypted,
 * if secure_rx is set — not yet implemented) body bytes. Returns the
 * number of records parsed, or -1 on framing error.
 *
 * Side effects:
 *   - flips st->secure_rx to 1 upon a valid ChangeCipherSpec record
 *   - updates the handshake hash for Handshake-content-type records
 *     after invoking the callback (so the callback sees its slice
 *     before it's mixed into the running hash) */
typedef int (*fp_tls_record_cb)(uint8_t content_type,
                                const uint8_t *body, int body_len,
                                void *ctx);
int fp_tls_parse_records(struct fp_tls_state *st,
                         const uint8_t *buf, int len,
                         fp_tls_record_cb cb, void *ctx);


/* TLS handshake message types (RFC 5246 §7.4). */
#define FP_TLS_HS_HELLO_REQUEST       0x00
#define FP_TLS_HS_CLIENT_HELLO        0x01
#define FP_TLS_HS_SERVER_HELLO        0x02
#define FP_TLS_HS_CERTIFICATE         0x0b
#define FP_TLS_HS_SERVER_KEY_EXCHANGE 0x0c
#define FP_TLS_HS_CERTIFICATE_REQUEST 0x0d
#define FP_TLS_HS_SERVER_HELLO_DONE   0x0e
#define FP_TLS_HS_CERTIFICATE_VERIFY  0x0f
#define FP_TLS_HS_CLIENT_KEY_EXCHANGE 0x10
#define FP_TLS_HS_FINISHED            0x14

/* Cipher suite our sensor negotiates: TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384.
 * Same suite list as the DLL's ClientHello in try-3 frame 180. */
#define FP_TLS_CIPHER_ECDHE_PSK_AES256_CBC_SHA384 0xc02e

/* Build a ClientHello message body (just the handshake content — the
 * caller wraps it in the Handshake header `<type:1><len:3>` and the TLS
 * record header `<ct:1><ver:2><len:2>`).
 *
 * Uses `st->client_random` if non-zero, otherwise fills it from the
 * OpenSSL RNG. Matches the byte layout the Synaptics DLL produces:
 *   - 7-byte session ID of zeros
 *   - 5 cipher suites: c005 c02e 003d 008d 00a8
 *   - 2 extensions: truncated_hmac (0x04 → 0x0017),
 *     ec_point_formats (0x0b → "00")
 *   - **Quirk**: extensions list length field is encoded as (len-2),
 *     mirroring python-validity's `h += pack('>H', len(exts) - 2) + exts`
 *
 * Out must have at least 80 bytes capacity. Returns total bytes written
 * (~73), or -1. */
int fp_tls_make_client_hello(struct fp_tls_state *st,
                             uint8_t *out, int out_cap);

/* Parse a ServerHello message body (the handshake message after its
 * 4-byte handshake header has been stripped). Extracts server_random
 * (into st) and the chosen cipher_suite (into *cipher_out). Returns 0
 * on success, -1 on parse error or unexpected version. */
int fp_tls_parse_server_hello(struct fp_tls_state *st,
                              const uint8_t *body, int body_len,
                              uint16_t *cipher_out);

/* The ChangeCipherSpec message is a fixed 6-byte record. This builds
 * the full record (with header), since CCS doesn't go through the
 * handshake builder. Out cap must be >= 6. */
int fp_tls_make_change_cipher_spec(uint8_t *out, int out_cap);

/* Build a Finished handshake message body:
 *   <type=0x14:1><len:3><verify_data(12)>
 *
 * verify_data is `PRF-SHA384(master_secret, "client finished",
 * SHA-384(handshake_transcript_so_far), 12)`. The transcript is then
 * extended with the just-built bytes (so the server's symmetric Finished
 * can later be verified including our Finished).
 *
 * Caller is responsible for wrapping in a TLS record. Note: typically
 * called AFTER setting `secure_tx = 1` and sending ChangeCipherSpec, so
 * the resulting record is encrypted.
 *
 * Returns total bytes written (16 = 4 header + 12 verify_data) or -1. */
int fp_tls_make_finished(struct fp_tls_state *st,
                         uint8_t *out, int out_cap);

/* Verify a Finished message body received from the sensor. `body` points
 * past the 4-byte handshake header (i.e. directly at the verify_data
 * bytes); body_len must be 12. Returns 0 if the MAC matches the expected
 * value, -1 otherwise. */
int fp_tls_verify_server_finished(struct fp_tls_state *st,
                                  const uint8_t *body, int body_len);

/* Build a Certificate handshake message wrapping pre-supplied cert
 * bytes (the host's stored attestation envelope, normally read from the
 * pair-data blob). Mirrors python-validity's `make_certs`: the
 * Synaptics Certificate format double-wraps the cert in two `0 || u16
 * BE len` prefixes (non-standard, but what the sensor expects).
 *
 * Layout produced (matches our captured frame 184 first sub-message):
 *   <hs_type=0x0b><hs_len:3>             handshake header
 *     <0:1><list_len:2><0:1><cert_len:2> two layered 3-byte length prefixes
 *       cert_bytes                       opaque cert body
 *
 * Returns total bytes written (= 4 + 3 + 3 + cert_len), or -1. */
int fp_tls_make_certificate(struct fp_tls_state *st,
                            const uint8_t *cert_bytes, int cert_len,
                            uint8_t *out, int out_cap);

/* Build a ClientKeyExchange handshake message containing the host's
 * ephemeral ECDH P-256 public point in uncompressed form (0x04 || X || Y,
 * 65 bytes). Adds the message to the transcript hash. */
int fp_tls_make_client_key_exchange(struct fp_tls_state *st,
                                    const uint8_t pub_xy[64],
                                    uint8_t *out, int out_cap);

/* Build a CertificateVerify handshake message. Signs the current
 * transcript hash with the host's private key. The signature algorithm
 * for our protocol is ECDSA-with-SHA256 (matching python-validity's
 * `make_cert_verify`). Writes a DER-encoded signature into the message
 * body. Adds the message to the transcript hash. */
int fp_tls_make_certificate_verify(struct fp_tls_state *st,
                                   const uint8_t priv_d[32],
                                   uint8_t *out, int out_cap);


/* ---- Handshake orchestrator ---- */

/* Transport interface for the orchestrator. Each call carries a full
 * bulk-transfer payload (no fragmentation handling here). `send` writes
 * out_len bytes; `recv` reads up to cap and returns the actual count.
 * Both return 0 / count on success and negative on error. */
struct fp_tls_transport {
	int  (*send)(void *ctx, const void *buf, int len);
	int  (*recv)(void *ctx, void *buf,  int cap);
	void *ctx;
};

/* Inputs for the orchestrator. */
struct fp_tls_handshake_inputs {
	const uint8_t *cert_blob;
	int            cert_blob_len;
	const uint8_t *priv_d;        /* 32 B — host's long-term EC private key */
	const uint8_t *psk;
	int            psk_len;
	const uint8_t *sensor_pub_xy; /* 64 B — sensor's ECDH pubkey if known;
	                               * pass NULL to use a fake one (dryrun only) */
	/* The host's ephemeral ECDHE keypair. If `eph_priv` is NULL, the
	 * orchestrator generates one with the OpenSSL RNG. The corresponding
	 * pubkey lands in `eph_pub_out` for the caller's reference. */
	const uint8_t *eph_priv;
	uint8_t       *eph_pub_out;   /* 64 B receive buffer or NULL */
};

/* Run the full client-side TLS handshake. State must be freshly inited.
 * On success, st has session keys + secure_tx/rx set.
 *
 * Returns 0 on full success. Negative on any step that fails. */
int fp_tls_open(struct fp_tls_state *st,
                const struct fp_tls_handshake_inputs *in,
                const struct fp_tls_transport *xport);

/* Send a VCSFW command wrapped in a TLS application_data record over the
 * already-established secure session, and receive the (possibly multi-
 * record) encrypted response. Prepends the Synaptics `44 00 00 00` bulk
 * prefix on send. Returns the total decrypted response length in `resp`,
 * or -1 on error / TLS alert. */
int fp_tls_app_send_recv(struct fp_tls_state *st,
                         const struct fp_tls_transport *xport,
                         const void *cmd, int cmd_len,
                         uint8_t *resp, int resp_cap);

/* `fpdrv tls-dryrun` entry — exercises the orchestrator with a mock
 * transport that returns captured try-3 server response bytes, while
 * generating client-side messages with placeholder keys. Reports each
 * phase, and exits 0 even if the handshake "fails" at the verify step
 * (since we don't have real keys, the Finished MAC won't match). */
int fp_tls_dryrun(void);

/* Derive the TLS session keys for cipher 0xc02e
 * (TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384) using inputs available after
 * the host has done ECDH with the sensor and knows the PSK.
 *
 * Per RFC 4279 §2, the pre_master_secret for any *_PSK_* cipher is the
 * structure:
 *   pre_master = <u16 BE: ecdh_len><ecdh_shared><u16 BE: psk_len><psk>
 *
 * Then RFC 5246 §8.1:
 *   master_secret = PRF(pre_master, "master secret",
 *                       client_random + server_random, 48)
 *
 * Then RFC 5246 §6.3:
 *   key_block = PRF(master_secret, "key expansion",
 *                   server_random + client_random,
 *                   2*MAC_key_len + 2*enc_key_len)
 *   = 2*48 + 2*32 = 160 bytes for our cipher
 *
 * key_block is split client-first:
 *   mac_key_client | mac_key_server | enc_key_client | enc_key_server
 *
 * Reads st->client_random and st->server_random (so call after
 * ClientHello + ServerHello have been processed). Writes master_secret
 * and the four key fields into st. Returns 0 on success. */
int fp_tls_derive_session_keys(struct fp_tls_state *st,
                               const uint8_t *ecdh_shared, size_t ecdh_len,
                               const uint8_t *psk,         size_t psk_len);

/* Split the body of a Handshake-content-type TLS record into its
 * constituent handshake messages. A single record can carry several
 * messages back-to-back (e.g. our captured frame 183 has ServerHello +
 * CertificateRequest + ServerHelloDone in one record).
 *
 * Each invocation of the callback receives:
 *   - msg_type: handshake message type (FP_TLS_HS_*)
 *   - body: pointer into the input buffer, just past the 4-byte
 *     handshake header
 *   - body_len: the message body length from the handshake header
 *
 * Returns the number of messages, or -1 on framing error. */
typedef int (*fp_tls_hs_cb)(uint8_t msg_type,
                            const uint8_t *body, int body_len,
                            void *ctx);
int fp_tls_split_handshake(const uint8_t *record_body, int record_body_len,
                           fp_tls_hs_cb cb, void *ctx);

#endif
