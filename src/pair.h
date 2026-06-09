#ifndef FPDRV_PAIR_H
#define FPDRV_PAIR_H

#include "device.h"
#include <stdint.h>

/* Phase 2b — cleartext pair handshake.
 *
 * This is the host-to-sensor mutual challenge-response that establishes a
 * fresh shared PSK in the sensor's NVRAM (and on the host side, wrapped
 * with the host's local key-storage scheme). Only fires when the sensor's
 * stored pairing blob can't be decrypted by the host (different machine
 * identity, factory reset, etc.).
 *
 * See `protocol-notes.md` § "Phase 2b — Cleartext pair handshake" for the
 * wire-level field layout that this module implements. */

/* Send `0x3f 02` (pair-begin signal). The sensor responds `00 00` with no
 * body. Returns 0 on success. */
int fp_pair_begin(struct fp_device *dev);

/* Send the 401-byte `0x93` pair-request and read the sensor's multi-part
 * response (typically 768 + 34 + 3 bytes). On success the response data
 * is written to `resp_buf` (up to `resp_max` bytes) and `*resp_len` is
 * set to the total number of bytes received across all read fragments.
 *
 * `priv` is the host's P-256 private key used to sign the request.
 * `token` is the 4-byte session token (random per pair, will be echoed
 * by the sensor). `hash1` and `hash2` are the two 32-byte context hashes
 * the protocol carries. */
int fp_pair_request(struct fp_device *dev,
                    const uint8_t priv[32],
                    const uint8_t token[4],
                    const uint8_t hash1[32],
                    const uint8_t hash2[32],
                    uint8_t *resp_buf, int resp_max, int *resp_len);

/* High-level driver entry: generate placeholder material (random token,
 * fixed-string hashes, fresh keypair), call begin + request, and print a
 * diagnostic decomposition of what the sensor responded with. Returns 0
 * if all the commands at least transported correctly (NOT if the sensor
 * accepted the pair — that needs real crypto material). */
int fp_pair_attempt(struct fp_device *dev);

/* Replay the exact 401-byte 0x93 payload from captures/try-6.pcapng
 * frame 280 — the only known-valid pair request bytes we have.
 *
 * Used as a diagnostic to distinguish:
 *  - "request bytes are valid; sensor has no replay protection" (sensor
 *    accepts → 768+ B response)
 *  - "request bytes are valid; sensor has state-based replay protection
 *    or has rolled some per-session state" (sensor rejects with the
 *    same 0x0403 error)
 *  - "request bytes are valid only for the original sensor state and
 *    must include a freshly-issued token from the sensor that we
 *    haven't observed how to fetch" */
int fp_pair_replay_try6(struct fp_device *dev);

/* After pair-replay, continue with the captured 82-byte TLS ClientHello
 * (try-6 frame 288). Read response and compare against the captured 66-byte
 * ServerHello (frame 291). Diagnostic for whether the entire TLS-like
 * handshake is byte-deterministic from request inputs. */
int fp_tls_replay_try6(struct fp_device *dev);

/* Byte-bisection driver. Replays the captured TRY6 0x93 payload with a
 * sequence of targeted single-byte / region mutations and reports for each
 * test whether the sensor accepts (status 0x0000 — bytes are OPAQUE) or
 * rejects (status 0x0403 — bytes are CHECKED, either signature-bound or
 * directly inspected). Used to localize which fields of the 401-byte
 * request the sensor actually verifies. */
int fp_pair_bisect(struct fp_device *dev);

/* Signing-message hypothesis sweep. Builds a 0x93 request body using our
 * persisted pair-data (hash1 = host pubkey X, hash2 = SHA-256(host pub),
 * token = 3f 5f 17 00) and tries a sequence of candidate "what to sign"
 * schemes. For each, signs with host_priv and sends to the sensor. Reports
 * which (if any) produces status 0x0000 (sensor accepts). */
int fp_pair_sign_sweep(struct fp_device *dev,
                       const uint8_t priv[32],
                       const uint8_t pub_x[32]);

#endif
