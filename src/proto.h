#ifndef FPDRV_PROTO_H
#define FPDRV_PROTO_H

#include "device.h"
#include "storage.h"
#include "tls.h"
#include <stdint.h>

/* High-level protocol operations for the Synaptics 06cb:00e7 sensor,
 * factored out of the original main.c research harness so that both the
 * `fpdrv` CLI and the libfprint-2-tod driver drive the sensor through one
 * code path. Every function here is synchronous and blocking; the TOD
 * driver runs them on a worker thread (see tod/).
 *
 * The converged, known-good wire sequences these encode were established
 * over the protocol-reversing sessions logged in the memory store
 * (pairing + dual-key 0x93, the v7 plaintext-faithful enroll with
 * per-image FRAME_ACQ, on-chip misIdentifyMatch). */

struct fp_session {
	struct fp_device       *dev;
	struct fp_tls_state     st;
	struct fp_tls_transport xport;
	struct fp_pairdata      pd;
	int                     open;
};

/* Resolve + load persisted pair-data. Path resolution order:
 *   $FPDRV_PAIRDATA -> /var/lib/fpdrv/pairdata -> storage default ($HOME).
 * Returns 0 on success, -1 if no pair-data could be loaded. */
int fp_proto_load_pairdata(struct fp_pairdata *out);

/* Bring the session up: clear endpoint halts, run the two init query
 * passes, pair-begin, sign + send the 0x93 pairing request with the
 * persisted host identity, then run the full client TLS handshake. On
 * success the session holds an established secure channel and `open` is 1.
 * Returns 0 on success, negative on failure. */
int fp_proto_open(struct fp_session *s, struct fp_device *dev);

/* Tear down the TLS state. Does not touch the underlying USB device. */
void fp_proto_close(struct fp_session *s);

/* Enroll progress callback. Invoked after each accepted sample with the
 * running good-sample count (0..10). Return non-zero to abort the enroll
 * early (e.g. on cancellation). */
typedef int (*fp_proto_enroll_cb)(int samples, void *user);

/* Run a full enrollment: arm + FRAME_ACQ + AddImage until 10 good samples
 * are collected, then misEnrollCommit with the given WinBio finger subtype
 * and identity SID, then misEnrollFinish. The user must physically present
 * the finger repeatedly. On success, the sensor-assigned 16-byte template
 * GUID is written to out_guid.
 *
 * sid/sid_len: the WINBIO_IDENTITY SID bytes to bind (see
 * fp_proto_make_linux_sid). Pass sid=NULL to bind a NULL identity.
 *
 * Returns 0 on success, -2 if not enough samples were collected before
 * timeout/abort, negative on protocol error. */
int fp_proto_enroll(struct fp_session *s, uint8_t finger_subtype,
                    const uint8_t *sid, int sid_len,
                    fp_proto_enroll_cb cb, void *user,
                    uint8_t out_guid[16]);

/* Capture one frame and run on-chip misIdentifyMatch against all stored
 * templates. Returns 1 on a match (out_guid[16] + *out_finger set), 0 on
 * no match (sensor status 0x0509), -1 when no finger was presented within
 * the capture window (retryable), -2 on a fatal protocol error. */
int fp_proto_identify(struct fp_session *s, uint8_t out_guid[16],
                      uint8_t *out_finger);

/* Enumerate stored templates. The callback is invoked once per finger
 * object with its owning user GUID, the finger object GUID, and the WinBio
 * finger subtype (read from the finger object data). Return non-zero from
 * the callback to stop early. Returns the number of fingers seen, or
 * negative on error. */
typedef int (*fp_proto_list_cb)(const uint8_t user_guid[16],
                                const uint8_t finger_guid[16],
                                uint8_t finger_subtype, void *user);
int fp_proto_list(struct fp_session *s, fp_proto_list_cb cb, void *user);

/* Delete a single finger template by its user + finger object GUIDs (as
 * surfaced by fp_proto_list). Returns 0 on success, negative on error. */
int fp_proto_delete(struct fp_session *s, const uint8_t user_guid[16],
                    const uint8_t finger_guid[16]);

/* Delete every enrolled template (all users + child refs). Returns 0 on
 * success, negative on error. */
int fp_proto_clear(struct fp_session *s);

/* Build a well-formed Linux WINBIO_IDENTITY SID of the form
 * S-1-5-21-<"LNX">-0-0-<uid> into out[28]. Returns 28. */
int fp_proto_make_linux_sid(uint32_t uid, uint8_t out[28]);

#endif
