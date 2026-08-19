#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "proto.h"

#include "cmd.h"
#include "pair.h"
#include "parser.h"
#include "transport.h"

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Verbose tracing to stderr (captured in fprintd's journal). Gate behind
 * FPDRV_PROTO_DEBUG=1 so normal operation stays quiet. */
static int proto_dbg(void)
{
	static int v = -1;
	if (v < 0) v = getenv("FPDRV_PROTO_DEBUG") ? 1 : 0;
	return v;
}
#define DBG(...) do { if (proto_dbg()) fprintf(stderr, __VA_ARGS__); } while (0)

/* 2026-05-24: dual-key model. KEY2_PRIV signs the 0x93 pairing request;
 * the host's persistent identity (pd.host_pub_xy / pd.host_priv) is what
 * the sensor stores and later checks against the TLS CertificateVerify.
 * See [[project-key2-confirmed-2026-05-24]]. */
static const uint8_t KEY2_PRIV_BE[32] = {
	0xe8, 0xa2, 0xa2, 0xb6, 0x65, 0x62, 0x54, 0xd6,
	0xac, 0xb0, 0xef, 0x47, 0x9c, 0xae, 0x41, 0x40,
	0xc7, 0xe8, 0xe2, 0x60, 0xdb, 0x3f, 0x64, 0x2e,
	0x35, 0xd4, 0x09, 0x9c, 0x01, 0xb3, 0x6a, 0x86,
};

/* ---- TLS transport adapter over the device's bulk endpoints ---- */

static int xport_send(void *ctx, const void *buf, int len)
{
	struct fp_device *dev = ctx;
	int sent = 0;
	int rc = fp_bulk_send(dev, buf, len, &sent);
	if (rc != 0) {
		DBG("proto: bulk_send: %s\n", libusb_error_name(rc));
		return -1;
	}
	return sent;
}

static int xport_recv(void *ctx, void *buf, int cap)
{
	struct fp_device *dev = ctx;
	int got = 0;
	int rc = fp_bulk_recv(dev, buf, cap, &got);
	if (rc != 0) {
		DBG("proto: bulk_recv: %s\n", libusb_error_name(rc));
		return -1;
	}
	return got;
}

/* Convenience: send a VCSFW command over the secure channel and return the
 * 16-bit status (low 2 bytes) plus the full response in resp. */
static int app_cmd(struct fp_session *s, const void *cmd, int cmd_len,
                   uint8_t *resp, int resp_cap, int *out_len)
{
	int n = fp_tls_app_send_recv(&s->st, &s->xport, cmd, cmd_len, resp, resp_cap);
	if (out_len) *out_len = n;
	if (n < 2) return -1;
	return resp[0] | (resp[1] << 8);
}

/* ---- pair-data loading ---- */

int fp_proto_load_pairdata(struct fp_pairdata *out)
{
	const char *env = getenv("FPDRV_PAIRDATA");
	if (env && fp_storage_load(out, env) == 0) return 0;
	if (fp_storage_load(out, "/var/lib/fpdrv/pairdata") == 0) return 0;
	if (fp_storage_load(out, NULL) == 0) return 0;
	return -1;
}

/* ---- session open: pair + TLS handshake ---- */

int fp_proto_open(struct fp_session *s, struct fp_device *dev)
{
	memset(s, 0, sizeof(*s));
	s->dev = dev;

	if (fp_proto_load_pairdata(&s->pd) != 0) {
		fprintf(stderr, "proto: no pair-data (run `fpdrv pair-init` and install it)\n");
		return -1;
	}

	/* Windows clears endpoint halts right before the bulk pair flow. */
	(void)fp_clear_halt(dev, 0x01);
	(void)fp_clear_halt(dev, 0x81);
	(void)fp_clear_halt(dev, 0x83);

	int rc = fp_cmd_init_basic(dev);
	if (rc != 0) { fprintf(stderr, "proto: init pass 1: %s\n", libusb_error_name(rc)); return -1; }
	rc = fp_cmd_init_basic(dev);
	if (rc != 0) { fprintf(stderr, "proto: init pass 2: %s\n", libusb_error_name(rc)); return -1; }

	if (fp_pair_begin(dev) != 0) { fprintf(stderr, "proto: pair_begin failed\n"); return -1; }

	uint8_t token[4] = { 0x3f, 0x5f, 0x17, 0x00 };
	uint8_t hash1[32], hash2[32];
	for (int i = 0; i < 32; i++) {
		hash1[i] = s->pd.host_pub_xy[31 - i];   /* host pub X in LE */
		hash2[i] = s->pd.host_pub_xy[63 - i];   /* host pub Y in LE */
	}

	uint8_t resp[1024];
	int resp_len = 0;
	rc = fp_pair_request(dev, KEY2_PRIV_BE, token, hash1, hash2,
	                     resp, sizeof(resp), &resp_len);
	if (rc != 0) { fprintf(stderr, "proto: pair_request rc=%d\n", rc); return -1; }
	if (resp_len < 2 || (resp[0] | (resp[1] << 8)) != 0x0000) {
		fprintf(stderr, "proto: 0x93 rejected (len=%d status=0x%04x)\n",
		        resp_len, resp_len >= 2 ? (resp[0] | (resp[1] << 8)) : 0xffff);
		return -1;
	}
	if (resp_len < 506) { fprintf(stderr, "proto: pair resp too short (%d)\n", resp_len); return -1; }

	/* Vendor "get TLS status" read, mirroring Windows frame 170. */
	{
		uint8_t tls_status[2] = { 0xff, 0xff };
		(void)fp_control_transfer(dev, 0xc0, 0x14, 0, 0, tls_status, 2, 1000);
	}

	/* Build the 400-byte host cert blob (Synaptics 00e7 format). */
	uint8_t cert_blob[400];
	memset(cert_blob, 0, sizeof(cert_blob));
	memcpy(cert_blob + 0,  token, 4);
	memcpy(cert_blob + 4,  hash1, 32);
	memcpy(cert_blob + 72, hash2, 32);
	cert_blob[140] = 0x00; cert_blob[141] = 0x02;
	cert_blob[142] = 0x20; cert_blob[143] = 0x00;
	if (resp_len >= 178) memcpy(cert_blob + 144, resp + 146, 32);

	/* Sensor static ECDH pubkey: X at resp[406] LE, Y at resp[474] LE. */
	uint8_t sensor_pub_xy[64];
	for (int i = 0; i < 32; i++) {
		sensor_pub_xy[i]      = resp[406 + 31 - i];
		sensor_pub_xy[32 + i] = resp[474 + 31 - i];
	}

	if (fp_tls_state_init(&s->st) != 0) { fprintf(stderr, "proto: tls_state_init failed\n"); return -1; }

	struct fp_tls_handshake_inputs in = {
		.cert_blob = cert_blob, .cert_blob_len = sizeof(cert_blob),
		.priv_d = s->pd.host_priv, .psk = s->pd.psk, .psk_len = FP_PSK_LEN,
		.sensor_pub_xy = sensor_pub_xy, .eph_priv = NULL, .eph_pub_out = NULL,
	};
	s->xport.send = xport_send;
	s->xport.recv = xport_recv;
	s->xport.ctx  = dev;

	int tls_rc = fp_tls_open(&s->st, &in, &s->xport);
	if (tls_rc != 0) {
		fprintf(stderr, "proto: TLS handshake failed (rc=%d)\n", tls_rc);
		fp_tls_state_destroy(&s->st);
		return -1;
	}
	s->open = 1;
	DBG("proto: session open (secure_tx=%d secure_rx=%d)\n", s->st.secure_tx, s->st.secure_rx);
	return 0;
}

void fp_proto_close(struct fp_session *s)
{
	if (s->open) {
		fp_tls_state_destroy(&s->st);
		s->open = 0;
	}
}

/* ---- event subsystem helpers (EVENT_CONFIG / EVENT_READ) ---- */

/* EVENT_CONFIG (0x86, 37 B). mask at off1+off17, frame-ready flag at
 * off4+off20; byte[33]=0x04 on a full disarm. The 66-B reply carries the
 * sensor's current event seq at [64:65], returned via *ev_seq. */
static void ev_config(struct fp_session *s, uint8_t mask, uint8_t flag,
                      unsigned *ev_seq)
{
	uint8_t ec[37];
	uint8_t resp[256];
	memset(ec, 0, sizeof(ec));
	ec[0] = 0x86;
	ec[1] = mask;  ec[4]  = flag;
	ec[17] = mask; ec[20] = flag;
	if (mask == 0 && flag == 0) ec[33] = 0x04;
	int n = fp_tls_app_send_recv(&s->st, &s->xport, ec, sizeof(ec), resp, sizeof(resp));
	if (ev_seq && n >= 66) *ev_seq = resp[64] | (resp[65] << 8);
}

/* EVENT_READ (0x87) polled at a fixed cursor until an event arrives or
 * `ms` elapses. Returns the first event's code (0 on timeout) and advances
 * *cursor by the number of events consumed. */
static unsigned ev_read_wait(struct fp_session *s, uint16_t *cursor, int ms)
{
	uint8_t resp[256];
	int iters = ms / 50; if (iters < 1) iters = 1;
	for (int w = 0; w < iters; w++) {
		uint8_t er[9] = { 0x87, 0, 0, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00 };
		er[1] = (uint8_t)(*cursor & 0xff);
		er[2] = (uint8_t)(*cursor >> 8);
		int n = fp_tls_app_send_recv(&s->st, &s->xport, er, sizeof(er), resp, sizeof(resp));
		unsigned ne = (n >= 4) ? (resp[2] | (resp[3] << 8)) : 0;
		if (ne > 0) {
			unsigned code = (n >= 7) ? resp[6] : 0;
			*cursor = (uint16_t)(*cursor + ne);
			return code;
		}
		usleep(50 * 1000);
	}
	return 0;
}

/* The FRAME_ACQ command for a single enroll/identify capture. */
static const uint8_t FRAME_ACQ[17] = {
	0x80, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x01, 0x00
};

/* Prime imageMetrics (0x9d) — Windows issues this before capture. */
static void prime_image_metrics(struct fp_session *s)
{
	uint8_t cmd[5] = { 0x9d, 0x00, 0x00, 0x01, 0x00 };
	uint8_t resp[256];
	fp_tls_app_send_recv(&s->st, &s->xport, cmd, sizeof(cmd), resp, sizeof(resp));
}

/* Drive the per-image arm/FRAME_ACQ/finalize sequence and return the
 * frame event code (0x18 == captured). Mirrors the v7 plaintext trace. */
static unsigned capture_one_frame(struct fp_session *s, uint16_t *cursor)
{
	unsigned code;
	uint8_t resp[256];

	/* wait-for-finger: arm 0x06, EP2 paces the wait, then read 0x01 evt */
	ev_config(s, 0x06, 0x00, NULL);
	{ uint8_t evb[8]; int got = 0; fp_intr_recv(s->dev, evb, sizeof(evb), &got, 5000); }
	code = ev_read_wait(s, cursor, 6000);
	ev_config(s, 0x00, 0x00, NULL);
	if (code == 0) return 0;          /* no finger */

	/* arm frame-class (0x04), wait for 0x02 */
	ev_config(s, 0x04, 0x00, NULL);
	ev_read_wait(s, cursor, 3000);
	ev_config(s, 0x00, 0x00, NULL);

	/* arm frame-ready, FRAME_ACQ, wait for frame-captured (0x18) */
	ev_config(s, 0x00, 0x01, NULL);
	fp_tls_app_send_recv(&s->st, &s->xport, FRAME_ACQ, sizeof(FRAME_ACQ), resp, sizeof(resp));
	code = ev_read_wait(s, cursor, 3000);
	ev_config(s, 0x00, 0x00, NULL);

	/* frame finalize (0x81) */
	{ uint8_t flush = 0x81; fp_tls_app_send_recv(&s->st, &s->xport, &flush, 1, resp, sizeof(resp)); }
	return code;
}

/* ---- identify ---- */

int fp_proto_identify(struct fp_session *s, uint8_t out_guid[16], uint8_t *out_finger)
{
	uint8_t resp[256];
	prime_image_metrics(s);

	unsigned ev_seq = 0;
	ev_config(s, 0x00, 0x00, &ev_seq);
	uint16_t cursor = (uint16_t)ev_seq;

	unsigned code = capture_one_frame(s, &cursor);
	if (code == 0) { DBG("proto: identify — no finger\n"); return -1; }

	uint8_t id_cmd[13] = { 0x99, 0x01, 0,0,0, 0,0,0,0, 0,0,0,0 };
	int idn = 0;
	int status = app_cmd(s, id_cmd, sizeof(id_cmd), resp, sizeof(resp), &idn);
	DBG("proto: misIdentifyMatch status=0x%04x len=%d\n", status, idn);
	if (status == 0x0509) return 0;          /* no match */
	if (!fp_status_is_ok(status)) return -2; /* fatal protocol error */
	if (idn < 18) return -2;
	/* The match record reports the matched *user* object GUID at offset 2
	 * (it equals the user_guid that 0x9f/02 lists), NOT the finger GUID. */
	if (out_guid) memcpy(out_guid, resp + 2, 16);
	if (out_finger) *out_finger = (idn >= 19) ? resp[18] : 1;
	return 1;
}

/* ---- enroll ---- */

int fp_proto_make_linux_sid(uint32_t uid, uint8_t out[28])
{
	static const uint8_t base[28] = {
		0x01, 0x05,                      /* rev 1, 5 sub-authorities */
		0x00,0x00,0x00,0x00,0x00,0x05,   /* NT authority = 5 */
		0x15,0x00,0x00,0x00,             /* sub0 = 21 */
		'L','N','X',0x00,                /* sub1 = "LNX" marker */
		0x00,0x00,0x00,0x00,             /* sub2 */
		0x00,0x00,0x00,0x00,             /* sub3 */
		0x00,0x00,0x00,0x00              /* sub4 = uid (RID) */
	};
	memcpy(out, base, 28);
	out[24] = (uint8_t)(uid & 0xff);
	out[25] = (uint8_t)((uid >> 8) & 0xff);
	out[26] = (uint8_t)((uid >> 16) & 0xff);
	out[27] = (uint8_t)((uid >> 24) & 0xff);
	return 28;
}

/* Snapshot of stored finger GUIDs, used to discover which finger object the
 * sensor freshly created at commit (its assigned GUID — NOT the one we asked
 * for in the commit body — is what identify/list report and what fprintd
 * reconciles disk prints against). */
struct guid_snapshot {
	uint8_t guids[64][16];
	uint8_t subtypes[64];
	int     n;
};

static int guid_snapshot_cb(const uint8_t user_guid[16], const uint8_t finger_guid[16],
                            uint8_t finger_subtype, void *user)
{
	(void)user_guid;
	struct guid_snapshot *g = user;
	if (g->n < 64) {
		memcpy(g->guids[g->n], finger_guid, 16);
		g->subtypes[g->n] = finger_subtype;
		g->n++;
	}
	return 0;
}

static int snapshot_has(const struct guid_snapshot *g, const uint8_t guid[16])
{
	for (int i = 0; i < g->n; i++)
		if (memcmp(g->guids[i], guid, 16) == 0) return 1;
	return 0;
}

static int snapshot_capture(struct fp_session *s, struct guid_snapshot *out,
                           const char *tag)
{
	out->n = 0;
	int rc = fp_proto_list(s, guid_snapshot_cb, out);
	if (rc < 0) {
		fprintf(stderr, "proto: %s snapshot failed\n", tag ? tag : "guid");
		return -1;
	}
	return 0;
}

int fp_proto_enroll(struct fp_session *s, uint8_t finger_subtype,
                    const uint8_t *sid, int sid_len,
                    fp_proto_enroll_cb cb, void *user,
                    uint8_t out_guid[16])
{
	uint8_t resp[256];
	int n;

	/* Drain any stale enroll session (0x0404 == nothing to finish). */
	uint8_t fin_cmd[5] = { 0x96, 0x04, 0x00, 0x00, 0x00 };
	for (int it = 0; it < 4; it++) {
		int st = app_cmd(s, fin_cmd, sizeof(fin_cmd), resp, sizeof(resp), &n);
		if (st == 0x0404) break;
		usleep(200 * 1000);
	}

	/* Snapshot existing finger GUIDs so we can tell which one the sensor
	 * creates for this enrollment. */
	struct guid_snapshot before = { .n = 0 };
	if (snapshot_capture(s, &before, "pre-enroll") != 0)
		return -1;

	/* Priming commands Windows sends before misEnrollStart. */
	prime_image_metrics(s);
	{ uint8_t mi[13] = { 0x99, 0x01, 0,0,0, 0,0,0,0, 0,0,0,0 };
	  app_cmd(s, mi, sizeof(mi), resp, sizeof(resp), &n); }

	/* misEnrollStart — ALL-ZERO body (a non-zero tag breaks Commit with
	 * 0x06db; see [[project-v7-plaintext-trace-2026-05-29]]). */
	uint8_t start[13]; memset(start, 0, sizeof(start));
	start[0] = 0x96; start[1] = 1;
	int sstat = app_cmd(s, start, sizeof(start), resp, sizeof(resp), &n);
	if (!fp_status_is_ok(sstat)) {
		fprintf(stderr, "proto: misEnrollStart status=0x%04x\n", sstat);
		return -1;
	}

	unsigned ev_seq = 0;
	ev_config(s, 0x00, 0x00, &ev_seq);
	uint16_t cursor = (uint16_t)ev_seq;

	unsigned progress = 0;        /* 10-bit good-sample bitmask, target 0x3ff */
	uint8_t guid[16] = {0}; int have_guid = 0;
	int no_finger_retries = 0;
	int last_samples = -1;

	for (int img = 0; img < 24 && progress != 0x3ff; img++) {
		unsigned code = capture_one_frame(s, &cursor);
		if (code == 0) {
			if (++no_finger_retries >= 20) { DBG("proto: enroll gave up (no finger)\n"); break; }
			img--;
			continue;
		}
		no_finger_retries = 0;

		uint8_t add[5] = { 0x96, 0x02, 0x00, 0x00, 0x00 };
		int astat = -1, alen = 0;
		for (int poll = 0; poll < 6; poll++) {
			astat = app_cmd(s, add, sizeof(add), resp, sizeof(resp), &alen);
			if (astat != 0x050b) break;
			usleep(120 * 1000);
		}
		if (fp_status_is_ok(astat)) {
			if (alen >= 18) { memcpy(guid, resp + 2, 16); have_guid = 1; }
			if (alen >= 24) progress = resp[22] | (resp[23] << 8);
			int samples = __builtin_popcount(progress);
			DBG("proto: enroll sample %d/10 (bitmask 0x%03x)\n", samples, progress);
			if (samples != last_samples) {
				last_samples = samples;
				if (cb && cb(samples, user)) { DBG("proto: enroll aborted by cb\n");
					app_cmd(s, fin_cmd, sizeof(fin_cmd), resp, sizeof(resp), &n);
					return -2; }
			}
		}
	}

	if (progress != 0x3ff || !have_guid) {
		fprintf(stderr, "proto: enroll incomplete (bitmask 0x%03x)\n", progress);
		app_cmd(s, fin_cmd, sizeof(fin_cmd), resp, sizeof(resp), &n);
		return -2;
	}

	/* misEnrollCommit (124 B). GUID at [19:35], finger subtype at [35],
	 * WINBIO_IDENTITY at [37]: [41]=Type, [45]=size, [49]=union buffer. */
	uint8_t commit[124] = {
		0x96, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x4c, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01,
		0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00,
		0x00, 0xf8, 0x9e, 0x12, 0x91, 0x49, 0x4e, 0x68, 0x75, 0xe7,
		0x18, 0x31, 0x2c, 0xe9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		0x00, 0x00, 0x00, 0xf5
	};
	memcpy(commit + 19, guid, 16);
	commit[35] = finger_subtype;
	if (sid && sid_len > 0 && sid_len <= 68) {
		commit[41] = 0x03;                 /* WINBIO_ID_TYPE_SID */
		commit[45] = (uint8_t)sid_len;
		memset(commit + 49, 0, 68);
		memcpy(commit + 49, sid, sid_len);
	} else if (!sid) {
		commit[41] = 0x00;                 /* WINBIO_ID_TYPE_NULL */
		commit[45] = 0x00;
		memset(commit + 49, 0, 68);
	}

	int cstat = app_cmd(s, commit, sizeof(commit), resp, sizeof(resp), &n);
	int fstat = app_cmd(s, fin_cmd, sizeof(fin_cmd), resp, sizeof(resp), &n);
	if (!fp_status_is_ok(cstat)) {
		fprintf(stderr, "proto: misEnrollCommit status=0x%04x\n", cstat);
		return -1;
	}
	/* 0x0404 = nothing-to-finish (already committed); anything else non-OK
	 * means the template was not persisted to NVRAM. */
	if (!fp_status_is_ok(fstat) && fstat != 0x0404) {
		fprintf(stderr, "proto: misEnrollFinish status=0x%04x\n", fstat);
		return -1;
	}
	/* The sensor assigns its own finger-object GUID at commit (ignoring the
	 * one in the commit body). identify/list and fprintd's disk-print
	 * reconciliation all key off that assigned GUID, so recover it by
	 * diffing the post-commit finger list against the pre-enroll snapshot.
	 * Prefer a newly-appeared GUID; fall back to the finger matching this
	 * subtype, then to the requested GUID. */
	struct guid_snapshot after = { .n = 0 };
	if (snapshot_capture(s, &after, "post-enroll") != 0) {
		/* Commit already succeeded: the sensor may now hold a template with
		 * no matching disk print. `fpdrv clear` reclaims it. */
		fprintf(stderr, "proto: committed template may be orphaned on sensor\n");
		return -1;
	}

	int new_idx = -1, subtype_idx = -1;
	for (int i = 0; i < after.n; i++) {
		if (after.subtypes[i] == finger_subtype) subtype_idx = i;
		if (!snapshot_has(&before, after.guids[i])) {
			new_idx = i;
			if (after.subtypes[i] == finger_subtype) break;
		}
	}
	int pick = (new_idx >= 0) ? new_idx : subtype_idx;
	if (pick < 0) {
		/* The new template is not visible in the sensor DB. Either the
		 * commit was not persisted or the post-commit enumeration failed.
		 * Report as a protocol error so fprintd does not store a stale
		 * GUID that will disappear after the next power cycle. */
		fprintf(stderr, "proto: enrollment not visible in sensor DB after commit\n");
		return -1;
	}
	memcpy(guid, after.guids[pick], 16);

	if (out_guid) memcpy(out_guid, guid, 16);
	DBG("proto: enroll committed and verified in sensor DB\n");
	return 0;
}

/* ---- db2 enumeration / deletion ---- */

int fp_proto_list(struct fp_session *s, fp_proto_list_cb cb, void *user)
{
	uint8_t resp[4096];
	int n, count = 0;

	uint8_t list_users[21] = { 0x9f, 0x02, 0x00, 0x00, 0x00 };
	memset(list_users + 5, 0xff, 16);
	int st = app_cmd(s, list_users, sizeof(list_users), resp, sizeof(resp), &n);
	if (!fp_status_is_ok(st)) {
		DBG("proto: user-list status=0x%04x\n", st);
		return -1;
	}
	if (n < 4) {
		DBG("proto: user-list short (%d bytes)\n", n);
		return -1;
	}
	unsigned ucount = resp[2] | (resp[3] << 8);
	int users_need = 4 + (int)(ucount * 16u);
	if (users_need > n) {
		DBG("proto: user-list malformed count=%u len=%d\n", ucount, n);
		return -1;
	}

	/* Copy user GUIDs out before reusing resp. */
	uint8_t uguids[64][16];
	if (ucount > 64) {
		DBG("proto: user-list count=%u clamped to 64\n", ucount);
		ucount = 64;
	}
	for (unsigned u = 0; u < ucount; u++)
		memcpy(uguids[u], resp + 4 + u * 16, 16);

	for (unsigned u = 0; u < ucount; u++) {
		uint8_t list_f[21] = { 0x9f, 0x03, 0x00, 0x00, 0x00 };
		memcpy(list_f + 5, uguids[u], 16);
		uint8_t fresp[1024];
		int fn = 0;
		int fst = app_cmd(s, list_f, sizeof(list_f), fresp, sizeof(fresp), &fn);
		if (!fp_status_is_ok(fst)) {
			DBG("proto: finger-list for user %u status=0x%04x\n", u, fst);
			return -1;
		}
		if (fn < 4) {
			DBG("proto: finger-list for user %u short (%d bytes)\n", u, fn);
			return -1;
		}
		unsigned fcount = fresp[2] | (fresp[3] << 8);
		int fingers_need = 4 + (int)(fcount * 16u);
		if (fingers_need > fn) {
			DBG("proto: finger-list for user %u malformed count=%u len=%d\n", u, fcount, fn);
			return -1;
		}
		for (unsigned f = 0; f < fcount; f++) {
			uint8_t fg[16];
			memcpy(fg, fresp + 4 + f * 16, 16);
			/* Read finger object data to recover the WinBio subtype. */
			uint8_t od[21] = { 0xa1, 0x03, 0x00, 0x00, 0x00 };
			memcpy(od + 5, fg, 16);
			uint8_t oresp[1024];
			int on = 0;
			int ost = app_cmd(s, od, sizeof(od), oresp, sizeof(oresp), &on);
			/* A single unreadable record (e.g. orphan from a failed commit)
			 * must not fail the whole listing; fall back to subtype 1. */
			uint8_t subtype = 1;
			if (!fp_status_is_ok(ost) || on < 36)
				DBG("proto: finger-object for user %u finger %u unreadable (status=0x%04x len=%d)\n",
				    u, f, ost, on);
			else
				subtype = oresp[35];
			count++;
			if (cb && cb(uguids[u], fg, subtype, user)) return count;
		}
	}
	return count;
}

/* Delete a finger object, then its user object if it has no remaining
 * fingers. user_guid/finger_guid as surfaced by fp_proto_list. */
int fp_proto_delete(struct fp_session *s, const uint8_t user_guid[16],
                    const uint8_t finger_guid[16])
{
	uint8_t resp[256];
	int n;
	uint8_t del_f[21] = { 0xa3, 0x03, 0x00, 0x00, 0x00 };
	memcpy(del_f + 5, finger_guid, 16);
	int fs = app_cmd(s, del_f, sizeof(del_f), resp, sizeof(resp), &n);
	if (!fp_status_is_ok(fs) && fs != 0x0683) return -1;

	/* Any remaining fingers under this user? */
	uint8_t list_f[21] = { 0x9f, 0x03, 0x00, 0x00, 0x00 };
	memcpy(list_f + 5, user_guid, 16);
	int ln = 0;
	int ls = app_cmd(s, list_f, sizeof(list_f), resp, sizeof(resp), &ln);
	unsigned fcount = (fp_status_is_ok(ls) && ln >= 4) ? (resp[2] | (resp[3] << 8)) : 0;
	if (fcount == 0) {
		uint8_t del_u[21] = { 0xa3, 0x02, 0x00, 0x00, 0x00 };
		memcpy(del_u + 5, user_guid, 16);
		app_cmd(s, del_u, sizeof(del_u), resp, sizeof(resp), &n);
	}
	return 0;
}

int fp_proto_clear(struct fp_session *s)
{
	uint8_t resp[4096];
	int n;
	uint8_t list_users[21] = { 0x9f, 0x02, 0x00, 0x00, 0x00 };
	memset(list_users + 5, 0xff, 16);
	int st = app_cmd(s, list_users, sizeof(list_users), resp, sizeof(resp), &n);
	if (!fp_status_is_ok(st)) return -1;
	unsigned ucount = (n >= 4) ? (resp[2] | (resp[3] << 8)) : 0;
	if (ucount > 64) ucount = 64;
	uint8_t uguids[64][16];
	for (unsigned u = 0; u < ucount && (int)(4 + (u + 1) * 16) <= n; u++)
		memcpy(uguids[u], resp + 4 + u * 16, 16);

	for (unsigned u = 0; u < ucount; u++) {
		/* objinfo to get the child-ref the failed commits may have left. */
		uint8_t oi[21] = { 0xa0, 0x02, 0x00, 0x00, 0x00 };
		memcpy(oi + 5, uguids[u], 16);
		uint8_t oresp[1024];
		int on = fp_tls_app_send_recv(&s->st, &s->xport, oi, sizeof(oi), oresp, sizeof(oresp));
		uint8_t child_ref[16]; int have_child = 0;
		if (on >= 36) { memcpy(child_ref, oresp + 20, 16); have_child = 1; }

		/* Delete fingers under the user. */
		uint8_t list_f[21] = { 0x9f, 0x03, 0x00, 0x00, 0x00 };
		memcpy(list_f + 5, uguids[u], 16);
		uint8_t fresp[1024];
		int fn = fp_tls_app_send_recv(&s->st, &s->xport, list_f, sizeof(list_f), fresp, sizeof(fresp));
		unsigned fcount = (fn >= 4) ? (fresp[2] | (fresp[3] << 8)) : 0;
		for (unsigned f = 0; f < fcount && (int)(4 + (f + 1) * 16) <= fn; f++) {
			uint8_t del[21] = { 0xa3, 0x03, 0x00, 0x00, 0x00 };
			memcpy(del + 5, fresp + 4 + f * 16, 16);
			app_cmd(s, del, sizeof(del), oresp, sizeof(oresp), &n);
		}
		if (have_child) {
			uint8_t del[21] = { 0xa3, 0x03, 0x00, 0x00, 0x00 };
			memcpy(del + 5, child_ref, 16);
			app_cmd(s, del, sizeof(del), oresp, sizeof(oresp), &n);
		}
		uint8_t del_u[21] = { 0xa3, 0x02, 0x00, 0x00, 0x00 };
		memcpy(del_u + 5, uguids[u], 16);
		app_cmd(s, del_u, sizeof(del_u), oresp, sizeof(oresp), &n);
	}
	return 0;
}
