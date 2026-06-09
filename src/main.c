#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "cmd.h"
#include "crypto.h"
#include "device.h"
#include "pair.h"
#include "parser.h"
#include "proto.h"
#include "storage.h"
#include "tls.h"
#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Default to the user's target sensor when no vid/pid is given. */
#define DEFAULT_VID 0x06cb
#define DEFAULT_PID 0x00e7

/* TLS transport adapter on top of fp_bulk_send/recv. */
static int live_xport_send(void *ctx, const void *buf, int len)
{
	struct fp_device *dev = ctx;
	/* Log full outgoing bytes to a file for offline diff against the
	 * synaTudor reference trace. */
	static int seq = 0;
	char path[64]; snprintf(path, sizeof(path), "/tmp/fpdrv-tls-out-%d.bin", seq++);
	FILE *f = fopen(path, "wb"); if (f) { fwrite(buf, 1, len, f); fclose(f); }
	printf("[XPORT-OUT %d B → %s]\n", len, path);
	int sent = 0;
	int rc = fp_bulk_send(dev, buf, len, &sent);
	if (rc != 0) {
		fprintf(stderr, "live xport send: %s\n", libusb_error_name(rc));
		return -1;
	}
	return sent;
}

static int live_xport_recv(void *ctx, void *buf, int cap)
{
	struct fp_device *dev = ctx;
	int got = 0;
	int rc = fp_bulk_recv(dev, buf, cap, &got);
	if (rc != 0) {
		fprintf(stderr, "live xport recv: %s\n", libusb_error_name(rc));
		return -1;
	}
	static int seq = 0;
	char path[64]; snprintf(path, sizeof(path), "/tmp/fpdrv-tls-in-%d.bin", seq++);
	FILE *f = fopen(path, "wb"); if (f) { fwrite(buf, 1, got, f); fclose(f); }
	printf("[XPORT-IN  %d B → %s]: ", got, path);
	int show = got > 64 ? 64 : got;
	for (int i = 0; i < show; i++) printf("%02x", ((const uint8_t*)buf)[i]);
	if (got > 64) printf("...");
	printf("\n");
	return got;
}

/* Verbatim 401-byte 0x93 from captures/clean-install-capture.pcapng frame
 * 252.  Replaying these exact bytes should put the sensor into the same
 * post-0x93 state Windows had at that moment.  Per protocol-notes the
 * sensor's response is byte-deterministic for given request bytes. */
static const uint8_t CLEAN_PAIR_REQ[401] = {
	0x93, 0x3f, 0x5f, 0x17, 0x00, 0xfb, 0xbf, 0xb8, 0x42, 0x47, 0xf9, 0x1e,
	0x8f, 0xbf, 0x8a, 0x68, 0x0d, 0x19, 0xf3, 0x12, 0x0f, 0x13, 0x5e, 0xfe,
	0x01, 0xf8, 0xed, 0x8b, 0xe3, 0x9b, 0x2f, 0xb3, 0x8f, 0xc7, 0x5e, 0x2e,
	0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x2f, 0xde, 0xe7, 0x16, 0x74, 0xed, 0x39, 0x59, 0x6e, 0xb4, 0x14,
	0xe7, 0x01, 0xb3, 0x05, 0x14, 0x9d, 0x00, 0x79, 0xc9, 0x07, 0xa4, 0xfe,
	0x35, 0x3d, 0xda, 0x4f, 0x2b, 0x55, 0x60, 0x86, 0x11, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
	0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xa3, 0x99, 0x9c, 0xf3, 0x50, 0x34,
	0x42, 0x67, 0xd4, 0x9d, 0xbc, 0x6a, 0xd3, 0xcf, 0xf0, 0x95, 0xa1, 0x7e,
	0xd7, 0xe8, 0xce, 0xeb, 0x3a, 0x43, 0x43, 0x34, 0x84, 0x8c, 0x2b, 0x8c,
	0xad, 0x48, 0x02, 0x21, 0x00, 0xc8, 0xd2, 0x7e, 0x67, 0xf9, 0x5e, 0x03,
	0x0e, 0xcf, 0x8e, 0x5c, 0x74, 0x78, 0xeb, 0xf9, 0xbb, 0xb9, 0xe7, 0xfd,
	0x80, 0x24, 0xf8, 0x4d, 0xd0, 0x39, 0xca, 0xd9, 0x02, 0x12, 0x17, 0x31,
	0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
};

/* db2_mode: 0 = full enroll; 1 = walk db2 then exit (read-only);
 * 2 = walk db2, DELETE every user object (+ its child-ref), then exit;
 * 3 = capture one frame and misIdentifyMatch (0x99) against stored templates. */
static int cmd_pair_live(struct fp_device *dev, int db2_mode)
{
	printf("pair-live: loading persisted pair-data...\n");
	struct fp_pairdata pd;
	if (fp_storage_load(&pd, NULL) != 0) {
		fprintf(stderr, "no pair-data; run `fpdrv pair-init` first\n");
		return 1;
	}
	printf("pair-live: host identity pub X[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", pd.host_pub_xy[i]);
	printf("\n");

	/* 2026-05-24: dual-key model confirmed by RE of synaWudfBioUsb111.dll
	 * `_tudorSecuritySignHPubK` (fcn.180087800) → `palGenHSPrivKey`
	 * (fcn.180069e20) → `palSymKeyGen("HS_KEY_PAIR_GEN", ...)`:
	 *
	 *   - The 0x93 signature is produced by a DETERMINISTIC, driver-wide
	 *     priv key that palSymKeyGen always returns for the
	 *     "HS_KEY_PAIR_GEN" label.  Value from libtudor trace:
	 *     `e8a2a2b6656254d6acb0ef479cae4140c7e8e260db3f642e35d4099c01b36a86`
	 *     (KEY2_PRIV).  Verified 2026-05-24: the captured clean-install
	 *     Windows 0x93 signature verifies against the corresponding
	 *     KEY2_PUB (X=89e54130..., Y=eb05008f...) for SHA-256(req[1..143]).
	 *     Sensor firmware has KEY2_PUB hardcoded — only KEY2-signed
	 *     0x93 requests pass.
	 *
	 *   - hash1/hash2 in 0x93 carry the host's PERSISTENT identity pub
	 *     (unique per pair).  Sensor stores it after a successful pair
	 *     and uses it later to verify the TLS CertificateVerify.
	 *
	 *   - Sensor's static ECDH pub is in the 0x93 response: X at offset
	 *     406 LE, Y at 474 LE.  Both try-6 and clean-install captures
	 *     return the same `f298486128b3a96d...` — per-device constant.
	 *
	 *   - No PSK transmission: cipher 0xc02e takes ECDH shared as PMS
	 *     directly (verified from libtudor BCryptDeriveKey trace).
	 *
	 * Implementation: KEY2_PRIV signs 0x93; pd.host_pub_xy goes into
	 * hash1/hash2 and the TLS cert; pd.host_priv signs CertVerify. */
	static const uint8_t KEY2_PRIV_BE[32] = {
		0xe8, 0xa2, 0xa2, 0xb6, 0x65, 0x62, 0x54, 0xd6,
		0xac, 0xb0, 0xef, 0x47, 0x9c, 0xae, 0x41, 0x40,
		0xc7, 0xe8, 0xe2, 0x60, 0xdb, 0x3f, 0x64, 0x2e,
		0x35, 0xd4, 0x09, 0x9c, 0x01, 0xb3, 0x6a, 0x86,
	};

	/* 2026-05-25: Windows USB capture (all-messages-capture.pcapng frames
	 * 124-128) shows the driver issues CLEAR_FEATURE(ENDPOINT_HALT) on
	 * all 3 endpoints (0x01, 0x81, 0x83) right before bulk pair flow
	 * starts.  Mimic to ensure sensor enters the same state. */
	(void)fp_clear_halt(dev, 0x01);
	(void)fp_clear_halt(dev, 0x81);
	(void)fp_clear_halt(dev, 0x83);
	printf("pair-live: cleared HALT on EP 0x01, 0x81, 0x83\n");

	printf("\npair-live: running Phase 1 init queries (pass 1)...\n");
	int rc = fp_cmd_init_dump(dev);
	if (rc != 0) {
		fprintf(stderr, "Phase 1 pass 1 failed: %s\n", libusb_error_name(rc));
		return 1;
	}

	/* DISCOVERED 2026-05-21 from try-6 capture and libtudor trace: BOTH
	 * captures run the init queries TWICE before 0x3f02/0x93. The SECOND
	 * pass omits CAPABILITIES (0x3e) and GET_CERTIFICATE_EX (0x40) — only
	 * the 6 basic queries (0x01, 8e/09, 8e/1a, 8e/2f, af/01, 0x19). */
	printf("\npair-live: running basic init queries (pass 2)...\n");
	rc = fp_cmd_init_basic(dev);
	if (rc != 0) {
		fprintf(stderr, "Phase 1 pass 2 failed: %s\n", libusb_error_name(rc));
		return 1;
	}

	printf("\npair-live: sending 0x3f 02 (pair-begin)...\n");
	if (fp_pair_begin(dev) != 0) {
		fprintf(stderr, "pair_begin failed\n");
		return 1;
	}

	/* Construct 0x93 payload using OUR keys as the host identity.
	 *
	 * Per static analysis of `_tudorSecurityPreparePairingParams` + python-validity's
	 * `init_flash.make_cert()` analog, the protocol stores X and Y in
	 * LITTLE-ENDIAN byte order. Our stored pubkey is BE (OpenSSL convention),
	 * so we byte-reverse each 32-byte half before sending.
	 *
	 *   hash1 = host pubkey X bytes in LE order (32 B)
	 *   hash2 = host pubkey Y bytes in LE order (32 B)
	 *   token = 3f 5f 17 00 (factory constant the sensor expects)
	 *   signature = ECDSA(host_priv, SHA-256(wire[1..143]))
	 *                where wire[1..143] = token + hash1 + 36pad + hash2 + 36pad + 00 00 */
	uint8_t token[4] = { 0x3f, 0x5f, 0x17, 0x00 };

	/* hash1 = host pub X in LE, hash2 = host pub Y in LE (our stored pub
	 * is BE; reverse each 32-byte half).  Same key is used here AND in
	 * the TLS cert below. */
	uint8_t hash1[32], hash2[32];
	for (int i = 0; i < 32; i++) {
		hash1[i] = pd.host_pub_xy[31 - i];
		hash2[i] = pd.host_pub_xy[63 - i];
	}

	printf("\npair-live: sending 0x93 with our identity...\n");
	printf("  token: ");
	for (int i = 0; i < 4; i++) printf("%02x", token[i]);
	printf("\n  hash1 (host pub X_LE): ");
	for (int i = 0; i < 16; i++) printf("%02x", hash1[i]);
	printf("...\n  hash2 (host pub Y_LE): ");
	for (int i = 0; i < 16; i++) printf("%02x", hash2[i]);
	printf("...\n");

	uint8_t resp[1024];
	int resp_len = 0;
	const char *replay = getenv("FPDRV_REPLAY");
	if (replay && replay[0] == '1') {
		printf("pair-live: REPLAY MODE — sending captured clean-install 0x93\n");
		rc = fp_bulk_send(dev, CLEAN_PAIR_REQ, sizeof(CLEAN_PAIR_REQ), NULL);
		if (rc != 0) {
			fprintf(stderr, "pair_request replay send failed: %s\n", libusb_error_name(rc));
			return 1;
		}
		/* Read the multi-part response */
		while (resp_len < (int)sizeof(resp)) {
			int got = 0;
			rc = fp_bulk_recv(dev, resp + resp_len, sizeof(resp) - resp_len, &got);
			if (rc == LIBUSB_ERROR_TIMEOUT) { rc = 0; break; }
			if (rc != 0) break;
			resp_len += got;
			if (got < 16) break;
		}
		/* Replace hash1/hash2 buffers with Windows captured host pub
		 * (LE bytes), so the cert we build later matches what the sensor
		 * just stored from the replayed 0x93. */
		memcpy(hash1, CLEAN_PAIR_REQ + 5,  32);   /* X_LE from req */
		memcpy(hash2, CLEAN_PAIR_REQ + 73, 32);   /* Y_LE from req */
	} else {
		rc = fp_pair_request(dev, KEY2_PRIV_BE, token, hash1, hash2,
		                     resp, sizeof(resp), &resp_len);
	}
	if (rc != 0) {
		fprintf(stderr, "pair_request transport failed: rc=%d\n", rc);
		return 1;
	}

	printf("\nSensor response (%d B):\n", resp_len);
	int show = resp_len > 64 ? 64 : resp_len;
	printf("  first %d B: ", show);
	for (int i = 0; i < show; i++) printf("%02x", resp[i]);
	printf("\n");

	if (resp_len >= 2) {
		uint16_t status = (uint16_t)(resp[0] | (resp[1] << 8));
		if (status == 0x0000) {
			printf("\n  *** status 0x0000 — SENSOR ACCEPTED THE PAIR REQUEST ***\n");
			printf("  Response length %d (expected ~802 for success, smaller for some failures)\n", resp_len);

			/* Save response so we can offline-decode sensor's identity. */
			FILE *rf = fopen("/tmp/pair-live-response.bin", "wb");
			if (rf) { fwrite(resp, 1, resp_len, rf); fclose(rf);
			          printf("  wrote response to /tmp/pair-live-response.bin\n"); }

			/* Phase 3: continue with TLS handshake on the same open device
			 * session, while the sensor is still in post-pair state. */
			printf("\n=== Phase 3: TLS handshake ===\n");

			/* 2026-05-25: confirmed from captures/all-messages-capture.pcapng
			 * frame 170: Windows DOES send vendor IN 0xc0/0x14 wValue=0
			 * wIndex=0 wLength=2 to read 2 bytes ("Get TLS status").
			 * Our prior tries with wLength=1 stalled. */
			{
				uint8_t tls_status[2] = {0xff, 0xff};
				int n = fp_control_transfer(dev,
					0xc0, 0x14, 0x0000, 0x0000,
					tls_status, 2, 1000);
				printf("  vendor IN 0xc0/0x14 (wLen=2): rc=%d bytes=%02x %02x\n",
					n, tls_status[0], tls_status[1]);
			}

			/* Build the 400-byte host cert blob (Synaptics 00e7 format):
			 *   [0..3]    token (4 B)
			 *   [4..35]   host pub X in LE
			 *   [36..71]  36 zero pad
			 *   [72..103] host pub Y in LE
			 *   [104..139] 36 zero pad
			 *   [140..143] TLV: type=2 len=32 BE (`00 02 20 00`)
			 *   [144..175] type-2 field — echoed back from the pair response
			 *   [176..399] zero pad */
			uint8_t cert_blob[400];
			memset(cert_blob, 0, sizeof(cert_blob));
			memcpy(cert_blob + 0,   token, 4);
			memcpy(cert_blob + 4,   hash1, 32);    /* host X_LE */
			memcpy(cert_blob + 72,  hash2, 32);    /* host Y_LE */
			cert_blob[140] = 0x00;
			cert_blob[141] = 0x02;
			cert_blob[142] = 0x20;
			cert_blob[143] = 0x00;
			if (resp_len >= 178)
				memcpy(cert_blob + 144, resp + 146, 32);

			/* Extract the sensor's static ECDH pubkey from the pair
			 * response. Layout (verified 2026-05-24 from both try-6 and
			 * clean-install captures, identical values both times):
			 *   resp[406..437]  sensor pub X in LE
			 *   resp[474..505]  sensor pub Y in LE
			 * Reverse each 32-byte half to BE for our crypto layer. */
			uint8_t sensor_pub_xy[64];
			if (resp_len < 506) {
				fprintf(stderr, "pair response too short (%d B) to carry sensor pub\n", resp_len);
				return 1;
			}
			for (int i = 0; i < 32; i++) {
				sensor_pub_xy[i]      = resp[406 + 31 - i];  /* X_BE */
				sensor_pub_xy[32 + i] = resp[474 + 31 - i];  /* Y_BE */
			}
			printf("  sensor pub X (BE): ");
			for (int i = 0; i < 16; i++) printf("%02x", sensor_pub_xy[i]);
			printf("...\n  sensor pub Y (BE): ");
			for (int i = 32; i < 32 + 16; i++) printf("%02x", sensor_pub_xy[i]);
			printf("...\n");

			struct fp_tls_state st;
			if (fp_tls_state_init(&st) != 0) {
				fprintf(stderr, "fp_tls_state_init failed\n");
				return 1;
			}

			/* PSK is ignored by fp_tls_derive_session_keys (verified from
			 * libtudor BCryptDeriveKey trace 2026-05-19: cipher 0xc02e
			 * derives master_secret from the pure ECDH shared, no PSK
			 * mixed in). Pass pd.psk as a placeholder. */
			struct fp_tls_handshake_inputs in = {
				.cert_blob     = cert_blob,
				.cert_blob_len = sizeof(cert_blob),
				.priv_d        = pd.host_priv,
				.psk           = pd.psk,
				.psk_len       = FP_PSK_LEN,
				.sensor_pub_xy = sensor_pub_xy,
				.eph_priv      = NULL,
				.eph_pub_out   = NULL,
			};
			struct fp_tls_transport xport = {
				.send = live_xport_send,
				.recv = live_xport_recv,
				.ctx  = dev,
			};
			int tls_rc = fp_tls_open(&st, &in, &xport);
			printf("\nfp_tls_open returned %d  (secure_tx=%d secure_rx=%d)\n",
				tls_rc, st.secure_tx, st.secure_rx);

			if (tls_rc == 0) {
				printf("\n=== Phase 4: secure smoke test (GET_VERSION over TLS) ===\n");
				uint8_t cmd = 0x01;
				uint8_t resp[256];
				int rlen = fp_tls_app_send_recv(&st, &xport, &cmd, 1,
				                                resp, sizeof(resp));
				if (rlen < 0) {
					printf("  smoke test FAILED (rlen=%d)\n", rlen);
				} else {
					printf("  decrypted response (%d B):\n    ", rlen);
					int show = rlen > 64 ? 64 : rlen;
					for (int i = 0; i < show; i++) printf("%02x", resp[i]);
					if (rlen > 64) printf("...");
					printf("\n");
					if (rlen >= 2) {
						unsigned status = resp[0] | (resp[1] << 8);
						printf("  VCSFW status: 0x%04x %s\n", status,
						       status == 0 ? "(OK)" : "(non-zero)");
					}
				}

				printf("\n=== Phase 4b: storage_info_get (0x3e) over TLS ===\n");
				uint8_t si_cmd = 0x3e;
				rlen = fp_tls_app_send_recv(&st, &xport, &si_cmd, 1,
				                            resp, sizeof(resp));
				if (rlen < 0) {
					printf("  0x3e FAILED (rlen=%d)\n", rlen);
				} else {
					unsigned status = (rlen >= 2) ? (resp[0] | (resp[1] << 8)) : 0xffff;
					printf("  resp len=%d status=0x%04x %s\n", rlen, status,
					       status == 0 ? "(OK)" : "(non-zero)");
					if (rlen >= 16) {
						unsigned num_sths = resp[14] | (resp[15] << 8);
						printf("  num sths (proto.txt offset 0xe..0xf): %u\n", num_sths);
					}
					printf("    first %d B: ", rlen > 64 ? 64 : rlen);
					int show = rlen > 64 ? 64 : rlen;
					for (int i = 0; i < show; i++) printf("%02x", resp[i]);
					if (rlen > 64) printf("...");
					printf("\n");
				}

				printf("\n=== Phase 5: frame_state_get (0x82) over TLS ===\n");
				/* proto.txt: req[0]=0x82, [1..6]=0, [7]=2, [8]=7. */
				uint8_t fs_cmd[9] = { 0x82, 0, 0, 0, 0, 0, 0, 0x02, 0x07 };
				rlen = fp_tls_app_send_recv(&st, &xport, fs_cmd, sizeof(fs_cmd),
				                            resp, sizeof(resp));
				if (rlen < 0) {
					printf("  0x82 FAILED (rlen=%d)\n", rlen);
				} else {
					printf("  decrypted response (%d B):\n    ", rlen);
					int show = rlen > 64 ? 64 : rlen;
					for (int i = 0; i < show; i++) printf("%02x", resp[i]);
					if (rlen > 64) printf("...");
					printf("\n");
					if (rlen >= 2) {
						unsigned status = resp[0] | (resp[1] << 8);
						printf("  VCSFW status: 0x%04x %s\n", status,
						       status == 0 ? "(OK)" : "(non-zero)");
					}
					if (rlen >= 32) {
						/* Dimensions block starts at resp[14], each field
						 * is a little-endian u16. */
						const uint8_t *d = resp + 14;
						#define RD16(p) ((unsigned)((p)[0] | ((p)[1] << 8)))
						printf("  pixel bits        : %u\n", RD16(d + 0));
						printf("  width             : %u\n", RD16(d + 2));
						printf("  frame header size : %u\n", RD16(d + 4));
						printf("  x offset          : %u\n", RD16(d + 6));
						printf("  x size            : %u\n", RD16(d + 8));
						printf("  height            : %u\n", RD16(d + 10));
						printf("  column header size: %u\n", RD16(d + 12));
						printf("  y offset          : %u\n", RD16(d + 14));
						printf("  y size            : %u\n", RD16(d + 16));
						#undef RD16
					}
				}

				printf("\n=== Phase 5b: read 3 init-time IOTAs over TLS (0x1a, 0x2e, 0x2f) ===\n");
				{
					uint16_t iota_ids[3] = { 0x001a, 0x002e, 0x002f };
					for (int ii = 0; ii < 3; ii++) {
						uint8_t io_cmd[17];
						memset(io_cmd, 0, sizeof(io_cmd));
						io_cmd[0] = 0x8e;
						io_cmd[1] = (uint8_t)(iota_ids[ii] & 0xff);
						io_cmd[2] = (uint8_t)((iota_ids[ii] >> 8) & 0xff);
						io_cmd[3] = 0x02;   /* flags = 2 per proto.txt */
						/* bytes 5-8: 0 (zero region) */
						/* bytes 9-12: offset = 0 */
						/* bytes 13-16: unknown, leave 0 */
						static uint8_t io_resp[16384];
						int n = fp_tls_app_send_recv(&st, &xport,
						          io_cmd, sizeof(io_cmd),
						          io_resp, sizeof(io_resp));
						if (n < 0) {
							printf("  iota 0x%02x FAILED (n=%d)\n", iota_ids[ii], n);
							continue;
						}
						unsigned status = (n >= 2) ? (io_resp[0] | (io_resp[1] << 8)) : 0xffff;
						unsigned size = (n >= 6) ? (io_resp[2] | (io_resp[3] << 8)
						                          | (io_resp[4] << 16) | (io_resp[5] << 24))
						                         : 0;
						printf("  iota 0x%02x: resp len=%d status=0x%04x iota_size=%u\n",
						       iota_ids[ii], n, status, size);
						if (n > 6) {
							printf("    first 32 B: ");
							int show = (n - 6) > 32 ? 32 : (n - 6);
							for (int j = 0; j < show; j++) printf("%02x", io_resp[6 + j]);
							printf("\n");
						}
					}
				}

				printf("\n=== Phase 6: DB2 on-chip template database walk ===\n");
				static uint8_t db_resp[4096];
				/* Proper hierarchical enumeration, mirroring v7 trace recs 291-299:
				 *   9e 01                     -> db info (object counts)
				 *   9f 02 00000000 ff*16      -> list USER object GUIDs
				 *   9f 03 00000000 <userGUID> -> list FINGER GUIDs under a user
				 *   a1 03 00000000 <fingGUID> -> finger object data (stored template
				 *                                metadata incl. the owning SID)
				 * Goal: see whether the Windows enrollment is still resident on the
				 * sensor (would make our enroll a DUPLICATE -> commit 0x06db). */
				{
					uint8_t info_cmd[2] = { 0x9e, 0x01 };
					rlen = fp_tls_app_send_recv(&st, &xport, info_cmd, sizeof(info_cmd),
					                            db_resp, sizeof(db_resp));
					unsigned status = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : 0xffff;
					printf("  db2_dbinfo (9e 01): len=%d status=0x%04x  payload: ", rlen, status);
					for (int i = 0; i < rlen && i < 40; i++) printf("%02x", db_resp[i]);
					printf("\n");

					/* List user objects: parent id = all-0xFF. */
					uint8_t list_users[21] = { 0x9f, 0x02, 0x00, 0x00, 0x00 };
					memset(list_users + 5, 0xff, 16);
					rlen = fp_tls_app_send_recv(&st, &xport, list_users, sizeof(list_users),
					                            db_resp, sizeof(db_resp));
					status = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : 0xffff;
					unsigned ucount = (rlen >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0;
					printf("  db2 list users (9f 02): len=%d status=0x%04x  user_count=%u\n",
					       rlen, status, ucount);
					if (status == 0 && ucount == 0)
						printf("    -> NO users enrolled: sensor db2 is EMPTY. Duplicate theory KILLED.\n");
					for (unsigned u = 0; u < ucount && (int)(4 + (u + 1) * 16) <= rlen; u++) {
						uint8_t uguid[16];
						memcpy(uguid, db_resp + 4 + u * 16, 16);
						printf("    USER[%u] guid=", u);
						for (int i = 0; i < 16; i++) printf("%02x", uguid[i]);
						printf("\n");
						/* Dump this user object's stored data (a0 02 = objinfo,
						 * a1 02 = objdata). The objdata carries the identity blob
						 * (Windows SID if it came from our commit). */
						uint8_t child_ref[16];
						int have_child = 0;
						{
							uint8_t oresp[1024];
							uint8_t oi[21] = { 0xa0, 0x02, 0x00, 0x00, 0x00 };
							memcpy(oi + 5, uguid, 16);
							int on = fp_tls_app_send_recv(&st, &xport, oi, sizeof(oi),
							                              oresp, sizeof(oresp));
							printf("      objinfo (a0 02): len=%d  ", on);
							for (int i = 0; i < on && i < 56; i++) printf("%02x", oresp[i]);
							printf("\n");
							/* objinfo layout: [0:2]status [2:4]pad [4:20]parent
							 * [20:36]child-ref. Grab the child-ref so we can purge
							 * the dangling finger object the failed commits left. */
							if (on >= 36) { memcpy(child_ref, oresp + 20, 16); have_child = 1; }
							uint8_t od[21] = { 0xa1, 0x02, 0x00, 0x00, 0x00 };
							memcpy(od + 5, uguid, 16);
							int dn = fp_tls_app_send_recv(&st, &xport, od, sizeof(od),
							                              oresp, sizeof(oresp));
							printf("      objdata (a1 02): len=%d  ", dn);
							for (int i = 0; i < dn && i < 128; i++) printf("%02x", oresp[i]);
							if (dn > 128) printf("...");
							printf("\n");
						}
						/* List fingers under this user. */
						uint8_t list_f[21] = { 0x9f, 0x03, 0x00, 0x00, 0x00 };
						memcpy(list_f + 5, uguid, 16);
						uint8_t fresp[1024];
						int fn = fp_tls_app_send_recv(&st, &xport, list_f, sizeof(list_f),
						                              fresp, sizeof(fresp));
						unsigned fstat = (fn >= 2) ? (fresp[0] | (fresp[1] << 8)) : 0xffff;
						unsigned fcount = (fn >= 4) ? (fresp[2] | (fresp[3] << 8)) : 0;
						printf("      fingers (9f 03): len=%d status=0x%04x finger_count=%u\n",
						       fn, fstat, fcount);
						for (unsigned f = 0; f < fcount && (int)(4 + (f + 1) * 16) <= fn; f++) {
							uint8_t fg[16];
							memcpy(fg, fresp + 4 + f * 16, 16);
							printf("      FINGER[%u] guid=", f);
							for (int i = 0; i < 16; i++) printf("%02x", fg[i]);
							printf("\n");
							if (db2_mode == 2) {
								uint8_t del[21] = { 0xa3, 0x03, 0x00, 0x00, 0x00 };
								memcpy(del + 5, fg, 16);
								uint8_t dr[64];
								int drn = fp_tls_app_send_recv(&st, &xport, del, sizeof(del),
								                               dr, sizeof(dr));
								int ds = (drn >= 2) ? (dr[0] | (dr[1] << 8)) : -1;
								printf("        -> delete finger (a3 03): status=0x%04x\n", ds);
							}
						}

						if (db2_mode == 2) {
							/* Purge the dangling child-ref (finger object the failed
							 * commits half-wrote) first, then the user object. */
							if (have_child) {
								uint8_t del[21] = { 0xa3, 0x03, 0x00, 0x00, 0x00 };
								memcpy(del + 5, child_ref, 16);
								uint8_t dr[64];
								int drn = fp_tls_app_send_recv(&st, &xport, del, sizeof(del),
								                               dr, sizeof(dr));
								int ds = (drn >= 2) ? (dr[0] | (dr[1] << 8)) : -1;
								printf("      -> delete child-ref (a3 03): status=0x%04x\n", ds);
							}
							uint8_t del[21] = { 0xa3, 0x02, 0x00, 0x00, 0x00 };
							memcpy(del + 5, uguid, 16);
							uint8_t dr[64];
							int drn = fp_tls_app_send_recv(&st, &xport, del, sizeof(del),
							                               dr, sizeof(dr));
							int ds = (drn >= 2) ? (dr[0] | (dr[1] << 8)) : -1;
							printf("      -> delete user (a3 02): status=0x%04x\n", ds);
						}
					}

					if (db2_mode == 2) {
						/* Re-list to confirm the db2 is now empty. */
						uint8_t relist[21] = { 0x9f, 0x02, 0x00, 0x00, 0x00 };
						memset(relist + 5, 0xff, 16);
						int rn = fp_tls_app_send_recv(&st, &xport, relist, sizeof(relist),
						                              db_resp, sizeof(db_resp));
						unsigned rs = (rn >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : 0xffff;
						unsigned rc2 = (rn >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0;
						printf("  db2 re-list after delete: status=0x%04x user_count=%u %s\n",
						       rs, rc2, (rs == 0 && rc2 == 0) ? "(EMPTY)" : "");
					}
				}

				if (db2_mode == 3) {
					/* Identify: capture ONE frame (same FRAME_ACQ sequence as a
					 * single enroll sample) then misIdentifyMatch (0x99). The
					 * sensor matches the captured image against its stored
					 * templates on-chip and returns the matched template GUID +
					 * finger subfactor. No host-side template data needed. */
					printf("\n=== Identify: capture one frame, match on-chip ===\n");
					/* Prime imageMetrics, mirroring init/enroll Step 1b. */
					{
						uint8_t im_cmd[5] = { 0x9d, 0x00, 0x00, 0x01, 0x00 };
						fp_tls_app_send_recv(&st, &xport, im_cmd, sizeof(im_cmd),
						                     db_resp, sizeof(db_resp));
					}
					unsigned ev_seq = 0;
					uint16_t evc = 0;
					#define IEVCFG(m, fl) do { \
						uint8_t _ec[37]; memset(_ec, 0, sizeof(_ec)); _ec[0] = 0x86; \
						_ec[1]  = (uint8_t)(m);  _ec[4]  = (uint8_t)(fl); \
						_ec[17] = (uint8_t)(m);  _ec[20] = (uint8_t)(fl); \
						if ((m) == 0 && (fl) == 0) _ec[33] = 0x04; \
						int _cn = fp_tls_app_send_recv(&st, &xport, _ec, sizeof(_ec), \
						                     db_resp, sizeof(db_resp)); \
						if (_cn >= 66) ev_seq = db_resp[64] | (db_resp[65] << 8); \
					} while (0)
					#define IEVRD_WAIT(codevar, ms) do { \
						(codevar) = 0; \
						int _iters = (ms) / 50; if (_iters < 1) _iters = 1; \
						for (int _w = 0; _w < _iters; _w++) { \
							uint8_t _er[9] = {0x87, 0,0, 0x20,0x00, 0x01,0x00,0x00,0x00}; \
							_er[1] = (uint8_t)(evc & 0xff); _er[2] = (uint8_t)(evc >> 8); \
							int _n = fp_tls_app_send_recv(&st, &xport, _er, sizeof(_er), \
							                              db_resp, sizeof(db_resp)); \
							unsigned _ne = (_n >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0; \
							if (_ne > 0) { \
								(codevar) = (_n >= 7) ? db_resp[6] : 0; \
								evc = (uint16_t)(evc + _ne); \
								break; \
							} \
							usleep(50 * 1000); \
						} \
					} while (0)

					IEVCFG(0x00, 0x00);
					evc = (uint16_t)ev_seq;
					printf("  Touch the sensor once with an enrolled finger.\n");

					unsigned code;
					IEVCFG(0x06, 0x00);
					{
						uint8_t evb[8]; int got = 0;
						fp_intr_recv(dev, evb, sizeof(evb), &got, 5000);
					}
					IEVRD_WAIT(code, 8000);
					IEVCFG(0x00, 0x00);
					if (code == 0) {
						printf("  no finger detected — aborting identify\n");
						return 1;
					}
					IEVCFG(0x04, 0x00);
					IEVRD_WAIT(code, 3000);
					IEVCFG(0x00, 0x00);
					IEVCFG(0x00, 0x01);
					{
						uint8_t acq[17] = {
							0x80, 0x0c, 0x00, 0x00, 0x00,
							0x01, 0x00, 0x00, 0x00,
							0x01, 0x00, 0x00,
							0x08, 0x01, 0x01, 0x01, 0x00
						};
						int an = fp_tls_app_send_recv(&st, &xport, acq, sizeof(acq),
						                              db_resp, sizeof(db_resp));
						int astat = (an >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						IEVRD_WAIT(code, 3000);
						printf("  FRAME_ACQ status=0x%04x frame-evt code=0x%02x%s\n",
						       astat, code, code == 0x18 ? " (CAPTURED)" : "");
					}
					IEVCFG(0x00, 0x00);
					{
						uint8_t flush = 0x81;
						fp_tls_app_send_recv(&st, &xport, &flush, 1,
						                     db_resp, sizeof(db_resp));
					}

					/* misIdentifyMatch (0x99 sub1 + 11 zeros), as the enroll
					 * trace's pre-enroll probe (rec 51). On an empty db2 it
					 * returned 0x0509 (not enrolled); with a finger enrolled a
					 * match should return 0x0000 and carry the template GUID. */
					uint8_t id_cmd[13] = { 0x99, 0x01, 0,0,0, 0,0,0,0, 0,0,0,0 };
					int idn = fp_tls_app_send_recv(&st, &xport, id_cmd, sizeof(id_cmd),
					                               db_resp, sizeof(db_resp));
					int idstat = (idn >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  misIdentifyMatch (0x99): len=%d status=0x%04x %s\n",
					       idn, idstat, fp_status_is_ok(idstat) ? "(MATCH/OK)" : "(no match / err)");
					printf("    full response: ");
					for (int i = 0; i < idn; i++) printf("%02x", db_resp[i]);
					printf("\n");
					if (fp_status_is_ok(idstat) && idn >= 18) {
						printf("    matched GUID (resp[2:18]): ");
						for (int i = 2; i < 18; i++) printf("%02x", db_resp[i]);
						printf("\n");
					} else if (idstat == 0x0509) {
						printf("    -> 0x0509: captured finger does NOT match any enrolled template\n");
					}
					#undef IEVCFG
					#undef IEVRD_WAIT
					return 0;
				}

				if (db2_mode == 1 || db2_mode == 2) {
					printf("\n(db2 %s mode: stopping before enrollment)\n",
					       db2_mode == 2 ? "delete" : "list");
					return 0;
				}

				printf("\n=== Phase 7: event-driven enrollment ===\n");
				/* Ground truth (all-messages-capture.pcapng): a real Windows
				 * enroll does ~97 EVENT_CONFIG (0x86) round-trips over ~80s, so
				 * events ARE central to enroll — the earlier "Windows sends no
				 * events" reading was an artifact of the request-only DLL trace
				 * (EVENT_CONFIG goes through the unhooked vfmDeviceEventConfigure
				 * site, so it never appeared in enroll_trace.bin).
				 *
				 * Open question driving this experiment: every event run so far
				 * has subscribed ONLY to mask 0x06 = (1<<FINGER_PRESS=1) |
				 * (1<<FINGER_REMOVE=2). python-validity waits for a *capture
				 * complete* event (its type 3, b[2]&4) before consuming the
				 * image. If the sensor filters reported events by the subscribed
				 * mask, a capture-complete event could be firing every touch and
				 * we'd never see it — which would explain why AddImage always
				 * gets 0x050b "no image yet".
				 *
				 * So the mask is now overridable: FPDRV_EVENT_MASK (hex/dec).
				 * Run the probe with FPDRV_EVENT_MASK=0xffffffff to subscribe to
				 * everything and log which event TYPES the sensor actually emits.
				 * EVENT_CONFIG req=37 B plaintext -> 66 B on-wire, matching the
				 * capture's 66-B EVENT_CONFIG requests, so the format is right.
				 *
				 * SUCCESS_STATUS = {0, 0x412, 0x5cc} — fp_status_is_ok. */
				/* The mask is a 256-bit bitmap, one bit per event TYPE
				 * (bit N => type N): 0x06 = bits 1,2 = FINGER_PRESS +
				 * FINGER_REMOVE, exactly the pair the sensor emits. So we
				 * write the value into dword[0] ONLY and leave dwords[1..7]
				 * zero — a wide low mask (e.g. 0xffff = types 0..15) is then a
				 * VALID subscription. The earlier 0xffffffff-in-all-8-dwords
				 * probe set reserved high bits and the sensor rejected it
				 * (0x064b). FPDRV_EVENT_MASK_ALL=1 restores the old layout. */
				uint32_t ev_mask = (1u << 1) | (1u << 2);
				int ev_mask_all = getenv("FPDRV_EVENT_MASK_ALL") != NULL;
				{
					const char *em = getenv("FPDRV_EVENT_MASK");
					if (em) ev_mask = (uint32_t)strtoul(em, NULL, 0);
				}
				if (getenv("FPDRV_ENROLL_EVENTS")) {
					uint8_t ec_cmd[37];
					memset(ec_cmd, 0, sizeof(ec_cmd));
					ec_cmd[0] = 0x86;
					uint32_t mask = ev_mask;
					int ndw = ev_mask_all ? 8 : 1;
					for (int k = 0; k < ndw; k++) {
						int off = 1 + k * 4;
						ec_cmd[off + 0] = (uint8_t)(mask & 0xff);
						ec_cmd[off + 1] = (uint8_t)((mask >> 8) & 0xff);
						ec_cmd[off + 2] = (uint8_t)((mask >> 16) & 0xff);
						ec_cmd[off + 3] = (uint8_t)((mask >> 24) & 0xff);
					}
					/* Trailer u32: per pydrv, 0 when mask != 0, else 4. Mask
					 * is non-zero, so leave trailer at 0. */
					int n = fp_tls_app_send_recv(&st, &xport, ec_cmd, sizeof(ec_cmd),
					                             db_resp, sizeof(db_resp));
					int ecstatus = (n >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  event_config(mask=0x%08x, dwords=%d): len=%d status=0x%04x %s\n",
					       mask, ndw, n, ecstatus,
					       fp_status_is_ok(ecstatus) ? "(OK)" : "(non-zero)");
					unsigned init_seq = 0;
					if (n >= 66) {
						init_seq = db_resp[64] | (db_resp[65] << 8);
						printf("  initial sensor event seq: 0x%04x\n", init_seq);
					}
				}

				/* Step 1: drain any stale session via misEnrollFinish.
				 * 0x0404 means "no session to finish" — clean idle state. */
				uint8_t fin_cmd[5] = { 0x96, 0x04, 0x00, 0x00, 0x00 };
				for (int it = 0; it < 4; it++) {
					rlen = fp_tls_app_send_recv(&st, &xport, fin_cmd, sizeof(fin_cmd),
					                            db_resp, sizeof(db_resp));
					unsigned s = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : 0xffff;
					printf("  [drain %d] misEnrollFinish: status=0x%04x\n", it, s);
					if (s == 0x0404) break;
					usleep(200 * 1000);
				}

				/* Step 1a: optional DB2_FORMAT (cmd 0xa5) — python-validity
				 * uses this to factory-reset the on-chip template DB. If our
				 * session has format privilege, this may put the sensor into
				 * a state where AddImage actually works for us. Gated by env
				 * var FPDRV_DB2_FORMAT=1 since it's destructive. */
				if (getenv("FPDRV_DB2_FORMAT")) {
					uint8_t fmt_cmd = 0xa5;
					rlen = fp_tls_app_send_recv(&st, &xport, &fmt_cmd, 1,
					                            db_resp, sizeof(db_resp));
					int s = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  [prime] DB2_FORMAT (0xa5): len=%d status=0x%04x %s\n",
					       rlen, s, fp_status_is_ok(s) ? "(OK)" : "(non-OK)");
				}

				/* Step 1b: priming commands that Windows sends BEFORE
				 * misEnrollStart (captured via DLL patch 2026-05-28). Without
				 * these, misEnrollAddImage returns 0x050b forever — the sensor
				 * isn't in a state to capture for enrollment yet.
				 *
				 * Order from the captured trace:
				 *   imageMetrics:        0x9d 0x00 0x00 0x01 0x00  (5 B)
				 *   misIdentifyMatchCmd: 0x99 0x01 + 11 B zeros    (13 B) */
				{
					uint8_t im_cmd[5] = { 0x9d, 0x00, 0x00, 0x01, 0x00 };
					rlen = fp_tls_app_send_recv(&st, &xport, im_cmd, sizeof(im_cmd),
					                            db_resp, sizeof(db_resp));
					int s = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  [prime] imageMetrics (0x9d/0x10000): len=%d status=0x%04x %s  raw: ",
					       rlen, s, fp_status_is_ok(s) ? "(OK)" : "(non-OK)");
					for (int j = 0; j < rlen && j < 48; j++) printf("%02x", db_resp[j]);
					printf("\n");
				}
				{
					uint8_t mi_cmd[13] = { 0x99, 0x01, 0,0,0, 0,0,0,0, 0,0,0,0 };
					rlen = fp_tls_app_send_recv(&st, &xport, mi_cmd, sizeof(mi_cmd),
					                            db_resp, sizeof(db_resp));
					int s = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  [prime] misIdentifyMatch (0x99 sub=1): len=%d status=0x%04x %s  raw: ",
					       rlen, s, fp_status_is_ok(s) ? "(OK)" : "(non-OK)");
					for (int j = 0; j < rlen && j < 48; j++) printf("%02x", db_resp[j]);
					printf("\n");
				}

				/* Step 2: misEnrollStart. The authoritative v7 plaintext
				 * trace (rec 53) starts enrollment with an ALL-ZERO body:
				 *   96 01 00 00 00 00 00 00 00 00 00 00 00
				 * A non-zero "tag" (byte[5]/byte[9]) still lets AddImage
				 * succeed but makes misEnrollCommit fail with 0x06db -
				 * that was the long-standing commit wall. Default = 0 to
				 * match Windows; FPDRV_ENROLL_TAG kept only for experiments. */
				uint8_t enroll_cmd[13];
				memset(enroll_cmd, 0, sizeof(enroll_cmd));
				enroll_cmd[0] = 0x96;
				enroll_cmd[1] = 1;
				const char *tag_env = getenv("FPDRV_ENROLL_TAG");
				uint32_t tag = tag_env ? (uint32_t)strtoul(tag_env, NULL, 0) : 0;
				if (tag != 0) {
					enroll_cmd[5] = 1;
					enroll_cmd[9]  = (uint8_t)(tag & 0xff);
					enroll_cmd[10] = (uint8_t)((tag >> 8) & 0xff);
					enroll_cmd[11] = (uint8_t)((tag >> 16) & 0xff);
					enroll_cmd[12] = (uint8_t)((tag >> 24) & 0xff);
				}
				printf("  misEnrollStart tag=%u cmd: ", tag);
				for (int i = 0; i < 13; i++) printf("%02x", enroll_cmd[i]);
				printf("\n");
				rlen = fp_tls_app_send_recv(&st, &xport, enroll_cmd, sizeof(enroll_cmd),
				                            db_resp, sizeof(db_resp));
				int start_status = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
				printf("  misEnrollStart: resp len=%d status=0x%04x %s  bytes: ",
				       rlen, start_status,
				       fp_status_is_ok(start_status) ? "(OK)" : "(non-zero)");
				for (int i = 0; i < rlen; i++) printf("%02x", db_resp[i]);
				printf("\n");

				if (!fp_status_is_ok(start_status)) {
					printf("  enrollment didn't start — skipping event loop\n");
				} else if (getenv("FPDRV_ENROLL_EVENTS")) {
					/* (FRAME_ACQ experiment 2026-05-26: cmd 0x80 with synaTudor's
					 * format returned status=0 but silenced all FINGER_PRESS event
					 * pushes — sensor flipped into capture-mode, incompatible
					 * with enroll-mode event subscription. Skipping.) */

					/* Re-issue EVENT_CONFIG after Start AND capture sensor's
					 * current seq number, so we start the loop with the right
					 * reference point. */
					unsigned post_start_seq = 0;
					{
						uint8_t ec2_cmd[37];
						memset(ec2_cmd, 0, sizeof(ec2_cmd));
						ec2_cmd[0] = 0x86;
						uint32_t mask2 = ev_mask;
						int ndw2 = ev_mask_all ? 8 : 1;
						for (int k = 0; k < ndw2; k++) {
							int off = 1 + k * 4;
							ec2_cmd[off + 0] = (uint8_t)(mask2 & 0xff);
							ec2_cmd[off + 1] = (uint8_t)((mask2 >> 8) & 0xff);
							ec2_cmd[off + 2] = (uint8_t)((mask2 >> 16) & 0xff);
							ec2_cmd[off + 3] = (uint8_t)((mask2 >> 24) & 0xff);
						}
						int ecn = fp_tls_app_send_recv(&st, &xport,
						             ec2_cmd, sizeof(ec2_cmd),
						             db_resp, sizeof(db_resp));
						int ec2_status = (ecn >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						if (ecn >= 66) {
							post_start_seq = db_resp[64] | (db_resp[65] << 8);
						}
						printf("  [post-Start re-EVENT_CONFIG] status=0x%04x seq=0x%04x\n",
						       ec2_status, post_start_seq);
					}

					/* Step 3: event-driven AddImage loop.
					 *
					 * Block on the interrupt EP. Sensor pushes 8 bytes when
					 * an event is queued (pydrv: byte 5 low 5 bits = seq num).
					 * On each push, drain via EVENT_READ (0x87), then for every
					 * FINGER_PRESS event, issue misEnrollAddImage. */
					const char *wait_env = getenv("FPDRV_CAPTURE_WAIT_MS");
					int wait_ms_total = wait_env ? atoi(wait_env) : 60000;
					printf("  Waiting up to %d ms for finger events. Touch the sensor 8-12 times.\n",
					       wait_ms_total);

					/* Drain backlog of buffered events: many tests have left a
					 * large delta between host_seq=0 and sensor_seq. Drain in
					 * batches of 32 until we're caught up. */
					{
						uint16_t hseq = 0;
						for (int drain_iter = 0; drain_iter < 8 && hseq < post_start_seq; drain_iter++) {
							uint8_t er0[9];
							er0[0] = 0x87;
							er0[1] = (uint8_t)(hseq & 0xff);
							er0[2] = (uint8_t)((hseq >> 8) & 0xff);
							er0[3] = 32; er0[4] = 0;
							er0[5] = 1; er0[6] = 0; er0[7] = 0; er0[8] = 0;
							int dn = fp_tls_app_send_recv(&st, &xport,
							           er0, sizeof(er0), db_resp, sizeof(db_resp));
							int dstat = (dn >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
							unsigned dnum = (dn >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0;
							printf("    [drain backlog %d] status=0x%04x num_evts=%u\n",
							       drain_iter, dstat, dnum);
							if (!fp_status_is_ok(dstat) || dnum == 0) break;
							hseq = (uint16_t)((hseq + dnum) & 0xffff);
						}
						post_start_seq = hseq;
						printf("    drained backlog up to seq=0x%04x\n", post_start_seq);
					}

					/* Start event_seq at the sensor's current value — the sensor
					 * only pushes EP2 interrupts when its seq advances PAST our
					 * subscribed value. If we start at 0 with sensor at 0x6f,
					 * we'd miss pushes because the sensor sees no advance. */
					uint16_t event_seq = (uint16_t)post_start_seq;
					int ms_remaining = wait_ms_total;
					int add_attempts = 0;
					int add_success = 0;
					int finger_press_events = 0;

					/* Drain any pending interrupts from before this phase. */
					{
						uint8_t evb[8]; int got = 0;
						while (fp_intr_recv(dev, evb, sizeof(evb), &got, 50) == 0
						       && got > 0) {
							if (got >= 6) {
								int s = evb[5] & 0x1f;
								printf("    (pre-drain EP2: seq=%d)\n", s);
								event_seq = (uint16_t)s;
							}
						}
					}
					printf("  starting from event_seq=0x%04x\n", event_seq);

					unsigned type_seen[256];
					memset(type_seen, 0, sizeof(type_seen));
					int idle_reads = 0;
					while (ms_remaining > 0 && add_attempts < 80) {
						/* Consume an interrupt push if one is waiting, but do
						 * NOT require it: the short timeout just paces the loop.
						 * The unconditional EVENT_READ below is what drains
						 * events — including any that never raise an EP2
						 * interrupt (the whole point of this probe). */
						uint8_t evb[8] = {0};
						int got = 0;
						int rc = fp_intr_recv(dev, evb, sizeof(evb), &got, 400);
						ms_remaining -= 400;
						if (rc == 0 && got > 0) {
							unsigned sensor_seq = (got >= 6) ? (evb[5] & 0x1f) : 0;
							printf("    EP2 push (%d B): seq=%u  hex=", got, sensor_seq);
							for (int j = 0; j < got; j++) printf("%02x", evb[j]);
							printf("\n");
						} else if (rc != 0 && rc != LIBUSB_ERROR_TIMEOUT) {
							printf("    EP2 read error: %s\n", libusb_error_name(rc));
							break;
						}

						/* EVENT_READ (cmd 0x87) — drain queued events.
						 * pydrv non-legacy format: <BHHI>
						 *   B: 0x87
						 *   H: host seq
						 *   H: 32 (max events to read)
						 *   I: 1 (mode flag) */
						uint8_t er_cmd[9];
						er_cmd[0] = 0x87;
						er_cmd[1] = (uint8_t)(event_seq & 0xff);
						er_cmd[2] = (uint8_t)((event_seq >> 8) & 0xff);
						er_cmd[3] = 32;
						er_cmd[4] = 0;
						er_cmd[5] = 1;
						er_cmd[6] = 0;
						er_cmd[7] = 0;
						er_cmd[8] = 0;
						int en = fp_tls_app_send_recv(&st, &xport, er_cmd, sizeof(er_cmd),
						                              db_resp, sizeof(db_resp));
						int erstatus = (en >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						if (!fp_status_is_ok(erstatus)) {
							printf("    event_read: len=%d status=0x%04x (non-OK)\n", en, erstatus);
							continue;
						}
						/* parse: [2..3]=num_evts [4..5]=num_pending, then 12 B
						 * per event, event byte 0 = type. */
						unsigned num_evts = (en >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0;
						unsigned num_pending = (en >= 6) ? (db_resp[4] | (db_resp[5] << 8)) : 0;
						if (num_evts == 0) {
							if ((idle_reads++ % 12) == 0)
								printf("    (event_read idle: num_pending=%u, %d ms left)\n",
								       num_pending, ms_remaining);
							continue;
						}
						printf("    event_read: num_evts=%u num_pending=%u  raw: ",
						       num_evts, num_pending);
						for (int j = 0; j < en && j < 96; j++) printf("%02x", db_resp[j]);
						printf("\n");

						int saw_any = 0;
						for (unsigned i = 0; i < num_evts; i++) {
							int eoff = 6 + i * 12;
							if (eoff + 12 > en) break;
							uint8_t etype = db_resp[eoff];
							type_seen[etype]++;
							saw_any = 1;
							if (etype == 1) finger_press_events++;
							printf("      event[%u] type=%u  rec=", i, etype);
							for (int j = 0; j < 12; j++) printf("%02x", db_resp[eoff + j]);
							printf("%s\n",
							       etype == 1 ? "  (FINGER_PRESS)" :
							       etype == 2 ? "  (FINGER_REMOVE)" :
							       "  (** UNKNOWN — candidate capture-complete **)");
						}
						event_seq = (uint16_t)((event_seq + num_evts) & 0xffff);

						/* Probe misEnrollAddImage after ANY event, so a new
						 * (non press/remove) type also gets exercised. */
						if (saw_any) {

							/* Step 3b: misEnrollAddImage (cmd 0x96 sub 2) — 5 bytes
							 * per DLL fcn.180099870 RE. Hypothesis: 0x050b means
							 * "capture not finished yet, retry" (python-validity's
							 * append_new_image issues enrollment_update repeatedly
							 * after arming a capture). Poll until status changes. */
							uint8_t add_cmd[5] = { 0x96, 0x02, 0x00, 0x00, 0x00 };
							int astatus = -1, alen = 0;
							for (int poll = 0; poll < 12; poll++) {
								usleep(150 * 1000);
								alen = fp_tls_app_send_recv(&st, &xport,
								            add_cmd, sizeof(add_cmd),
								            db_resp, sizeof(db_resp));
								astatus = (alen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
								add_attempts++;
								printf("    AddImage[%d] poll=%d: len=%d status=0x%04x %s  payload: ",
								       add_attempts, poll, alen, astatus,
								       fp_status_is_ok(astatus) ? "(OK)" : "(non-OK)");
								int show = alen > 32 ? 32 : alen;
								for (int j = 0; j < show; j++) printf("%02x", db_resp[j]);
								if (alen > 32) printf("...");
								printf("\n");
								if (astatus != 0x050b) break;
							}
							if (fp_status_is_ok(astatus)) {
								add_success++;
								/* Decode enroll progress struct at offset 0x16
								 * (per DLL fcn.180099870 RE). */
								if (alen >= 0x16 + 60) {
									const uint8_t *p = db_resp + 0x16;
									printf("      progress=%u templateCount=%u redundant=%u quality=%u rejected=%u\n",
									       p[0], p[1], p[2], p[3], p[4]);
								}
							}
						}
					}
					printf("  loop ended: %d finger_press events, %d AddImage attempts, %d accepted\n",
					       finger_press_events, add_attempts, add_success);
					printf("  ===> event types observed this run:");
					{
						int any_type = 0;
						for (int t = 0; t < 256; t++)
							if (type_seen[t]) { printf(" type%d=%u", t, type_seen[t]); any_type = 1; }
						if (!any_type) printf(" (none)");
						printf("\n");
						printf("  ===> if any type besides 1/2 appears, that is the missing capture signal.\n");
					}

					/* Step 4: misEnrollFinish */
					rlen = fp_tls_app_send_recv(&st, &xport, fin_cmd, sizeof(fin_cmd),
					                            db_resp, sizeof(db_resp));
					int fstatus = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  misEnrollFinish: status=0x%04x %s\n", fstatus,
					       fp_status_is_ok(fstatus) ? "(OK)" : "(non-OK)");
				} else if (getenv("FPDRV_ENROLL_FRAME_ACQ")) {
					/* v7 plaintext-trace-faithful enroll (2026-05-29).
					 *
					 * DECISIVE finding from enroll_trace_v7.bin (the TLS-chokepoint
					 * plaintext capture): Windows arms the event subsystem with
					 * EVENT_CONFIG (0x86) and issues a FRAME_ACQ (0x80) BEFORE every
					 * single misEnrollAddImage. Our old code never sent a correct
					 * FRAME_ACQ, so the sensor had no captured image -> 0x050b. This
					 * replays the exact per-image sequence Windows uses:
					 *   EVENT_CONFIG mask=0x06   (arm wait-for-finger)
					 *   EVENT_READ               (finger event, code 0x01)
					 *   EVENT_CONFIG mask=0x00   (disarm)
					 *   EVENT_CONFIG mask=0x04   (arm frame-class)
					 *   EVENT_READ               (code 0x02)
					 *   EVENT_CONFIG mask=0x00
					 *   EVENT_CONFIG flag@4=0x01 (arm frame-ready)
					 *   FRAME_ACQ 80 0c 00 00 00 01 00 00 00 01 00 00 08 01 01 01 00
					 *   EVENT_READ               (frame-captured, code 0x18)
					 *   EVENT_CONFIG mask=0x00
					 *   cmd 0x81                 (frame finalize)
					 *   misEnrollAddImage (0x96 02) -> progress bitmask @off22 (u16)
					 * Loop until the bitmask reaches 0x3ff (10 good samples). */

					/* EVENT_CONFIG (37 B): mask at off1 AND off17, frame-ready flag
					 * at off4 AND off20 — two identical 16-B blocks, per the trace.
					 * The Windows trace also sets byte[33]=0x04 on every DISARM
					 * (mask 0 + flag 0) config and 0 on every arm; we replicate that
					 * exactly. The 66-B response carries the sensor's current event
					 * seq at offset [64:65]. */
					unsigned ev_seq = 0;
					#define EVCFG(m, fl) do { \
						uint8_t _ec[37]; memset(_ec, 0, sizeof(_ec)); _ec[0] = 0x86; \
						_ec[1]  = (uint8_t)(m);  _ec[4]  = (uint8_t)(fl); \
						_ec[17] = (uint8_t)(m);  _ec[20] = (uint8_t)(fl); \
						if ((m) == 0 && (fl) == 0) _ec[33] = 0x04; \
						int _cn = fp_tls_app_send_recv(&st, &xport, _ec, sizeof(_ec), \
						                     db_resp, sizeof(db_resp)); \
						if (_cn >= 66) ev_seq = db_resp[64] | (db_resp[65] << 8); \
					} while (0)

					/* EVENT_READ (9 B): 87 <cursor:u16> 20 00 01 00 00 00. Response:
					 * [0:2]=status [2:4]=num_evts [4:6]=num_pending [6]=event code.
					 *
					 * The cursor is a TRUE read pointer: it must advance ONLY by the
					 * number of events actually consumed. (The earlier code added 1 on
					 * every read even when num_evts==0, so the cursor ran ahead of the
					 * sensor's real seq and we permanently missed the finger/0x18
					 * events — every read after the first empty one returned nothing.)
					 *
					 * EVRD_WAIT polls at a FIXED cursor every 50 ms until an event
					 * arrives or ~`ms` elapses, mirroring the blocking EVENT_READ
					 * Windows does at each step; returns the first event's code (0 on
					 * timeout) and advances the cursor by num_evts only on success. */
					uint16_t evc = 0;
					#define EVRD_WAIT(codevar, ms) do { \
						(codevar) = 0; \
						int _iters = (ms) / 50; if (_iters < 1) _iters = 1; \
						for (int _w = 0; _w < _iters; _w++) { \
							uint8_t _er[9] = {0x87, 0,0, 0x20,0x00, 0x01,0x00,0x00,0x00}; \
							_er[1] = (uint8_t)(evc & 0xff); _er[2] = (uint8_t)(evc >> 8); \
							int _n = fp_tls_app_send_recv(&st, &xport, _er, sizeof(_er), \
							                              db_resp, sizeof(db_resp)); \
							unsigned _ne = (_n >= 4) ? (db_resp[2] | (db_resp[3] << 8)) : 0; \
							if (_ne > 0) { \
								(codevar) = (_n >= 7) ? db_resp[6] : 0; \
								printf("      EVRD cur=0x%04x num=%u code=0x%02x\n", \
								       evc, _ne, (unsigned)(codevar)); \
								evc = (uint16_t)(evc + _ne); \
								break; \
							} \
							usleep(50 * 1000); \
						} \
					} while (0)

					int target = 16;
					const char *ti = getenv("FPDRV_ENROLL_IMAGES");
					if (ti) target = atoi(ti);
					int add_success = 0, add_attempts = 0;
					unsigned progress = 0;          /* enroll bitmask @off22 */
					uint8_t guid[16]; int have_guid = 0;
					printf("  v7 enroll: touch the sensor repeatedly (lift + re-touch).\n");
					printf("  Arming up to %d frames; target bitmask 0x3ff.\n", target);

					/* Seed the cursor to the sensor's current event seq (0 on a
					 * fresh power-cycle, as observed). One disarm fetches the seq. */
					EVCFG(0x00, 0x00);
					printf("  sensor current event seq=0x%04x; seeding cursor there.\n",
					       ev_seq);
					evc = (uint16_t)ev_seq;

					int no_finger_retries = 0;
					for (int img = 0; img < target && progress != 0x3ff; img++) {
						unsigned code;

						/* --- wait-for-finger: arm 0x06, block until a finger
						 * (0x01) event arrives. Windows reads this BLOCKING; if no
						 * finger lands within the window we retry this image rather
						 * than firing FRAME_ACQ on an empty sensor (which produces
						 * no capture -> 0x050b). EP2 interrupt just paces the wait. */
						EVCFG(0x06, 0x00);
						{
							uint8_t evb[8]; int got = 0;
							int rc2 = fp_intr_recv(dev, evb, sizeof(evb), &got, 5000);
							if (rc2 != 0 && rc2 != LIBUSB_ERROR_TIMEOUT) {
								printf("    EP2 wait error: %s\n", libusb_error_name(rc2));
							}
						}
						EVRD_WAIT(code, 6000);
						EVCFG(0x00, 0x00);
						if (code == 0) {
							printf("  [img %d] no finger event (touch the sensor); retrying\n", img);
							if (++no_finger_retries >= 20) {
								printf("  giving up: no finger events after %d retries\n",
								       no_finger_retries);
								break;
							}
							img--;            /* don't consume an image slot */
							continue;
						}
						no_finger_retries = 0;

						/* --- arm frame-class (0x04), wait for the 0x02 event --- */
						EVCFG(0x04, 0x00);
						EVRD_WAIT(code, 3000);
						EVCFG(0x00, 0x00);

						/* --- arm frame-ready, FRAME_ACQ, wait for frame-captured
						 * (0x18). Only that event means an image is in the buffer. */
						EVCFG(0x00, 0x01);
						uint8_t acq[17] = {
							0x80, 0x0c, 0x00, 0x00, 0x00,
							0x01, 0x00, 0x00, 0x00,
							0x01, 0x00, 0x00,
							0x08, 0x01, 0x01, 0x01, 0x00
						};
						int an = fp_tls_app_send_recv(&st, &xport, acq, sizeof(acq),
						                              db_resp, sizeof(db_resp));
						int astat = (an >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						EVRD_WAIT(code, 3000);
						EVCFG(0x00, 0x00);
						printf("  [img %d] FRAME_ACQ status=0x%04x  frame-evt code=0x%02x%s\n",
						       img, astat, code,
						       code == 0x18 ? " (CAPTURED)" : "");

						/* --- frame finalize (cmd 0x81), then AddImage --- */
						uint8_t flush = 0x81;
						fp_tls_app_send_recv(&st, &xport, &flush, 1,
						                     db_resp, sizeof(db_resp));

						uint8_t add_cmd[5] = { 0x96, 0x02, 0x00, 0x00, 0x00 };
						int astatus = -1, alen = 0;
						for (int poll = 0; poll < 6; poll++) {
							alen = fp_tls_app_send_recv(&st, &xport, add_cmd, sizeof(add_cmd),
							                            db_resp, sizeof(db_resp));
							astatus = (alen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
							add_attempts++;
							if (astatus != 0x050b) break;
							usleep(120 * 1000);
						}
						printf("    AddImage: len=%d status=0x%04x %s  payload: ",
						       alen, astatus,
						       fp_status_is_ok(astatus) ? "(OK)" : "(non-OK)");
						{
							int show = alen > 32 ? 32 : alen;
							for (int j = 0; j < show; j++) printf("%02x", db_resp[j]);
							if (alen > 32) printf("...");
							printf("\n");
						}
						if (fp_status_is_ok(astatus)) {
							add_success++;
							/* GUID at resp[2..17], progress bitmask u16 at resp[22]. */
							if (alen >= 18) { memcpy(guid, db_resp + 2, 16); have_guid = 1; }
							if (alen >= 24) {
								progress = db_resp[22] | (db_resp[23] << 8);
								printf("      progress bitmask=0x%03x (%d/10 samples)\n",
								       progress, __builtin_popcount(progress));
							}
						}
					}
					printf("  v7 enroll loop ended: %d attempts, %d accepted, bitmask=0x%03x\n",
					       add_attempts, add_success, progress);

					/* --- Commit (0x96 sub3) + Finish (0x96 sub4) ---
					 * The 124-B Commit payload carries the sensor-issued template
					 * GUID plus a host-identity block. We replay the structure
					 * captured in enroll_trace_v7.bin, patching in the live GUID
					 * harvested from the final AddImage. NOTE: the identity block
					 * (offset 35..) is a Windows SID from the capture; on Linux this
					 * is a placeholder — template encryption/identity binding is the
					 * known-open part (see CLAUDE.md). */
					if (progress == 0x3ff && have_guid) {
						uint8_t commit[124] = {
							/* GUID occupies [19..34], patched in below from the
							 * final AddImage response. Bytes verified against
							 * record 289 of enroll_trace_v7.bin. */
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

						/* Finger subtype (WinBio subfactor) at commit offset 35.
						 * Default 1; FPDRV_ENROLL_FINGER picks a distinct value so
						 * multiple fingers under the same identity are
						 * distinguishable (identify returns this subfactor). */
						{
							const char *fe = getenv("FPDRV_ENROLL_FINGER");
							if (fe) commit[35] = (uint8_t)strtoul(fe, NULL, 0);
							printf("  [commit finger subtype = %u]\n", commit[35]);
						}

						/* Identity-binding experiment (0x06db investigation).
						 * The commit embeds a WINBIO_IDENTITY at offset 37:
						 *   [37]=u32 struct size (0x4c=76)
						 *   [41]=u32 Type (0=NULL,2=GUID,3=SID)
						 *   [45]=u32 payload size
						 *   [49]=68-byte union buffer (SID data / GUID)
						 * Default replays the captured Windows SID verbatim
						 * (S-1-5-21-...-1001). FPDRV_COMMIT_IDENTITY lets us swap
						 * the identity without a recompile so each physical enroll
						 * cycle can test a different hypothesis:
						 *   null     -> Type=NULL, no identity payload
						 *   localsid -> Type=SID, distinct synthetic SID (..-1000)
						 *   guid     -> Type=GUID, identity = the template GUID */
						const char *idmode = getenv("FPDRV_COMMIT_IDENTITY");
						if (idmode && !strcmp(idmode, "null")) {
							commit[41] = 0x00;          /* WINBIO_ID_TYPE_NULL */
							commit[45] = 0x00;          /* payload size 0 */
							memset(commit + 49, 0, 68); /* clear SID buffer */
							printf("  [commit identity: NULL]\n");
						} else if (idmode && !strcmp(idmode, "localsid")) {
							/* Well-formed but distinct synthetic SID:
							 * S-1-5-21-1-2-3-1000. Tests identity-collision vs.
							 * generic foreign-SID rejection. */
							static const uint8_t lsid[28] = {
								0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
								0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
								0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
								0xe8, 0x03, 0x00, 0x00
							};
							commit[41] = 0x03;          /* WINBIO_ID_TYPE_SID */
							commit[45] = 0x1c;          /* 28 */
							memset(commit + 49, 0, 68);
							memcpy(commit + 49, lsid, sizeof(lsid));
							printf("  [commit identity: local SID S-1-5-21-1-2-3-1000]\n");
						} else if (idmode && !strcmp(idmode, "guid")) {
							commit[41] = 0x02;          /* WINBIO_ID_TYPE_GUID */
							commit[45] = 0x10;          /* 16 */
							memset(commit + 49, 0, 68);
							memcpy(commit + 49, guid, 16); /* identity = template GUID */
							printf("  [commit identity: GUID = template GUID]\n");
						} else if (idmode && !strcmp(idmode, "linux")) {
							/* A genuine host-chosen Linux identity: a well-formed
							 * SID S-1-5-21-<"LNX" marker>-<uid>, where uid is the
							 * invoking user (SUDO_UID under sudo, else getuid()).
							 * Replaces the captured Windows SID entirely. */
							const char *su = getenv("SUDO_UID");
							unsigned long uid = su ? strtoul(su, NULL, 10)
							                       : (unsigned long)getuid();
							uint8_t sid[28] = {
								0x01, 0x05,                 /* rev 1, 5 sub-auths */
								0x00,0x00,0x00,0x00,0x00,0x05, /* NT authority = 5 */
								0x15,0x00,0x00,0x00,        /* sub0 = 21 */
								'L','N','X',0x00,           /* sub1 = "LNX" marker */
								0x00,0x00,0x00,0x00,        /* sub2 */
								0x00,0x00,0x00,0x00,        /* sub3 */
								0x00,0x00,0x00,0x00         /* sub4 = uid (RID) */
							};
							sid[24] = (uint8_t)(uid & 0xff);
							sid[25] = (uint8_t)((uid >> 8) & 0xff);
							sid[26] = (uint8_t)((uid >> 16) & 0xff);
							sid[27] = (uint8_t)((uid >> 24) & 0xff);
							commit[41] = 0x03;          /* WINBIO_ID_TYPE_SID */
							commit[45] = 0x1c;          /* 28 */
							memset(commit + 49, 0, 68);
							memcpy(commit + 49, sid, sizeof(sid));
							printf("  [commit identity: Linux SID S-1-5-21-LNX-%lu]\n", uid);
						} else {
							printf("  [commit identity: captured Windows SID (default)]\n");
						}

						int cn = fp_tls_app_send_recv(&st, &xport, commit, sizeof(commit),
						                              db_resp, sizeof(db_resp));
						int cstat = (cn >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						printf("  misEnrollCommit (0x96/3): len=%d status=0x%04x %s\n",
						       cn, cstat, fp_status_is_ok(cstat) ? "(OK)" : "(non-OK)");
					} else {
						printf("  skipping Commit (bitmask 0x%03x != 0x3ff)\n", progress);
					}

					rlen = fp_tls_app_send_recv(&st, &xport, fin_cmd, sizeof(fin_cmd),
					                            db_resp, sizeof(db_resp));
					int fstatus2 = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  misEnrollFinish: status=0x%04x %s\n", fstatus2,
					       fp_status_is_ok(fstatus2) ? "(OK)" : "(non-OK)");
					#undef EVCFG
					#undef EVRD_WAIT
				} else {
					/* Bare poll (no event subscription). DEFAULT only because
					 * it is the simplest baseline — NOT because Windows is
					 * keyless: all-messages-capture.pcapng shows a real Windows
					 * enroll does ~97 EVENT_CONFIG round-trips. The request-only
					 * DLL trace just couldn't see them (EVENT_CONFIG goes through
					 * the unhooked vfmDeviceEventConfigure site). This path polls
					 * misEnrollAddImage (96 02 00 00 00), ignoring 0x050b, then
					 * commits (96 03) + finishes (96 04). Both this and the event
					 * path (FPDRV_ENROLL_EVENTS) currently stall at 0x050b. */
					int max_polls = 200;
					const char *np = getenv("FPDRV_ENROLL_POLLS");
					if (np) max_polls = atoi(np);
					printf("  Windows-style poll: place your finger on the sensor and\n");
					printf("  lift / re-touch slowly. Polling misEnrollAddImage up to %d times.\n",
					       max_polls);
					uint8_t add_cmd[5] = { 0x96, 0x02, 0x00, 0x00, 0x00 };
					int add_attempts = 0, add_success = 0, last_progress = -1;
					for (int poll = 0; poll < max_polls; poll++) {
						int alen = fp_tls_app_send_recv(&st, &xport,
						            add_cmd, sizeof(add_cmd),
						            db_resp, sizeof(db_resp));
						int astatus = (alen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
						add_attempts++;
						if (astatus == 0x050b) {
							if ((poll % 20) == 0)
								printf("    (waiting for frames... poll %d/%d)\n",
								       poll, max_polls);
							usleep(100 * 1000);
							continue;
						}
						printf("    AddImage[%d]: len=%d status=0x%04x %s  payload: ",
						       add_attempts, alen, astatus,
						       fp_status_is_ok(astatus) ? "(OK)" : "(non-OK)");
						int show = alen > 40 ? 40 : alen;
						for (int j = 0; j < show; j++) printf("%02x", db_resp[j]);
						if (alen > 40) printf("...");
						printf("\n");
						if (fp_status_is_ok(astatus)) {
							add_success++;
							if (alen >= 0x16 + 5) {
								const uint8_t *p = db_resp + 0x16;
								printf("      progress=%u templateCount=%u redundant=%u quality=%u rejected=%u\n",
								       p[0], p[1], p[2], p[3], p[4]);
								last_progress = p[0];
								if (p[0] >= 100) {
									printf("  enrollment progress reports complete (100%%)\n");
									break;
								}
							}
						}
						usleep(80 * 1000);
					}
					printf("  poll ended: %d attempts, %d accepted, last_progress=%d\n",
					       add_attempts, add_success, last_progress);

					/* misEnrollFinish (96 04) to release the enroll context. */
					rlen = fp_tls_app_send_recv(&st, &xport, fin_cmd, sizeof(fin_cmd),
					                            db_resp, sizeof(db_resp));
					int fstatus = (rlen >= 2) ? (db_resp[0] | (db_resp[1] << 8)) : -1;
					printf("  misEnrollFinish: status=0x%04x %s\n", fstatus,
					       fp_status_is_ok(fstatus) ? "(OK)" : "(non-OK)");
				}

				/* Step 5: post-enrollment check via db2_get_obj_list. */
				printf("\n  [post-enrollment] db2_get_obj_list:\n");
				uint8_t qcmd = 0x9f;
				rlen = fp_tls_app_send_recv(&st, &xport, &qcmd, 1, db_resp, sizeof(db_resp));
				if (rlen >= 2) {
					int s = db_resp[0] | (db_resp[1] << 8);
					printf("    status=0x%04x %s payload: ", s,
					       fp_status_is_ok(s) ? "(OK)" : "(non-OK)");
					int show = rlen > 64 ? 64 : rlen;
					for (int i = 0; i < show; i++) printf("%02x", db_resp[i]);
					if (rlen > 64) printf("...");
					printf("\n");
				}
			}

			fp_tls_state_destroy(&st);
		} else {
			printf("\n  status 0x%04x — sensor rejected\n", status);
			if (status == 0x0403)
				printf("    0x0403 = same error we saw with placeholder crypto earlier.\n"
				       "    Likely signature verification or input-shape issue.\n");
		}
	}

	return 0;
}

static int cmd_tls_test_live(struct fp_device *dev)
{
	printf("tls-test-live: loading persisted pair-data...\n");
	struct fp_pairdata pd;
	if (fp_storage_load(&pd, NULL) != 0) {
		fprintf(stderr, "no pair-data found; run `fpdrv pair-init` first\n");
		return 1;
	}
	printf("  loaded host pubkey X[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", pd.host_pub_xy[i]);
	printf(", PSK[0..7] = ");
	for (int i = 0; i < 8; i++) printf("%02x", pd.psk[i]);
	printf("\n");

	printf("\ntls-test-live: running Phase 1 init queries first (sensor needs them)...\n");
	int rc = fp_cmd_init_dump(dev);
	if (rc != 0) {
		fprintf(stderr, "Phase 1 failed: %s\n", libusb_error_name(rc));
		return 1;
	}

	printf("\ntls-test-live: opening TLS session with persisted keys...\n");
	/* Dummy cert blob for now — placeholder bytes the sensor will see in
	 * the Certificate message. Real impl will use bytes derived from
	 * pair-data (host's local credential blob). */
	uint8_t cert_blob[64];
	memset(cert_blob, 0xab, sizeof(cert_blob));

	struct fp_tls_state st;
	if (fp_tls_state_init(&st) != 0) return 1;

	struct fp_tls_handshake_inputs in = {
		.cert_blob = cert_blob,
		.cert_blob_len = sizeof(cert_blob),
		.priv_d = pd.host_priv,
		.psk = pd.psk,
		.psk_len = FP_PSK_LEN,
		.sensor_pub_xy = NULL,    /* recover from ServerHello.random */
		.eph_priv = NULL,         /* let orchestrator generate */
		.eph_pub_out = NULL,
	};
	struct fp_tls_transport xport = {
		.send = live_xport_send,
		.recv = live_xport_recv,
		.ctx  = dev,
	};

	int orc_rc = fp_tls_open(&st, &in, &xport);
	printf("\nfp_tls_open returned %d\n", orc_rc);
	printf("  secure_tx = %d, secure_rx = %d\n", st.secure_tx, st.secure_rx);
	printf("  client_random[0..7]  = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.client_random[i]);
	printf("\n  server_random[0..7]  = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.server_random[i]);
	printf("\n  master_secret[0..7]  = ");
	for (int i = 0; i < 8; i++) printf("%02x", st.master_secret[i]);
	printf("\n\nExpected: handshake transitions advance (secure_rx=1) but fails at MAC verify\n"
	       "because the sensor doesn't yet have OUR generated keys registered. This run\n"
	       "tells us if the wire format is accepted up to that point.\n");

	fp_tls_state_destroy(&st);
	return 0;
}

/* Thin front-ends over proto.c — the SAME code path the libfprint-2-tod
 * driver uses. These let us validate the extracted protocol module against
 * real hardware before the GObject layer is involved. */

static int proto_list_print_cb(const uint8_t uguid[16], const uint8_t fguid[16],
                               uint8_t subtype, void *user)
{
	(void)fguid; (void)user;
	printf("  template guid=");
	for (int i = 0; i < 16; i++) printf("%02x", uguid[i]);
	printf(" finger=%u\n", subtype);
	return 0;
}

static int proto_enroll_progress_cb(int samples, void *user)
{
	(void)user;
	printf("  enroll progress: %d/10 samples\n", samples);
	return 0;
}

static int cmd_proto(struct fp_device *dev, const char *sub, const char *arg)
{
	struct fp_session s;
	if (fp_proto_open(&s, dev) != 0) return 1;
	int rc = 0;

	if (strcmp(sub, "proto-open") == 0) {
		printf("proto-open: secure session established\n");
	} else if (strcmp(sub, "proto-id") == 0) {
		printf("proto-id: touch the sensor with an enrolled finger...\n");
		uint8_t guid[16]; uint8_t finger = 0;
		int r = fp_proto_identify(&s, guid, &finger);
		if (r == 1) {
			printf("MATCH finger=%u guid=", finger);
			for (int i = 0; i < 16; i++) printf("%02x", guid[i]);
			printf("\n");
		} else if (r == 0) {
			printf("NO MATCH (finger not enrolled)\n");
		} else {
			printf("identify error/no-finger\n"); rc = 1;
		}
	} else if (strcmp(sub, "proto-enroll") == 0) {
		uint8_t subtype = arg ? (uint8_t)strtoul(arg, NULL, 0) : 1;
		uint8_t sid[28];
		const char *su = getenv("SUDO_UID");
		uint32_t uid = su ? (uint32_t)strtoul(su, NULL, 10) : (uint32_t)getuid();
		fp_proto_make_linux_sid(uid, sid);
		printf("proto-enroll: finger=%u uid=%u — touch + lift repeatedly\n", subtype, uid);
		uint8_t guid[16];
		int r = fp_proto_enroll(&s, subtype, sid, 28,
		                        proto_enroll_progress_cb, NULL, guid);
		if (r == 0) {
			printf("ENROLLED guid=");
			for (int i = 0; i < 16; i++) printf("%02x", guid[i]);
			printf("\n");
		} else { printf("enroll failed (r=%d)\n", r); rc = 1; }
	} else if (strcmp(sub, "proto-list") == 0) {
		int n = fp_proto_list(&s, proto_list_print_cb, NULL);
		printf("proto-list: %d template(s)\n", n);
		if (n < 0) rc = 1;
	} else if (strcmp(sub, "proto-clear") == 0) {
		int r = fp_proto_clear(&s);
		printf("proto-clear: %s\n", r == 0 ? "OK" : "failed");
		if (r != 0) rc = 1;
	}

	fp_proto_close(&s);
	return rc;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-d <vid>:<pid>] <command>\n"
		"\n"
		"commands:\n"
		"  open      open the device, claim interface 0, print endpoint map, exit\n"
		"  info      run the cleartext Phase 1 init queries and dump every response\n"
		"  pair      attempt the Phase 2b pair handshake with placeholder material\n"
		"            (won't succeed, but reveals how the sensor rejects bad crypto)\n"
		"  pair-replay  replay the exact 0x93 payload from captures/try-6 frame 280\n"
		"  pair-bisect  systematically mutate the TRY6 0x93 payload to localize\n"
		"               which fields are signature-bound vs opaque\n"
		"  tls-replay   replay pair then continue with try-6 ClientHello\n"
		"  flash <p>    parse the captured 4 KB sensor_cert.bin at <p> and dump blocks\n"
		"  tls-dryrun   run the TLS handshake state machine offline with captured try-3 server bytes\n"
		"  pair-init    generate fresh host EC keypair + PSK, save to ~/.local/state/fpdrv/pairdata\n"
		"  pair-show    print summary of current host pair-data (does not reveal secrets)\n"
		"  tls-test-live  open the device, run Phase 1, then attempt the TLS handshake with persisted keys\n"
		"  pair-live    construct a 0x93 pair-request from our persisted keys and send it to the sensor\n"
		"  db2-list     pair-live up through the Phase 6 db2 template walk, then exit (read-only, no enroll)\n"
		"  db2-del      walk db2 then DELETE every user object + child-ref, then exit (destructive, no enroll)\n"
		"  identify     capture one finger frame and match on-chip against enrolled templates\n"
		"  proto-open   bring up a secure session via proto.c (shared with the TOD driver) and exit\n"
		"  proto-id     proto.c identify: capture one frame, match on-chip\n"
		"  proto-enroll [finger]  proto.c enroll (default finger subtype 1)\n"
		"  proto-list   proto.c list enrolled templates\n"
		"  proto-clear  proto.c delete all enrolled templates\n"
		"  selftest  run the crypto self-tests (no device access)\n"
		"\n"
		"vid/pid are hex without 0x prefix; default 06cb:00e7\n",
		prog);
}

static int parse_vidpid(const char *s, uint16_t *vid, uint16_t *pid)
{
	const char *sep = strchr(s, ':');
	if (!sep) return -1;
	*vid = (uint16_t)strtoul(s, NULL, 16);
	*pid = (uint16_t)strtoul(sep + 1, NULL, 16);
	return 0;
}

int main(int argc, char **argv)
{
	uint16_t vid = DEFAULT_VID;
	uint16_t pid = DEFAULT_PID;

	int argi = 1;
	if (argi < argc && strcmp(argv[argi], "-d") == 0) {
		if (argi + 1 >= argc || parse_vidpid(argv[argi + 1], &vid, &pid) != 0) {
			usage(argv[0]);
			return 2;
		}
		argi += 2;
	}

	if (argi >= argc) {
		usage(argv[0]);
		return 2;
	}

	const char *cmd = argv[argi];

	/* selftest doesn't need the device. */
	if (strcmp(cmd, "selftest") == 0) {
		printf("crypto self-test:\n");
		return fp_crypto_selftest() == 0 ? 0 : 1;
	}

	/* tls-dryrun: exercise the orchestrator with captured try-3 bytes. */
	if (strcmp(cmd, "tls-dryrun") == 0) {
		return fp_tls_dryrun();
	}

	if (strcmp(cmd, "pair-init") == 0) {
		struct fp_pairdata pd;
		if (fp_storage_generate_fresh(&pd) != 0) {
			fprintf(stderr, "pair-init: keygen failed\n");
			return 1;
		}
		char path[1024];
		fp_storage_default_path(path, sizeof(path));
		if (fp_storage_save(&pd, NULL) != 0) {
			fprintf(stderr, "pair-init: save failed\n");
			return 1;
		}
		printf("pair-init: wrote fresh pair-data to %s\n", path);
		printf("  host pubkey X: ");
		for (int i = 0; i < 16; i++) printf("%02x", pd.host_pub_xy[i]);
		printf("...\n  host pubkey Y: ");
		for (int i = 0; i < 16; i++) printf("%02x", pd.host_pub_xy[32 + i]);
		printf("...\n  PSK (first 8 B): ");
		for (int i = 0; i < 8; i++) printf("%02x", pd.psk[i]);
		printf("...\n");
		return 0;
	}

	if (strcmp(cmd, "pair-show") == 0) {
		struct fp_pairdata pd;
		if (fp_storage_load(&pd, NULL) != 0) {
			fprintf(stderr, "pair-show: no pair-data found; run `fpdrv pair-init` first\n");
			return 1;
		}
		char path[1024];
		fp_storage_default_path(path, sizeof(path));
		printf("pair-show: loaded pair-data from %s\n", path);
		printf("  host pubkey X: ");
		for (int i = 0; i < 32; i++) printf("%02x", pd.host_pub_xy[i]);
		printf("\n  host pubkey Y: ");
		for (int i = 0; i < 32; i++) printf("%02x", pd.host_pub_xy[32 + i]);
		printf("\n  PSK length: %d\n", FP_PSK_LEN);
		printf("  PSK fingerprint (SHA-256[:16]): ");
		uint8_t fp[FP_SHA256_LEN];
		fp_crypto_sha256(pd.psk, FP_PSK_LEN, fp);
		for (int i = 0; i < 8; i++) printf("%02x", fp[i]);
		printf("\n");
		return 0;
	}

	/* flash <path> doesn't need the device — it just parses a saved blob. */
	if (strcmp(cmd, "flash") == 0) {
		if (argi + 1 >= argc) {
			fprintf(stderr, "flash: missing path argument\n");
			usage(argv[0]);
			return 2;
		}
		const char *path = argv[argi + 1];
		FILE *f = fopen(path, "rb");
		if (!f) {
			fprintf(stderr, "flash: cannot open %s\n", path);
			return 1;
		}
		fseek(f, 0, SEEK_END);
		long sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		if (sz <= 0 || sz > 16384) {
			fprintf(stderr, "flash: implausible size %ld\n", sz);
			fclose(f);
			return 1;
		}
		uint8_t *buf = malloc((size_t)sz);
		if (!buf || fread(buf, 1, sz, f) != (size_t)sz) {
			fprintf(stderr, "flash: read failed\n");
			free(buf); fclose(f);
			return 1;
		}
		fclose(f);
		printf("parsing %ld bytes from %s\n", sz, path);
		int n = fp_tls_flash_dump(buf, (int)sz);
		free(buf);
		return n >= 0 ? 0 : 1;
	}

	struct fp_device dev;
	int rc = fpdrv_usb_open(&dev, vid, pid);
	if (rc != 0) return 1;

	printf("opened %04x:%04x  interface=%u  ep_bulk_in=0x%02x  ep_bulk_out=0x%02x  ep_intr_in=0x%02x\n",
		vid, pid, dev.interface, dev.ep_bulk_in, dev.ep_bulk_out, dev.ep_intr_in);

	if (strcmp(cmd, "open") == 0) {
		/* nothing more to do */
		rc = 0;
	} else if (strcmp(cmd, "info") == 0) {
		rc = fp_cmd_init_dump(&dev);
	} else if (strcmp(cmd, "tls-test-live") == 0) {
		rc = cmd_tls_test_live(&dev);
	} else if (strcmp(cmd, "pair-live") == 0) {
		rc = cmd_pair_live(&dev, 0);
	} else if (strcmp(cmd, "db2-list") == 0) {
		/* Read-only: run the session setup through the Phase 6 db2 walk,
		 * then exit before enrollment. No finger touch needed. */
		rc = cmd_pair_live(&dev, 1);
	} else if (strcmp(cmd, "db2-del") == 0) {
		/* Destructive: delete every db2 user object (and its child-ref),
		 * then exit. Clears failed-commit residue. No finger touch. */
		rc = cmd_pair_live(&dev, 2);
	} else if (strcmp(cmd, "identify") == 0) {
		/* Capture one frame, match on-chip against enrolled templates. */
		rc = cmd_pair_live(&dev, 3);
	} else if (strcmp(cmd, "capture") == 0) {
		/* `capture` is `pair-live` with the Phase 6 event-read loop turned
		 * into a blocking poll for FINGER_PRESS, then frame_read drain.
		 * Default wait is 30 s — override with FPDRV_CAPTURE_WAIT_MS=N. */
		if (getenv("FPDRV_CAPTURE_WAIT_MS") == NULL)
			setenv("FPDRV_CAPTURE_WAIT_MS", "30000", 1);
		printf("capture: will wait up to %s ms for FINGER_PRESS\n",
		       getenv("FPDRV_CAPTURE_WAIT_MS"));
		printf("capture: PLACE FINGER ON SENSOR NOW\n");
		rc = cmd_pair_live(&dev, 0);
	} else if (strcmp(cmd, "pair") == 0) {
		rc = fp_pair_attempt(&dev);
	} else if (strcmp(cmd, "pair-replay") == 0) {
		rc = fp_pair_replay_try6(&dev);
	} else if (strcmp(cmd, "pair-bisect") == 0) {
		rc = fp_pair_bisect(&dev);
	} else if (strcmp(cmd, "pair-sign-sweep") == 0) {
		struct fp_pairdata pd;
		if (fp_storage_load(&pd, NULL) != 0) {
			fprintf(stderr, "pair-sign-sweep: no pair-data; run pair-init first\n");
			rc = 1;
		} else {
			rc = fp_pair_sign_sweep(&dev, pd.host_priv, pd.host_pub_xy);
		}
	} else if (strcmp(cmd, "cert-dump") == 0) {
		/* Issue GET_CERTIFICATE_EX (0x40) and write the full response
		 * (header + 4 KB cert body + trailer) to /tmp/cert-live.bin
		 * so it can be diffed against captures/try-6 to see whether
		 * the wiped-sensor cert blob contains the pair-template token. */
		uint8_t req[] = { 0x40, 0x02, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
		                  0x01, 0x00, 0x00, 0x00, 0x01 };
		uint8_t resp[8192];
		int got = 0;
		rc = fp_cmd_exec(&dev, req, sizeof(req), resp, sizeof(resp), &got);
		if (rc == 0) {
			/* Drain trailers. */
			int total = got;
			while (total < (int)sizeof(resp)) {
				int g = 0;
				int r2 = fp_bulk_recv(&dev, resp + total, sizeof(resp) - total, &g);
				if (r2 == LIBUSB_ERROR_TIMEOUT) break;
				if (r2 != 0) { rc = r2; break; }
				total += g;
			}
			FILE *f = fopen("/tmp/cert-live.bin", "wb");
			if (f) {
				fwrite(resp, 1, total, f);
				fclose(f);
				printf("cert-dump: wrote %d bytes to /tmp/cert-live.bin\n", total);
			} else {
				fprintf(stderr, "cert-dump: cannot open /tmp/cert-live.bin\n");
				rc = 1;
			}
		}
	} else if (strcmp(cmd, "tls-replay") == 0) {
		rc = fp_tls_replay_try6(&dev);
	} else if (strncmp(cmd, "proto-", 6) == 0) {
		/* proto.c front-ends (shared with the libfprint-2-tod driver). */
		const char *arg = (argi + 1 < argc) ? argv[argi + 1] : NULL;
		rc = cmd_proto(&dev, cmd, arg);
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		usage(argv[0]);
		rc = 2;
	}

	fpdrv_usb_close(&dev);
	return rc == 0 ? 0 : 1;
}
