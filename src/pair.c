#include "pair.h"
#include "cmd.h"
#include "crypto.h"
#include "parser.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>

#define PAIR_REQ_LEN 401

/* Offsets within the 401-byte 0x93 request payload, derived from
 * captures/try-6.pcapng frame 280 (corrected 2026-05-18 via byte-bisection
 * — original values were off-by-4). */
#define OFF_CMD       0
#define OFF_TOKEN     1
#define OFF_HASH1     5
#define OFF_HASH2     73
#define OFF_SIG_LEN   141   /* 4 B TLV: 00 00 48 00 = type=0 len=72 */
#define OFF_SIG       145   /* up to 72 bytes DER ECDSA sig */

static void hexdump_short(const char *label, const uint8_t *data, int len)
{
	printf("    %s (%d B): ", label, len);
	int show = len > 32 ? 32 : len;
	for (int i = 0; i < show; i++) printf("%02x", data[i]);
	if (len > show) printf("...");
	printf("\n");
}

int fp_pair_begin(struct fp_device *dev)
{
	uint8_t cmd[2] = { 0x3f, 0x02 };
	uint8_t resp[16];
	int got = 0;

	int rc = fp_cmd_exec(dev, cmd, sizeof(cmd), resp, sizeof(resp), &got);
	if (rc != 0) return rc;

	if (got < 2) {
		fprintf(stderr, "pair_begin: short response (%d B)\n", got);
		return -1;
	}
	int status = fp_resp_status(resp, got);
	if (status != 0) {
		fprintf(stderr, "pair_begin: sensor returned status 0x%04x\n", status);
		return -1;
	}
	printf("    pair_begin: ok (resp %d B, status 0x%04x)\n", got, status);
	return 0;
}

int fp_pair_request(struct fp_device *dev,
                    const uint8_t priv[32],
                    const uint8_t token[4],
                    const uint8_t hash1[32],
                    const uint8_t hash2[32],
                    uint8_t *resp_buf, int resp_max, int *resp_len)
{
	uint8_t req[PAIR_REQ_LEN];
	memset(req, 0, sizeof(req));

	req[OFF_CMD] = 0x93;
	memcpy(req + OFF_TOKEN, token, 4);
	memcpy(req + OFF_HASH1, hash1, 32);
	memcpy(req + OFF_HASH2, hash2, 32);
	/* TLV type bytes at OFF_SIG_LEN..+1 are 0x0000 (sig follows).
	 * Length (LE u16) gets filled in after we know sig_len. */

	/* Per the DLL's `_tudorSecuritySignHPubK` disassembly: sign
	 *   SHA-256(buf[0..142])   where buf[i] = wire[i+1]
	 * i.e., the 142 bytes from wire offset 1 through 142 inclusive:
	 *   token(4) + hash1(32) + 36 zero-pad + hash2(32) + 36 zero-pad
	 *      + 2 bytes of TLV type (both 0x00). */
	uint8_t digest[FP_SHA256_LEN];
	if (fp_crypto_sha256(req + 1, 142, digest) != 0) {
		fprintf(stderr, "pair_request: sha256 failed\n");
		return -1;
	}

	uint8_t sig[FP_P256_SIG_MAX];
	size_t sig_len = sizeof(sig);
	if (fp_crypto_p256_ecdsa_sign(priv, digest, sig, &sig_len) != 0) {
		fprintf(stderr, "pair_request: ecdsa sign failed\n");
		return -1;
	}
	if (sig_len > 72) {
		fprintf(stderr, "pair_request: sig too long (%zu B, max 72)\n", sig_len);
		return -1;
	}

	/* Length prefix: 4-byte LE, 00 00 LL 00 in the captures. */
	req[OFF_SIG_LEN + 0] = 0x00;
	req[OFF_SIG_LEN + 1] = 0x00;
	req[OFF_SIG_LEN + 2] = (uint8_t)sig_len;
	req[OFF_SIG_LEN + 3] = 0x00;
	memcpy(req + OFF_SIG, sig, sig_len);

	hexdump_short("pair req header", req, 16);
	hexdump_short("pair req sig", req + OFF_SIG, (int)sig_len);

	/* Send the 401-byte request. */
	int rc = fp_bulk_send(dev, req, sizeof(req), NULL);
	if (rc != 0) {
		fprintf(stderr, "pair_request: bulk_send: %s\n", libusb_error_name(rc));
		return rc;
	}

	/* Read the multi-part response.  Fresh-pair capture shows the sensor
	 * sends exactly 768 + 34 = 802 bytes in two URBs.  Stop as soon as we
	 * have the expected total to avoid a 1-second trailing bulk-IN timeout
	 * that could cause the sensor to drop pair-state (verified culprit of
	 * the post-0x93 TLS Alert 47). */
	int total = 0;
	while (total < resp_max) {
		int got = 0;
		rc = fp_bulk_recv(dev, resp_buf + total, resp_max - total, &got);
		if (rc == LIBUSB_ERROR_TIMEOUT) {
			rc = 0;
			break;
		}
		if (rc != 0) {
			fprintf(stderr, "pair_request: bulk_recv chunk %d: %s\n",
				total, libusb_error_name(rc));
			return rc;
		}
		total += got;
		if (total >= 802) break;   /* expected full response */
		if (got < 16) break;
	}
	if (resp_len) *resp_len = total;
	return 0;
}

/* Verbatim bytes of captures/try-6.pcapng frame 280 (the only successful
 * fresh-pair 0x93 request we have on tape). For replay diagnostics only. */
static const uint8_t TRY6_PAIR_REQ[401] = {
	0x93, 0x3f, 0x5f, 0x17, 0x00, 0x4e, 0xd2, 0xde, 0xfd, 0x4e, 0xc2, 0x49,
	0xc4, 0xbe, 0x45, 0x7f, 0x3f, 0x61, 0xe4, 0x9c, 0x18, 0x6c, 0x45, 0xa0,
	0x0c, 0xa3, 0x30, 0xbb, 0x69, 0xbe, 0x72, 0x5c, 0xd2, 0xb2, 0x6f, 0x4a,
	0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x50, 0xcd, 0xd7, 0x7b, 0x01, 0x77, 0x85, 0xa3, 0x8f, 0x82, 0xa1,
	0x4a, 0xe3, 0x88, 0x9c, 0xaf, 0xa7, 0x62, 0x95, 0xcf, 0xab, 0x4b, 0x92,
	0x99, 0x4b, 0xf0, 0x41, 0xd9, 0x13, 0xf3, 0x77, 0x19, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48,
	0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xd3, 0x50, 0x52, 0x52, 0xd4, 0x09,
	0x45, 0x0a, 0x8a, 0xb5, 0xa5, 0x61, 0xc0, 0x6e, 0x7f, 0x3f, 0x7d, 0xea,
	0xf8, 0x4f, 0x92, 0xd4, 0x3c, 0x40, 0x4e, 0x77, 0x2a, 0x86, 0x3a, 0xb7,
	0xba, 0x3c, 0x02, 0x21, 0x00, 0x8d, 0xf1, 0xf3, 0xc8, 0x7f, 0x37, 0xf5,
	0x8a, 0xb0, 0x89, 0x77, 0x9c, 0x8d, 0x8f, 0x4b, 0xbc, 0x47, 0xd4, 0xb4,
	0x5e, 0x6f, 0xae, 0x8a, 0x95, 0x2c, 0xff, 0x6d, 0x50, 0x8b, 0x25, 0xda,
	0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

int fp_pair_replay_try6(struct fp_device *dev)
{
	printf("  Phase 2b replay: pair_begin (0x3f 02)\n");
	if (fp_pair_begin(dev) != 0) return -1;

	printf("\n  Phase 2b replay: sending captured 0x93 payload from try-6 frame 280\n");
	hexdump_short("first 16 B", TRY6_PAIR_REQ, 16);

	int rc = fp_bulk_send(dev, TRY6_PAIR_REQ, sizeof(TRY6_PAIR_REQ), NULL);
	if (rc != 0) {
		fprintf(stderr, "pair_replay: bulk_send: %s\n", libusb_error_name(rc));
		return rc;
	}

	/* The captured response in try-6 was 768 + 34 + 3 bytes across three
	 * URBs separated by ~500ms. We keep reading until the sensor goes
	 * idle (read times out) rather than short-circuiting on small reads —
	 * the trailing 3-byte status is small but real. */
	uint8_t resp[1024];
	int total = 0;
	while (total < (int)sizeof(resp)) {
		int got = 0;
		rc = fp_bulk_recv(dev, resp + total, sizeof(resp) - total, &got);
		if (rc == LIBUSB_ERROR_TIMEOUT) break;
		if (rc != 0) {
			fprintf(stderr, "pair_replay: bulk_recv: %s\n", libusb_error_name(rc));
			return rc;
		}
		total += got;
	}

	printf("\n  sensor response (%d B total):\n", total);
	hexdump_short("first 64 B", resp, total < 64 ? total : 64);
	if (total >= 2) {
		int status = fp_resp_status(resp, total);
		printf("    status word: 0x%04x %s\n", status,
			status == 0 ? "(OK — sensor accepted replayed request!)"
			            : "(ERROR — sensor rejected replayed request)");
	}
	if (total == 805) {
		printf("    *** got 768+34+3 = 805 B response, matching try-6 frame 283 ***\n");
	}

	/* Save for offline comparison against captures/try-6 frames 283/285. */
	FILE *f = fopen("/tmp/pair-replay-response.bin", "wb");
	if (f) {
		fwrite(resp, 1, total, f);
		fclose(f);
		printf("    wrote /tmp/pair-replay-response.bin for offline diff\n");
	}
	return 0;
}

/* Verbatim bytes of captures/try-6.pcapng frame 288 — the ClientHello with
 * Synaptics 4-byte length prefix (`44 00 00 00` + 78-byte TLS record). */
static const uint8_t TRY6_CLIENTHELLO[82] = {
	0x44, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x49, 0x01, 0x00, 0x00,
	0x45, 0x03, 0x03, 0x1b, 0x5c, 0xc9, 0x4b, 0xc7, 0x7f, 0x43, 0xa6, 0xdd,
	0x25, 0xde, 0xea, 0xa3, 0x30, 0xdf, 0xc3, 0xa6, 0xa2, 0xe9, 0x34, 0xaa,
	0xa2, 0xff, 0xe3, 0x3f, 0x87, 0x1b, 0x2f, 0xb5, 0x10, 0xc0, 0x45, 0x07,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x05, 0xc0,
	0x2e, 0x00, 0x3d, 0x00, 0x8d, 0x00, 0xa8, 0x00, 0x00, 0x0a, 0x00, 0x04,
	0x00, 0x02, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
};

/* Expected ServerHello bytes from try-6 frame 291 (no length prefix on
 * sensor→host responses). */
static const uint8_t TRY6_SERVERHELLO_EXPECTED[66] = {
	0x16, 0x03, 0x03, 0x00, 0x3d, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x83, 0x00,
	0x01, 0x95, 0xc2, 0x0b, 0xae, 0x96, 0x86, 0xdd, 0x3d, 0x15, 0x16, 0x40,
	0x62, 0xec, 0x4c, 0xe5, 0x40, 0x03, 0x2f, 0x06, 0x05, 0x5f, 0x41, 0x70,
	0xe6, 0x24, 0x4b, 0xef, 0x85, 0xec, 0xc1, 0x07, 0x54, 0x4c, 0x53, 0x0b,
	0xae, 0x96, 0x86, 0xc0, 0x2e, 0x00, 0x0d, 0x00, 0x00, 0x04, 0x01, 0x40,
	0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
};

int fp_tls_replay_try6(struct fp_device *dev)
{
	int rc = fp_pair_replay_try6(dev);
	if (rc != 0) return rc;

	printf("\n  Phase 3 replay: sending captured ClientHello (frame 288, 82 B)\n");
	rc = fp_bulk_send(dev, TRY6_CLIENTHELLO, sizeof(TRY6_CLIENTHELLO), NULL);
	if (rc != 0) {
		fprintf(stderr, "tls_replay: ClientHello send: %s\n", libusb_error_name(rc));
		return rc;
	}

	uint8_t resp[256];
	int got = 0;
	rc = fp_bulk_recv(dev, resp, sizeof(resp), &got);
	if (rc != 0) {
		fprintf(stderr, "tls_replay: ServerHello recv: %s\n", libusb_error_name(rc));
		return rc;
	}
	printf("    ServerHello response (%d B)\n", got);
	hexdump_short("first 32 B", resp, got < 32 ? got : 32);

	if (got == sizeof(TRY6_SERVERHELLO_EXPECTED) &&
	    memcmp(resp, TRY6_SERVERHELLO_EXPECTED, sizeof(TRY6_SERVERHELLO_EXPECTED)) == 0) {
		printf("    *** ServerHello byte-identical to try-6 frame 291 — handshake is deterministic ***\n");
	} else {
		printf("    ServerHello DIFFERS from try-6 frame 291:\n");
		printf("    expected (%zu B): ", sizeof(TRY6_SERVERHELLO_EXPECTED));
		for (size_t i = 0; i < sizeof(TRY6_SERVERHELLO_EXPECTED) && i < 32; i++)
			printf("%02x", TRY6_SERVERHELLO_EXPECTED[i]);
		printf("...\n");
		printf("    got      (%d B): ", got);
		for (int i = 0; i < got && i < 32; i++) printf("%02x", resp[i]);
		printf("...\n");
		/* Find first differing byte. */
		int n = (int)sizeof(TRY6_SERVERHELLO_EXPECTED);
		if (got < n) n = got;
		for (int i = 0; i < n; i++) {
			if (resp[i] != TRY6_SERVERHELLO_EXPECTED[i]) {
				printf("    first diff at offset %d: expected 0x%02x, got 0x%02x\n",
					i, TRY6_SERVERHELLO_EXPECTED[i], resp[i]);
				break;
			}
		}
	}
	return 0;
}

/* === Byte-bisection ====================================================
 *
 * The 401-byte TRY6 payload accepted by the sensor (status 0x0000) is our
 * known-good baseline. By mutating targeted regions and re-sending, we
 * partition the payload into:
 *
 *   OPAQUE   — sensor still accepts ⇒ those bytes are NOT signature-bound
 *              and NOT directly inspected. They are either pure padding or
 *              echo-only fields the sensor copies into its response without
 *              verification.
 *
 *   CHECKED  — sensor rejects (0x0403) ⇒ those bytes are either:
 *                (a) part of the signature itself
 *                (b) signature-bound payload (covered by what's hashed)
 *                (c) directly inspected by the sensor (e.g. length prefix)
 *
 * Together with knowledge of the field offsets (cmd / token / hash1 /
 * pad / hash2 / pad / sig_len / sig_DER / trailing) this gives us a map
 * of what the sensor actually verifies. Once the map is known, we can
 * narrow the hypothesis of "what bytes are signed" significantly.
 *
 * Each test re-arms the sensor with a fresh pair_begin (0x3f 02). The
 * baseline is run twice (start + end) so that "the sensor changed its
 * mind mid-bisection" can be ruled out. */

struct fp_bisect_mutation {
	int offset;      /* -1 means no mutation (baseline) */
	int len;
	uint8_t value;   /* either byte to write or byte to XOR with */
	int xor_mode;    /* 1: XOR existing byte with value, 0: replace */
	const char *label;
};

/* Updated bisection: corrected field offsets (sig at 145–216, not 141–212).
 * Adds (a) middle token bytes 2, 3 to confirm full token is checked, and
 * (b) finer-grained probes at offsets 217–290 to localize the upper
 * boundary of the signature-bound region. */
static const struct fp_bisect_mutation BISECT_TESTS[] = {
	{ -1,  0, 0x00, 0, "baseline #1 (verbatim TRY6)" },

	/* Token: tests bytes 1, 2, 3, 4 — does full 4-byte field gate on 0x0403? */
	{   1, 1, 0xff, 1, "flip token[0] (offset 1, was 0x3f)" },
	{   2, 1, 0xff, 1, "flip token[1] (offset 2, was 0x5f)" },
	{   3, 1, 0xff, 1, "flip token[2] (offset 3, was 0x17)" },
	{   4, 1, 0xff, 1, "flip token[3] (offset 4, was 0x00)" },

	/* Body sample (signed region): confirm 0x044f at edges */
	{   5, 1, 0xff, 1, "flip hash1[0] (offset 5)" },
	{  36, 1, 0xff, 1, "flip hash1[31] (offset 36)" },
	{  73, 1, 0xff, 1, "flip hash2[0] (offset 73)" },
	{ 104, 1, 0xff, 1, "flip hash2[31] (offset 104)" },

	/* TLV/sig region (corrected offsets) */
	{ 141, 1, 0xff, 1, "flip TLV type[0] (offset 141, was 0x00)" },
	{ 143, 1, 0x01, 1, "tweak TLV len[0] (offset 143, was 0x48 → 0x49)" },
	{ 145, 1, 0xff, 1, "flip sig_DER[0] (offset 145, SEQUENCE marker 0x30)" },
	{ 180, 1, 0xff, 1, "flip sig_DER[35] (offset 180, mid r||s)" },
	{ 216, 1, 0xff, 1, "flip sig_DER[71] (offset 216, true last sig byte)" },

	/* Upper-boundary scan: where does CHECKED → OPAQUE transition? */
	{ 217, 1, 0xff, 0, "set byte[217]=0xff (just after sig)" },
	{ 220, 1, 0xff, 0, "set byte[220]=0xff" },
	{ 230, 1, 0xff, 0, "set byte[230]=0xff" },
	{ 250, 1, 0xff, 0, "set byte[250]=0xff" },
	{ 270, 1, 0xff, 0, "set byte[270]=0xff" },
	{ 290, 1, 0xff, 0, "set byte[290]=0xff" },

	{ -1,  0, 0x00, 0, "baseline #2 (verbatim TRY6 — sanity re-check)" },
};
#define BISECT_N ((int)(sizeof(BISECT_TESTS) / sizeof(BISECT_TESTS[0])))

static int bisect_run_one(struct fp_device *dev,
                          const struct fp_bisect_mutation *m,
                          int *status_out, int *resp_len_out)
{
	uint8_t req[PAIR_REQ_LEN];
	memcpy(req, TRY6_PAIR_REQ, PAIR_REQ_LEN);
	if (m->offset >= 0) {
		for (int j = 0; j < m->len; j++) {
			if (m->xor_mode)
				req[m->offset + j] ^= m->value;
			else
				req[m->offset + j] = m->value;
		}
	}

	/* Re-arm sensor. */
	if (fp_pair_begin(dev) != 0) {
		fprintf(stderr, "  bisect: pair_begin failed before test\n");
		return -1;
	}

	int rc = fp_bulk_send(dev, req, PAIR_REQ_LEN, NULL);
	if (rc != 0) {
		fprintf(stderr, "  bisect: bulk_send: %s\n", libusb_error_name(rc));
		return -1;
	}

	uint8_t resp[1024];
	int total = 0;
	while (total < (int)sizeof(resp)) {
		int got = 0;
		rc = fp_bulk_recv(dev, resp + total, sizeof(resp) - total, &got);
		if (rc == LIBUSB_ERROR_TIMEOUT) break;
		if (rc != 0) {
			fprintf(stderr, "  bisect: bulk_recv: %s\n", libusb_error_name(rc));
			break;
		}
		total += got;
	}

	int status = -1;
	if (total >= 2)
		status = (int)(resp[0] | (resp[1] << 8));

	if (status_out)   *status_out   = status;
	if (resp_len_out) *resp_len_out = total;
	return 0;
}

int fp_pair_bisect(struct fp_device *dev)
{
	printf("\n=== TRY6 0x93 byte-bisection ===\n");
	printf("Running %d tests against TRY6 baseline.\n", BISECT_N);
	printf("Expected: baseline accepts (0x0000). Mutations either accept\n"
	       "(byte is OPAQUE) or reject with 0x0403 (byte is CHECKED).\n\n");

	int statuses[BISECT_N];
	int lens[BISECT_N];
	for (int i = 0; i < BISECT_N; i++) {
		const struct fp_bisect_mutation *m = &BISECT_TESTS[i];
		printf("[%02d/%d] %s\n", i + 1, BISECT_N, m->label);
		if (m->offset >= 0) {
			uint8_t orig = TRY6_PAIR_REQ[m->offset];
			uint8_t mut  = m->xor_mode ? (uint8_t)(orig ^ m->value) : m->value;
			printf("       mutate offset %d: 0x%02x → 0x%02x\n",
				m->offset, orig, mut);
		}
		int s = -1, l = 0;
		if (bisect_run_one(dev, m, &s, &l) != 0) {
			statuses[i] = -1;
			lens[i]     = 0;
			printf("       → transport error, aborting bisection\n");
			break;
		}
		statuses[i] = s;
		lens[i]     = l;
		const char *verdict = (s == 0x0000)  ? "ACCEPTED → OPAQUE"
		                    : (s == 0x0403)  ? "REJECTED → CHECKED"
		                                     :  "REJECTED (other code)";
		printf("       → %d B response, status=0x%04x  [%s]\n\n", l, s, verdict);
	}

	printf("\n=== Bisection summary ===\n");
	printf("idx  off   verdict             status  len   description\n");
	printf("---  ----  ------------------  ------  ----  -----------\n");
	for (int i = 0; i < BISECT_N; i++) {
		const struct fp_bisect_mutation *m = &BISECT_TESTS[i];
		const char *verdict = (statuses[i] == 0x0000) ? "ACCEPT (opaque)"
		                    : (statuses[i] == 0x0403) ? "REJECT (checked)"
		                    : (statuses[i] == -1)     ? "TRANSPORT ERR"
		                                              : "REJECT (other)";
		if (m->offset >= 0)
			printf("%3d  %4d  %-18s  0x%04x  %4d  %s\n",
				i + 1, m->offset, verdict, statuses[i], lens[i], m->label);
		else
			printf("%3d  ----  %-18s  0x%04x  %4d  %s\n",
				i + 1, verdict, statuses[i], lens[i], m->label);
	}
	printf("\nInterpretation:\n");
	printf("  ACCEPT (opaque)  = byte is NOT signature-bound and NOT inspected\n");
	printf("  REJECT (checked) = byte is signature-bound OR directly inspected\n");
	printf("  Compare baseline #1 vs #2: if both ACCEPT, results are reliable\n");
	return 0;
}

/* === Signing-message sweep =============================================
 *
 * The bisection localized that token (1-4) and body (5-216) are checked,
 * and the live test confirmed token=`3f 5f 17 00` is correct. Now we
 * need to find what data the sensor expects the ECDSA signature to cover.
 *
 * For each test:
 *  1. Build a 0x93 body with our hash1 = pub_x, hash2 = SHA-256(pub).
 *  2. Pick a "signed message" candidate (a slice of the body or a
 *     concatenation of fields).
 *  3. Sign SHA-256(signed_message) with priv.
 *  4. Write the sig + TLV at offsets 141-216.
 *  5. Send. Report sensor status.
 *
 * If any hypothesis gives 0x0000 we've cracked the signing scheme. */

struct fp_sign_test {
	int (*build_msg)(const uint8_t req[401], const uint8_t pub_x[32],
	                 uint8_t *out, int *out_len);
	const char *label;
};

/* Built bodies are pre-populated via build_body() with token+hash1+hash2,
 * then each candidate extracts its signed-message bytes from the body. */
static int msg_token_h1_h2(const uint8_t req[401], const uint8_t pub_x[32],
                           uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out + 0,  req + 1,  4);   /* token */
	memcpy(out + 4,  req + 5,  32);  /* hash1 */
	memcpy(out + 36, req + 73, 32);  /* hash2 */
	*out_len = 68;
	return 0;
}
static int msg_bytes_5_145(const uint8_t req[401], const uint8_t pub_x[32],
                           uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out, req + 5, 140);
	*out_len = 140;
	return 0;
}
static int msg_bytes_5_141(const uint8_t req[401], const uint8_t pub_x[32],
                           uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out, req + 5, 136);
	*out_len = 136;
	return 0;
}
static int msg_bytes_0_145(const uint8_t req[401], const uint8_t pub_x[32],
                           uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out, req, 145);
	*out_len = 145;
	return 0;
}
static int msg_bytes_1_145(const uint8_t req[401], const uint8_t pub_x[32],
                           uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out, req + 1, 144);
	*out_len = 144;
	return 0;
}
static int msg_h1_h2_only(const uint8_t req[401], const uint8_t pub_x[32],
                          uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out + 0,  req + 5,  32);  /* hash1 */
	memcpy(out + 32, req + 73, 32);  /* hash2 */
	*out_len = 64;
	return 0;
}
static int msg_h1_only(const uint8_t req[401], const uint8_t pub_x[32],
                       uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out, req + 5, 32);
	*out_len = 32;
	return 0;
}
static int msg_token_h1(const uint8_t req[401], const uint8_t pub_x[32],
                        uint8_t *out, int *out_len)
{
	(void)pub_x;
	memcpy(out + 0, req + 1, 4);
	memcpy(out + 4, req + 5, 32);
	*out_len = 36;
	return 0;
}

static const struct fp_sign_test SIGN_TESTS[] = {
	{ msg_token_h1_h2, "SHA256(token || hash1 || hash2)  [current scheme]" },
	{ msg_bytes_5_145, "SHA256(bytes[5..145])  [140 B signed body]" },
	{ msg_bytes_5_141, "SHA256(bytes[5..141])  [136 B body, no TLV header]" },
	{ msg_bytes_0_145, "SHA256(bytes[0..145])  [145 B whole prefix incl. cmd]" },
	{ msg_bytes_1_145, "SHA256(bytes[1..145])  [144 B token+body]" },
	{ msg_h1_h2_only,  "SHA256(hash1 || hash2)" },
	{ msg_h1_only,     "SHA256(hash1)  [just X-coord]" },
	{ msg_token_h1,    "SHA256(token || hash1)" },
};
#define SIGN_TESTS_N ((int)(sizeof(SIGN_TESTS) / sizeof(SIGN_TESTS[0])))

int fp_pair_sign_sweep(struct fp_device *dev,
                       const uint8_t priv[32],
                       const uint8_t pub_x[32])
{
	printf("\n=== Sign-message sweep ===\n");
	printf("%d candidates, each builds a fresh 0x93 with different sig.\n", SIGN_TESTS_N);
	printf("Token forced to 3f 5f 17 00; hash1 = our pubkey X; hash2 = SHA-256(our pub).\n\n");

	/* Build the static body once — same hash1, hash2, token across all tests. */
	uint8_t base_req[PAIR_REQ_LEN];
	memset(base_req, 0, sizeof(base_req));
	base_req[OFF_CMD] = 0x93;
	base_req[OFF_TOKEN + 0] = 0x3f;
	base_req[OFF_TOKEN + 1] = 0x5f;
	base_req[OFF_TOKEN + 2] = 0x17;
	base_req[OFF_TOKEN + 3] = 0x00;
	memcpy(base_req + OFF_HASH1, pub_x, 32);

	uint8_t pub_full[64];
	memcpy(pub_full, pub_x, 32);
	/* hash2 placeholder: SHA-256(pub_x) — won't be the right value but
	 * keeps the test repeatable. */
	uint8_t hash2[32];
	if (fp_crypto_sha256(pub_x, 32, hash2) != 0) return -1;
	memcpy(base_req + OFF_HASH2, hash2, 32);
	(void)pub_full;

	int statuses[SIGN_TESTS_N];

	for (int i = 0; i < SIGN_TESTS_N; i++) {
		const struct fp_sign_test *t = &SIGN_TESTS[i];
		printf("[%d/%d] %s\n", i + 1, SIGN_TESTS_N, t->label);

		uint8_t msg[256];
		int msg_len = 0;
		if (t->build_msg(base_req, pub_x, msg, &msg_len) != 0) {
			printf("       build_msg failed\n");
			statuses[i] = -1;
			continue;
		}

		uint8_t digest[FP_SHA256_LEN];
		if (fp_crypto_sha256(msg, (size_t)msg_len, digest) != 0) {
			printf("       sha256 failed\n");
			statuses[i] = -1;
			continue;
		}

		uint8_t sig[FP_P256_SIG_MAX];
		size_t sig_len = sizeof(sig);
		if (fp_crypto_p256_ecdsa_sign(priv, digest, sig, &sig_len) != 0) {
			printf("       ecdsa sign failed\n");
			statuses[i] = -1;
			continue;
		}

		uint8_t req[PAIR_REQ_LEN];
		memcpy(req, base_req, PAIR_REQ_LEN);
		req[OFF_SIG_LEN + 0] = 0x00;
		req[OFF_SIG_LEN + 1] = 0x00;
		req[OFF_SIG_LEN + 2] = (uint8_t)sig_len;
		req[OFF_SIG_LEN + 3] = 0x00;
		memcpy(req + OFF_SIG, sig, sig_len);
		/* trailing bytes beyond sig stay zero */

		if (fp_pair_begin(dev) != 0) {
			fprintf(stderr, "  pair_begin failed\n");
			break;
		}

		int rc = fp_bulk_send(dev, req, PAIR_REQ_LEN, NULL);
		if (rc != 0) {
			fprintf(stderr, "  bulk_send: %s\n", libusb_error_name(rc));
			statuses[i] = -1;
			continue;
		}

		uint8_t resp[1024];
		int total = 0;
		while (total < (int)sizeof(resp)) {
			int got = 0;
			rc = fp_bulk_recv(dev, resp + total, sizeof(resp) - total, &got);
			if (rc == LIBUSB_ERROR_TIMEOUT) break;
			if (rc != 0) break;
			total += got;
		}
		int status = (total >= 2) ? (int)(resp[0] | (resp[1] << 8)) : -1;
		statuses[i] = status;
		const char *verdict = (status == 0x0000) ? "*** ACCEPTED ***"
		                    : (status == 0x044f) ? "rejected (sig fail)"
		                    : (status == 0x0403) ? "rejected (token fail)"
		                                         : "rejected";
		printf("       sig_len=%zu, resp %d B, status=0x%04x  [%s]\n\n",
			sig_len, total, status, verdict);
	}

	printf("\n=== Sign-sweep summary ===\n");
	for (int i = 0; i < SIGN_TESTS_N; i++) {
		const char *verdict = (statuses[i] == 0x0000) ? "ACCEPT"
		                    : (statuses[i] == 0x044f) ? "REJECT (sig)"
		                    : (statuses[i] == 0x0403) ? "REJECT (token)"
		                    : (statuses[i] == -1)     ? "ERROR"
		                                              : "REJECT (other)";
		printf("  %d. %-50s  status=0x%04x  [%s]\n",
			i + 1, SIGN_TESTS[i].label, statuses[i], verdict);
	}
	return 0;
}

int fp_pair_attempt(struct fp_device *dev)
{
	printf("  Phase 2b: pair_begin (0x3f 02)\n");
	if (fp_pair_begin(dev) != 0) return -1;

	printf("\n  Phase 2b: pair_request (0x93 + 401 B)\n");

	uint8_t priv[FP_P256_PRIV_LEN], pub[FP_P256_PUB_LEN];
	if (fp_crypto_p256_keygen(priv, pub) != 0) {
		fprintf(stderr, "pair: keygen failed\n");
		return -1;
	}
	hexdump_short("host pubkey", pub, FP_P256_PUB_LEN);

	uint8_t token[4];
	if (fp_crypto_rand(token, sizeof(token)) != 0) {
		fprintf(stderr, "pair: rand failed\n");
		return -1;
	}
	hexdump_short("token", token, 4);

	/* Placeholder hashes — we don't yet know what the protocol expects
	 * the two context hashes to cover. Using SHA-256 of fixed strings
	 * so the bytes are deterministic across runs and easy to recognise
	 * in any future trace. The sensor will likely reject these. */
	uint8_t hash1[32], hash2[32];
	fp_crypto_sha256("fpdrv-pair-context-placeholder-1", 32, hash1);
	fp_crypto_sha256("fpdrv-pair-context-placeholder-2", 32, hash2);

	uint8_t resp[1024];
	int got = 0;
	int rc = fp_pair_request(dev, priv, token, hash1, hash2, resp, sizeof(resp), &got);
	if (rc != 0) return rc;

	printf("\n  sensor response (%d B total):\n", got);
	hexdump_short("first 64 B", resp, got < 64 ? got : 64);
	if (got >= 2) {
		int status = fp_resp_status(resp, got);
		printf("    status word: 0x%04x %s\n", status,
			status == 0 ? "(OK)" : "(ERROR — sensor rejected pair attempt)");
	}
	if (got > 0) {
		printf("    last bytes: ");
		int show = got < 8 ? got : 8;
		for (int i = got - show; i < got; i++) printf("%02x ", resp[i]);
		printf("\n");
	}
	return 0;
}
