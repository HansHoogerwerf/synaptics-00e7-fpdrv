#include "cmd.h"
#include "parser.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>

/* TLS 1.2 Alert content type at the start of a response means the sensor
 * still has stale TLS session state from a previous host. Sending the
 * command again "kicks" the sensor back to cleartext. Windows does the
 * same on first contact (try-3 frames 138/142). */
static int response_is_tls_alert(const uint8_t *resp, int len)
{
	return len >= 5
	    && resp[0] == 0x15 && resp[1] == 0x03 && resp[2] == 0x03;
}

int fp_cmd_exec(struct fp_device *dev,
                const void *cmd, int cmd_len,
                void *resp, int resp_max, int *resp_len)
{
	for (int attempt = 0; attempt < 2; attempt++) {
		int rc = fp_bulk_send(dev, cmd, cmd_len, NULL);
		if (rc != 0) return rc;

		int got = 0;
		rc = fp_bulk_recv(dev, resp, resp_max, &got);
		if (rc != 0) return rc;

		if (response_is_tls_alert(resp, got) && attempt == 0) {
			/* retry once */
			continue;
		}

		if (resp_len) *resp_len = got;
		return 0;
	}
	return LIBUSB_ERROR_OTHER;
}

static void hexdump(const uint8_t *data, int len)
{
	for (int i = 0; i < len; i++) {
		printf("%02x", data[i]);
		if ((i + 1) % 32 == 0) printf("\n        ");
		else if ((i + 1) % 4 == 0) printf(" ");
	}
	printf("\n");
}

/* Each entry: a name, the cleartext command bytes to send, expected
 * response handling notes. */
struct init_step {
	const char *name;
	const char *desc;
	uint8_t     cmd[32];
	int         cmd_len;
	int         followup_reads;  /* extra fp_bulk_recv calls after first */
};

static const struct init_step init_steps[] = {
	{ "GET_VERSION", "0x01: identity blob",
	  { 0x01 }, 1, 0 },

	/* 0x8e family — multi-purpose query with a sub-op selector. */
	{ "QUERY 0x8e/09", "0x8e sub=0x09: status flags",
	  { 0x8e, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 17, 0 },

	{ "GET_STARTINFO", "0x8e sub=0x1a: 72-byte startinfo block",
	  { 0x8e, 0x1a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 17, 0 },

	{ "QUERY 0x8e/2f", "0x8e sub=0x2f: state query",
	  { 0x8e, 0x2f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 17, 0 },

	{ "STATUS 0xaf", "0xaf 01: post-init status",
	  { 0xaf, 0x01, 0x00, 0x00, 0x00 }, 5, 0 },

	{ "GET_VERSION_EX", "0x19: extended version + serial",
	  { 0x19 }, 1, 0 },   /* data+trailer arrive in one short-terminated URB */

	{ "CAPABILITIES", "0x3e: sensor capabilities bitmap",
	  { 0x3e }, 1, 0 },

	{ "GET_CERTIFICATE_EX", "0x40: read sensor's stored pairing blob",
	  { 0x40, 0x02, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x10, 0x00, 0x00 }, 13, 0 },   /* 4096+8 in one URB */
};

static void annotate(const struct init_step *s, const uint8_t *resp, int got)
{
	int status = fp_resp_status(resp, got);
	if (status < 0) {
		printf("    decoded: <response too short to read status>\n");
		return;
	}
	printf("    status: 0x%04x\n", (unsigned)status);

	/* Per-command structured decode. */
	if (strcmp(s->name, "GET_VERSION") == 0) {
		uint8_t id[7];
		if (fp_resp_parse_version(resp, got, id) == 0) {
			printf("    sensor identity (7 B): %02x %02x %02x %02x %02x %02x %02x\n",
				id[0], id[1], id[2], id[3], id[4], id[5], id[6]);
		}
	} else if (strncmp(s->name, "QUERY 0x8e/", 11) == 0
	        || strcmp(s->name, "GET_STARTINFO") == 0) {
		uint16_t subop = 0;
		const uint8_t *data = NULL;
		int data_len = 0;
		if (fp_resp_parse_8e(resp, got, &subop, &data, &data_len) == 0) {
			printf("    8e subop=0x%02x payload=%d bytes\n", subop, data_len);
			if (subop == 0x1a && data_len >= 12) {
				uint32_t triple[3];
				fp_resp_parse_startinfo(data, data_len, triple);
				printf("    startinfo first u32s: 0x%08x 0x%08x 0x%08x\n",
					triple[0], triple[1], triple[2]);
			}
		} else {
			printf("    (8e envelope decode failed)\n");
		}
	} else if (strcmp(s->name, "GET_VERSION_EX") == 0) {
		uint32_t serial = 0;
		if (fp_resp_parse_serial(resp, got, &serial) == 0) {
			printf("    sensor serial (4 B LE): 0x%08x\n", serial);
		}
	} else if (strcmp(s->name, "CAPABILITIES") == 0) {
		struct fp_capabilities caps;
		if (fp_resp_parse_capabilities(resp, got, &caps) == 0) {
			printf("    feature bitmap: ");
			for (int j = 0; j < 12; j++) printf("%02x", caps.bitmap[j]);
			printf("\n    %d capability entries:\n", caps.n_entries);
			for (int j = 0; j < caps.n_entries; j++) {
				printf("      [%d] id=0x%02x type=0x%02x params=",
					j, caps.entries[j].id, caps.entries[j].type);
				for (int k = 0; k < 10; k++) printf("%02x", caps.entries[j].params[k]);
				printf("\n");
			}
		}
	} else if (strcmp(s->name, "GET_CERTIFICATE_EX") == 0) {
		printf("    fixed header (40 B): ");
		for (int j = 2; j < 42 && j < got; j++) printf("%02x", resp[j]);
		printf("\n");

		struct fp_cert_summary cs;
		if (fp_cert_summarize(resp, got, &cs) == 0) {
			printf("    populated region: %d bytes (rest is 0xff padding to %d B)\n",
				cs.data_end_offset, got);
			printf("    DPAPI GUID markers found: %d\n", cs.n_dpapi_blobs);
			int show = cs.n_dpapi_blobs;
			if (show > (int)(sizeof(cs.dpapi_offsets) / sizeof(cs.dpapi_offsets[0])))
				show = sizeof(cs.dpapi_offsets) / sizeof(cs.dpapi_offsets[0]);
			for (int j = 0; j < show; j++) {
				printf("      [%d] DPAPI provider GUID at offset %d\n",
					j, cs.dpapi_offsets[j]);
			}
		}
	}
}

/* fp_cmd_init_basic: run the second init pass before pair-begin.  2026-05-25
 * full-USB capture of a Windows clean-install fresh-pair shows pass 2 runs
 * the FULL set of 8 commands including 0x3e CAPABILITIES and 0x40
 * GET_CERTIFICATE_EX — NOT a 6-command subset as previously believed. */
int fp_cmd_init_basic(struct fp_device *dev)
{
	uint8_t resp[FP_RESP_MAX];
	int rc = 0;

	for (size_t i = 0; i < sizeof(init_steps) / sizeof(init_steps[0]); i++) {
		const struct init_step *s = &init_steps[i];
		int got = 0;
		rc = fp_cmd_exec(dev, s->cmd, s->cmd_len, resp, sizeof(resp), &got);
		if (rc != 0) return rc;
		for (int k = 0; k < s->followup_reads; k++) {
			rc = fp_bulk_recv(dev, resp, sizeof(resp), &got);
			if (rc == LIBUSB_ERROR_TIMEOUT) { rc = 0; break; }
			if (rc != 0) return rc;
		}
	}
	return 0;
}

int fp_cmd_init_dump(struct fp_device *dev)
{
	uint8_t resp[FP_RESP_MAX];
	int rc = 0;

	for (size_t i = 0; i < sizeof(init_steps) / sizeof(init_steps[0]); i++) {
		const struct init_step *s = &init_steps[i];

		printf("\n=== %s ===\n", s->name);
		printf("    %s\n", s->desc);
		printf("    cmd:  ");
		hexdump(s->cmd, s->cmd_len);

		int got = 0;
		rc = fp_cmd_exec(dev, s->cmd, s->cmd_len, resp, sizeof(resp), &got);
		if (rc != 0) {
			fprintf(stderr, "  *** failed: %s\n", libusb_error_name(rc));
			return rc;
		}

		printf("    resp (%d bytes):\n        ", got);
		hexdump(resp, got);

		annotate(s, resp, got);

		for (int k = 0; k < s->followup_reads; k++) {
			rc = fp_bulk_recv(dev, resp, sizeof(resp), &got);
			if (rc == LIBUSB_ERROR_TIMEOUT) {
				printf("    (no trailer packet — sensor combined into one URB)\n");
				rc = 0;
				break;
			}
			if (rc != 0) {
				fprintf(stderr, "  *** followup read failed: %s\n", libusb_error_name(rc));
				return rc;
			}
			printf("    resp tail %d (%d bytes):\n        ", k + 1, got);
			hexdump(resp, got);
		}
	}

	return 0;
}
