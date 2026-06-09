#include "parser.h"

#include <string.h>

static uint16_t rd_u16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32le(const uint8_t *p)
{
	return (uint32_t)p[0]
	     | ((uint32_t)p[1] << 8)
	     | ((uint32_t)p[2] << 16)
	     | ((uint32_t)p[3] << 24);
}

int fp_resp_status(const uint8_t *buf, int len)
{
	if (len < 2) return -1;
	return rd_u16le(buf);
}

int fp_status_is_ok(int status)
{
	return status == 0 || status == 0x412 || status == 0x5cc;
}

int fp_resp_parse_8e(const uint8_t *buf, int len,
                     uint16_t *subop, const uint8_t **data, int *data_len)
{
	if (len < 10) return -1;
	if (fp_resp_status(buf, len) != 0) return -1;

	uint32_t total = rd_u32le(buf + 2);
	if ((int)total + 6 != len) return -1;
	uint16_t inner = rd_u16le(buf + 6);
	if (inner + 4 != (int)total) return -1;
	if (subop)    *subop = rd_u16le(buf + 8);
	if (data)     *data = buf + 10;
	if (data_len) *data_len = inner;
	return 0;
}

int fp_resp_parse_version(const uint8_t *buf, int len, uint8_t out[7])
{
	if (len < 9) return -1;
	if (fp_resp_status(buf, len) != 0) return -1;
	memcpy(out, buf + 2, 7);
	return 0;
}

int fp_resp_parse_serial(const uint8_t *buf, int len, uint32_t *serial_out)
{
	if (len < 28) return -1;
	if (fp_resp_status(buf, len) != 0) return -1;
	if (serial_out) *serial_out = rd_u32le(buf + 24);
	return 0;
}

int fp_resp_parse_startinfo(const uint8_t *payload, int payload_len, uint32_t out[3])
{
	if (payload_len < 12) return -1;
	if (out) {
		out[0] = rd_u32le(payload + 0);
		out[1] = rd_u32le(payload + 4);
		out[2] = rd_u32le(payload + 8);
	}
	return 0;
}

int fp_resp_parse_capabilities(const uint8_t *buf, int len, struct fp_capabilities *out)
{
	/* Layout: 2 B status | 12 B bitmap | 2 B count_u16 | count * 12 B entry */
	if (len < 16) return -1;
	if (fp_resp_status(buf, len) != 0) return -1;
	memcpy(out->bitmap, buf + 2, 12);

	int count = rd_u16le(buf + 14);
	if (count < 0 || count > FP_CAPS_MAX_ENTRIES) return -1;
	if (16 + count * 12 > len) return -1;

	out->n_entries = count;
	for (int i = 0; i < count; i++) {
		const uint8_t *p = buf + 16 + i * 12;
		out->entries[i].id = p[0];
		out->entries[i].type = p[1];
		memcpy(out->entries[i].params, p + 2, 10);
	}
	return 0;
}

/* Microsoft DPAPI provider GUID {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
 * in little-endian bytes. */
static const uint8_t DPAPI_GUID[16] = {
	0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11,
	0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
};

int fp_cert_summarize(const uint8_t *buf, int len, struct fp_cert_summary *out)
{
	if (len < 8) return -1;
	if (fp_resp_status(buf, len) != 0) return -1;

	memset(out, 0, sizeof(*out));

	/* Find the offset where the 0xff padding tail begins by scanning
	 * backwards from the end. */
	int end = len;
	while (end > 0 && buf[end - 1] == 0xff) end--;
	out->data_end_offset = end;

	/* Scan the populated region for DPAPI GUID markers. */
	for (int i = 2; i + 16 <= end; i++) {
		if (memcmp(buf + i, DPAPI_GUID, 16) == 0) {
			if (out->n_dpapi_blobs < (int)(sizeof(out->dpapi_offsets) / sizeof(out->dpapi_offsets[0]))) {
				out->dpapi_offsets[out->n_dpapi_blobs] = i;
			}
			out->n_dpapi_blobs++;
			i += 16 - 1;   /* skip past this GUID */
		}
	}
	return 0;
}
