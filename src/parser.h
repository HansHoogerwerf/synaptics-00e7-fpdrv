#ifndef FPDRV_PARSER_H
#define FPDRV_PARSER_H

#include <stdint.h>

/* Every Synaptics 06cb:00e7 cleartext response begins with a 2-byte
 * little-endian status word. 0x0000 = OK. Anything else is an error
 * whose meaning depends on the command. */
int fp_resp_status(const uint8_t *buf, int len);

/* Returns 1 if the 16-bit wire status counts as success.
 * synaTudor's pydrv defines SUCCESS_STATUS = {0, 0x412, 0x5cc} — sub-states
 * the sensor uses to convey "OK with extra info" rather than an error. */
int fp_status_is_ok(int status);

/* Responses to the 0x8e command family have a nested envelope:
 *
 *   bytes 0..1   status         (already returned by fp_resp_status)
 *   bytes 2..5   total_size_u32 (LE) — bytes following this field
 *   bytes 6..7   inner_size_u16 (LE) — bytes of payload after this u16
 *   bytes 8..9   subop_echo_u16 (LE) — the sub-op the host had sent
 *   bytes 10..   payload bytes
 *
 * Returns 0 on success and writes pointers to the payload region into
 * *data / *data_len, and the echoed sub-op into *subop. The pointer is
 * into the caller's buffer; no copy is made. Returns -1 on a malformed
 * response. */
int fp_resp_parse_8e(const uint8_t *buf, int len,
                     uint16_t *subop,
                     const uint8_t **data, int *data_len);

/* The 0x01 GET_VERSION response carries a 7-byte sensor identity blob
 * at offset 2 (right after status). Writes those 7 bytes into out[0..6]. */
int fp_resp_parse_version(const uint8_t *buf, int len, uint8_t out[7]);

/* The 0x19 GET_VERSION_EX response carries a 4-byte serial (LE) at
 * offset 24. Writes it as a u32. */
int fp_resp_parse_serial(const uint8_t *buf, int len, uint32_t *serial_out);

/* The 0x8e/0x1a GET_STARTINFO payload (after fp_resp_parse_8e) contains
 * a handful of u32 fields right at the start — likely firmware version
 * triples and CRC. Returns the first three u32s for display. */
int fp_resp_parse_startinfo(const uint8_t *payload, int payload_len,
                            uint32_t out[3]);

/* The 0x3e CAPABILITIES response carries a 12-byte feature bitmap
 * followed by a count and a list of fixed-size entries. */
#define FP_CAPS_MAX_ENTRIES 8
struct fp_capabilities {
	uint8_t  bitmap[12];   /* feature bits, observed all-1s on 06cb:00e7 */
	int      n_entries;
	struct {
		uint8_t id;
		uint8_t type;
		uint8_t params[10];
	} entries[FP_CAPS_MAX_ENTRIES];
};
int fp_resp_parse_capabilities(const uint8_t *buf, int len,
                               struct fp_capabilities *out);

/* The 0x40 GET_CERTIFICATE_EX response carries a Synaptics-format
 * container that we have not yet fully reverse-engineered. What we DO
 * know:
 *   bytes 0..1     status_u16
 *   bytes 2..5     total_size_u32 (== 0x1000 in all observed captures)
 *   bytes 10..13   fixed type marker 01 00 04 00
 *   bytes 14..29   fixed 16-byte sensor-family GUID
 *   bytes 30..41   fixed 12-byte identifier
 *   bytes 42..N    structured data containing zero or more DPAPI blobs
 *                  (the Microsoft DPAPI provider GUID
 *                  {df9d8cd0-1501-11d1-8c7a-00c04fc297eb} appears once
 *                  per encrypted record)
 *   bytes N..end   0xff padding to fill the 4096-byte allocation
 *
 * Returns a structural summary rather than a full TLV walk. */
struct fp_cert_summary {
	int data_end_offset;     /* offset within `buf` where 0xff padding begins */
	int n_dpapi_blobs;       /* number of DPAPI GUID markers found */
	int dpapi_offsets[4];    /* offsets of those markers (within `buf`) */
};

int fp_cert_summarize(const uint8_t *buf, int len, struct fp_cert_summary *out);

#endif
