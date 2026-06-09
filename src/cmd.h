#ifndef FPDRV_CMD_H
#define FPDRV_CMD_H

#include "device.h"
#include <stddef.h>
#include <stdint.h>

/* Maximum size of any single bulk transfer we expect from the sensor.
 * The largest in the captured cleartext phase is the 4096-byte
 * GET_CERTIFICATE_EX response. Round up for safety. */
#define FP_RESP_MAX 8192

/* Send a cleartext command and read a single response.
 *
 * The "command" is the raw bytes to write on bulk OUT (cmd ID + any
 * arguments). The response is read in full on bulk IN, including the
 * 2-byte status word and any payload. Returns 0 on success, *resp_len
 * set to the number of bytes read.
 *
 * Note: some commands produce multiple bulk-IN packets (e.g. 0x40
 * GET_CERTIFICATE_EX returns a 4096-byte chunk followed by a small
 * trailer). This helper only does ONE read — callers that expect
 * multi-packet responses must call fp_bulk_recv again. */
int fp_cmd_exec(struct fp_device *dev,
                const void *cmd, int cmd_len,
                void *resp, int resp_max, int *resp_len);

/* Run the Phase 1 cleartext initialization queries, printing each one's
 * response in hex with annotation, to verify our protocol understanding
 * end-to-end. Returns 0 if every command succeeded. */
int fp_cmd_init_dump(struct fp_device *dev);

/* Run only the basic init queries (no CAPABILITIES, no GET_CERTIFICATE_EX) —
 * matches the second init pass in try-6 and libtudor captures. Quiet (no
 * per-step printing). */
int fp_cmd_init_basic(struct fp_device *dev);

#endif
