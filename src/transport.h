#ifndef FPDRV_TRANSPORT_H
#define FPDRV_TRANSPORT_H

#include "device.h"
#include <stddef.h>

/* Default timeout for bulk transfers, in milliseconds. The sensor normally
 * responds within ~1ms, but the final enroll AddImage consolidates the
 * template on-chip and can take several seconds; a recv timeout mid-stream
 * desyncs the AES-GCM record counters and kills the TLS channel, so keep
 * this generous. */
#define FP_BULK_TIMEOUT_MS 10000

/* Send `len` bytes from `data` on the bulk OUT endpoint.
 * Returns 0 on success or a libusb error code. On success, sets *sent
 * (if non-NULL) to the number of bytes transferred (always == len for
 * a successful transfer). */
int fp_bulk_send(struct fp_device *dev, const void *data, int len, int *sent);

/* Receive up to `max_len` bytes into `buf` from the bulk IN endpoint.
 * Returns 0 on success or a libusb error code. On success, sets *received
 * to the number of bytes actually received. */
int fp_bulk_recv(struct fp_device *dev, void *buf, int max_len, int *received);

/* Read up to `max_len` bytes from the interrupt IN endpoint (EP 0x83 on
 * the 06cb:00e7 sensor). Per proto.txt, the sensor sends 8-byte event
 * messages on this endpoint signalling frame-ready (byte 5 = frame_index
 * & 0x7) and event-pending (byte 6 = event_seq & 0x1f). Used between
 * frame_acq and frame_read to wait for the sensor to finish capturing
 * each frame. Returns 0 / received bytes on success, or libusb error
 * (notably LIBUSB_ERROR_TIMEOUT if no event arrives within timeout). */
int fp_intr_recv(struct fp_device *dev, void *buf, int max_len,
                 int *received, int timeout_ms);

/* Issue a USB control transfer on endpoint 0. Used for the vendor "get
 * TLS status" read (0xc0/0x14) and for clearing endpoint halts. Returns
 * the number of bytes transferred (>=0) or a negative libusb error code. */
int fp_control_transfer(struct fp_device *dev, uint8_t bmRequestType,
                        uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
                        void *buf, int len, int timeout_ms);

/* Clear a halt/stall condition on the given endpoint
 * (CLEAR_FEATURE ENDPOINT_HALT). Returns 0 on success or a libusb error. */
int fp_clear_halt(struct fp_device *dev, uint8_t endpoint);

#endif
