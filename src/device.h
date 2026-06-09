#ifndef FPDRV_DEVICE_H
#define FPDRV_DEVICE_H

#include <libusb-1.0/libusb.h>
#include <stdint.h>

struct fp_device;

/* Transport backend vtable. The protocol code talks to the sensor only
 * through fp_bulk_send/recv, fp_intr_recv, fp_control_transfer and
 * fp_clear_halt (see transport.h); those dispatch to one of these op
 * tables. Two backends exist:
 *   - transport_libusb.c : synchronous libusb (the `fpdrv` CLI)
 *   - transport_gusb.c   : GUSB transfers on libfprint's GUsbDevice (the
 *                          libfprint-2-tod driver)
 * All ops return 0 / a count on success and a negative libusb-style error
 * code on failure (the GUSB backend maps GError to the nearest libusb
 * code so existing `libusb_error_name()` logging keeps working). */
struct fp_transport_ops {
	int (*bulk_send)(struct fp_device *dev, const void *data, int len, int *sent);
	int (*bulk_recv)(struct fp_device *dev, void *buf, int max_len, int *received);
	int (*intr_recv)(struct fp_device *dev, void *buf, int max_len,
	                 int *received, int timeout_ms);
	int (*control)(struct fp_device *dev, uint8_t bmRequestType, uint8_t bRequest,
	               uint16_t wValue, uint16_t wIndex, void *buf, int len,
	               int timeout_ms);
	int (*clear_halt)(struct fp_device *dev, uint8_t endpoint);
};

/* Endpoints on the Synaptics 06cb:00e7 sensor are discovered from the
 * active interface's endpoint descriptors at open time. interface defaults
 * to 0 (the only one on this sensor). */
struct fp_device {
	const struct fp_transport_ops *ops;     /* transport backend dispatch */
	void                  *backend;          /* GUsbDevice* for the GUSB backend */
	libusb_context        *ctx;              /* libusb backend only */
	libusb_device_handle  *handle;           /* libusb backend only */
	uint8_t                interface;
	uint8_t                ep_bulk_in;       /* 0x81 on 06cb:00e7 */
	uint8_t                ep_bulk_out;      /* 0x01 on 06cb:00e7 */
	uint8_t                ep_intr_in;       /* 0x83 on 06cb:00e7, 0 if not present */
	uint16_t               max_pkt_bulk_in;
	uint16_t               max_pkt_bulk_out;
};

/* libusb-backed open/close (the CLI). Sets dev->ops to the libusb backend. */
int  fpdrv_usb_open(struct fp_device *dev, uint16_t vid, uint16_t pid);
void fpdrv_usb_close(struct fp_device *dev);

/* The libusb transport op table, defined in transport_libusb.c. */
extern const struct fp_transport_ops fp_transport_libusb;

#endif
