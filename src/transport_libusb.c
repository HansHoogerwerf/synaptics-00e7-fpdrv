#include "transport.h"

#include <libusb-1.0/libusb.h>

/* Synchronous libusb backend for the `fpdrv` CLI. Registered into
 * dev->ops by fp_device_open (device.c). */

static int lu_bulk_send(struct fp_device *dev, const void *data, int len, int *sent)
{
	int transferred = 0;
	int rc = libusb_bulk_transfer(dev->handle, dev->ep_bulk_out,
		(unsigned char *)data, len, &transferred, FP_BULK_TIMEOUT_MS);
	if (rc != 0) return rc;
	if (sent) *sent = transferred;
	return 0;
}

static int lu_bulk_recv(struct fp_device *dev, void *buf, int max_len, int *received)
{
	int transferred = 0;
	int rc = libusb_bulk_transfer(dev->handle, dev->ep_bulk_in,
		(unsigned char *)buf, max_len, &transferred, FP_BULK_TIMEOUT_MS);
	if (rc != 0) return rc;
	if (received) *received = transferred;
	return 0;
}

static int lu_intr_recv(struct fp_device *dev, void *buf, int max_len,
                        int *received, int timeout_ms)
{
	if (dev->ep_intr_in == 0) return LIBUSB_ERROR_NOT_FOUND;
	int transferred = 0;
	int rc = libusb_interrupt_transfer(dev->handle, dev->ep_intr_in,
		(unsigned char *)buf, max_len, &transferred, timeout_ms);
	if (rc != 0) return rc;
	if (received) *received = transferred;
	return 0;
}

static int lu_control(struct fp_device *dev, uint8_t bmRequestType, uint8_t bRequest,
                      uint16_t wValue, uint16_t wIndex, void *buf, int len,
                      int timeout_ms)
{
	return libusb_control_transfer(dev->handle, bmRequestType, bRequest,
		wValue, wIndex, (unsigned char *)buf, (uint16_t)len, timeout_ms);
}

static int lu_clear_halt(struct fp_device *dev, uint8_t endpoint)
{
	return libusb_clear_halt(dev->handle, endpoint);
}

const struct fp_transport_ops fp_transport_libusb = {
	.bulk_send  = lu_bulk_send,
	.bulk_recv  = lu_bulk_recv,
	.intr_recv  = lu_intr_recv,
	.control    = lu_control,
	.clear_halt = lu_clear_halt,
};
