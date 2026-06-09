#include "transport.h"

#include <libusb-1.0/libusb.h>

/* Transport-layer functions are thin dispatchers over the device's backend
 * op table (see struct fp_transport_ops in device.h). They return libusb
 * error codes as-is and do NOT log to stderr — the caller has more context
 * about whether a given failure is expected (e.g. timeout on an optional
 * trailer read) or surprising. */

int fp_bulk_send(struct fp_device *dev, const void *data, int len, int *sent)
{
	return dev->ops->bulk_send(dev, data, len, sent);
}

int fp_bulk_recv(struct fp_device *dev, void *buf, int max_len, int *received)
{
	return dev->ops->bulk_recv(dev, buf, max_len, received);
}

int fp_intr_recv(struct fp_device *dev, void *buf, int max_len,
                 int *received, int timeout_ms)
{
	return dev->ops->intr_recv(dev, buf, max_len, received, timeout_ms);
}

int fp_control_transfer(struct fp_device *dev, uint8_t bmRequestType,
                        uint8_t bRequest, uint16_t wValue, uint16_t wIndex,
                        void *buf, int len, int timeout_ms)
{
	if (!dev->ops->control) return LIBUSB_ERROR_NOT_SUPPORTED;
	return dev->ops->control(dev, bmRequestType, bRequest, wValue, wIndex,
	                         buf, len, timeout_ms);
}

int fp_clear_halt(struct fp_device *dev, uint8_t endpoint)
{
	if (!dev->ops->clear_halt) return LIBUSB_ERROR_NOT_SUPPORTED;
	return dev->ops->clear_halt(dev, endpoint);
}
