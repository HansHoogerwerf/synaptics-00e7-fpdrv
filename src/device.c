#include "device.h"

#include <stdio.h>
#include <string.h>

static int discover_endpoints(struct fp_device *dev)
{
	libusb_device *udev = libusb_get_device(dev->handle);
	struct libusb_config_descriptor *cfg = NULL;

	int rc = libusb_get_active_config_descriptor(udev, &cfg);
	if (rc != 0) {
		fprintf(stderr, "get_active_config_descriptor: %s\n", libusb_error_name(rc));
		return rc;
	}

	if (dev->interface >= cfg->bNumInterfaces) {
		fprintf(stderr, "interface %u out of range (have %u)\n",
			dev->interface, cfg->bNumInterfaces);
		libusb_free_config_descriptor(cfg);
		return LIBUSB_ERROR_NOT_FOUND;
	}

	const struct libusb_interface *iface = &cfg->interface[dev->interface];
	const struct libusb_interface_descriptor *alt = &iface->altsetting[0];

	for (int i = 0; i < alt->bNumEndpoints; i++) {
		const struct libusb_endpoint_descriptor *ep = &alt->endpoint[i];
		uint8_t type = ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
		uint8_t dir  = ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK;

		if (type == LIBUSB_TRANSFER_TYPE_BULK && dir == LIBUSB_ENDPOINT_IN) {
			dev->ep_bulk_in = ep->bEndpointAddress;
			dev->max_pkt_bulk_in = ep->wMaxPacketSize;
		} else if (type == LIBUSB_TRANSFER_TYPE_BULK && dir == LIBUSB_ENDPOINT_OUT) {
			dev->ep_bulk_out = ep->bEndpointAddress;
			dev->max_pkt_bulk_out = ep->wMaxPacketSize;
		} else if (type == LIBUSB_TRANSFER_TYPE_INTERRUPT && dir == LIBUSB_ENDPOINT_IN) {
			dev->ep_intr_in = ep->bEndpointAddress;
		}
	}

	libusb_free_config_descriptor(cfg);

	if (!dev->ep_bulk_in || !dev->ep_bulk_out) {
		fprintf(stderr, "missing required bulk endpoints (in=0x%02x out=0x%02x)\n",
			dev->ep_bulk_in, dev->ep_bulk_out);
		return LIBUSB_ERROR_NOT_FOUND;
	}

	return 0;
}

int fpdrv_usb_open(struct fp_device *dev, uint16_t vid, uint16_t pid)
{
	memset(dev, 0, sizeof(*dev));

	int rc = libusb_init(&dev->ctx);
	if (rc != 0) {
		fprintf(stderr, "libusb_init: %s\n", libusb_error_name(rc));
		return rc;
	}

	dev->handle = libusb_open_device_with_vid_pid(dev->ctx, vid, pid);
	if (!dev->handle) {
		fprintf(stderr, "device %04x:%04x not found\n", vid, pid);
		libusb_exit(dev->ctx);
		dev->ctx = NULL;
		return LIBUSB_ERROR_NO_DEVICE;
	}

	libusb_set_auto_detach_kernel_driver(dev->handle, 1);

	rc = libusb_claim_interface(dev->handle, dev->interface);
	if (rc != 0) {
		fprintf(stderr, "claim_interface: %s\n", libusb_error_name(rc));
		fpdrv_usb_close(dev);
		return rc;
	}

	rc = discover_endpoints(dev);
	if (rc != 0) {
		fpdrv_usb_close(dev);
		return rc;
	}

	dev->ops = &fp_transport_libusb;
	return 0;
}

void fpdrv_usb_close(struct fp_device *dev)
{
	if (dev->handle) {
		libusb_release_interface(dev->handle, dev->interface);
		libusb_close(dev->handle);
		dev->handle = NULL;
	}
	if (dev->ctx) {
		libusb_exit(dev->ctx);
		dev->ctx = NULL;
	}
}
