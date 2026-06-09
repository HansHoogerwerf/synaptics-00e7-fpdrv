#include "transport.h"
#include "device.h"

#include <stdio.h>
#include <gusb.h>
#include <libusb-1.0/libusb.h>

/* GUSB transport backend for the libfprint-2-tod driver. dev->backend is
 * a GUsbDevice* (libfprint's handle for the sensor).
 *
 * The protocol code (src/proto.c) is linear and blocking and runs on a
 * GTask worker thread. We must NOT use gusb's *synchronous* transfer
 * helpers here: their internal GMainLoop deadlocks (g_cond_wait on context
 * acquisition) when driven from a worker thread under libfprint's context.
 * Instead each transfer drives gusb's *async* API on a private
 * GMainContext + GMainLoop pushed as thread-default for the call, so the
 * async completion (a GTask that captures the thread-default context at
 * submit time) is dispatched by the very loop we run, then quits it.
 *
 * GError is mapped to the nearest libusb error code so the protocol code's
 * existing `rc == LIBUSB_ERROR_TIMEOUT` checks and libusb_error_name()
 * logging keep working unchanged. */

static int map_gerror(GError *err)
{
	int rc = LIBUSB_ERROR_OTHER;
	if (!err) return rc;
	if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
		rc = LIBUSB_ERROR_TIMEOUT;
	else if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE))
		rc = LIBUSB_ERROR_NO_DEVICE;
	else if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NOT_SUPPORTED))
		rc = LIBUSB_ERROR_NOT_SUPPORTED;
	else if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_PERMISSION_DENIED))
		rc = LIBUSB_ERROR_ACCESS;
	else if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_BUSY))
		rc = LIBUSB_ERROR_BUSY;
	else
		rc = LIBUSB_ERROR_IO;
	g_error_free(err);
	return rc;
}

#define GU_DBG(...) do { if (g_getenv("FPDRV_GUSB_DEBUG")) { \
	fprintf(stderr, "gusb: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* Per-call async->sync bridge. */
struct gu_wait {
	GMainLoop    *loop;
	GAsyncResult *res;
};

static void gu_done(GObject *src, GAsyncResult *res, gpointer user)
{
	(void)src;
	struct gu_wait *w = user;
	w->res = g_object_ref(res);
	g_main_loop_quit(w->loop);
}

static GMainLoop *gu_begin(GMainContext **ctx, struct gu_wait *w)
{
	*ctx = g_main_context_new();
	g_main_context_push_thread_default(*ctx);
	w->res = NULL;
	w->loop = g_main_loop_new(*ctx, FALSE);
	return w->loop;
}

static void gu_finish(GMainContext *ctx, struct gu_wait *w)
{
	g_main_loop_unref(w->loop);
	if (w->res) g_object_unref(w->res);
	g_main_context_pop_thread_default(ctx);
	g_main_context_unref(ctx);
}

static int gu_bulk_send(struct fp_device *dev, const void *data, int len, int *sent)
{
	GUsbDevice *gdev = dev->backend;
	GMainContext *ctx;
	struct gu_wait w;
	GU_DBG("bulk_send ep=0x%02x len=%d ...", dev->ep_bulk_out, len);
	gu_begin(&ctx, &w);
	g_usb_device_bulk_transfer_async(gdev, dev->ep_bulk_out, (guint8 *)data,
		(gsize)len, FP_BULK_TIMEOUT_MS, NULL, gu_done, &w);
	g_main_loop_run(w.loop);
	GError *err = NULL;
	gssize n = g_usb_device_bulk_transfer_finish(gdev, w.res, &err);
	GU_DBG("bulk_send done n=%zd err=%s", n, err ? err->message : "(none)");
	gu_finish(ctx, &w);
	if (n < 0) return map_gerror(err);
	if (sent) *sent = (int)n;
	return 0;
}

static int gu_bulk_recv(struct fp_device *dev, void *buf, int max_len, int *received)
{
	GUsbDevice *gdev = dev->backend;
	GMainContext *ctx;
	struct gu_wait w;
	GU_DBG("bulk_recv ep=0x%02x max=%d ...", dev->ep_bulk_in, max_len);
	gu_begin(&ctx, &w);
	g_usb_device_bulk_transfer_async(gdev, dev->ep_bulk_in, (guint8 *)buf,
		(gsize)max_len, FP_BULK_TIMEOUT_MS, NULL, gu_done, &w);
	g_main_loop_run(w.loop);
	GError *err = NULL;
	gssize n = g_usb_device_bulk_transfer_finish(gdev, w.res, &err);
	GU_DBG("bulk_recv done n=%zd err=%s", n, err ? err->message : "(none)");
	gu_finish(ctx, &w);
	if (n < 0) return map_gerror(err);
	if (received) *received = (int)n;
	return 0;
}

static int gu_intr_recv(struct fp_device *dev, void *buf, int max_len,
                        int *received, int timeout_ms)
{
	GUsbDevice *gdev = dev->backend;
	if (dev->ep_intr_in == 0) return LIBUSB_ERROR_NOT_FOUND;
	GMainContext *ctx;
	struct gu_wait w;
	gu_begin(&ctx, &w);
	g_usb_device_interrupt_transfer_async(gdev, dev->ep_intr_in, (guint8 *)buf,
		(gsize)max_len, (guint)timeout_ms, NULL, gu_done, &w);
	g_main_loop_run(w.loop);
	GError *err = NULL;
	gssize n = g_usb_device_interrupt_transfer_finish(gdev, w.res, &err);
	gu_finish(ctx, &w);
	if (n < 0) return map_gerror(err);
	if (received) *received = (int)n;
	return 0;
}

static int gu_control(struct fp_device *dev, uint8_t bmRequestType, uint8_t bRequest,
                      uint16_t wValue, uint16_t wIndex, void *buf, int len,
                      int timeout_ms)
{
	GUsbDevice *gdev = dev->backend;
	GUsbDeviceDirection dir = (bmRequestType & 0x80)
		? G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST
		: G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE;
	GUsbDeviceRequestType rtype;
	switch ((bmRequestType >> 5) & 0x3) {
		case 1:  rtype = G_USB_DEVICE_REQUEST_TYPE_CLASS;    break;
		case 2:  rtype = G_USB_DEVICE_REQUEST_TYPE_VENDOR;   break;
		default: rtype = G_USB_DEVICE_REQUEST_TYPE_STANDARD; break;
	}
	GUsbDeviceRecipient recip;
	switch (bmRequestType & 0x1f) {
		case 1:  recip = G_USB_DEVICE_RECIPIENT_INTERFACE; break;
		case 2:  recip = G_USB_DEVICE_RECIPIENT_ENDPOINT;  break;
		case 3:  recip = G_USB_DEVICE_RECIPIENT_OTHER;     break;
		default: recip = G_USB_DEVICE_RECIPIENT_DEVICE;    break;
	}
	GMainContext *ctx;
	struct gu_wait w;
	GU_DBG("control bmReq=0x%02x bReq=0x%02x wVal=0x%04x wIdx=0x%04x len=%d ...",
		bmRequestType, bRequest, wValue, wIndex, len);
	gu_begin(&ctx, &w);
	g_usb_device_control_transfer_async(gdev, dir, rtype, recip, bRequest,
		wValue, wIndex, (guint8 *)buf, (gsize)len, (guint)timeout_ms,
		NULL, gu_done, &w);
	g_main_loop_run(w.loop);
	GError *err = NULL;
	gssize n = g_usb_device_control_transfer_finish(gdev, w.res, &err);
	GU_DBG("control done n=%zd err=%s", n, err ? err->message : "(none)");
	gu_finish(ctx, &w);
	if (n < 0) return map_gerror(err);
	return (int)n;
}

static int gu_clear_halt(struct fp_device *dev, uint8_t endpoint)
{
	/* CLEAR_FEATURE(ENDPOINT_HALT=0) on the given endpoint. */
	return gu_control(dev, 0x02 /* OUT|standard|endpoint */, 0x01 /* CLEAR_FEATURE */,
	                  0x0000 /* ENDPOINT_HALT */, endpoint, NULL, 0, 1000) < 0
		? LIBUSB_ERROR_IO : 0;
}

const struct fp_transport_ops fp_transport_gusb = {
	.bulk_send  = gu_bulk_send,
	.bulk_recv  = gu_bulk_recv,
	.intr_recv  = gu_intr_recv,
	.control    = gu_control,
	.clear_halt = gu_clear_halt,
};
