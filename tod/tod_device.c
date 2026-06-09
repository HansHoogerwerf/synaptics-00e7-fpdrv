#include "tod_device.h"

#include <pwd.h>
#include <stdio.h>
#include <string.h>

/* libfprint-2-tod driver for the Synaptics 06cb:00e7 match-on-chip sensor.
 *
 * Every sensor operation is the blocking, linear protocol code in
 * src/proto.c. fprintd calls our vfuncs on its GMainContext; we run the
 * blocking work on a GTask worker thread (gusb's synchronous transfer API
 * spins its own private GMainContext per call, so there is no reentrancy
 * with fprintd's loop) and finish on the main thread via the
 * fpi_device_*_complete family.
 *
 * The FpPrint<->template link is the 16-byte sensor GUID: enroll stores it
 * in the print's "fpi-data" GVariant ("ay"), and identify/verify compare
 * the on-chip match GUID against the gallery prints' stored GUIDs. */

#define EP_BULK_OUT 0x01
#define EP_BULK_IN  0x81
#define EP_INTR_IN  0x83

struct _FpiDevice00e7 {
	FpDevice       parent;
	struct fp_device dev;
	struct fp_session sess;
	gboolean       session_open;
	gboolean       we_opened_usb;   /* did WE open the GUsbDevice, or did libfprint core? */

	/* transient result for the in-flight identify/verify. The sensor's
	 * misIdentifyMatch reports the matched *user* GUID (not the finger);
	 * we then resolve that user's finger GUIDs so verify/identify can test
	 * a requested print (which stores its finger GUID) for membership. */
	uint8_t        match_user_guid[16];
	uint8_t        match_finger;
	int            have_match;
	uint8_t        match_fingers[16][16];
	int            match_finger_count;
};

G_DEFINE_FINAL_TYPE(FpiDevice00e7, fpi_device_00e7, FP_TYPE_DEVICE)

GType fpi_tod_shared_driver_get_type(void)
{
	return FPI_TYPE_DEVICE_00E7;
}

static const FpIdEntry id_table[] = {
	{ .vid = 0x06cb, .pid = 0x00e7 },
	{ .vid = 0, .pid = 0 },
};

/* gusb's synchronous transfers dispatch their completion on the
 * thread-default GMainContext. On a GTask worker thread there is none, so
 * the internal wait would never wake and every transfer would time out.
 * Push a private context for the duration of the blocking proto work. */
static GMainContext *worker_ctx_push(void)
{
	GMainContext *c = g_main_context_new();
	g_main_context_push_thread_default(c);
	return c;
}

static void worker_ctx_pop(GMainContext *c)
{
	g_main_context_pop_thread_default(c);
	g_main_context_unref(c);
}

/* ---- FpPrint <-> GUID helpers ---- */

static FpPrint *make_print(FpDevice *dev, const uint8_t guid[16], uint8_t finger)
{
	FpPrint *p = fp_print_new(dev);
	fpi_print_set_type(p, FPI_PRINT_RAW);
	fpi_print_set_device_stored(p, TRUE);
	if (FP_FINGER_IS_VALID(finger))
		fp_print_set_finger(p, finger);
	GVariant *v = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, guid, 16, 1);
	g_object_set(p, "fpi-data", v, NULL);
	return p;
}

static gboolean print_guid(FpPrint *p, uint8_t out[16])
{
	GVariant *v = NULL;
	g_object_get(p, "fpi-data", &v, NULL);
	if (!v) return FALSE;
	gboolean ok = FALSE;
	if (g_variant_is_of_type(v, G_VARIANT_TYPE("ay"))) {
		gsize n = 0;
		const guint8 *d = g_variant_get_fixed_array(v, &n, 1);
		if (n == 16) { memcpy(out, d, 16); ok = TRUE; }
	}
	g_variant_unref(v);
	return ok;
}

/* ---- enroll progress (worker thread -> main thread) ---- */

struct progress_msg { FpDevice *dev; int stages; };

static gboolean progress_idle(gpointer data)
{
	struct progress_msg *m = data;
	fpi_device_enroll_progress(m->dev, m->stages, NULL, NULL);
	return G_SOURCE_REMOVE;
}

struct enroll_ctx {
	FpiDevice00e7 *self;
	GCancellable  *cancel;
	uint8_t        finger_subtype;
	uint8_t        sid[28];
	int            sid_len;
	uint8_t        guid[16];
};

static int enroll_progress_cb(int samples, void *user)
{
	struct enroll_ctx *e = user;
	struct progress_msg *m = g_new0(struct progress_msg, 1);
	m->dev = FP_DEVICE(e->self);
	m->stages = samples;
	g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT, progress_idle, m, g_free);
	return (e->cancel && g_cancellable_is_cancelled(e->cancel)) ? 1 : 0;
}

/* ---- probe ---- */

static void dev_probe(FpDevice *device)
{
	GUsbDevice *usb = fpi_device_get_usb_device(device);
	const gchar *serial = usb ? g_usb_device_get_platform_id(usb) : NULL;
	fpi_device_probe_complete(device, serial, "Synaptics 06cb:00e7", NULL);
}

/* ---- open ---- */

static void open_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)data; (void)cancel;
	FpiDevice00e7 *self = src;
	GMainContext *wctx = worker_ctx_push();
	int rc = fp_proto_open(&self->sess, &self->dev);
	worker_ctx_pop(wctx);
	if (rc != 0) {
		g_task_return_error(task, fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
			"pairing / TLS handshake failed (rc=%d) — is pairdata installed?", rc));
		return;
	}
	self->session_open = TRUE;
	g_task_return_boolean(task, TRUE);
}

static void open_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	GError *err = NULL;
	g_task_propagate_boolean(G_TASK(res), &err);
	fpi_device_open_complete(FP_DEVICE(src), err);
}

static void dev_open(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GUsbDevice *usb = fpi_device_get_usb_device(device);
	GError *err = NULL;

	/* libfprint's core opens the GUsbDevice for USB-type devices before
	 * invoking this vfunc, so g_usb_device_open normally reports ALREADY_OPEN
	 * — core owns the handle and will close it after our ->close. Only when
	 * our open actually succeeds do WE own (and must later close) the handle.
	 * Closing a core-owned handle ourselves makes core's later close fail with
	 * "device has not been opened" (surfaced to fprintd as a Release error). */
	self->we_opened_usb = FALSE;
	if (!g_usb_device_open(usb, &err)) {
		if (g_error_matches(err, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_ALREADY_OPEN)) {
			g_clear_error(&err);
		} else {
			fpi_device_open_complete(device, err);
			return;
		}
	} else {
		self->we_opened_usb = TRUE;
	}
	/* gusb has no clear-halt; a prior aborted session can leave the sensor
	 * mid-TLS with a stalled bulk-IN endpoint, making the cleartext
	 * GET_VERSION time out. A port reset restores a clean post-plug state.
	 * Must precede claim_interface (the reset drops any claim). */
	if (!g_usb_device_reset(usb, &err)) {
		fpi_device_open_complete(device, err);
		return;
	}
	if (!g_usb_device_claim_interface(usb, 0, G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &err)) {
		fpi_device_open_complete(device, err);
		return;
	}

	memset(&self->dev, 0, sizeof(self->dev));
	self->dev.ops         = &fp_transport_gusb;
	self->dev.backend     = usb;
	self->dev.interface   = 0;
	self->dev.ep_bulk_out = EP_BULK_OUT;
	self->dev.ep_bulk_in  = EP_BULK_IN;
	self->dev.ep_intr_in  = EP_INTR_IN;

	GTask *task = g_task_new(device, fpi_device_get_cancellable(device), open_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, open_thread);
	g_object_unref(task);
}

/* ---- close ---- */

static void close_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)data; (void)cancel;
	FpiDevice00e7 *self = src;
	if (self->session_open) {
		fp_proto_close(&self->sess);
		self->session_open = FALSE;
	}
	g_task_return_boolean(task, TRUE);
}

static void close_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	GError *err = NULL;
	g_task_propagate_boolean(G_TASK(res), &err);

	FpDevice *device = FP_DEVICE(src);
	FpiDevice00e7 *self = FPI_DEVICE_00E7(src);
	GUsbDevice *usb = fpi_device_get_usb_device(device);
	if (usb) {
		g_usb_device_release_interface(usb, 0, 0, NULL);
		if (self->we_opened_usb)
			g_usb_device_close(usb, NULL);
	}
	fpi_device_close_complete(device, err);
}

static void dev_close(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GTask *task = g_task_new(device, NULL, close_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, close_thread);
	g_object_unref(task);
}

/* ---- enroll ---- */

static void enroll_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)src; (void)cancel;
	struct enroll_ctx *e = data;
	GMainContext *wctx = worker_ctx_push();
	int rc = fp_proto_enroll(&e->self->sess, e->finger_subtype,
	                         e->sid_len ? e->sid : NULL, e->sid_len,
	                         enroll_progress_cb, e, e->guid);
	worker_ctx_pop(wctx);
	if (rc == 0)       g_task_return_boolean(task, TRUE);
	else if (rc == -2) g_task_return_error(task,
		fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL, "enrollment did not complete"));
	else               g_task_return_error(task,
		fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "enroll protocol error (rc=%d)", rc));
}

static void enroll_done(GObject *src, GAsyncResult *res, gpointer u)
{
	struct enroll_ctx *e = u;
	GError *err = NULL;
	FpPrint *print = NULL;

	if (g_task_propagate_boolean(G_TASK(res), &err)) {
		fpi_device_get_enroll_data(FP_DEVICE(src), &print);
		fpi_print_set_type(print, FPI_PRINT_RAW);
		fpi_print_set_device_stored(print, TRUE);
		GVariant *v = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, e->guid, 16, 1);
		g_object_set(print, "fpi-data", v, NULL);
	}
	fpi_device_enroll_complete(FP_DEVICE(src), print ? g_object_ref(print) : NULL, err);
	g_free(e);
}

static void dev_enroll(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	FpPrint *print = NULL;
	fpi_device_get_enroll_data(device, &print);

	struct enroll_ctx *e = g_new0(struct enroll_ctx, 1);
	e->self = self;
	e->cancel = fpi_device_get_cancellable(device);
	e->finger_subtype = print ? (uint8_t)fp_print_get_finger(print) : 0;

	/* Bind the enrolling Linux user's SID so distinct users land in
	 * distinct on-chip user objects. */
	uint32_t uid = 0;
	const gchar *uname = print ? fp_print_get_username(print) : NULL;
	if (uname) {
		struct passwd *pw = getpwnam(uname);
		if (pw) uid = (uint32_t)pw->pw_uid;
	}
	e->sid_len = fp_proto_make_linux_sid(uid, e->sid);

	GTask *task = g_task_new(device, e->cancel, enroll_done, e);
	g_task_set_task_data(task, e, NULL);
	g_task_run_in_thread(task, enroll_thread);
	g_object_unref(task);
}

/* ---- identify / verify (shared capture+match) ---- */

/* Collect the finger GUIDs belonging to the matched user. */
static int match_finger_collect_cb(const uint8_t user_guid[16],
                                   const uint8_t finger_guid[16],
                                   uint8_t finger_subtype, void *user)
{
	(void)finger_subtype;
	FpiDevice00e7 *self = user;
	if (memcmp(user_guid, self->match_user_guid, 16) == 0 &&
	    self->match_finger_count < 16) {
		memcpy(self->match_fingers[self->match_finger_count++], finger_guid, 16);
	}
	return 0;
}

/* Worker outcome codes carried back via g_task_return_int:
 *   1  = match (match_user_guid + match_fingers[] set)
 *   0  = no match
 *  -1  = no finger presented within the window (retryable)
 * A fatal protocol error is returned via g_task_return_error instead. */
static void match_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)data;
	FpiDevice00e7 *self = src;
	self->have_match = 0;
	self->match_finger_count = 0;
	GMainContext *wctx = worker_ctx_push();
	/* fp_proto_identify waits ~6s per call for a finger; loop a few times
	 * so the user gets a generous press window. Stop on a real outcome
	 * (match / no-match / fatal) or when fprintd cancels the operation. */
	int rc = -1;
	for (int attempt = 0; attempt < 5; attempt++) {
		if (g_cancellable_is_cancelled(cancel)) break;
		rc = fp_proto_identify(&self->sess, self->match_user_guid, &self->match_finger);
		if (rc != -1) break;
	}
	/* The sensor reported the matched user; resolve that user's finger
	 * GUIDs so the caller can test a requested print for membership. */
	if (rc == 1)
		fp_proto_list(&self->sess, match_finger_collect_cb, self);
	worker_ctx_pop(wctx);
	if (rc == -2)
		g_task_return_error(task, fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
			"capture / on-chip match failed"));
	else { self->have_match = rc; g_task_return_int(task, rc); }
}

/* True if `p`'s stored finger GUID belongs to the just-matched user. */
static gboolean print_in_match_set(FpiDevice00e7 *self, FpPrint *p)
{
	uint8_t g[16];
	if (!print_guid(p, g)) return FALSE;
	for (int i = 0; i < self->match_finger_count; i++)
		if (memcmp(g, self->match_fingers[i], 16) == 0) return TRUE;
	return FALSE;
}

static void identify_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	FpDevice *device = FP_DEVICE(src);
	FpiDevice00e7 *self = FPI_DEVICE_00E7(src);
	GError *err = NULL;

	gint rc = g_task_propagate_int(G_TASK(res), &err);
	if (err) { fpi_device_identify_complete(device, err); return; }

	/* No finger within the window: a retry, not a result. Report it via
	 * the retry arg of identify_report (NOT identify_complete, which
	 * libfprint rejects for retry errors) then complete cleanly. */
	if (rc < 0) {
		fpi_device_identify_report(device, NULL, NULL,
			fpi_device_retry_new(FP_DEVICE_RETRY_GENERAL));
		fpi_device_identify_complete(device, NULL);
		return;
	}

	FpPrint *match = NULL;
	if (rc == 1) {
		GPtrArray *gallery = NULL;
		fpi_device_get_identify_data(device, &gallery);
		for (guint i = 0; gallery && i < gallery->len; i++) {
			FpPrint *cand = g_ptr_array_index(gallery, i);
			if (print_in_match_set(self, cand)) {
				match = cand;
				break;
			}
		}
	}

	/* `match` (when set) is a gallery print owned by the caller and stays
	 * alive through fp_device_identify_finish; the scanned-print arg is left
	 * NULL (a freshly-made print unreffed here would be use-after-free'd by
	 * the finish callback). Mirrors the upstream tudor TOD driver. */
	fpi_device_identify_report(device, match, NULL, NULL);
	fpi_device_identify_complete(device, NULL);
}

static void dev_identify(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GTask *task = g_task_new(device, fpi_device_get_cancellable(device), identify_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, match_thread);
	g_object_unref(task);
}

static void verify_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	FpDevice *device = FP_DEVICE(src);
	FpiDevice00e7 *self = FPI_DEVICE_00E7(src);
	GError *err = NULL;

	gint rc = g_task_propagate_int(G_TASK(res), &err);
	if (err) { fpi_device_verify_complete(device, err); return; }

	/* No finger within the window: a retry, not a result. Report it via
	 * the retry arg of verify_report (NOT verify_complete, which libfprint
	 * rejects for retry errors) then complete cleanly. */
	if (rc < 0) {
		fpi_device_verify_report(device, FPI_MATCH_ERROR, NULL,
			fpi_device_retry_new(FP_DEVICE_RETRY_GENERAL));
		fpi_device_verify_complete(device, NULL);
		return;
	}

	FpPrint *enrolled = NULL;
	fpi_device_get_verify_data(device, &enrolled);

	FpiMatchResult result = FPI_MATCH_FAIL;
	if (rc == 1 && enrolled && print_in_match_set(self, enrolled))
		result = FPI_MATCH_SUCCESS;

	fpi_device_verify_report(device, result, NULL, NULL);
	fpi_device_verify_complete(device, NULL);
}

static void dev_verify(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GTask *task = g_task_new(device, fpi_device_get_cancellable(device), verify_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, match_thread);
	g_object_unref(task);
}

/* ---- list ---- */

struct list_collect { GPtrArray *prints; FpDevice *dev; };

static int list_cb(const uint8_t user_guid[16], const uint8_t finger_guid[16],
                   uint8_t finger_subtype, void *user)
{
	(void)user_guid;
	struct list_collect *c = user;
	g_ptr_array_add(c->prints, make_print(c->dev, finger_guid, finger_subtype));
	return 0;
}

static void list_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)data; (void)cancel;
	FpiDevice00e7 *self = src;
	struct list_collect c = {
		.prints = g_ptr_array_new_with_free_func(g_object_unref),
		.dev = FP_DEVICE(self),
	};
	GMainContext *wctx = worker_ctx_push();
	int rc = fp_proto_list(&self->sess, list_cb, &c);
	worker_ctx_pop(wctx);
	if (rc < 0) {
		g_ptr_array_unref(c.prints);
		g_task_return_error(task, fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
			"failed to enumerate stored templates"));
		return;
	}
	g_task_return_pointer(task, c.prints, (GDestroyNotify)g_ptr_array_unref);
}

static void list_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	GError *err = NULL;
	GPtrArray *prints = g_task_propagate_pointer(G_TASK(res), &err);
	fpi_device_list_complete(FP_DEVICE(src), prints, err);
}

static void dev_list(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GTask *task = g_task_new(device, fpi_device_get_cancellable(device), list_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, list_thread);
	g_object_unref(task);
}

/* ---- delete ---- */

struct del_find { uint8_t target[16]; uint8_t user[16]; int found; };

static int del_find_cb(const uint8_t user_guid[16], const uint8_t finger_guid[16],
                       uint8_t finger_subtype, void *user)
{
	(void)finger_subtype;
	struct del_find *f = user;
	if (memcmp(finger_guid, f->target, 16) == 0) {
		memcpy(f->user, user_guid, 16);
		f->found = 1;
		return 1;
	}
	return 0;
}

static void delete_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)cancel;
	FpiDevice00e7 *self = src;
	struct del_find *f = data;

	GMainContext *wctx = worker_ctx_push();
	int found = (fp_proto_list(&self->sess, del_find_cb, f) >= 0 && f->found);
	int del_rc = found ? fp_proto_delete(&self->sess, f->user, f->target) : 0;
	worker_ctx_pop(wctx);

	if (!found) {
		g_task_return_error(task, fpi_device_error_new(FP_DEVICE_ERROR_DATA_NOT_FOUND));
		return;
	}
	if (del_rc != 0) {
		g_task_return_error(task, fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
			"failed to delete template"));
		return;
	}
	g_task_return_boolean(task, TRUE);
}

static void delete_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	GError *err = NULL;
	g_task_propagate_boolean(G_TASK(res), &err);
	fpi_device_delete_complete(FP_DEVICE(src), err);
}

static void dev_delete(FpDevice *device)
{
	FpPrint *print = NULL;
	fpi_device_get_delete_data(device, &print);

	struct del_find *f = g_new0(struct del_find, 1);
	if (!print || !print_guid(print, f->target)) {
		g_free(f);
		fpi_device_delete_complete(device, fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID));
		return;
	}
	GTask *task = g_task_new(device, NULL, delete_done, NULL);
	g_task_set_task_data(task, f, g_free);
	g_task_run_in_thread(task, delete_thread);
	g_object_unref(task);
}

/* ---- clear_storage ---- */

static void clear_thread(GTask *task, gpointer src, gpointer data, GCancellable *cancel)
{
	(void)data; (void)cancel;
	FpiDevice00e7 *self = src;
	GMainContext *wctx = worker_ctx_push();
	int rc = fp_proto_clear(&self->sess);
	worker_ctx_pop(wctx);
	if (rc != 0)
		g_task_return_error(task, fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
			"failed to clear storage"));
	else
		g_task_return_boolean(task, TRUE);
}

static void clear_done(GObject *src, GAsyncResult *res, gpointer u)
{
	(void)u;
	GError *err = NULL;
	g_task_propagate_boolean(G_TASK(res), &err);
	fpi_device_clear_storage_complete(FP_DEVICE(src), err);
}

static void dev_clear_storage(FpDevice *device)
{
	FpiDevice00e7 *self = FPI_DEVICE_00E7(device);
	GTask *task = g_task_new(device, NULL, clear_done, NULL);
	g_task_set_task_data(task, self, NULL);
	g_task_run_in_thread(task, clear_thread);
	g_object_unref(task);
}

/* ---- suspend / resume ----
 *
 * Called only while an interactive action (verify/identify/enroll/capture) is
 * in flight and the system is about to sleep / has woken. The sensor is a
 * match-on-chip device behind a per-boot paired TLS session; an S3 cycle
 * powers the sensor down and re-enumerates it, so the session cannot be
 * carried across suspend. We therefore decline to suspend the running action
 * (FP_DEVICE_ERROR_NOT_SUPPORTED), which makes libfprint abort it; fprintd
 * then reopens the device for the next attempt and dev_open rebuilds the
 * session (and recovers a stale handle). This mirrors the upstream synaptics
 * driver's handling of actions it cannot carry across suspend. These vfuncs
 * run on fprintd's main context, so they must not do blocking USB work. */
static void dev_suspend(FpDevice *device)
{
	fpi_device_suspend_complete(device,
		fpi_device_error_new(FP_DEVICE_ERROR_NOT_SUPPORTED));
}

static void dev_resume(FpDevice *device)
{
	fpi_device_resume_complete(device, NULL);
}

/* ---- GObject boilerplate ---- */

static void fpi_device_00e7_init(FpiDevice00e7 *self)
{
	self->session_open = FALSE;
}

static void fpi_device_00e7_class_init(FpiDevice00e7Class *klass)
{
	FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);

	dev_class->id = "fpdrv_00e7";
	dev_class->full_name = "Synaptics 06cb:00e7 (fpdrv match-on-chip)";
	dev_class->type = FP_DEVICE_TYPE_USB;
	dev_class->id_table = id_table;
	dev_class->nr_enroll_stages = 10;
	dev_class->scan_type = FP_SCAN_TYPE_PRESS;

	dev_class->probe = dev_probe;
	dev_class->open = dev_open;
	dev_class->close = dev_close;
	dev_class->enroll = dev_enroll;
	dev_class->verify = dev_verify;
	dev_class->identify = dev_identify;
	dev_class->list = dev_list;
	dev_class->delete = dev_delete;
	dev_class->clear_storage = dev_clear_storage;
	dev_class->suspend = dev_suspend;
	dev_class->resume = dev_resume;

	fpi_device_class_auto_initialize_features(dev_class);
}
