#ifndef FPDRV_TOD_DEVICE_H
#define FPDRV_TOD_DEVICE_H

#include <fprint.h>
#include <fpi-device.h>

#include "device.h"   /* src/device.h: struct fp_device + transport vtable */
#include "proto.h"    /* src/proto.h:  struct fp_session + fp_proto_* ops  */

/* GUSB transport op table (tod/transport_gusb.c). The CLI uses
 * fp_transport_libusb; the TOD driver swaps in this GUsbDevice-backed
 * backend so the very same proto.c drives the sensor under fprintd. */
extern const struct fp_transport_ops fp_transport_gusb;

/* Final FpDevice subclass for the Synaptics 06cb:00e7 match-on-chip
 * sensor. fpi_tod_shared_driver_get_type() (the TOD entry point) returns
 * this type. */
#define FPI_TYPE_DEVICE_00E7 (fpi_device_00e7_get_type())
G_DECLARE_FINAL_TYPE(FpiDevice00e7, fpi_device_00e7, FPI, DEVICE_00E7, FpDevice)

#endif
