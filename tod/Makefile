CC         ?= cc
PKG_CONFIG ?= pkg-config

# The .so is loaded by libfprint inside fprintd; build PIC and link the
# tod/gusb/glib stack plus our crypto + libusb deps.
PKGS := libfprint-2-tod-1 gusb glib-2.0 gobject-2.0 gio-2.0 libcrypto libusb-1.0

CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -g -fPIC
CFLAGS  += -I../src
CFLAGS  += $(shell $(PKG_CONFIG) --cflags $(PKGS))
LDFLAGS += -shared
LDLIBS  += $(shell $(PKG_CONFIG) --libs $(PKGS))

# Shared protocol sources (NOT src/device.c, src/transport_libusb.c, src/main.c).
SHARED := proto pair cmd tls crypto parser storage transport
SRC := $(addprefix ../src/,$(addsuffix .c,$(SHARED))) transport_gusb.c tod_device.c
OBJ := $(notdir $(SRC:.c=.o))

SO  := libfpdrv_00e7_tod.so

# Install location from the tod pkg-config (tod_driversdir).
DRIVERSDIR := $(shell $(PKG_CONFIG) --variable=tod_driversdir libfprint-2-tod-1)

all: $(SO)

$(SO): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: ../src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(SO)
	install -d $(DESTDIR)$(DRIVERSDIR)
	install -m 0644 $(SO) $(DESTDIR)$(DRIVERSDIR)/$(SO)

clean:
	rm -f $(OBJ) $(SO)

.PHONY: all install clean
