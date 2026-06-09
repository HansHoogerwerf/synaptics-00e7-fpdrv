CC      ?= cc
PKG_CONFIG ?= pkg-config

CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CFLAGS  += $(shell $(PKG_CONFIG) --cflags libusb-1.0 libcrypto)
LDLIBS  += $(shell $(PKG_CONFIG) --libs   libusb-1.0 libcrypto)

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
BIN := fpdrv

PREFIX    ?= /usr/local
BINDIR    ?= $(PREFIX)/bin
UDEVDIR   ?= /etc/udev/rules.d
UDEV_RULE := 60-synaptics-fp.rules

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Installs the CLI helper and the udev rule that grants the plugdev group
# access to the sensor. Does NOT install the fprintd driver — run
# `make -C tod install` for that. Reloads udev so the rule takes effect.
install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(UDEVDIR)
	install -m 0644 $(UDEV_RULE) $(DESTDIR)$(UDEVDIR)/$(UDEV_RULE)
	@if [ -z "$(DESTDIR)" ]; then \
		udevadm control --reload-rules && \
		udevadm trigger --attr-match=idVendor=06cb --attr-match=idProduct=00e7 || true; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(UDEVDIR)/$(UDEV_RULE)

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all install uninstall clean
