# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Three strands of work, kept side-by-side:

1. **Scaffold for a from-scratch userspace USB fingerprint driver in C against
   libusb-1.0** (`src/`, `Makefile`). Minimal — device-open helper plus a CLI
   stub. The destination for the work in strand 3.
2. **`synaTudor-00e7.patch`** — patches against `Popax21/synaTudor` (commit
   `31dfdb0`) to make it attempt to drive the user's HP-variant `06cb:00e7`
   sensor. The patchset gets the HP Windows driver loading and through initial
   pairing, but enrollment record encryption and pairing-data persistence
   are still broken. **Not daily-usable** — kept as a fallback / reference
   implementation.
3. **`protocol-notes.md` + `tools/decode_capture.py`** — protocol reversing
   of the `06cb:00e7` wire format from a Windows-VM USB capture. Documents
   the pre-pair cleartext command set, the custom TLS-like handshake, and
   the structure of the sensor's stored pairing blob. This is the
   foundation for the from-scratch driver in strand 1. See
   `USB-CAPTURE-GUIDE.md` for how to take a fresh capture.

See `[[project-synatudor-research]]`, `[[project-synatudor-debug-session-2026-05-13]]`,
and `[[project-synatudor-session-2-2026-05-13]]` in the memory store for
full context on the synaTudor relinking attempts.

## Build & run (scaffold)

- `make` — builds the `fpdrv` binary. Uses `pkg-config libusb-1.0`.
- `make clean` — removes objects and the binary.
- `./fpdrv <vid> <pid>` — opens the device by USB vendor/product ID (hex,
  no `0x` prefix) and exits. Needs udev or root.

## Resuming the synaTudor work

The patchset lives at `synaTudor-00e7.patch`. To resume:

```
git clone https://github.com/Popax21/synaTudor /tmp/synaTudor
git -C /tmp/synaTudor checkout 31dfdb0
git -C /tmp/synaTudor apply <this-repo>/synaTudor-00e7.patch
```

Build deps already present on the user's machine (Linux Mint 22.2):
`meson ninja-build libfprint-2-dev libfprint-2-tod-dev libcap-dev
libseccomp-dev libdbus-1-dev libudev-dev libgusb-dev libjson-glib-dev
libglib2.0-dev innoextract`.

The launcher service is currently `systemctl mask`-ed to keep it from
auto-starting and hanging fprintd. To re-enable:
`sudo systemctl unmask tudor-host-launcher.service`.

## Architecture (scaffold)

Two translation units under `src/`:

- `device.c` / `device.h` — owns the libusb lifecycle. `fp_device_open`
  initializes a libusb context, opens the device by VID/PID, enables
  auto-detach of any kernel driver, and claims interface 0. The endpoints
  in `struct fp_device` are zero-initialized — populate them from the
  active interface's endpoint descriptors when adding protocol code,
  rather than hardcoding `0x81` / `0x01`.
- `main.c` — CLI front-end. Scratch entry point for bring-up.

## Working on this codebase

- The Synaptics `06cb:00e7` sensor in the target hardware uses encrypted
  TLS match-on-chip with one-time host pairing. Naive bulk USB transfers
  will not work — any protocol layer needs to deal with TLS state and
  pairing certificates.
- The synaTudor approach (relinking the HP Windows driver into Linux user
  space) sidesteps protocol reversing at the cost of being glove-fit to
  the HP `00e7` SKU's quirks. The patchset documents which quirks we hit.
  If `synaTudor-00e7.patch` ultimately turns out to be a dead end, the
  scaffold here is the destination for a from-scratch driver built on
  protocol knowledge from option 2 (Windows VM + USB capture).
- Interface 0 is claimed unconditionally by the scaffold. If the target
  exposes fingerprint functions on a different interface, set
  `fp_device.interface` before calling `fp_device_open`.
