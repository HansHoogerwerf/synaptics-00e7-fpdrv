# fpdrv — Synaptics 06cb:00e7 fingerprint driver for Linux

A from-scratch userspace driver for the **Synaptics 06cb:00e7** match-on-chip
fingerprint sensor, written in C. It ships as a
[libfprint TOD](https://fprint.freedesktop.org/) module so that `fprintd`,
PAM, and your display manager can use the sensor for fingerprint login — plus a
standalone `fpdrv` CLI for pairing, diagnostics, and on-chip template
management.

The sensor speaks an encrypted, TLS-like protocol with on-chip matching and
per-host pairing. This driver implements that protocol directly; it does **not**
relink any Windows driver and ships no proprietary firmware.

> **Status: experimental.** Developed and verified on an **HP Envy x360
> 13-ay0001nd** (the HP variant of `06cb:00e7`), Linux Mint 22.2,
> libfprint 1.94.7+tod1. Enroll, verify, and fingerprint login (LightDM login
> screen + lock screen, with password fallback) all work there. Other `00e7`
> SKUs report different capability blobs and may need adjustment. Use at your
> own risk on hardware you own.

## How it works

`fprintd` (a system D-Bus service) loads libfprint, which loads this driver
(`libfpdrv_00e7_tod.so`) for `06cb:00e7`. The driver and the `fpdrv` CLI share
one protocol implementation (`src/`):

- **Pairing identity** — an EC keypair + PSK generated once per host
  ("pairdata"). The driver replays a signed pairing request and runs the full
  TLS-like handshake on every session; the sensor validates the signature, so
  no on-sensor enrollment of the host is required.
- **Match on chip** — enrollment and verification happen inside the sensor.
  Fingerprint templates never leave the device; only match results do.

## Requirements

- An `06cb:00e7` sensor (`lsusb | grep 06cb:00e7`).
- libfprint with TOD support (`libfprint-2-tod`), `fprintd`, and `pam_fprintd`
  — standard on most modern desktop distros.
- Build tools and dev headers:

  ```sh
  sudo apt install build-essential pkg-config \
      libusb-1.0-0-dev libssl-dev libfprint-2-tod-dev \
      libgusb-dev libglib2.0-dev libjson-glib-dev
  ```

## Build

```sh
make              # builds the fpdrv CLI
make -C tod       # builds the libfprint TOD driver (libfpdrv_00e7_tod.so)
```

## Install

```sh
sudo make install         # installs fpdrv to /usr/local/bin + the udev rule
sudo make -C tod install  # installs the driver into libfprint's TOD dir
```

The udev rule (`60-synaptics-fp.rules`) grants the `plugdev` group read/write
access to the sensor so you can run the `fpdrv` CLI without root. Make sure your
user is in `plugdev` (`groups | grep plugdev`), then unplug/replug or reboot for
it to take effect. `fprintd` itself runs as root and does not need the rule.

### Avoid driver conflicts

Only one driver may claim `06cb:00e7`. If another libfprint TOD module (for
example a `libtudor_tod.so`) is present in the TOD directory, it will contend
for the device — move it aside:

```sh
ls /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/
# move any other *_tod.so that matches 06cb:00e7 out of this directory
```

## Set up pairing

Generate this host's pairing identity and deploy it where the root-run
`fprintd` can read it:

```sh
./scripts/setup-pairing.sh
```

That runs `fpdrv pair-init` (writes `~/.local/state/fpdrv/pairdata`), copies it
to `/var/lib/fpdrv/pairdata`, and restarts `fprintd`. To do it by hand:

```sh
./fpdrv pair-init
sudo install -D -m 0600 ~/.local/state/fpdrv/pairdata /var/lib/fpdrv/pairdata
sudo systemctl restart fprintd
```

## Enroll and enable login

```sh
fprintd-enroll                         # enroll a finger (follow the prompts)
fprintd-verify                         # confirm it matches
sudo pam-auth-update --enable fprintd  # enable fingerprint for PAM login
```

Fingerprint auth now works at the login screen and lock screen, with your
password still available as a fallback. To turn it back off:
`sudo pam-auth-update --disable fprintd`.

> Note: on a NOPASSWD `sudo` setup, `sudo` does not exercise the PAM auth stack
> — test with `su <user>` or by locking the screen, not `sudo`.

## Troubleshooting

- **`Device 06cb:00e7 has not been opened` on release, or device seems wedged**
  — restart the service: `sudo systemctl restart fprintd`.
- **Verify fails right after resume from suspend** — the encrypted session does
  not survive an S3 cycle; any in-flight verify is aborted on suspend. Just
  press again after resume; the next session re-handshakes cleanly.
- **Nothing happens / wrong driver** — confirm libfprint picked up this driver
  and not another (see *Avoid driver conflicts*), and that
  `/var/lib/fpdrv/pairdata` exists.
- **Inspect or reset on-chip state** (stop `fprintd` first to free the device):

  ```sh
  sudo systemctl stop fprintd
  ./fpdrv proto-list     # how many templates are stored on the sensor
  ./fpdrv proto-clear    # wipe all on-chip templates
  sudo systemctl start fprintd
  ```

## `fpdrv` CLI

`fpdrv` is primarily a diagnostic and bring-up harness. The commands relevant to
normal use:

| Command | Purpose |
|---|---|
| `pair-init` | Generate a fresh host pairing identity. |
| `pair-show` | Summarize the current pairdata (no secrets revealed). |
| `proto-open` | Bring up a secure session and exit (connectivity check). |
| `proto-enroll [finger]` | Enroll a finger via the shared protocol code. |
| `proto-id` | Capture one frame and match on-chip. |
| `proto-list` | List enrolled templates. |
| `proto-clear` | Delete all enrolled templates. |
| `selftest` | Run crypto self-tests (no device needed). |

Run `fpdrv` with no arguments for the full list. Some additional subcommands are
capture-replay tools used during reverse engineering and require capture files
that are not part of this release.

## Repository layout

```
src/        Shared protocol implementation + the fpdrv CLI (main.c)
tod/        The libfprint TOD driver (.so) — shares src/, adds the gusb transport
scripts/    setup-pairing.sh
protocol-notes.md     Notes on the 06cb:00e7 wire protocol
USB-CAPTURE-GUIDE.md  How to capture the sensor's USB traffic for RE
synaTudor-00e7.patch  Fallback: patches against the synaTudor relinking project
```

## Scope and legality

This is interoperability reverse engineering of a sensor the developer owns, to
make it usable on Linux. The repository contains no proprietary firmware,
captured traffic, or extracted keys; each host generates its own pairing
identity locally.

## License

GPL-3.0. See [LICENSE](LICENSE).

## Credits

Built on protocol knowledge from the libfprint project, the
[python-validity](https://github.com/uunicorn/python-validity) reference
implementation, and the [synaTudor](https://github.com/Popax21/synaTudor)
relinking project.
