# USB protocol RE — capturing Synaptics 06cb:00e7 traffic on a Windows VM

Goal: capture the on-the-wire USB traffic during a real Windows pair/enroll/verify
cycle, then use it to build a from-scratch Linux driver. By the end of this
process you'll have a `.pcap` you can replay byte-for-byte from `src/` in this
repo.

What we already know from session-2 RE (don't re-derive — see
`[[project-synatudor-session-2-2026-05-13]]` memory and `synaTudor-00e7.patch`):

- The sensor uses Synaptics' **SSI TLS** wrap (`ssiTlsWrap`/`ssiTlsUnwrap` in the
  DLL) with **AES-GCM** as the bulk cipher (`palCryptoAesGcm`).
- Wire commands are named `VCSFW_CMD_*` — we've already seen
  `GET_VERSION, RESET, GET_STARTINFO, TAKE_OWNERSHIP_EX2, RESET_OWNERSHIP,
  FRAME_ACQ, FRAME_READ, FRAME_FINISH, FRAME_STATE_GET, EVENT_CONFIG, EVENT_READ,
  PROVISION, GET_CERTIFICATE_EX, DB2_*` in traces.
- The pair handshake is what we need most — it's the moment when TLS keys are
  established, and it's the only window where cleartext is exchanged. Everything
  after pair is encrypted.
- Unpair from Linux **already works** (CLI `u` command) — you can put the sensor
  back into "wants-pair" state without touching Windows.

## What you need

- **A Windows ISO** with a Synaptics-supported version (Windows 10 or 11; we know
  Windows 10 20H2 worked with HP softpaq sp111400). A free Windows 11 evaluation
  works for this — no activation needed for the capture window.
- **~30 GB of disk** for the VM image. SSD strongly recommended — fingerprint
  enrollment is sensitive to timing.
- **QEMU/KVM** (Linux Mint 22.2 already has it): `sudo apt install qemu-kvm
  libvirt-daemon-system virt-manager ovmf`. `virt-manager` is the easiest GUI;
  command-line `virsh`/`qemu-system-x86_64` work too.
- **Wireshark with usbmon support** (Mint has this by default):
  `sudo apt install wireshark`. The `usbmon` kernel module is also already
  available; just `sudo modprobe usbmon` to load.
- **The HP softpaq driver** — we're already pinned to Lenovo `r19fp02w.exe` in
  our build but for Windows you want HP's actual installer. From session-2
  research, sp111400 is the version that ships with this exact laptop SKU:
  `https://ftp.hp.com/pub/softpaq/sp111001-111500/sp111400.exe`
  SHA1 `beccdefe314c3072490b468090848610039807e2`.

## Step 1 — Make sure the sensor is unpaired before capture

This is critical. If the sensor is already paired with the Windows host inside
the VM (or with anything else), pair won't happen on first enroll and you'll
miss the cleartext handshake — only encrypted frames will be visible.

From a Linux session:

```
sudo systemctl stop tudor-host-launcher.service
sudo systemctl mask tudor-host-launcher.service
sudo /tmp/synaTudor/build/cli/tudor_cli /tmp/scratch.dat -vt
```

At the menu type `u` then `y` to dispatch the unpair IOCTL. The trace should
show `vfmSecurityUnPair >>> ... <<<` and the pdata callback firing with
`size=0` — that confirms host-side pairing data is cleared. Then `s` to exit.

This puts the sensor back into "needs to perform pairing" state.

## Step 2 — Create the VM

Use `virt-manager` (easier) or `virsh` (scriptable). Key VM settings:

- **CPUs**: 4+ cores. Fingerprint sensor work is event-driven; under-provisioned
  CPU sometimes causes timing-sensitive USB transfers to behave differently.
- **RAM**: 8 GB+. Windows 11 needs it.
- **Firmware**: UEFI (OVMF). Windows 11 requires UEFI + TPM emulation. Add a
  TPM 2.0 emulated device via virt-manager → Add Hardware → TPM → CRB → Emulated.
- **Secure Boot**: enabled for Win11 install. Some sources say you can skip,
  but Windows Update sometimes fights it.
- **Disk**: virtio bus, qcow2, 60+ GB. Thin-provisioned is fine.
- **Network**: NAT. The Synaptics driver works offline so you can disconnect
  during capture if you want clean traces.

Install Windows. Do NOT enroll a fingerprint yet — that has to happen *during*
capture.

## Step 3 — Install the HP softpaq inside the VM

Once Windows is up:

1. Add USB passthrough for the fingerprint sensor: virt-manager → VM details →
   Add Hardware → USB Host Device → choose the `06cb:00e7` entry.
2. Inside Windows, run `sp111400.exe`. It extracts and installs the driver.
   Verify in Device Manager → Biometric devices → "Synaptics WBDI"
   (or similar) shows up without errors.
3. Don't enroll yet. Restart the VM once after install to make sure the driver
   is loading cleanly.

## Step 4 — Set up the host-side capture

On the Linux host (outside the VM):

```bash
sudo modprobe usbmon
# Find the sensor's bus
lsusb -d 06cb:00e7
# Output: Bus 001 Device NNN: ID 06cb:00e7 Synaptics, Inc.
```

Note the bus number. For bus 001 you'll capture on `usbmon1`.

Important: the sensor needs to be USB-passthrough'd to the VM *and*
visible to usbmon on the host. usbmon sees ALL traffic on the bus regardless
of which guest the device is assigned to — this is how we can sniff the
VM-side driver's communication from outside.

Start Wireshark:

```bash
sudo wireshark
```

Pick interface `usbmon1` (or whichever matches your bus). Set the capture
filter to:

```
usb.idVendor == 0x06cb && usb.idProduct == 0x00e7
```

or display filter (filtering after capture is also fine; the volume isn't
huge for a single enroll cycle).

Click record. Leave it running.

## Step 5 — Drive the capture

Inside the Windows VM, with the capture rolling:

1. **First, capture pair**:
   - Open Settings → Accounts → Sign-in options → Fingerprint → Set up.
   - This triggers WinBioEnrollBegin, which detects no pairing and initiates the
     pair handshake. **The first few seconds of the capture are the pair flow —
     this is the gold.**
   - Complete the enrollment by placing your finger several times.

2. **Then verify** (separate run, separate capture file ideally):
   - Lock the screen (Win+L), then unlock with your fingerprint.
   - This triggers a `FRAME_ACQ`/`FRAME_READ`/`IdentifyFeatureSet` cycle —
     useful to see what a successful verify looks like.

3. **Stop the Wireshark capture.** Save as a `.pcapng` file. Two files: one
   labeled `enroll-with-pair.pcapng`, one labeled `verify.pcapng`. Move both
   to the Linux host (the captures are already there if you ran Wireshark on
   the host).

## Step 6 — Initial analysis

The captures will be a sequence of USB bulk transfers (the sensor uses bulk-in
and bulk-out endpoints).

Open `enroll-with-pair.pcapng` in Wireshark. The interesting frames:

- **Pair handshake** (first dozen bulk transfers): mostly cleartext. Look for:
  - A short bulk-out from host (probably `VCSFW_CMD_GET_VERSION` or similar
    init). The Synaptics command format is documented in the
    [Popax21/synaTudor](https://github.com/Popax21/synaTudor) source
    (`libtudor/src/winapi/...` and the firmware header) — each command has a
    1-byte ID and request payload.
  - A bulk-in response from sensor containing a **certificate** (large blob,
    usually 256-1024 bytes, ASN.1-DER encoded). Identifiable by the leading
    `0x30 0x82 ...` (DER SEQUENCE). This is the sensor's per-unit cert
    signed by Synaptics.
  - The host's response with **its public key** (an EC point on P-256, ~65 bytes
    `0x04` + X + Y) and possibly a nonce.
  - The sensor's response with **its public key** + signed handshake data.
  - **TLS Finished**-equivalent messages — short messages confirming the
    session key is derived.

- After pair, everything is AES-GCM encrypted. Encrypted bulk transfers all
  start with a small TLS-like header (likely 5 bytes) followed by ciphertext
  + 16-byte GCM tag.

Cross-reference with our session-2 memory:

- `palCryptoRng` calls in DLL traces correspond to the nonce generation.
- `palCryptoEncryptAuth` / `palCryptoDecryptAuth` are the AES-GCM operations.
- `ssiTlsWrap` / `ssiTlsUnwrap` are the TLS-record envelope.
- `tudorUsbProtoIoControl` is the layer that actually does the bulk
  transfer — there's typically a small header before the TLS-wrapped data.

## Step 7 — Document the handshake

Write down, in order:
1. Each bulk transfer's direction (host→sensor or sensor→host)
2. The total size
3. The first few bytes (command ID / message type)
4. Any structure you can recognize (cert, EC point, nonce)

You'll end up with a "pair script" of, roughly:

```
1.  H→S  6 bytes   CMD_GET_VERSION
2.  S→H  64 bytes  version reply
3.  H→S  20 bytes  CMD_GET_STARTINFO
4.  S→H  72 bytes  startinfo (we already see this in DLL traces — match the
                    reset_nvinfo values to confirm)
5.  H→S  ??        CMD_TAKE_OWNERSHIP_EX2 (this is likely the pair-initiate)
6.  S→H  ??        cert + sensor pubkey
7.  H→S  ??        host pubkey + signed challenge
8.  S→H  ??        TLS-finished equivalent
```

From there, the from-scratch driver in `src/` does each step:

1. Implement bulk-transfer helpers using libusb (already scaffolded in
   `src/device.c`).
2. Implement the Synaptics TLS layer — ECDH on P-256, AES-GCM. OpenSSL has
   everything; the only Synaptics-specific bit is the message framing.
3. Issue the same command sequence we recorded, with the same crypto.
4. Once the pair completes, persist the negotiated session key (and the
   host-side cert if there is one) to disk so we don't have to re-pair on
   every run.

## What to do if the pair handshake is hard to identify

If the captures look like opaque blobs with no obvious cleartext:

- **Verify the unpair from step 1 actually took effect.** If the sensor was
  already paired (e.g., factory-paired or paired in a previous Windows session
  on this hardware), the "pair" you triggered in the VM would have used a
  fast-path that reuses the existing session, not a fresh ECDH. Re-do unpair
  via the Linux CLI and re-capture.
- **Capture with the higher-level CLI traces in parallel.** The Lenovo DLL's
  trace channel emits readable function names. Run the Linux CLI in parallel
  with the Windows-side enrollment (different USB session, different sensor
  ideally — but in practice, just use the trace from a prior session as
  reference for what the function-level order should be). Match each USB
  transfer to the trace lines `CMD SEND: VCSFW_CMD_XXX` and
  `CMD REPLY: VCSFW_CMD_XXX`. Session-2 captures should still be in
  `/tmp/tudor-*.log` if you didn't reboot.

## What to skip (or revisit later)

- **Don't try to reverse the TLS keys.** ECDH derives a session key that's
  unique per pair; you don't need to derive it offline because you'll
  re-establish a fresh session each time the driver pairs.
- **Don't worry about firmware update commands.** The HP driver does periodic
  firmware checks but our sensor is on a version that the Lenovo DLL knows.
  Skip these in the from-scratch driver.
- **`OnAppRequest` and the E_NOTIMPL stub path are dead ends** — session-2
  proved the COM-style dispatch can't be driven from Linux without putting the
  DLL into specific internal states. The from-scratch driver doesn't need to
  emulate OnAppRequest at all; we just need to speak the wire protocol.

## Estimated effort

- VM + driver setup: half a day
- Capture session: 1-2 hours (enroll + verify + retake if needed)
- Initial protocol analysis from the captures: 1 day
- Implementing the wire protocol in `src/`: 1-2 weeks (mostly TLS framing,
  bulk-transfer state machine, and tying it into libfprint)

Total: ~3 weeks of evenings, vs. the multi-session indefinite slog of
continuing to RE the DLL internals.

## Reference artifacts already in this repo

- `synaTudor-00e7.patch` — the patches against synaTudor that got us to working
  unpair. Has the `tudor_unpair()` IOCTL dispatcher and the Lenovo softpaq
  pinning. Useful as a working unpair tool while you develop the from-scratch
  driver.
- `src/device.c` / `src/main.c` — the scaffold for the from-scratch driver.
  Currently just opens the USB device; this is where you'll add the pair
  state machine, TLS, and command implementations.
- The memory files under `~/.claude/projects/-usr-local-src-fingerprint-driver/memory/`
  document the IOCTL dispatch table, function VAs, and the wall we hit. Useful
  context when interpreting captures.
