#!/usr/bin/env bash
#
# Generate this host's pairing identity and deploy it where the fprintd
# driver can read it.
#
# The driver pairs with the sensor on every session using a persisted host
# EC keypair + PSK ("pairdata"). `fpdrv pair-init` creates that file in your
# XDG state dir; fprintd runs as root, so a copy must also live at
# /var/lib/fpdrv/pairdata (the path the driver checks when $HOME is root's).
#
# This script is idempotent: it never overwrites an existing host identity
# unless you pass --regenerate.

set -euo pipefail

REGEN=0
[ "${1:-}" = "--regenerate" ] && REGEN=1

FPDRV="${FPDRV:-./fpdrv}"
USER_PAIRDATA="${XDG_STATE_HOME:-$HOME/.local/state}/fpdrv/pairdata"
SYS_PAIRDATA="/var/lib/fpdrv/pairdata"

if [ ! -x "$FPDRV" ] && ! command -v "$FPDRV" >/dev/null 2>&1; then
	echo "error: fpdrv not found (looked for '$FPDRV'). Build it first with 'make'," >&2
	echo "       or set FPDRV=/path/to/fpdrv." >&2
	exit 1
fi

if [ -f "$USER_PAIRDATA" ] && [ "$REGEN" -eq 0 ]; then
	echo "Host pairdata already exists at $USER_PAIRDATA (keeping it)."
	echo "Pass --regenerate to create a fresh identity."
else
	echo "Generating fresh host pairing identity..."
	"$FPDRV" pair-init
fi

echo "Deploying pairdata to $SYS_PAIRDATA (needs sudo)..."
sudo install -D -m 0600 "$USER_PAIRDATA" "$SYS_PAIRDATA"

echo "Restarting fprintd..."
sudo systemctl restart fprintd || true

echo
echo "Done. Next: 'fprintd-enroll' to enroll a finger, then 'fprintd-verify'."
