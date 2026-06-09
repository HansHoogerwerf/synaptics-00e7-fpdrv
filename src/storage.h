#ifndef FPDRV_STORAGE_H
#define FPDRV_STORAGE_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

/* Host-side pair-state storage.
 *
 * On Windows the DLL encrypts the analogous data with DPAPI and stores
 * it in the registry under `HKCU\Software\Synaptics\PairingData`. On
 * Linux we have no DPAPI — we use a plain file under
 * `~/.local/state/fpdrv/pairdata` with 0600 perms.
 *
 * The PSK + host private key are the only secrets; everything else can
 * be re-derived. Atomic write via write-to-temp-then-rename.
 *
 * On-disk format (versioned, little-endian):
 *
 *   magic[4]       "FPDS"  (FingerPrint Driver Storage)
 *   version_u32    1
 *   psk_len_u32    e.g. 64
 *   psk[psk_len]
 *   host_priv[32]
 *   host_pub_xy[64]
 *   reserved[8]    zero
 *
 * Future versions may add fields (sensor identifier, host certificate
 * bytes, etc) — the version field controls compat. */

#define FP_PSK_LEN 64

struct fp_pairdata {
	uint8_t psk[FP_PSK_LEN];
	uint8_t host_priv[FP_P256_PRIV_LEN];
	uint8_t host_pub_xy[FP_P256_PUB_LEN];
};

/* Generate a fresh pair-data struct with random PSK + random P-256 keypair. */
int fp_storage_generate_fresh(struct fp_pairdata *out);

/* Default path is `~/.local/state/fpdrv/pairdata`. If `path` is NULL,
 * uses the default; otherwise uses the supplied path. Creates parent
 * directories as needed (0700 perms on dirs, 0600 on the file). */
int fp_storage_save(const struct fp_pairdata *in, const char *path);
int fp_storage_load(struct fp_pairdata *out, const char *path);

/* Resolve the default storage path into `out`. */
int fp_storage_default_path(char *out, size_t out_cap);

#endif
