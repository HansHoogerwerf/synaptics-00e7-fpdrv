#include "storage.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const uint8_t MAGIC[4] = { 'F', 'P', 'D', 'S' };
#define VERSION 1

int fp_storage_generate_fresh(struct fp_pairdata *out)
{
	memset(out, 0, sizeof(*out));
	if (fp_crypto_rand(out->psk, FP_PSK_LEN) != 0) return -1;
	/* Use the canonical-Y variant so our pubkey works with the Synaptics
	 * sensor's +sqrt-only Y recovery in the 0x93 pair protocol. */
	if (fp_crypto_p256_keygen_canonical_y(out->host_priv, out->host_pub_xy) != 0)
		return -1;
	return 0;
}

int fp_storage_default_path(char *out, size_t out_cap)
{
	const char *xdg = getenv("XDG_STATE_HOME");
	const char *home = getenv("HOME");
	if (xdg && xdg[0]) {
		return snprintf(out, out_cap, "%s/fpdrv/pairdata", xdg) > 0 ? 0 : -1;
	}
	if (home && home[0]) {
		return snprintf(out, out_cap, "%s/.local/state/fpdrv/pairdata", home) > 0 ? 0 : -1;
	}
	return -1;
}

/* Make sure all parent directories of `path` exist, with 0700 perms. */
static int ensure_parent_dirs(const char *path)
{
	char buf[1024];
	if (strlen(path) + 1 > sizeof(buf)) return -1;
	strcpy(buf, path);
	for (char *p = buf + 1; *p; p++) {
		if (*p != '/') continue;
		*p = '\0';
		if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
		*p = '/';
	}
	return 0;
}

int fp_storage_save(const struct fp_pairdata *in, const char *path)
{
	char default_buf[1024];
	if (!path) {
		if (fp_storage_default_path(default_buf, sizeof(default_buf)) != 0) return -1;
		path = default_buf;
	}
	if (ensure_parent_dirs(path) != 0) {
		fprintf(stderr, "storage: cannot create parent dirs for %s\n", path);
		return -1;
	}

	char tmp[1100];
	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) <= 0) return -1;

	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "storage: cannot open %s: %s\n", tmp, strerror(errno));
		return -1;
	}

	/* Build the on-disk image. */
	uint8_t buf[256];
	int p = 0;
	memcpy(buf + p, MAGIC, 4); p += 4;
	uint32_t v = VERSION;
	memcpy(buf + p, &v, 4); p += 4;
	uint32_t pl = FP_PSK_LEN;
	memcpy(buf + p, &pl, 4); p += 4;
	memcpy(buf + p, in->psk, FP_PSK_LEN); p += FP_PSK_LEN;
	memcpy(buf + p, in->host_priv, FP_P256_PRIV_LEN); p += FP_P256_PRIV_LEN;
	memcpy(buf + p, in->host_pub_xy, FP_P256_PUB_LEN); p += FP_P256_PUB_LEN;
	memset(buf + p, 0, 8); p += 8;

	if (write(fd, buf, (size_t)p) != p) {
		fprintf(stderr, "storage: short write\n");
		close(fd);
		unlink(tmp);
		return -1;
	}
	if (fsync(fd) != 0) {
		fprintf(stderr, "storage: fsync failed: %s\n", strerror(errno));
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);

	if (rename(tmp, path) != 0) {
		fprintf(stderr, "storage: rename failed: %s\n", strerror(errno));
		unlink(tmp);
		return -1;
	}
	return 0;
}

int fp_storage_load(struct fp_pairdata *out, const char *path)
{
	char default_buf[1024];
	if (!path) {
		if (fp_storage_default_path(default_buf, sizeof(default_buf)) != 0) return -1;
		path = default_buf;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "storage: cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	uint8_t buf[256];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 4 + 4 + 4 + FP_PSK_LEN + FP_P256_PRIV_LEN + FP_P256_PUB_LEN + 8) {
		fprintf(stderr, "storage: truncated file (%zd bytes)\n", n);
		return -1;
	}
	if (memcmp(buf, MAGIC, 4) != 0) {
		fprintf(stderr, "storage: bad magic\n");
		return -1;
	}
	int p = 4;
	uint32_t version;
	memcpy(&version, buf + p, 4); p += 4;
	if (version != VERSION) {
		fprintf(stderr, "storage: unknown version %u\n", version);
		return -1;
	}
	uint32_t pl;
	memcpy(&pl, buf + p, 4); p += 4;
	if (pl != FP_PSK_LEN) {
		fprintf(stderr, "storage: unexpected psk_len %u\n", pl);
		return -1;
	}
	memcpy(out->psk, buf + p, FP_PSK_LEN); p += FP_PSK_LEN;
	memcpy(out->host_priv, buf + p, FP_P256_PRIV_LEN); p += FP_P256_PRIV_LEN;
	memcpy(out->host_pub_xy, buf + p, FP_P256_PUB_LEN); p += FP_P256_PUB_LEN;
	/* reserved[8] ignored */
	return 0;
}
