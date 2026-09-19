/* SPDX-License-Identifier: MPL-2.0 */

#ifndef EROFS_TEST_COMMON_H
#define EROFS_TEST_COMMON_H

/*
 * Shared helpers for the erofs regression tests (T-020).
 *
 * Include this header FIRST in every test .c file of this directory: it
 * defines _GNU_SOURCE before any system include and pulls in
 * ../../common/test.h, whose embedded main() turns each .c file into one
 * self-contained binary. That is also why every helper below is a static
 * inline function in this header: a separate helpers .c would be picked
 * up by the wildcard build as a 15th binary and break the 14-binary vs
 * 14-curated-line reconciliation of fs/run_test.sh (S05 §10-5).
 *
 * Single sources consumed here (never re-derive locally):
 *   device letters / mount points  docs/T-020/S01/index.md §3.2/§3.3
 *   guard predicate family         docs/T-016/S05/index.md §6, extended
 *                                  per docs/T-020/S01/index.md §6-1
 *   content formulas               docs/T-016/S01/index.md §3.0
 *   privilege-drop runner shape    docs/T-016/S05/index.md §8
 *
 * Directory rule: no .sh files in this directory (common/Makefile copies
 * any .sh into the build products); test binaries register themselves
 * through the wildcard.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

/*
 * Init-managed persistent mount point (S04 §5.3). Under the canonical
 * single-run complement init mounts it from /dev/vdf = x7/C2 base_cpt
 * (errata T-020/S01); tests must never umount or remount it.
 */
#define EROFS_INIT_MNT "/erofs"

/*
 * Single self-mount point for option/result/modulated-image tests,
 * reused serially by the FN_TEST constructors within one binary
 * (S05 §7.2).
 */
#define EROFS_SELF_MNT "/tmp/erofs_mnt"

/*
 * Device path constants. The letters follow the erofs single-run
 * 18-disk complement (3 resident + 15 erofs disks); single source =
 * docs/T-020/S01/index.md §3.2 (errata chain: docs/T-019/S04/index.md
 * §6). Under the 20-disk co-existence complement every letter shifts by
 * two (vdf-vdt) and this whole block is invalid -- running the binaries
 * in that form is undefined behavior (T-020/S01 §3.1). Macro names are
 * image-semantic and map 1:1 to slot ids; do not hand-drift them.
 */
#define EROFS_DEV_BASE "/dev/vdd" /* x5  C1  base (uniform-extended) */
#define EROFS_DEV_BLOB "/dev/vde" /* x6  C11 attached blob (device=) */
/* x7 C2 base_cpt -- the disk the init mount point mounts, NOT BASE */
#define EROFS_DEV_CPT "/dev/vdf"
#define EROFS_DEV_UUID0 "/dev/vdg" /* x8  C3  uuid all-zero */
#define EROFS_DEV_BS512 "/dev/vdh" /* x9  C4 */
#define EROFS_DEV_BS1K "/dev/vdi" /* x10 C5 */
#define EROFS_DEV_BS2K "/dev/vdj" /* x11 C6 */
#define EROFS_DEV_COMP "/dev/vdk" /* x12 C7  comp_lz4 */
#define EROFS_DEV_XSHARED "/dev/vdl" /* x13 C8  xattr_shared_all */
#define EROFS_DEV_XNONE "/dev/vdm" /* x14 C9  xattr_none */
#define EROFS_DEV_PREFIX "/dev/vdn" /* x15 C10 prefix */
#define EROFS_DEV_FLATDEV "/dev/vdo" /* x16 C11 flatdev main image */
#define EROFS_DEV_CHUNK4B "/dev/vdp" /* x17 C12 chunk4b */
#define EROFS_DEV_CONCAT "/dev/vdq" /* x18 D1  flatdev_concat */
#define EROFS_DEV_BADTAG "/dev/vdr" /* x19 D2  flatdev_badtag */

/*
 * Self-guard predicate family (S05 §6, single point of implementation).
 *
 * Unimplemented-state extensions per T-020/S01 §6-1: with the images
 * attached but erofs not yet registered in the kernel, (a) the plain
 * device branch would not short-circuit -- the device nodes exist while
 * mount(2) returns ENODEV instead of the expected EINVAL/EOPNOTSUPP --
 * so self-mount guards additionally require fs registration; and (b)
 * init does `mkdir -p /erofs` before the failing mount, which leaves an
 * EMPTY directory that plain access("/erofs", F_OK) would accept, so
 * the init-mount guard requires mount-success evidence instead.
 */

/* Device branch: stat + S_ISBLK (S04 §6-3 lock family, letter-agnostic). */
static inline int ero_dev_ok(const char *dev)
{
	struct stat st;

	return stat(dev, &st) == 0 && S_ISBLK(st.st_mode);
}

/*
 * One line of /proc/filesystems: optional "nodev" marker followed by
 * whitespace and the fs name. The name must match "erofs" exactly up to
 * a token boundary (no substring match).
 */
static inline int ero_line_names_erofs(const char *line)
{
	const char *p = line;

	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, "nodev", 5) == 0 && (p[5] == ' ' || p[5] == '\t')) {
		p += 5;
		while (*p == ' ' || *p == '\t')
			p++;
	}
	if (strncmp(p, "erofs", 5) != 0)
		return 0;
	p += 5;
	return *p == '\0' || *p == ' ' || *p == '\t';
}

/*
 * Registration branch: /proc/filesystems contains an "erofs" line. The
 * file is generated from the kernel fs registry, and aster currently
 * registers no erofs fs_type, so the line is absent until the
 * implementation lands. Raw syscalls only (open/read/close); no stdio.
 */
static inline int ero_fs_registered(void)
{
	char buf[4096];
	ssize_t total = 0;
	char *p;
	int fd;

	fd = open("/proc/filesystems", O_RDONLY);
	if (fd < 0)
		return 0;
	while (total < (ssize_t)sizeof(buf) - 1) {
		ssize_t n =
			read(fd, buf + total, sizeof(buf) - 1 - (size_t)total);

		if (n <= 0)
			break;
		total += n;
	}
	close(fd);
	buf[total] = '\0';

	p = buf;
	for (;;) {
		char *nl = strchr(p, '\n');

		if (nl != NULL)
			*nl = '\0';
		if (ero_line_names_erofs(p))
			return 1;
		if (nl == NULL)
			break;
		p = nl + 1;
	}
	return 0;
}

/*
 * Init-mount branch: mount-success evidence. The probe is
 * content-addressed -- a known top-level entry of the canonical
 * full-feature tree (S01 §2 layout) must be visible through the mount
 * point; the empty directory left behind by a failed init mount does
 * not pass.
 *
 * AUTO-DECISION: chosen over scanning /proc/mounts for a " /erofs "
 * row (extra parsing surface and buffer-size sensitivity) and over
 * comparing statfs("/erofs") f_type against the erofs magic (couples
 * the guard to the f_type correctness of the not-yet-existing erofs
 * implementation and would silently SKIP on a quirk).
 */
#define EROFS_INIT_MNT_PROBE EROFS_INIT_MNT "/regular"

static inline int ero_init_mnt_mounted(void)
{
	return access(EROFS_INIT_MNT_PROBE, F_OK) == 0;
}

/*
 * Self-mount tests: device present AND erofs registered (extension ①).
 * Multi-device tests stack one macro per device (logical AND).
 */
#define EROFS_SKIP_IF_NO_DEV(dev) \
	SKIP_TEST_IF(!ero_dev_ok(dev) || !ero_fs_registered())

/* Init-mount-point tests: mount-success evidence (extension ②). */
#define EROFS_SKIP_IF_NO_INIT_MNT() SKIP_TEST_IF(!ero_init_mnt_mounted())

/*
 * Sysfs tests: the features tree exists iff the fs_type is registered,
 * so this branch inherently carries registration semantics
 * (extension ③: no change needed).
 */
#define EROFS_SYSFS_FEATURES "/sys/fs/erofs/features"
#define EROFS_SKIP_IF_NO_SYSFS() \
	SKIP_TEST_IF(access(EROFS_SYSFS_FEATURES, F_OK) < 0)

/*
 * Content formulas (S01 §3.0, the single source). Expected contents are
 * always mechanically regenerated through these helpers, never stored
 * as tables; test files must never fabricate their own fixtures.
 */
static inline unsigned char ero_content_byte(size_t i)
{
	return 'a' + (unsigned char)(i % 26);
}

static inline unsigned char ero_symlink_byte(size_t i)
{
	return "0123456789abcdef"[i % 16];
}

/* Fill `len` expected bytes starting at absolute offset `off`. */
static inline void ero_fill_content(char *buf, size_t len, size_t off)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (char)ero_content_byte(off + i);
}

/*
 * Compare `size` bytes starting at the current file position of `fd`
 * against the content formula. Returns 0 on full match; -1 on mismatch,
 * read error, or early EOF. EOF beyond `size` is the caller's business
 * (the usual pattern is a follow-up pread() expecting a zero result).
 */
static inline int ero_check_content_fd(int fd, size_t size)
{
	char expect[4096];
	char actual[4096];
	size_t done = 0;

	while (done < size) {
		size_t want = size - done;
		ssize_t n;

		if (want > sizeof(actual))
			want = sizeof(actual);
		ero_fill_content(expect, want, done);
		n = read(fd, actual, want);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1; /* early EOF */
		if (memcmp(actual, expect, (size_t)n) != 0)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

/* Path-based convenience wrapper: open O_RDONLY, check, close. */
static inline int ero_check_content_path(const char *path, size_t size)
{
	int fd = open(path, O_RDONLY);
	int rc;

	if (fd < 0)
		return -1;
	rc = ero_check_content_fd(fd, size);
	close(fd);
	return rc;
}

/*
 * Ensure the single self-mount point exists. Safe to call from FN_SETUP
 * (unconditionally safe work: mkdir under /tmp, EEXIST tolerated);
 * any other failure is a fatal CHECK abort, which is setup semantics --
 * all device-dependent work must stay behind the FN_TEST guards.
 */
static inline void ero_ensure_self_mnt(void)
{
	CHECK_WITH(mkdir(EROFS_SELF_MNT, 0755), _ret == 0 || errno == EEXIST);
}

/*
 * Privilege-drop runner (S05 §8): fork, drop the child to `uid`
 * (setresgid first, then setresuid; gid := uid, i.e. 65534/nobody for
 * both in all current uses), run fn(), and pass fn's return value back
 * through a pipe. Returns fn()'s value, or -1 when the construction
 * itself failed (pipe/fork/read-back) -- probe callbacks must keep -1
 * reserved. The test process is always root (started by the guest
 * init), so the dropped child is the minimal "non-root / no caps"
 * construction for W-M05 and the xattr visibility matrix.
 */
static inline int ero_run_as_uid(uid_t uid, int (*fn)(void))
{
	int pipefd[2];
	int status;
	pid_t pid;
	int result = -1;

	if (pipe(pipefd) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pipefd[0]);
		if (setresgid(uid, uid, uid) < 0)
			_exit(125);
		if (setresuid(uid, uid, uid) < 0)
			_exit(125);
		result = fn();
		if (write(pipefd[1], &result, sizeof(result)) !=
		    (ssize_t)sizeof(result))
			_exit(126);
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &result, sizeof(result)) != (ssize_t)sizeof(result))
		result = -1;
	close(pipefd[0]);
	waitpid(pid, &status, 0);
	return result;
}

#endif /* EROFS_TEST_COMMON_H */
