// SPDX-License-Identifier: MPL-2.0

/*
 * erofs sysfs features-tree assertions (T-020/S08; matrix sec. 2.6
 * row 4 G-M18 + sec. 7.2, S05 sec. 3 file #6).
 *
 * Carriers: the features tree itself -- mount-independent, it exists
 * iff the erofs fs_type is registered (G-O04 = A: sysnode() returns
 * the static features subtree) -- plus BASE (EROFS_DEV_BASE, slot
 * x5 / image C1) self-mounted at the single self-mount point for the
 * mount-unaffectedness half. This file carries:
 *   - the sec. 7.2 core: the 10 feature attributes under
 *     /sys/fs/erofs/features each read EXACTLY "supported\n"
 *     (AT6-12: the list is copied verbatim, never pruned -- including
 *     the M3 quirk that the static announcement does not track compile
 *     capability, so ZIP features keep announcing "supported" even
 *     though ZIP is not undertaken under AR-5 tier A);
 *   - the G-M18 mount half (parity): with the features tree present,
 *     mount(2)/umount(2) of BASE succeed and the static announcement
 *     reads the same before, under, and after the live mount;
 *   - the registered-difference half: no per-mount directory appears
 *     under /sys/fs/erofs while a mount is live (AR-S01-8: the strict
 *     parity empty per-mount dir is NOT compensated).
 *
 * Guard: sysfs class EROFS_SKIP_IF_NO_SYSFS() on every FN_TEST (the
 * features tree carries registration semantics by itself, S05 sec. 6
 * branch (3)); the two mount-consuming FN_TESTs additionally stack
 * EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE) (device present AND erofs
 * registered) -- stacked guards are a logical AND. Both the non-erofs
 * run form and the attached-but-unimplemented state SKIP with exit 0.
 *
 * Registered notes without assertions (matrix sec. 7.2): the two RW
 * attributes (sync_decompress/drop_caches) are reachable only in the
 * ZIP-undertaken state, so no case exists under AR-5 tier A; the
 * AT6-16 registration-failure semantics drift is registered without
 * an assertion (the static tree is built at FsType registration
 * time, off the mount path, which is exactly why mount success stays
 * parity here).
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.6 row 4 + sec. 7.2 quoting
 * T-006 sec. 3 M2/M3/candidate A and r1-scope sec. 1.2 AR-S01-8).
 * The per-mount absence assertion carries its Linux baseline inline
 * (marked "登记差异"). Never adjust an expected value to match
 * observed behavior -- go back to the matrix instead.
 */

#include "erofs_common.h"

#include <stdint.h>
#include <sys/mount.h>
#include <sys/syscall.h>

/* Parent of the features tree; per-mount dirs would appear here. */
#define EROFS_SYSFS_ROOT "/sys/fs/erofs"

#define EROFS_SUPPORTED_STR "supported\n"

/*
 * The 10 feature attributes, verbatim (T-006 sec. 3 M2 quoting Linux
 * fs/erofs/sysfs.c erofs_feat_attrs; AT6-12 decided against pruning).
 * The order matches the baseline array but carries no semantics.
 */
static const char *const ero_feat_attrs[] = {
	"zero_padding", "compr_cfgs",  "big_pcluster", "chunked_file",
	"device_table", "compr_head2", "sb_chksum",    "ztailpacking",
	"fragments",	"dedupe",
};

#define EROFS_FEAT_ATTR_COUNT \
	(sizeof(ero_feat_attrs) / sizeof(ero_feat_attrs[0]))

/* One EINTR-tolerant read (same shape as umount_show.c umnt_read). */
static ssize_t sysfs_read_once(int fd, char *buf, size_t bufsz)
{
	ssize_t n;

	do {
		n = read(fd, buf, bufsz);
	} while (n < 0 && errno == EINTR);
	return n;
}

/*
 * Read one feature attribute (bare name, opened under featdir) and
 * check it reads EXACTLY "supported\n" followed by EOF. Returns 0 on
 * match, -1 otherwise (open/read failure, wrong length, wrong bytes,
 * or trailing content).
 */
static int sysfs_feat_supported_at(int featdir, const char *name)
{
	char buf[32];
	ssize_t n;
	int fd;

	fd = openat(featdir, name, O_RDONLY);
	if (fd < 0)
		return -1;
	n = sysfs_read_once(fd, buf, sizeof(buf));
	if (n != (ssize_t)strlen(EROFS_SUPPORTED_STR))
		goto bad;
	if (memcmp(buf, EROFS_SUPPORTED_STR, (size_t)n) != 0)
		goto bad;
	if (sysfs_read_once(fd, buf, sizeof(buf)) != 0) /* EOF required */
		goto bad;
	close(fd);
	return 0;
bad:
	close(fd);
	return -1;
}

/* Hand-rolled getdents64 layout, same shape as fs/procfs/getdents.c. */
struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

/*
 * sec. 7.2 core + G-M18 readable-subtree half (parity): each of the
 * 10 attributes reads exactly "supported\n". Mount-independent.
 */
FN_TEST(sysfs_features_all_supported)
{
	int featdir;
	size_t i;

	EROFS_SKIP_IF_NO_SYSFS();

	featdir = TEST_SUCC(open(EROFS_SYSFS_FEATURES, O_RDONLY | O_DIRECTORY));
	for (i = 0; i < EROFS_FEAT_ATTR_COUNT; i++)
		TEST_RES(sysfs_feat_supported_at(featdir, ero_feat_attrs[i]),
			 _ret == 0);
	TEST_SUCC(close(featdir));
}
END_TEST()

/*
 * G-M18 mount half (parity): the features subtree does not sit on the
 * mount path -- with the tree present, mount(2)/umount(2) of BASE
 * succeed, and one witness attribute reads the same static value
 * before, under, and after the live mount (featdir stays open across
 * the mount cycle; each probe opens a fresh attribute fd).
 */
FN_TEST(sysfs_mount_unaffected)
{
	int featdir;

	EROFS_SKIP_IF_NO_SYSFS();
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	featdir = TEST_SUCC(open(EROFS_SYSFS_FEATURES, O_RDONLY | O_DIRECTORY));
	TEST_RES(sysfs_feat_supported_at(featdir, "zero_padding"), _ret == 0);
	TEST_SUCC(mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, NULL));
	TEST_RES(sysfs_feat_supported_at(featdir, "zero_padding"), _ret == 0);
	TEST_SUCC(umount(EROFS_SELF_MNT));
	TEST_RES(sysfs_feat_supported_at(featdir, "zero_padding"), _ret == 0);
	TEST_SUCC(close(featdir));
}
END_TEST()

/*
 * Per-mount directory absence (registered difference): while BASE is
 * self-mounted, /sys/fs/erofs holds no entry other than "features".
 *
 * 登记差异(AR-S01-8 / G-O04=A): Linux 基线为每个在挂实例在
 * /sys/fs/erofs 下建 per-mount 目录(设备名形态);aster 静态
 * 最小承接不补该目录(严苛对等空目录经 AR-S01-8 子决策否决)。
 *
 * The enumeration is name-agnostic: any per-mount naming form
 * (device name / fsid / bdi, cf. AT6-13) shows up as a non-features
 * entry and fails the test.
 */
FN_TEST(sysfs_no_per_mount_dir)
{
	char buf[512];
	int rootfd;

	EROFS_SKIP_IF_NO_SYSFS();
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, NULL));

	rootfd = TEST_SUCC(open(EROFS_SYSFS_ROOT, O_RDONLY | O_DIRECTORY));
	for (;;) {
		ssize_t bytes = TEST_RES(syscall(SYS_getdents64, rootfd, buf,
						 sizeof(buf)),
					 _ret >= 0);

		if (bytes <= 0)
			break;
		for (size_t pos = 0; pos < (size_t)bytes;) {
			struct linux_dirent64 *d =
				(struct linux_dirent64 *)(buf + pos);
			const char *name = d->d_name;

			pos += d->d_reclen;
			if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
				continue;
			if (strcmp(name, "features") != 0)
				fprintf(stderr, "%s: unexpected entry: %s\n",
					__func__, name);
			TEST_RES(strcmp(name, "features"), _ret == 0);
		}
	}
	TEST_SUCC(close(rootfd));

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
