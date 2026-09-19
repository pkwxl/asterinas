// SPDX-License-Identifier: MPL-2.0

/*
 * erofs statfs field face + remount face assertions (T-020/S06;
 * matrix sec. 2.4/2.5/7.3, S05 sec. 3 file #4).
 *
 * Carriers, all self-mounted at the single self-mount point and
 * unmounted serially inside each FN_TEST:
 *   - BASE (EROFS_DEV_BASE) carries the SF1-SF10 field face, the
 *     SF11/W-M03 f_flags face (default and explicit-noatime mount
 *     forms), and the whole remount row group -- RM1/RM4/RM12/O3/
 *     RM13/W-M07 all operate on the self-mounted BASE instance
 *     (the persistent /erofs mount point is never touched).
 *   - UUID0 (EROFS_DEV_UUID0) carries the SF9 zero-uuid dev-coded
 *     f_fsid branch, cross-checked against the non-zero XOR-folded
 *     branch on BASE (S05: "vdg = SF9 零分支与 vdd 非零互证").
 *   - FLATDEV (EROFS_DEV_FLATDEV, mounted WITHOUT any device=)
 *     carries the statfs f_blocks slot-accumulation half of matrix
 *     sec. 7.3 (MD8/AT6-26; the G-O06 read faces belong to
 *     data_path.c).
 *
 * Guard: self-mount class, one EROFS_SKIP_IF_NO_DEV() line per device
 * consumed by the FN_TEST (S05 sec. 6). The registration probe inside
 * the macro keeps both the non-erofs run form and the attached-but-
 * unimplemented state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.4/2.5/7.3 rows quoting T-002
 * sec. 4.1/4.2 and sec. 6.1-6.3, T-006 sec. 5 MD8). Image-derived
 * constants (dsb->blocks, dsb->inos, uuid bytes) are material facts
 * of the digest-pinned T-018 image set, registered with their
 * cross-checks in docs/T-020/S06/index.md sec. 2 (single source for
 * the numbers below). Registered-difference assertions carry their
 * Linux baseline inline (marked "登记差异"). Never adjust an expected
 * value to match observed behavior -- go back to the matrix instead.
 */

#include "erofs_common.h"

#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>

/*
 * ST_* f_flags bit numbers. This glibc's <sys/statfs.h> ships only
 * struct statfs (no ST_* numbers at all) and <linux/statfs.h> is
 * absent, so define the three consumed bits from the pinned Linux
 * 6.12 baseline tree's include/linux/statfs.h: ST_RDONLY 0x0001,
 * ST_NOATIME 0x0400, ST_VALID 0x0020. ST_VALID is kernel-internal
 * (its value equals MS_REMOUNT, which is why it is never exported to
 * the UAPI); Linux sets it unconditionally in calculate_f_flags
 * ("ST_VALID | flags_by_mnt | flags_by_sb", fs/statfs.c). Bit-number
 * reconciliation against the doc chain is registered in
 * docs/T-020/S06/index.md sec. 5-7.
 */
#ifndef ST_RDONLY
#define ST_RDONLY 0x0001
#endif
#ifndef ST_NOATIME
#define ST_NOATIME 0x0400
#endif
#ifndef ST_VALID
#define ST_VALID 0x0020
#endif

/*
 * Image-derived material facts (docs/T-020/S06/index.md sec. 2):
 *   BASE/UUID0: 479232 B / 4096 = 117 blocks, dsb->inos = 262;
 *   FLATDEV: main 49152 B = 12 blocks + blob 53248 B = 13 blocks
 *   (concat derivative 102400 B = 25 blocks cross-checks the sum).
 */
#define EROFS_F_TYPE 0xE0F5E1E2u /* SF1: f_type = sb magic (V1) */
#define EROFS_BASE_BLOCKS 117ULL /* SF3: dsb->blocks, taken verbatim */
#define EROFS_STAGE_INOS 262ULL /* SF6: dsb->inos, same staged tree */
#define EROFS_FLATDEV_TOTAL_BLOCKS 25ULL /* MD8: 12 (main) + 13 (blob) */

/*
 * C1 uuid = EROFS_UUID_BASE (test/initramfs/Makefile:77), byte for
 * byte. The XOR-fold expectation below is mechanically regenerated
 * from these bytes -- never stored as a value table.
 */
static const unsigned char ero_uuid_base[16] = {
	0xe2, 0xe4, 0xf0, 0xc8, 0x1a, 0x2b, 0x4c, 0x3d,
	0x9e, 0x8f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f,
};

static unsigned long long ero_le64(const unsigned char *b)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | b[i];
	return v;
}

/* SF8 expectation: uuid_to_fsid = le64(uuid[0..8)) ^ le64(uuid[8..16)),
 * split into the two 32-bit f_fsid words (little-endian targets). */
static void ero_expect_fsid_uuid(unsigned int v[2], const unsigned char *uuid)
{
	unsigned long long folded = ero_le64(uuid) ^ ero_le64(uuid + 8);

	v[0] = (unsigned int)(folded & 0xffffffffu);
	v[1] = (unsigned int)(folded >> 32);
}

/* SF9 expectation: new_encode_dev(bd_dev) =
 * (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12). */
static unsigned int ero_new_encode_dev(dev_t rdev)
{
	unsigned int maj = major(rdev);
	unsigned int min = minor(rdev);

	return (min & 0xffu) | (maj << 8) | ((min & ~0xffu) << 12);
}

/* f_fsid word extraction via memcpy: immune to the __fsid_t member
 * naming differences between libc implementations. */
static void ero_fsid_words(const struct statfs *st, unsigned int v[2])
{
	memcpy(v, &st->f_fsid, sizeof(v[0]) * 2);
}

static int mount_dev(const char *dev, unsigned long flags, const char *data)
{
	return mount(dev, EROFS_SELF_MNT, "erofs", flags, data);
}

/* Remount the self-mounted BASE instance (RM row group carrier). */
static int remount_base(unsigned long flags, const char *data)
{
	return mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs",
		     flags | MS_REMOUNT, data);
}

/*
 * RM12 observability probe: user.v on the image-preset host
 * xattr_host/xattr_user_short.bin (S01 sec. 3.4, 1-byte value).
 * Under nouser_xattr the user.* get gate is EOPNOTSUPP (X3); with the
 * default option set the get succeeds and returns the value length.
 */
static int probe_user_xattr(void)
{
	char buf[16];

	return getxattr(EROFS_SELF_MNT "/xattr_host/xattr_user_short.bin",
			"user.v", buf, sizeof(buf));
}

/*
 * SF1-SF10 (parity): the statfs field face on a default BASE mount.
 * f_files/f_frsize are asserted explicitly to guard against a
 * default-0 drift (matrix sec. 2.4 row 1 note).
 */
FN_TEST(statfs_remount_field_face)
{
	struct statfs st;
	unsigned int want[2];
	unsigned int got[2];

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));

	/* SF1: f_type = sb magic. */
	TEST_RES((unsigned int)st.f_type, _ret == EROFS_F_TYPE);
	/* SF2: f_bsize follows the on-image block size (4k image). */
	TEST_RES(st.f_bsize, _ret == 4096);
	/* SF10: f_frsize = f_bsize explicitly (no VFS fallback here). */
	TEST_RES(st.f_frsize, _ret == st.f_bsize);
	/* SF3: f_blocks = dsb->blocks taken verbatim, never clamped to
	 * the device capacity. */
	TEST_RES((unsigned long long)st.f_blocks, _ret == EROFS_BASE_BLOCKS);
	/* SF4: read-only fs -- both free counters are always 0. */
	TEST_RES(st.f_bfree, _ret == 0);
	TEST_RES(st.f_bavail, _ret == 0);
	/* SF5: f_files = ULLONG_MAX (explicit, guards default-0 drift). */
	TEST_RES((unsigned long long)st.f_files, _ret == ~0ULL);
	/* SF6: f_ffree = ULLONG_MAX - inos (mount-time snapshot). */
	TEST_RES((unsigned long long)st.f_ffree,
		 _ret == ~0ULL - EROFS_STAGE_INOS);
	/* SF7: f_namelen = EROFS_NAME_LEN. */
	TEST_RES(st.f_namelen, _ret == 255);
	/* SF8: f_fsid = XOR fold of the non-zero image uuid. */
	ero_expect_fsid_uuid(want, ero_uuid_base);
	ero_fsid_words(&st, got);
	TEST_RES(got[0], _ret == want[0]);
	TEST_RES(got[1], _ret == want[1]);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * SF11 + W-M03 (parity + registered difference): f_flags on the two
 * mount forms. ST_RDONLY is always set; SB_NOATIME never maps into
 * f_flags, so ST_NOATIME appears only on an explicit noatime mount
 * ("勿恒 ro 顺手带 noatime").
 */
FN_TEST(statfs_remount_f_flags_forms)
{
	struct statfs st;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/* Default form. */
	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	TEST_RES(st.f_flags & ST_RDONLY, _ret != 0);
	TEST_RES(st.f_flags & ST_NOATIME, _ret == 0);
	/* 登记差异(W-M03): Linux 基线 f_flags 恒置 ST_VALID(bit5,
	 * 0x20,与 MS_REMOUNT 同值故不导出 UAPI);aster 恒 0。 */
	TEST_RES(st.f_flags & ST_VALID, _ret == 0);
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* Explicit noatime form (-o noatime = MS_NOATIME mount flag). */
	TEST_SUCC(mount_dev(EROFS_DEV_BASE, MS_NOATIME, NULL));
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	TEST_RES(st.f_flags & ST_RDONLY, _ret != 0);
	TEST_RES(st.f_flags & ST_NOATIME, _ret != 0);
	/* 登记差异(W-M03): 同上,aster 恒无 ST_VALID。 */
	TEST_RES(st.f_flags & ST_VALID, _ret == 0);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * SF9 (parity): zero-uuid image -- f_fsid is dev-coded from the mount
 * source device. val[1] is always 0 in this branch; val[0] is the
 * new_encode_dev of bd_dev, so the expectation is derived from the
 * device node's own rdev (no hardcoded device numbers). Cross-checks
 * against the XOR-folded branch on BASE (which yields a non-zero
 * val[1], see statfs_remount_field_face).
 */
FN_TEST(statfs_remount_uuid0_fsid_dev_coded)
{
	struct statfs st;
	struct stat sb;
	unsigned int got[2];
	unsigned int want0;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_UUID0);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_UUID0, 0, NULL));
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	ero_fsid_words(&st, got);
	TEST_RES(got[1], _ret == 0);
	TEST_SUCC(stat(EROFS_DEV_UUID0, &sb));
	want0 = ero_new_encode_dev(sb.st_rdev);
	TEST_RES(got[0], _ret == want0);
	/* 互证: same staged tree, same mkfs parameters except -U -- the
	 * block and inode counters equal the BASE values (SF3/SF6). */
	TEST_RES((unsigned long long)st.f_blocks, _ret == EROFS_BASE_BLOCKS);
	TEST_RES((unsigned long long)st.f_ffree,
		 _ret == ~0ULL - EROFS_STAGE_INOS);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 7.3 / MD8 (parity, decision (3) F): statfs f_blocks on a
 * flatdev image mounted WITHOUT any device= -- total_blocks
 * accumulates every on-image device slot (main 12 + blob 13) even
 * though the attached-slot data is never read independently. The rest
 * of the field face is unchanged by the flatdev form (MD16).
 */
FN_TEST(statfs_remount_flatdev_blocks_accumulated)
{
	struct statfs st;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_FLATDEV);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_FLATDEV, 0, NULL));
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	TEST_RES((unsigned long long)st.f_blocks,
		 _ret == EROFS_FLATDEV_TOTAL_BLOCKS);
	TEST_RES(st.f_bsize, _ret == 4096);
	TEST_RES(st.f_frsize, _ret == st.f_bsize);
	TEST_RES(st.f_bfree, _ret == 0);
	TEST_RES(st.f_bavail, _ret == 0);
	TEST_RES((unsigned long long)st.f_ffree,
		 _ret == ~0ULL - EROFS_STAGE_INOS);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * RM1 (parity): remount on a path that is not a mount point. The
 * constructors run serially and every earlier FN_TEST has unmounted
 * the self-mount point, so the directory exists but carries no mount.
 */
FN_TEST(statfs_remount_not_mountpoint_einval)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_ERRNO(remount_base(0, NULL), EINVAL);
}
END_TEST()

/*
 * RM4 (parity): remount data parsing is the mount parser applied
 * token for token -- an unknown key and the dax family stay EINVAL.
 */
FN_TEST(statfs_remount_option_parity_einval)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	TEST_ERRNO(remount_base(0, "bogus"), EINVAL);
	TEST_ERRNO(remount_base(0, "dax=always"), EINVAL);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * RM12 (parity): a bare remount (no data) resets the option set to
 * the defaults -- "mount -o nouser_xattr" then a bare "remount,ro"
 * turns user_xattr back on. Observed through the X3 gate probe; the
 * value content itself belongs to xattr.c (#12), only the length is
 * checked here.
 */
FN_TEST(statfs_remount_bare_remount_resets_options)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, "nouser_xattr"));
	/* X3 probe: user.* get under nouser_xattr is EOPNOTSUPP. */
	TEST_ERRNO(probe_user_xattr(), EOPNOTSUPP);
	/* Bare remount: NULL data = no tokens = default option set. */
	TEST_SUCC(remount_base(0, NULL));
	/* user_xattr is back on: user.v reads out its 1-byte value. */
	TEST_RES(probe_user_xattr(), _ret == 1);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * O3 (parity): device= in remount data is accepted and silently
 * dropped -- no errno, and no effect on the mounted instance (the
 * option carries no reconfigure semantics, unlike the mount-time
 * scan-phase rejection).
 */
FN_TEST(statfs_remount_device_option_dropped)
{
	struct statfs st;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BLOB);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	TEST_SUCC(remount_base(0, "device=" EROFS_DEV_BLOB));
	/* Dropped means dropped: total_blocks still counts BASE only. */
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	TEST_RES((unsigned long long)st.f_blocks, _ret == EROFS_BASE_BLOCKS);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * RM13 (parity): "remount,rw" returns 0 and the superblock stays
 * read-only -- syscall success + write-family EROFS negative control
 * + the statfs ST_RDONLY witness (O1).
 */
FN_TEST(statfs_remount_rw_request_stays_ro)
{
	struct statfs st;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	/* remount,rw = MS_REMOUNT without MS_RDONLY. */
	TEST_SUCC(remount_base(0, NULL));
	/* Write-family EROFS negative control on the preset entry (name
	 * fixed to the S01 sec. 3.1 verbatim form by T-020/S07). */
	TEST_ERRNO(open(EROFS_SELF_MNT "/regular/empty_file.bin", O_WRONLY),
		   EROFS);
	/* O1 witness: f_flags still carries ST_RDONLY. */
	TEST_SUCC(statfs(EROFS_SELF_MNT, &st));
	TEST_RES(st.f_flags & ST_RDONLY, _ret != 0);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * W-M07 (registered difference): remount flags beyond MS_RMT_MASK.
 * MS_DIRSYNC is outside the remount flag mask and does not trigger
 * any other mount(2) sub-operation.
 */
FN_TEST(statfs_remount_sb_flags_overflow_dropped)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, 0, NULL));
	/*
	 * 登记差异(W-M07): Linux 基线对超 MS_RMT_MASK 的 remount
	 * 旗标返回 EINVAL;aster from_bits_truncate 静默丢位后接受
	 * (syscall 返回 0)。
	 */
	TEST_SUCC(remount_base(MS_DIRSYNC, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
