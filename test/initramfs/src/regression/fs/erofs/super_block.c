// SPDX-License-Identifier: MPL-2.0

/*
 * erofs superblock validation / mount-result assertions (T-020/S05;
 * matrix sec. 2.2, S05 sec. 3 file #3).
 *
 * Carriers, all self-mounted at the single self-mount point and
 * unmounted serially inside each FN_TEST: BASE carries the healthy
 * boot path (the V1-V10 healthy main sequence plus the healthy half
 * of G-M09 -- one successful mount is the userspace-observable face
 * of both; the ordering-crossover and bad-csum faces need crafted
 * superblocks and stay in the ktest FX-SB half); the three BS-ALT
 * images carry G-M08; the COMP image carries G-M11; BASE plus a real
 * device= string carries the G-M12 counting-mismatch home assertion;
 * the FLATDEV main image, its blob, and the BADTAG derivative carry
 * G-M13/G-M14.
 *
 * Guard: self-mount class, one EROFS_SKIP_IF_NO_DEV() line per device
 * consumed by the FN_TEST -- stacked per-device guards are a logical
 * AND (S05 sec. 6). The registration probe inside the macro keeps
 * both the non-erofs run form and the attached-but-unimplemented
 * state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.2 rows quoting T-002
 * sec. 2.2/2.3/8.1/8.2 and T-004 sec. 7.7 item 1; the AR-1/AR-4/AR-5
 * directions come from r1-scope sec. 1.2). Registered-difference
 * assertions carry their Linux baseline inline (marked "登记差异").
 * Never adjust an expected value to match observed behavior -- go
 * back to the matrix instead.
 */

#include "erofs_common.h"

#include <sys/mount.h>

/* Mount any image device at the self-mount point; no flag face here. */
static int mount_dev(const char *dev, const char *data)
{
	return mount(dev, EROFS_SELF_MNT, "erofs", 0, data);
}

/*
 * V1-V10 healthy main sequence + G-M09 healthy half (parity): a
 * healthy mkfs image passes the whole superblock validation chain,
 * observable as one successful mount. BASE is mkfs'ed with SB_CHKSUM
 * on, so the same success also proves the crc32c replica comparison
 * (the bad-csum half is crafted-only and stays in the ktest half).
 */
FN_TEST(super_block_healthy_mount)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BASE, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* G-M08 (AR-1): the block-size acceptance face is narrowed to 4k. */
FN_TEST(super_block_bs_alt_einval)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BS512);
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BS1K);
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BS2K);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(G-M08/AR-1): Linux 基线为 512B/1k/2k 块大小的
	 * 健康 mkfs 图像挂载成功;aster 收窄为 4k-only,
	 * blkszbits != 12 → EINVAL,三张 BS-ALT 图全部拒绝。
	 */
	TEST_ERRNO(mount_dev(EROFS_DEV_BS512, NULL), EINVAL);
	TEST_ERRNO(mount_dev(EROFS_DEV_BS1K, NULL), EINVAL);
	TEST_ERRNO(mount_dev(EROFS_DEV_BS2K, NULL), EINVAL);
}
END_TEST()

/* G-M11 + sec. 5.1 item 1 (AR-5, tier A): the compressed image face. */
FN_TEST(super_block_comp_image_eopnotsupp)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_COMP);
	ero_ensure_self_mnt();

	/*
	 * 负对照(G-M11 + §5.1① / AR-5 档 A): Linux 基线为压缩图像
	 * (algs != 0)挂载成功;aster 压缩整体暂缓,层 1 守卫
	 * (V9,u1 != 0)拒绝 EOPNOTSUPP。§5.1 ②–⑧ 的 crafted × 档位
	 * 对照归 ktest 半边(健康 mkfs 不产 crafted 形态)。
	 */
	TEST_ERRNO(mount_dev(EROFS_DEV_COMP, NULL), EOPNOTSUPP);
}
END_TEST()

/*
 * G-M12 counting-mismatch home assertion (parity): a single-device
 * image (no DEVICE_TABLE, extra == 0) given any device= option is
 * rejected in the scan phase -- the device counts do not match --
 * even when the named path is a real attached block device: path
 * validity is never consulted. The parse-half forms (bare/empty
 * key, repeat, nonexistent paths) live in mount_options.c.
 */
FN_TEST(super_block_device_count_mismatch)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BLOB);
	ero_ensure_self_mnt();

	TEST_ERRNO(mount_dev(EROFS_DEV_BASE, "device=" EROFS_DEV_BLOB), EINVAL);
}
END_TEST()

/*
 * G-M13 (AR-4): the true multi-device mount stays rejected during
 * the transition period.
 */
FN_TEST(super_block_multidev_transition_eopnotsupp)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_FLATDEV);
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BLOB);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(G-M13/AR-4): Linux 基线为 DEVICE_TABLE 图像 +
	 * `device=/dev/vde`(EROFS_DEV_BLOB)计数匹配的真·多设备
	 * 挂载成功;aster 过渡期拒绝(EOPNOTSUPP)。与
	 * super_block_device_count_mismatch 对照: 同一 data 串形态,
	 * BASE(extra=0)因计数不匹配拒(对等),FLATDEV(extra=1)
	 * 计数匹配但过渡拒(本行)。
	 *
	 * Expected-value revision (T-023/S08, registered per the
	 * frozen-expectation rule "revise only from the authority, in
	 * place, with a trace"): the errno here was frozen as EINVAL in
	 * the pre-design T-020 era; the design ledger then fixed
	 * EOPNOTSUPP for the V10-e transition-rejection arm (authority:
	 * docs/T-012/analysis.md sec. 4.1 and docs/T-012/S03/index.md
	 * sec. 4.1, design-time AUTO-RESOLVE under AR-S01-4; same
	 * wording as the T-023 task statement and its verification
	 * gate). Revised from the authority, never from observed
	 * behavior; the internal symbol name follows the errno (zero
	 * behavior impact, logged in docs/T-023/S08/index.md).
	 */
	TEST_ERRNO(mount_dev(EROFS_DEV_FLATDEV, "device=" EROFS_DEV_BLOB),
		   EOPNOTSUPP);
}
END_TEST()

/*
 * G-M14 flatdev acceptance (parity, decision (3) candidate F): an
 * image with DEVICE_TABLE set and extra_devices > 0 mounts fine
 * WITHOUT any device= option. The statfs f_blocks slot accumulation
 * face belongs to statfs_remount.c; the main-only out-of-bounds EIO
 * data face belongs to data_path.c.
 */
FN_TEST(super_block_flatdev_no_device_mounts)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_FLATDEV);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_FLATDEV, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * G-M14 damaged-tag half (parity): a flatdev image whose device
 * table slot tag is overwritten with nonzero garbage still mounts
 * successfully -- the tag value is not validated on the mount path.
 */
FN_TEST(super_block_badtag_still_mounts)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BADTAG);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_dev(EROFS_DEV_BADTAG, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
