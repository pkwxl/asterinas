// SPDX-License-Identifier: MPL-2.0

/*
 * erofs mount source/path face assertions (T-020/S04; matrix sec. 2.3,
 * S05 sec. 3 file #2).
 *
 * Carrier: BASE (EROFS_DEV_BASE, slot x5 / image C1) self-mounted at the
 * single self-mount point for the FsCache ro/rw combos and the
 * privilege-drop probes; VM-internal paths (a regular file, a directory,
 * a character device, and the resident ext2 disk) serve as mount SOURCES
 * for the source-resolution errno family -- all orthogonal to the image
 * content (matrix sec. 2.3: IMG-BASIC).
 *
 * Guard: self-mount class, EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE) in every
 * FN_TEST. Several faces below consume VM-internal sources instead of
 * BASE itself, but the guard keeps BASE as the all-or-nothing attachment
 * sentinel (S04 sec. 1) -- and, crucially, as the erofs-registration
 * probe, without which every EINVAL/ENODEV expectation below would be
 * shadowed by the not-registered ENODEV of the fs-type lookup.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.3 rows quoting T-002 sec. 3.1
 * G2/G3/G6/G7 and sec. 9.2/10.1 facts T2/T4/T5/T14). Registered-
 * difference assertions carry their Linux baseline inline (marked
 * "登记差异"). Never adjust an expected value to match observed
 * behavior -- go back to the matrix instead.
 */

#include "erofs_common.h"

#include <sys/mount.h>

/*
 * Resident ext2 test disk: attached in every run form (it precedes the
 * conditional erofs segment, so its letter never shifts) and NOT one of
 * the 15 erofs slots; used as a VM-internal mount source for the W-M10
 * cross-fs-type face (S05 sec. 3 file #2 carrier note). init mounts it
 * at /ext2 unconditionally (src/init:26), so a live ext2 instance holds
 * this device during the regression run.
 */
#define RESIDENT_EXT2_DEV "/dev/vda"

/* Drop-to uid for the W-M05 legacy-entry probes (nobody, S05 sec. 8). */
#define EROFS_NOBODY_UID 65534

/* Mount BASE at the self-mount point with mount flags and a data string. */
static int mount_base_flags(unsigned long flags, const char *data)
{
	return mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", flags, data);
}

/* Mount an arbitrary SOURCE as erofs (no flags, optional data string). */
static int mount_src(const char *source, const char *data)
{
	return mount(source, EROFS_SELF_MNT, "erofs", 0, data);
}

/* G2: no source specified at all. */
FN_TEST(mount_path_no_source_einval)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * A NULL device name reaches the fs layer as source == NULL and
	 * is rejected with EINVAL before any path lookup (parity).
	 */
	TEST_ERRNO(mount_src(NULL, NULL), EINVAL);
}
END_TEST()

/* G3: source path resolution errors are transmitted as-is. */
FN_TEST(mount_path_source_lookup_errnos)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/* A nonexistent source path resolves to ENOENT (parity). */
	TEST_ERRNO(mount_src("/nonexistent_erofs_source", NULL), ENOENT);

	/* The empty string is a lookup error, not a missing source. */
	TEST_ERRNO(mount_src("", NULL), ENOENT);

	/* A component below a regular file is ENOTDIR (kern_path family). */
	TEST_ERRNO(mount_src("/proc/filesystems/under", NULL), ENOTDIR);
}
END_TEST()

/* W-M09: non-device mount sources. */
FN_TEST(mount_path_non_device_sources_enodev)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(W-M09): Linux 基线为 ENOTBLK(source 存在但非块
	 * 设备);aster 的 resolve_block_device 对非设备文件统一返回
	 * ENODEV。三形态(常规文件/目录/字符设备,载体列原字面)。
	 */
	/* regular file (procfs, always mounted by init) */
	TEST_ERRNO(mount_src("/proc/filesystems", NULL), ENODEV);
	/* directory */
	TEST_ERRNO(mount_src("/tmp", NULL), ENODEV);
	/* character device (devtmpfs, 1,3) */
	TEST_ERRNO(mount_src("/dev/null", NULL), ENODEV);
}
END_TEST()

/* W-M02: bad source + bad option, device resolution wins. */
FN_TEST(mount_path_double_error_dev_before_options)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(W-M02/S06-D4): 坏源(非设备文件)+ 坏选项(未知
	 * key)双错场景,Linux 基线为 EINVAL(选项解析先于设备打开);
	 * aster 设备解析先于选项解析(框架层次序,fs 层不可闭合),
	 * 返回 ENODEV。
	 */
	TEST_ERRNO(mount_src("/proc/filesystems", "bogus=1"), ENODEV);
}
END_TEST()

/*
 * W-M05 probe callbacks: return 0 on success and the positive errno on
 * failure (-1 stays reserved for ero_run_as_uid construction failures).
 */
static int dropped_mount_erofs(void)
{
	if (mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, NULL) == 0)
		return 0;
	return errno;
}

static int dropped_umount_erofs(void)
{
	if (umount(EROFS_SELF_MNT) == 0)
		return 0;
	return errno;
}

/* W-M05: legacy mount/umount entries have no CAP_SYS_ADMIN check. */
FN_TEST(mount_path_unprivileged_legacy_entries)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(W-M05): Linux 基线为无 CAP_SYS_ADMIN 的 legacy
	 * mount(2)/umount(2) 返回 EPERM;aster 旧入口全链无权限检查,
	 * 降权(65534)子进程探测照常成功。remount 旧入口同属该登记
	 * (S06-D8),其行为面归 statfs_remount.c(RM 族),此处不重复。
	 */
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_mount_erofs),
		 _ret == 0);
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_umount_erofs),
		 _ret == 0);
}
END_TEST()

/* G6: a live instance rejects an RO-state-changing second mount. */
FN_TEST(mount_path_fscache_ro_mismatch_ebusy)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * erofs always stores RDONLY (F1), so after both a first-rw and
	 * a first-ro mount the live instance is ro; a second RW request
	 * would change the RO state and is rejected with EBUSY (parity;
	 * the two EBUSY combos of the matrix G6 four-combo face).
	 */
	TEST_SUCC(mount_base_flags(0, NULL));
	TEST_ERRNO(mount_base_flags(0, NULL), EBUSY);
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base_flags(MS_RDONLY, NULL));
	TEST_ERRNO(mount_base_flags(0, NULL), EBUSY);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* G7: an RO-matching second mount reuses the live instance. */
FN_TEST(mount_path_fscache_ro_match_reuse)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * A matching RO request reuses the live instance: the second
	 * mount succeeds, create is not re-run and the superblock is
	 * not re-read (parity; return-value face -- the no-revalidation
	 * half has no cheap userspace observable). Both mounts stack on
	 * the shared self-mount point and are unmounted in LIFO order.
	 */
	TEST_SUCC(mount_base_flags(0, NULL));
	TEST_SUCC(mount_base_flags(MS_RDONLY, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base_flags(MS_RDONLY, NULL));
	TEST_SUCC(mount_base_flags(MS_RDONLY, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* W-M10: the same device under a second fs type. */
FN_TEST(mount_path_cross_fs_same_device)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(W-M10): Linux 基线为同设备跨 fs 类型第二挂载
	 * EBUSY(bdev 独占,ext2 实例存活时先于超块读取);aster 无
	 * 跨 fs 设备占用面,挂载推进到 erofs 自身校验,在 ext2 内容
	 * 上因 magic 不符(V2)失败为 EINVAL——以「非 EBUSY 的内容性
	 * 失败」承载「无独占拒绝」的登记面。
	 */
	TEST_ERRNO(mount_src(RESIDENT_EXT2_DEV, NULL), EINVAL);
}
END_TEST()
