// SPDX-License-Identifier: MPL-2.0

/*
 * erofs mount option parsing assertions (T-020/S03; matrix sec. 2.1,
 * S05 sec. 3 file #1).
 *
 * Carrier: BASE (EROFS_DEV_BASE, slot x5 / image C1) self-mounted at the
 * single self-mount point EROFS_SELF_MNT, mounted and unmounted serially
 * inside each FN_TEST. The option face is orthogonal to the image content,
 * so one healthy image serves every row (matrix sec. 2.1: IMG-BASIC).
 *
 * Guard: self-mount class, EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE) -- the
 * device node is present AND erofs is registered, so both the non-erofs
 * run form and the attached-but-unimplemented state SKIP with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.1 rows quoting T-002 sec. 1.4 and
 * 1.5). Registered-difference assertions carry their Linux baseline
 * inline (marked "登记差异"). Never adjust an expected value to match
 * observed behavior -- go back to the matrix instead.
 */

#include "erofs_common.h"

#include <sys/mount.h>

/* Mount BASE at the self-mount point with mount flags and a data string. */
static int mount_base_flags(unsigned long flags, const char *data)
{
	return mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", flags, data);
}

/* The common shape: no mount flags, option string data (NULL = none). */
static int mount_base(const char *data)
{
	return mount_base_flags(0, data);
}

/* Monolithic data-string splitting edges (parser spec, matrix 2.1 row 1). */
FN_TEST(mount_options_monolithic_split_edges)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/* data == NULL: no tokens at all. */
	TEST_SUCC(mount_base(NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* Empty tokens are skipped. */
	TEST_SUCC(mount_base(",,"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* A token headed by '=' is skipped. */
	TEST_SUCC(mount_base("=skipped"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* Mixed: real tokens plus skipped filler in one data string. */
	TEST_SUCC(mount_base("acl,,=junk,noacl"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* A flag-type key given a value is rejected by the generic layer. */
	TEST_ERRNO(mount_base("acl=1"), EINVAL);
	TEST_ERRNO(mount_base("user_xattr=1"), EINVAL);
}
END_TEST()

/* Unknown keys, exact-case matching, no trimming, off-table no- prefix. */
FN_TEST(mount_options_unknown_keys)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/* G-M05 (AR-3): an unknown key is rejected with EINVAL. */
	TEST_ERRNO(mount_base("bogus"), EINVAL);
	TEST_ERRNO(mount_base("bogus=1"), EINVAL);

	/* Key matching is exact-case. */
	TEST_ERRNO(mount_base("USER_XATTR"), EINVAL);
	TEST_ERRNO(mount_base("Acl"), EINVAL);
	TEST_ERRNO(mount_base("Dax"), EINVAL);

	/* No trimming: the space is part of the key, hence unknown. */
	TEST_ERRNO(mount_base(" user_xattr"), EINVAL);

	/*
	 * The no- prefix only applies to flag_no specs; these off-table
	 * no- forms are unknown keys.
	 */
	TEST_ERRNO(mount_base("nofsid"), EINVAL);
	TEST_ERRNO(mount_base("nodomain_id"), EINVAL);
	TEST_ERRNO(mount_base("nodevice"), EINVAL);
	TEST_ERRNO(mount_base("nocache_strategy"), EINVAL);
}
END_TEST()

/* G-M07 storage flags and the repeat-last-wins rule (parity face). */
FN_TEST(mount_options_flag_storage_and_repeat)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * G-M07: user_xattr/nouser_xattr and acl/noacl are parsed and
	 * stored; both default to on, so "user_xattr,acl" is the
	 * default-equivalent string. Every combination mounts fine.
	 */
	TEST_SUCC(mount_base("user_xattr,acl"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("nouser_xattr,noacl"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* Repeated flag options: the last one wins. */
	TEST_SUCC(mount_base("acl,noacl"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("nouser_xattr,user_xattr"));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* W-M01: the MS_POSIXACL mount flag is dropped by aster. */
FN_TEST(mount_options_ms_posixacl_flag)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(W-M01): Linux 基线为 mount(2) 携 MS_POSIXACL 时置位
	 * sb 旗标;aster 丢弃该旗标——本断言面两端 mount(2) 返回值同为
	 * 成功,旗标的 ACL 执行语义缺口归 acl.c(X 域)承载。
	 */
	TEST_SUCC(mount_base_flags(MS_POSIXACL, NULL));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* G-M01: cache_strategy two-layer behavior. */
FN_TEST(mount_options_cache_strategy)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * Layer 1: legal values are warned about and ignored (ZIP is out
	 * of scope); the mount continues.
	 */
	TEST_SUCC(mount_base("cache_strategy=disabled"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("cache_strategy=readahead"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("cache_strategy=readaround"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/*
	 * Layer 2: an illegal value is rejected by the generic fs_parser
	 * layer, before any config ifdef -- always EINVAL.
	 */
	TEST_ERRNO(mount_base("cache_strategy=bogus"), EINVAL);
	TEST_ERRNO(mount_base("cache_strategy="), EINVAL);

	/* A value-type key given bare fails type conversion. */
	TEST_ERRNO(mount_base("cache_strategy"), EINVAL);
}
END_TEST()

/* G-M02: the whole dax family is rejected. */
FN_TEST(mount_options_dax_family)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * Every dax form is EINVAL (explicit enumeration duty, not
	 * reached through the unknown-key path).
	 */
	TEST_ERRNO(mount_base("dax"), EINVAL);
	TEST_ERRNO(mount_base("dax=always"), EINVAL);
	TEST_ERRNO(mount_base("dax=never"), EINVAL);
	TEST_ERRNO(mount_base("dax=bogus"), EINVAL);
	TEST_ERRNO(mount_base("dax="), EINVAL);

	/* "nodax": dax has no neg_with_no spec, so it is unknown. */
	TEST_ERRNO(mount_base("nodax"), EINVAL);
}
END_TEST()

/* G-M03/G-M04: pruned no-semantics options. */
FN_TEST(mount_options_fsid_domain_directio)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * G-M03: non-empty fsid/domain_id values are warned about and
	 * ignored; the mount continues. The value is everything after
	 * the FIRST '=' (parser spec), so '=' may appear inside it.
	 */
	TEST_SUCC(mount_base("fsid=some-id"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("fsid=a=b"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("domain_id=some-domain"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	/* Empty or bare value-type keys are rejected by the generic layer. */
	TEST_ERRNO(mount_base("fsid="), EINVAL);
	TEST_ERRNO(mount_base("fsid"), EINVAL);
	TEST_ERRNO(mount_base("domain_id="), EINVAL);
	TEST_ERRNO(mount_base("domain_id"), EINVAL);

	/*
	 * G-M04: directio/nodirectio (absent from the official docs
	 * table -- must not be pruned accordingly) are warned about and
	 * ignored, in both forms.
	 */
	TEST_SUCC(mount_base("directio"));
	TEST_SUCC(umount(EROFS_SELF_MNT));

	TEST_SUCC(mount_base("nodirectio"));
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/* G-M06: the reserved `source=` key (errno collision). */
FN_TEST(mount_options_reserved_source_key)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * 登记差异(G-M06): Linux 基线为 `source` 系 VFS 保留键,单次
	 * 出现 = 设置挂载源(合法;经 mount(2) 数据串给出且 source 实参
	 * 已先行传入时构成重复,Linux 亦报 EINVAL "Multiple sources");
	 * aster 将其按未知选项拒绝——errno 撞值 EINVAL、语义不同。
	 */
	TEST_ERRNO(mount_base("source=/dev/vdd"), EINVAL);
}
END_TEST()

/* G-M12 parse half: bare/empty device= rejected, non-empty accepted. */
FN_TEST(mount_options_device_parse)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/*
	 * String-spec type errors from the generic parser layer: bare
	 * key and empty value are both EINVAL.
	 */
	TEST_ERRNO(mount_base("device"), EINVAL);
	TEST_ERRNO(mount_base("device="), EINVAL);

	/*
	 * Parse-half forms on this single-device carrier: any non-empty
	 * string is accepted at parse time without path validation and
	 * may repeat; the later device-count check then fails. The errno
	 * is the counting-mismatch EINVAL (parity with Linux; the home
	 * assertion of that half is super_block.c). The AR-4 registered
	 * difference -- count MATCH on the MULTIDEV carrier, aster
	 * transition rejection vs Linux success -- is also asserted
	 * there, not here.
	 */
	TEST_ERRNO(mount_base("device=/nonexistent/erofs/blob"), EINVAL);
	TEST_ERRNO(mount_base("device=/nonexistent/a,device=/nonexistent/b"),
		   EINVAL);
}
END_TEST()
