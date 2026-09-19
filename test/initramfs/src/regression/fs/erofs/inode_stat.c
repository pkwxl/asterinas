// SPDX-License-Identifier: MPL-2.0

/*
 * erofs inode decode / statx field face assertions (T-020/S09; matrix
 * sec. 3.1/3.2/3.6-statx-half + S01 sec. 3.6 stat diversity, S05 sec. 3
 * file #7).
 *
 * Carriers:
 *   - MNT half: the persistent /erofs mount point, which under the
 *     canonical single-run complement carries x7/C2 base_cpt, a
 *     uniform-COMPACT image (errata T-020/S01 sec. 4) -- every MNT
 *     assertion below therefore exercises the compact half of the D4
 *     version branch.
 *   - Extended-contrast half: x5/C1 base (uniform-EXTENDED) self-mounted
 *     at the single self-mount point; the bit0 split assertion compares
 *     the same entries' field faces across the two uniform images
 *     (carrier swap, zero change of expected values).
 *
 * Guards (S05 sec. 6): MNT tests use EROFS_SKIP_IF_NO_INIT_MNT()
 * (mount-success evidence); the self-mount test additionally stacks
 * EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE). Both keep the non-erofs run
 * form and the attached-but-unimplemented state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists: matrix sec. 3.1 (D1-D13 healthy decode face),
 * sec. 3.2 (X1-X11/X15/X16, W-N01/W-N02/W-N03 registered faces, G-N03),
 * sec. 3.6 (layout aggregation, statx half), quoting T-003 sec. 1.1/
 * 1.2/2.5; material faces (entry sizes, staged chmod/chown values,
 * special nodes) from T-016/S01 sec. 3.1/3.5/3.6 and the digest-pinned
 * stage truth of T-018 (sparse size 401408 = erofs_stage.sh
 * SPARSE_SIZE). Registered-difference assertions carry their Linux
 * baseline inline (marked "登记差异"). Never adjust an expected value
 * to match observed behavior -- go back to the matrix instead.
 *
 * statx call form = raw syscall(SYS_statx) + <linux/stat.h> UAPI, along
 * the in-tree precedent fs/statx/btime.c (this host's glibc ships no
 * struct statx wrapper at all).
 */

#include "erofs_common.h"

#include <linux/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>

/*
 * UAPI bits consumed below. This host's <linux/stat.h> (6.8-era)
 * already defines all of them; the guards follow the statfs_remount.c
 * belt-and-braces precedent (values from the pinned Linux 6.12 UAPI,
 * include/uapi/linux/stat.h) for build environments with older
 * headers.
 */
#ifndef STATX_DIOALIGN
#define STATX_DIOALIGN 0x00002000U
#endif
#ifndef STATX_ATTR_COMPRESSED
#define STATX_ATTR_COMPRESSED 0x00000004
#endif
#ifndef STATX_ATTR_IMMUTABLE
#define STATX_ATTR_IMMUTABLE 0x00000010
#endif
#ifndef STATX_ATTR_AUTOMOUNT
#define STATX_ATTR_AUTOMOUNT 0x00001000
#endif
#ifndef STATX_ATTR_DAX
#define STATX_ATTR_DAX 0x00200000
#endif

/* C1/C2 are 4k images (blkszbits = 12): X11 stx_blksize, D12 >> 9. */
#define EROFS_IMG_BS 4096u

#define ERO_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int ero_statx(const char *path, int at_flags, unsigned int mask,
		     struct statx *stx)
{
	memset(stx, 0, sizeof(*stx));
	return (int)syscall(SYS_statx, AT_FDCWD, path, at_flags, mask, stx);
}

/*
 * D12/X10, non-compressed branch (nblks stays 0 on every healthy
 * image): st_blocks = round_up(i_size, bs) >> 9, 512B sectors. The
 * formula is size-based, so the inline_4095b INLINE<->PLAIN flip
 * uncertainty (S01 sec. 3.1, decided by image sampling) does not
 * affect the expectation.
 */
static unsigned long long ero_expect_blocks(unsigned long long size)
{
	return ((size + EROFS_IMG_BS - 1) / EROFS_IMG_BS) *
	       (EROFS_IMG_BS / 512u);
}

/* D10/X8: atime == mtime == ctime, seconds and nanoseconds. */
static int ero_times_identical(const struct statx *stx)
{
	return stx->stx_atime.tv_sec == stx->stx_mtime.tv_sec &&
	       stx->stx_atime.tv_nsec == stx->stx_mtime.tv_nsec &&
	       stx->stx_mtime.tv_sec == stx->stx_ctime.tv_sec &&
	       stx->stx_mtime.tv_nsec == stx->stx_ctime.tv_nsec;
}

/* S01 sec. 3.1 size ladder (sizes are the authority values; sparse
 * size 401408 is the stage truth, erofs_stage.sh SPARSE_SIZE). */
static const struct ero_size_row {
	const char *rel;
	unsigned long long size;
} ero_size_rows[] = {
	{ "/regular/empty_file.bin", 0 },
	{ "/regular/file_1b.bin", 1 },
	{ "/regular/inline_64b.bin", 64 },
	{ "/regular/inline_4095b.bin", 4095 },
	{ "/regular/flat_4096b.bin", 4096 },
	{ "/regular/flat_4097b.bin", 4097 },
	{ "/regular/flat_16k_plus_100b.bin", 16588 },
	{ "/regular/sparse_hole.bin", 401408 },
};

/* Seven S_IFMT types, one preset entry each (S01 sec. 3.1/3.2/3.3/
 * 3.5); rdev expectations are the mknod parameters verbatim (X6:
 * new_decode_dev bit pattern round-trips the encoded on-image rdev). */
static const struct ero_type_row {
	const char *rel;
	unsigned int ifmt;
	unsigned int rdev_major, rdev_minor;
} ero_type_rows[] = {
	{ "/regular/file_1b.bin", S_IFREG, 0, 0 },
	{ "/dirs/small", S_IFDIR, 0, 0 },
	{ "/symlink/to_file_short", S_IFLNK, 0, 0 },
	{ "/special/chr_dev", S_IFCHR, 1, 3 },
	{ "/special/blk_dev", S_IFBLK, 7, 200 },
	{ "/special/fifo_entry", S_IFIFO, 0, 0 },
	{ "/special/sock_entry", S_IFSOCK, 0, 0 },
};

/*
 * The bit0-split comparison face (errata T-020/S01 sec. 4): the
 * fs-decoded fields. Timestamps are deliberately NOT part of the face
 * -- the two D4 branches source them differently by design (compact =
 * superblock build_time, extended = on-image i_mtime), so their values
 * are not expected to agree across the two images; three-time identity
 * is asserted per image instead. stx_dev differs (distinct bdevs) and
 * the framework-owned result mask / attributes_mask are not fs faces.
 */
struct ero_face {
	unsigned int mode, nlink, uid, gid;
	unsigned int blksize, rdev_major, rdev_minor;
	unsigned long long size, ino, blocks, attributes;
};

static void ero_snap_face(const struct statx *stx, struct ero_face *f)
{
	f->mode = stx->stx_mode;
	f->nlink = stx->stx_nlink;
	f->uid = stx->stx_uid;
	f->gid = stx->stx_gid;
	f->blksize = stx->stx_blksize;
	f->rdev_major = stx->stx_rdev_major;
	f->rdev_minor = stx->stx_rdev_minor;
	f->size = stx->stx_size;
	f->ino = stx->stx_ino;
	f->blocks = stx->stx_blocks;
	f->attributes = stx->stx_attributes;
}

static const char *ero_face_diff(const struct ero_face *a,
				 const struct ero_face *b)
{
	if (a->mode != b->mode)
		return "stx_mode";
	if (a->nlink != b->nlink)
		return "stx_nlink";
	if (a->uid != b->uid)
		return "stx_uid";
	if (a->gid != b->gid)
		return "stx_gid";
	if (a->blksize != b->blksize)
		return "stx_blksize";
	if (a->rdev_major != b->rdev_major)
		return "stx_rdev_major";
	if (a->rdev_minor != b->rdev_minor)
		return "stx_rdev_minor";
	if (a->size != b->size)
		return "stx_size";
	if (a->ino != b->ino)
		return "stx_ino";
	if (a->blocks != b->blocks)
		return "stx_blocks";
	if (a->attributes != b->attributes)
		return "stx_attributes";
	return NULL;
}

/*
 * Compare the statx field face of the same tree entry as seen through
 * two mounts. Returns 0 when the faces agree; on mismatch (or statx
 * failure) prints a diagnostic line and returns -1.
 */
static int ero_face_compare(const char *path_a, const char *path_b,
			    const char *label)
{
	struct statx sa, sb;
	struct ero_face fa, fb;
	const char *field;

	if (ero_statx(path_a, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sa) <
		    0 ||
	    ero_statx(path_b, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sb) <
		    0) {
		fprintf(stderr, "face compare %s: statx failed: %s\n", label,
			strerror(errno));
		return -1;
	}
	ero_snap_face(&sa, &fa);
	ero_snap_face(&sb, &fb);
	field = ero_face_diff(&fa, &fb);
	if (field != NULL) {
		fprintf(stderr,
			"face compare %s: %s differs between the two images\n",
			label, field);
		return -1;
	}
	return 0;
}

/*
 * Matrix sec. 3.1 D7/D12 + sec. 3.2 X7/X10/X11 (parity): the size
 * ladder's statx face on the MNT half. The ladder spans FLAT_INLINE
 * (1/64/4095, plus the 0-size edge) and FLAT_PLAIN (4096/4097/16588/
 * sparse) file forms -- the sec. 3.6 aggregation statx half for file
 * layouts: the field face is form-blind, which is exactly the
 * aggregation row's point. The empty file doubles as the round_up(0)
 * edge of the D12 formula.
 */
FN_TEST(inode_stat_size_gradient_blocks)
{
	struct statx stx;
	char path[256];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(ero_size_rows); i++) {
		const unsigned long long size = ero_size_rows[i].size;

		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 ero_size_rows[i].rel);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS, &stx));
		/* D7/X7: st_size = i_size. */
		TEST_RES(stx.stx_size, _ret == size);
		/* D12/X10: st_blocks = round_up(i_size, bs) >> 9. */
		TEST_RES(stx.stx_blocks, _ret == ero_expect_blocks(size));
		/* X11: st_blksize = s_blocksize (4k image). */
		TEST_RES(stx.stx_blksize, _ret == EROFS_IMG_BS);
		/* X7/X10 visibility bits under a BASIC_STATS request. */
		TEST_RES(stx.stx_mask & (STATX_SIZE | STATX_BLOCKS), _ret != 0);
	}
}
END_TEST()

/*
 * Matrix sec. 3.1 D1-D13 seven-type visible fields + sec. 3.2 X2/X3/
 * X4/X6 (parity): every S_IFMT type decodes and stats. rdev comes back
 * split as major/minor; FIFO/SOCK and the non-special types report 0.
 * nlink is the on-image value taken verbatim (1 for a plain file,
 * 2 for a childless directory). st_ino is the nid passthrough, nonzero
 * for every non-root entry.
 */
FN_TEST(inode_stat_seven_types_face)
{
	struct statx stx;
	char path[256];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(ero_type_rows); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 ero_type_rows[i].rel);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS, &stx));
		/* D8/X3: the i_mode S_IFMT nibble lands verbatim. */
		TEST_RES(stx.stx_mode & S_IFMT, _ret == ero_type_rows[i].ifmt);
		/* X6: stx_rdev = new_decode_dev(i_u.rdev). */
		TEST_RES(stx.stx_rdev_major,
			 _ret == ero_type_rows[i].rdev_major);
		TEST_RES(stx.stx_rdev_minor,
			 _ret == ero_type_rows[i].rdev_minor);
		/* X11. */
		TEST_RES(stx.stx_blksize, _ret == EROFS_IMG_BS);
	}
	/* X4: nlink 原值照收. */
	snprintf(path, sizeof(path), "%s/regular/file_1b.bin", EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_nlink, _ret == 1);
	TEST_RES(stx.stx_ino, _ret != 0);
	snprintf(path, sizeof(path), "%s/dirs/small", EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_nlink, _ret == 2);
	TEST_RES(stx.stx_ino, _ret != 0);
	/* D12 zero-size edge on the four special nodes (i_size = 0). */
	for (i = 3; i < ERO_ARRAY_SIZE(ero_type_rows); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 ero_type_rows[i].rel);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS, &stx));
		TEST_RES(stx.stx_size, _ret == 0);
		TEST_RES(stx.stx_blocks, _ret == ero_expect_blocks(0));
	}
}
END_TEST()

/*
 * S01 sec. 3.6 stat diversity (served per S05 sec. 3 #7): the staged
 * chmod/chown faces -- non-default mode on a file, read-only mode on a
 * file, non-default mode on a directory, non-zero uid/gid, large
 * (nobody-range) uid/gid -- plus the default root ownership, cross
 * checked once through stat(2) as well. On the MNT half these ride the
 * compact decode path (16-bit uid/gid zero-extension is exercised by
 * the cross-format face test below).
 */
FN_TEST(inode_stat_mode_uid_gid_diversity)
{
	struct statx stx;
	struct stat sb;
	char path[256];

	EROFS_SKIP_IF_NO_INIT_MNT();
	/* chmod 0600 face (inline_64b.bin). */
	snprintf(path, sizeof(path), "%s/regular/inline_64b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_mode, _ret == (S_IFREG | 0600));
	/* chmod 0444 face (flat_4096b.bin). */
	snprintf(path, sizeof(path), "%s/regular/flat_4096b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_mode, _ret == (S_IFREG | 0444));
	/* chmod 0711 face (dirs/small). */
	snprintf(path, sizeof(path), "%s/dirs/small", EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_mode, _ret == (S_IFDIR | 0711));
	/* chown 1000:1000 face (flat_4097b.bin). */
	snprintf(path, sizeof(path), "%s/regular/flat_4097b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_uid, _ret == 1000);
	TEST_RES(stx.stx_gid, _ret == 1000);
	/* chown 65534:65534 face (xattr_multi.bin, nobody range). */
	snprintf(path, sizeof(path), "%s/xattr_host/xattr_multi.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_uid, _ret == 65534);
	TEST_RES(stx.stx_gid, _ret == 65534);
	/* Default ownership of an untouched entry stays root. */
	snprintf(path, sizeof(path), "%s/regular/empty_file.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(
		ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(stx.stx_uid, _ret == 0);
	TEST_RES(stx.stx_gid, _ret == 0);
	/* stat(2) cross-check of the same diversity face. */
	snprintf(path, sizeof(path), "%s/regular/inline_64b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(stat(path, &sb));
	TEST_RES(sb.st_mode, _ret == (S_IFREG | 0600));
	TEST_RES(sb.st_uid, _ret == 0);
	TEST_RES(sb.st_gid, _ret == 0);
	snprintf(path, sizeof(path), "%s/regular/flat_4097b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(stat(path, &sb));
	TEST_RES(sb.st_uid, _ret == 1000);
	TEST_RES(sb.st_gid, _ret == 1000);
}
END_TEST()

/*
 * Matrix sec. 3.1 D10 + sec. 3.2 X8/X9 (parity): atime == mtime ==
 * ctime on every entry kind (the value itself is not a tree-side
 * assertion face -- S01 sec. 1-2 -- only the identity is), and btime
 * has no source on either end: the STATX_BTIME bit never appears in
 * the result mask and the copied timestamp stays zero.
 */
FN_TEST(inode_stat_times_and_btime)
{
	static const char *const entries[] = {
		"/regular/file_1b.bin", "/dirs/small",
		"/dirs/many_entries",	"/symlink/to_file_short",
		"/special/chr_dev",	"/special/sock_entry",
	};
	struct statx stx;
	char path[256];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(entries); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 entries[i]);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS, &stx));
		/* D10/X8. */
		TEST_RES(ero_times_identical(&stx), _ret);
	}
	for (i = 0; i < 3; i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 entries[i]);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS | STATX_BTIME, &stx));
		/* X9: btime 无源, both ends absent and zero. */
		TEST_RES(stx.stx_mask & STATX_BTIME, _ret == 0);
		TEST_RES(stx.stx_btime.tv_sec == 0 &&
				 stx.stx_btime.tv_nsec == 0,
			 _ret);
	}
}
END_TEST()

/*
 * Matrix sec. 3.2 X12/X13 + W-N01 (registered difference): stx_
 * attributes / stx_attributes_mask. Asserted on non-mount-root
 * entries, so the full zero expectation holds; the mask assertion
 * checks the four Linux-authority bits (EROFS's IMMUTABLE|COMPRESSED
 * plus the VFS-fronted AUTOMOUNT|DAX) for absence.
 */
FN_TEST(inode_stat_attributes_registered)
{
	static const char *const entries[] = {
		"/regular/file_1b.bin",
		"/dirs/small",
		"/special/blk_dev",
	};
	struct statx stx;
	char path[256];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(entries); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 entries[i]);
		TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
				    STATX_BASIC_STATS, &stx));
		/*
		 * 登记差异(W-N01/X12/X13): Linux 基线 stx_attributes
		 * 恒报 STATX_ATTR_IMMUTABLE(EROFS 手工置,与 S_IMMUTABLE
		 * 无关联),attributes_mask 恒含 AUTOMOUNT|DAX|IMMUTABLE|
		 * COMPRESSED 四位;aster attributes 恒 0(非挂载根)、mask
		 * 仅 MOUNT_ROOT。
		 */
		TEST_RES(stx.stx_attributes, _ret == 0);
		TEST_RES(stx.stx_attributes_mask &
				 (STATX_ATTR_IMMUTABLE | STATX_ATTR_COMPRESSED |
				  STATX_ATTR_AUTOMOUNT | STATX_ATTR_DAX),
			 _ret == 0);
	}
}
END_TEST()

/*
 * Matrix sec. 3.2 W-N03 (registered difference): the result mask is
 * never negotiated down to the request. Both the empty-mask and the
 * partial-mask request forms still report the basic-stats bits.
 */
FN_TEST(inode_stat_result_mask_no_negotiation)
{
	struct statx stx;
	char path[256];

	EROFS_SKIP_IF_NO_INIT_MNT();
	snprintf(path, sizeof(path), "%s/regular/file_1b.bin", EROFS_INIT_MNT);
	/*
	 * 登记差异(W-N03): Linux 基线按请求 mask 裁剪 result_mask;
	 * aster stx_mask 恒满(不与请求协商)。
	 */
	TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW, 0, &stx));
	TEST_RES(stx.stx_mask &
			 (STATX_TYPE | STATX_MODE | STATX_SIZE | STATX_BLOCKS),
		 _ret != 0);
	TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW, STATX_TYPE, &stx));
	TEST_RES(stx.stx_mask & (STATX_MODE | STATX_SIZE | STATX_BLOCKS),
		 _ret != 0);
}
END_TEST()

/*
 * Matrix sec. 3.2 X14 + W-N02 + sec. 4.4 W-P03 (same batch, registered
 * difference): statx(STATX_DIOALIGN) on a non-compressed REG. The
 * non-REG half is parity -- Linux does not set the bit for non-REG
 * either.
 */
FN_TEST(inode_stat_dioalign_registered)
{
	struct statx stx;
	char path[256];

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * 登记差异(X14/W-N02/W-P03 同批): Linux 基线在非压缩 REG 上
	 * 置 STATX_DIOALIGN 并公告 bdev 逻辑块大小(典型 512/4096);
	 * aster mask 恒不含该位、stx_dio_* 恒 0。
	 */
	snprintf(path, sizeof(path), "%s/regular/flat_4096b.bin",
		 EROFS_INIT_MNT);
	TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
			    STATX_BASIC_STATS | STATX_DIOALIGN, &stx));
	TEST_RES(stx.stx_mask & STATX_DIOALIGN, _ret == 0);
	TEST_RES(stx.stx_dio_mem_align, _ret == 0);
	TEST_RES(stx.stx_dio_offset_align, _ret == 0);
	/* Non-REG half: parity absence on a directory. */
	snprintf(path, sizeof(path), "%s/dirs/small", EROFS_INIT_MNT);
	TEST_SUCC(ero_statx(path, AT_SYMLINK_NOFOLLOW,
			    STATX_BASIC_STATS | STATX_DIOALIGN, &stx));
	TEST_RES(stx.stx_mask & STATX_DIOALIGN, _ret == 0);
	TEST_RES(stx.stx_dio_mem_align, _ret == 0);
	TEST_RES(stx.stx_dio_offset_align, _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 3.2 G-N03: LNK/SOCK body open (non-O_PATH) -> ENODEV.
 * The socket half is the unambiguous parity anchor. The symlink half
 * is reached through O_NOFOLLOW, the only userland route to the link
 * body; the O_PATH exception is asserted as the boundary that must
 * keep succeeding.
 */
FN_TEST(inode_stat_open_lnk_sock_enodev)
{
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/* G-N03 parity: socket inode body open -> ENODEV. */
	TEST_ERRNO(open(EROFS_INIT_MNT "/special/sock_entry", O_RDONLY),
		   ENODEV);
	/* G-N03 boundary: the O_PATH exception keeps succeeding on the
	 * symlink body. */
	fd = TEST_SUCC(open(EROFS_INIT_MNT "/symlink/to_file_short",
			    O_PATH | O_NOFOLLOW));
	TEST_SUCC(close(fd));
	/*
	 * G-N03 LNK 半边(AR-7 候选①覆写 open,冻结 = ENODEV,None
	 * 路径 errno 核验注记随行): Linux 基线对 O_NOFOLLOW 落在
	 * symlink 上的形态为 ELOOP。
	 */
	TEST_ERRNO(open(EROFS_INIT_MNT "/symlink/to_file_short",
			O_RDONLY | O_NOFOLLOW),
		   ENODEV);
}
END_TEST()

/*
 * Bit0 split face (errata T-020/S01 sec. 4, matrix sec. 3.1 compact/
 * extended field face): the same tree entries stats identically
 * through /erofs (x7/C2, uniform-compact) and a self-mounted x5/C1
 * (uniform-extended). Carriers are swapped relative to the original
 * S05 wording; the assertion values do not change. Timestamps are
 * excluded from the face (see ero_face_compare); three-time identity
 * holds on each image separately (spot-checked here on the extended
 * half).
 */
FN_TEST(inode_stat_bit0_compact_extended_face)
{
	static const char *const entries[] = {
		"/regular/inline_64b.bin",  "/regular/flat_4097b.bin",
		"/regular/sparse_hole.bin", "/dirs/small",
		"/symlink/to_file_short",   "/special/chr_dev",
		"/special/blk_dev",	    "/special/fifo_entry",
		"/special/sock_entry",	    "/xattr_host/xattr_multi.bin",
	};
	struct statx stx;
	char cpt[256], ext[256];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, NULL));
	for (i = 0; i < ERO_ARRAY_SIZE(entries); i++) {
		snprintf(cpt, sizeof(cpt), "%s%s", EROFS_INIT_MNT, entries[i]);
		snprintf(ext, sizeof(ext), "%s%s", EROFS_SELF_MNT, entries[i]);
		TEST_RES(ero_face_compare(cpt, ext, entries[i]), _ret == 0);
	}
	/* D10 on the extended half: three-time identity holds on C1. */
	snprintf(ext, sizeof(ext), "%s/regular/flat_4096b.bin", EROFS_SELF_MNT);
	TEST_SUCC(ero_statx(ext, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &stx));
	TEST_RES(ero_times_identical(&stx), _ret);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
