// SPDX-License-Identifier: MPL-2.0

/*
 * erofs write-family EROFS panorama (T-020/S16; matrix sec. 1.4
 * element 3 concentrated carrier, the G-M20 wording promoted to
 * the whole-matrix organization principle -- S05 sec. 3 file #14).
 *
 * Face: every write path that a read-only erofs mount must
 * refuse. The enumeration is the S05 sec. 3 #14 row, verbatim:
 * open for writing (O_WRONLY/O_RDWR), creat, mkdir/rmdir, unlink,
 * rename, link, symlink creation, truncate/ftruncate, fchmod/
 * fchown/utimensat, O_TMPFILE, and write() on an already-open
 * read-only fd. Every attempt rides the persistent init mount
 * point MNT = /erofs (under the canonical single-run complement
 * it carries x7/C2 base_cpt, errata T-020/S01; write-family
 * behavior is image-orthogonal, so the C2 carrier costs nothing).
 *
 * Assertion directions:
 *   - negative control (dominant): every attempt that reaches the
 *     filesystem answers EROFS -- the write-family explicit-EROFS
 *     consensus (matrix sec. 1.4 element 3, quoting T-007
 *     sec. 10.3; Linux refuses each form at the read-only gate,
 *     anchors cited per test below);
 *   - two enumerated items are rejected one layer earlier, at the
 *     fd rights gate, before any filesystem code runs: write() on
 *     an fd opened O_RDONLY -> EBADF and ftruncate() on the same
 *     fd -> EINVAL. Both kernels agree today (Linux
 *     fs/read_write.c:667 and fs/open.c:168; aster
 *     kernel/core/src/fs/file/inode_handle.rs:288 and :379-381),
 *     so the parity errno is the frozen expectation while the
 *     negative-control essence -- no writable channel exists --
 *     still holds. Registered as AUTO-RESOLVE in
 *     docs/T-020/S16/index.md sec. 3 (a blanket "expect EROFS"
 *     reading would freeze a knowingly false expectation for
 *     these two fd-layer items).
 *
 * Targets: preset entries are addressed by their verbatim S01
 * sec. 3.1/3.2 names; the creation family targets fresh
 * wef_-prefixed names inside preset directories -- EROFS must
 * refuse them, so nothing ever lands on the image and the preset
 * tree stays unpolluted (the subtask row's sanctioned form).
 *
 * Guard: EROFS_SKIP_IF_NO_INIT_MNT() (mount-success evidence,
 * S05 sec. 6 extension 2) on every FN_TEST; the init mount point
 * is never unmounted or remounted, and this file does no
 * mount(2)/umount2 of its own (carriers beyond MNT belong to the
 * sibling files).
 *
 * Face boundaries (no overlap with sibling files): the in-file
 * write negatives riding their own faces stay there --
 * remount,rw then write (RM13) is statfs_remount.c's,
 * setxattr/removexattr EROFS (W-X01) is xattr.c's; this file is
 * the panorama of the remaining write family and adds no
 * mount-option or xattr face.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists; never adjust an expected value to match
 * observed behavior -- go back to the matrix instead.
 *
 * Sources (never re-derive locally): matrix sec. 1.2/1.4
 * (docs/R-01/phase-docs/a-analysis/r1-baseline-matrix.md), S05
 * sec. 3 #14 enumeration, S01 sec. 3.1/3.2 entry names, and the
 * Linux 6.12 anchors cited per test.
 */

#include "erofs_common.h"

#include <stdio.h>
#include <time.h>

/* Preset targets, addressed by the verbatim S01 sec. 3 names. */
#define WEF_REG EROFS_INIT_MNT "/regular"
#define WEF_FILE_1B WEF_REG "/file_1b.bin"
#define WEF_FILE_4K WEF_REG "/flat_4096b.bin" /* mode 0444, S01 sec. 3.6 */
#define WEF_FILE_4097 WEF_REG "/flat_4097b.bin"
#define WEF_FILE_16K WEF_REG "/flat_16k_plus_100b.bin" /* 16588 B */
#define WEF_FILE_INLINE WEF_REG "/inline_64b.bin"
#define WEF_ANCHOR WEF_REG "/content_anchor.txt"
#define WEF_SMALL_DIR EROFS_INIT_MNT "/dirs/small" /* mode 0711 */
#define WEF_EMPTY_DIR EROFS_INIT_MNT "/dirs/empty_dir" /* preset empty */

/*
 * Fresh names for the creation family, wef_-prefixed so their
 * negative-control origin is self-evident and they can never
 * collide with a preset entry. Every op below must fail with
 * EROFS, so none of these is ever created.
 */
#define WEF_NEW_CREAT WEF_REG "/wef_new_creat.bin"
#define WEF_NEW_DIR WEF_SMALL_DIR "/wef_new_dir"
#define WEF_NEW_LINK WEF_REG "/wef_new_link"
#define WEF_NEW_SLINK WEF_REG "/wef_new_slink"
#define WEF_RENAMED WEF_REG "/wef_renamed.bin"

/*
 * Panorama face 1 -- open-for-write family (negative control):
 * open(2) with O_WRONLY and with O_RDWR on preset regular files,
 * creat(3) on an existing preset entry and on a fresh name, and
 * O_TMPFILE in a preset directory. Linux refuses each form at the
 * read-only gate (fs/namei.c:496-498 sb_rdonly for the plain
 * write opens, fs/namei.c:3613-3627 for the O_CREAT path, and
 * do_tmpfile fs/namei.c:3954 mnt_want_write); erofs must answer
 * EROFS for all five forms.
 *
 * Expected-value revision (T-024/S04) on the two PLAIN write opens:
 * REGISTERED DIFFERENCE (docs/T-013/analysis.md sec. 9.1 row 3 /
 * S07 sec. 4.2 F-3): aster's open chain carries no SB_RDONLY gate,
 * so open(O_WRONLY/O_RDWR) on an erofs regular file SUCCEEDS and
 * the first refusal lands on write(2) -- the OPN-09 judgement form
 * ("open-time success is a mere prerequisite; assert write(2) ->
 * EROFS"). Revised from the authority, never from observed
 * behavior. The negative-control essence (no writable channel
 * exists) is carried by the write refusals; the creat forms below
 * still refuse AT open (their O_TRUNC/O_CREAT legs route through
 * resize/create, which the FS members gate with EROFS).
 */
FN_TEST(write_ero_fs_open_for_write)
{
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();

	fd = TEST_SUCC(open(WEF_FILE_4K, O_WRONLY));
	TEST_ERRNO(write(fd, "x", 1), EROFS);
	TEST_SUCC(close(fd));
	fd = TEST_SUCC(open(WEF_FILE_INLINE, O_RDWR));
	TEST_ERRNO(write(fd, "x", 1), EROFS);
	TEST_SUCC(close(fd));
	TEST_ERRNO(creat(WEF_FILE_1B, 0644), EROFS);
	TEST_ERRNO(creat(WEF_NEW_CREAT, 0644), EROFS);
	/*
	 * O_TMPFILE pairs with O_WRONLY (the accepted writing form,
	 * fs/tmpfile/tmpfile.c precedent); the inode creation itself
	 * must hit the RO gate -> EROFS.
	 */
	TEST_ERRNO(open(WEF_SMALL_DIR, O_TMPFILE | O_WRONLY, 0600), EROFS);
}
END_TEST()

/*
 * Panorama face 2 -- directory entry family (negative control):
 * mkdir, rmdir, unlink, symlink creation, link, rename. Linux
 * refuses each with EROFS at mnt_want_write before touching the
 * namespace; erofs must do the same. rmdir targets the preset
 * empty directory and unlink a preset 1-byte file -- the refusal
 * itself guarantees the preset tree survives untouched.
 */
FN_TEST(write_ero_fs_dentry_ops)
{
	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_ERRNO(mkdir(WEF_NEW_DIR, 0755), EROFS);
	TEST_ERRNO(rmdir(WEF_EMPTY_DIR), EROFS);
	TEST_ERRNO(unlink(WEF_FILE_1B), EROFS);
	TEST_ERRNO(symlink(WEF_ANCHOR, WEF_NEW_SLINK), EROFS);
	TEST_ERRNO(link(WEF_FILE_INLINE, WEF_NEW_LINK), EROFS);
	/*
	 * Rename a preset entry to a fresh name: removing the old
	 * name and creating the new one are both writes, refused up
	 * front with EROFS.
	 */
	TEST_ERRNO(rename(WEF_FILE_4097, WEF_RENAMED), EROFS);
}
END_TEST()

/*
 * Panorama face 3 -- truncate family: the path form reaches the
 * filesystem (Linux vfs_truncate, fs/open.c:84 mnt_want_write ->
 * EROFS) and must answer EROFS; the fd form cannot even construct
 * a writable descriptor on this mount (face 1 refuses every
 * write open), so ftruncate rides an O_RDONLY fd and is rejected
 * at the fd rights gate with EINVAL (Linux fs/open.c:168; aster
 * inode_handle.rs:379-381 -- the same parity errno both kernels
 * carry today). AUTO-RESOLVE entry: docs/T-020/S16/index.md
 * sec. 3.
 */
FN_TEST(write_ero_fs_truncate_family)
{
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_ERRNO(truncate(WEF_FILE_16K, 8192), EROFS);

	fd = TEST_SUCC(open(WEF_FILE_INLINE, O_RDONLY));
	TEST_ERRNO(ftruncate(fd, 0), EINVAL);
	TEST_SUCC(close(fd));
}
END_TEST()

/*
 * Panorama face 4 -- attribute-change family (negative control):
 * fchmod and fchown ride an O_RDONLY fd -- exactly like Linux,
 * aster raises no fd-rights gate for them (sys_fchmod/sys_fchown
 * dispatch straight to the inode layer), so the requests reach
 * the filesystem and must answer EROFS (Linux:
 * mnt_want_write_file, fs/open.c:853). fchown passes explicit
 * non-current ids (1000, 1000) and utimensat explicit non-NOW,
 * non-OMIT times, avoiding the early no-op returns both kernels
 * keep for the degenerate forms (aster chown.rs:19-21 for the
 * both-(-1) chown, utimens.rs:40-42 for the both-UTIME_OMIT
 * utimensat).
 *
 * Expected-value revision (T-024/S04) on the utimensat arm:
 * REGISTERED DIFFERENCE (docs/T-013/analysis.md sec. 9.1 row 2 /
 * S07 sec. 4.1, assertion form OPN-11): the set_atime/set_mtime/
 * set_ctime trait signatures carry no Result, so utimensat on this
 * read-only filesystem SUCCEEDS silently and the three times stay
 * identical -- vs the Linux -EROFS baseline. Revised from the
 * authority, never from observed behavior.
 */
FN_TEST(write_ero_fs_attr_change_family)
{
	struct timespec times[2] = {
		{ .tv_sec = 1600000000, .tv_nsec = 0 },
		{ .tv_sec = 1600000001, .tv_nsec = 0 },
	};
	struct stat before, after;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();

	fd = TEST_SUCC(open(WEF_FILE_4K, O_RDONLY));
	TEST_ERRNO(fchmod(fd, 0644), EROFS);
	TEST_ERRNO(fchown(fd, 1000, 1000), EROFS);
	TEST_SUCC(close(fd));

	/* OPN-11: silent success + the three-time identity. */
	TEST_SUCC(stat(WEF_ANCHOR, &before));
	TEST_RES(utimensat(AT_FDCWD, WEF_ANCHOR, times, 0), _ret == 0);
	TEST_SUCC(stat(WEF_ANCHOR, &after));
	TEST_RES(before.st_atim.tv_sec == after.st_atim.tv_sec &&
			 before.st_atim.tv_nsec == after.st_atim.tv_nsec,
		 _ret);
	TEST_RES(before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
			 before.st_mtim.tv_nsec == after.st_mtim.tv_nsec,
		 _ret);
	TEST_RES(before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
			 before.st_ctim.tv_nsec == after.st_ctim.tv_nsec,
		 _ret);
}
END_TEST()

/*
 * Panorama face 5 -- write() on an already-open read-only fd (the
 * last S05 sec. 3 #14 enumerated item): the only descriptor an
 * erofs file can ever hand out is O_RDONLY (face 1), and the
 * write is rejected at the fd rights gate -- EBADF, one layer
 * before the filesystem, on both kernels (Linux
 * fs/read_write.c:667; aster inode_handle.rs:288). Parity errno
 * frozen; what this witnesses is exactly the negative-control
 * essence -- no writable channel exists. AUTO-RESOLVE entry:
 * docs/T-020/S16/index.md sec. 3.
 */
FN_TEST(write_ero_fs_write_on_rdonly_fd)
{
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();

	fd = TEST_SUCC(open(WEF_FILE_INLINE, O_RDONLY));
	TEST_ERRNO(write(fd, "x", 1), EBADF);
	TEST_SUCC(close(fd));
}
END_TEST()
