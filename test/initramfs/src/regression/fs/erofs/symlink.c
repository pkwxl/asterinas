// SPDX-License-Identifier: MPL-2.0

/*
 * erofs symlink healthy-face assertions (T-020/S11; matrix sec. 3.3
 * L1-L6 healthy half -- S05 sec. 3 file #9: five entries / four
 * forms, readlink byte-exact against the pattern, lstat st_size,
 * the fast-form length bound).
 *
 * Carrier: MNT only (the persistent /erofs mount point; under the
 * canonical single-run complement it carries x7/C2 base_cpt, errata
 * T-020/S01). Every test starts with the init-mount guard
 * EROFS_SKIP_IF_NO_INIT_MNT() (mount-success evidence, S05 sec. 6
 * extension 2), which keeps the non-erofs run form and the
 * attached-but-unimplemented state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists and every assertion here is a parity
 * assertion; the group's registered difference (G-N02 non-UTF-8
 * targets -> EIO) rides FX-NAME on the ktest half (S05 sec. 3 #9
 * "ktest 余半边") and is not representable on a healthy image.
 * Per T-003 sec. 2.1 L3 the fast/slow split itself is implementation
 * freedom: its only external observables are the readlink output and
 * error codes, which is exactly what this file pins -- the S01 sec.
 * 3.3 expected-form column is coverage bookkeeping (which internal
 * path each preset material exercises), never an assertion value.
 *
 * Sources (never re-derive locally): matrix sec. 3.3 quoting T-003
 * sec. 2.1 (L1-L6) and T-001 sec. 4.6; materials from T-016/S01
 * sec. 3.3 (entry names verbatim; the two literal short targets;
 * 256 B / 4090 B pattern targets) with the pattern formula consumed
 * through ero_symlink_byte (S01 sec. 3.0 single source in
 * erofs_common.h -- expected bytes are mechanically regenerated,
 * never stored as tables); the empty-target removal from
 * T-018/S03 sec. 3 (LNK tail-count 5 -> 4; Linux offers no syscall
 * to create an empty-target symlink, so slink_empty left the staged
 * images -- its absence is asserted below as the anti-silent-
 * regression face, and the empty-form L4 fidelity itself rides
 * FX-INODE on the ktest half). Never adjust an expected value to
 * match observed behavior -- go back to the matrix instead.
 *
 * Fact alignment note (for S17 reconciliation, no authority
 * revision): S01 sec. 3.3 annotates to_file_short's target as
 * "30 B", but the literal string ../regular/content_anchor.txt is
 * 29 bytes and the T-018 staged tree carries it at 29 B. The
 * literal string is the addressing authority; the expected length
 * below is strlen() of that literal and the annotation number is
 * never consumed.
 *
 * Face boundaries (no overlap with sibling files): full statx field
 * faces for LNK belong to #7 inode_stat.c (including the LNK body
 * open(2) -> ENODEV anchor, G-N03); walking through symlinks (follow
 * vs no-follow) belongs to #8 namei.c; the write-family EROFS
 * negative for symlink creation belongs to #14 write_ero_fs.c
 * (G-M20). This file is the three-element form's ① image-preset
 * content addressing + ② read-only halves only.
 */

#include "erofs_common.h"

#define ERO_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Image block size of the healthy image family (G-M08 pins
 * blkszbits = 12); local constant, same shape as inode_stat.c.
 * Consumed only by the fast-form bound assertion.
 */
#define EROFS_IMG_BS 4096u

/* Largest preset target: slink_near_max = 4090 B (S01 sec. 3.3). */
#define EROFS_MAX_TARGET_LEN 4090

/*
 * Matrix sec. 3.3 L1-L6 row, fast-form half (parity): the two
 * fast-classified materials (S01 sec. 3.3: to_file_short -> literal
 * ../regular/content_anchor.txt, to_dir_short -> literal ../dirs)
 * resolve byte-exactly through readlink(2) with lstat st_size equal
 * to the target length. readlink(2) does not NUL-terminate its
 * output: the sentinel bytes past the returned length prove that
 * exactly len target bytes were written. The L4 bound face: a fast
 * symlink's inline payload ends inside its metadata block, so its
 * target length is necessarily below the block size (T-003 sec. 2.1
 * L4: m_pofs >= 32) -- asserted as the material precondition of the
 * fast classification.
 */
FN_TEST(symlink_fast_form_readlink)
{
	static const struct {
		const char *name;
		const char *target; /* literal target, S01 sec. 3.3 */
	} fast[] = {
		{ "to_file_short", "../regular/content_anchor.txt" },
		{ "to_dir_short", "../dirs" },
	};
	char buf[64];
	struct stat st;
	char path[512];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(fast); i++) {
		const size_t len = strlen(fast[i].target);

		snprintf(path, sizeof(path), "%s/symlink/%s", EROFS_INIT_MNT,
			 fast[i].name);
		TEST_SUCC(lstat(path, &st));
		TEST_RES(st.st_mode & S_IFMT, _ret == S_IFLNK);
		TEST_RES((size_t)st.st_size, _ret == len);
		/* L4 fast bound: fast target < bs (necessary condition). */
		TEST_RES((size_t)st.st_size, _ret < EROFS_IMG_BS);
		memset(buf, '@', sizeof(buf));
		TEST_RES(readlink(path, buf, len + 1), _ret == (ssize_t)len);
		TEST_RES(memcmp(buf, fast[i].target, len), _ret == 0);
		TEST_RES(buf[len], _ret == '@');
		TEST_RES(buf[len + 1], _ret == '@');
	}
}
END_TEST()

/*
 * Matrix sec. 3.3 L1-L6 row, slow-path half (parity): the two
 * slow-classified materials -- slow_256b_target (256 B) and the
 * stage-made slink_near_max (4090 B, near PATH_MAX capacity edge,
 * S01 sec. 3.3/4.2-5) -- carry pattern targets regenerated
 * mechanically through ero_symlink_byte ("0123456789abcdef" cycled
 * and truncated to the exact length). Byte-exact readlink output
 * with st_size equal to the exact target length exercises the
 * slow-path page-read form (L5) at both ends of its capacity range.
 * The trailing block is the output-length boundary anchor of the
 * readlink face: a window of exactly st_size bytes still returns
 * the full 256-byte target (smaller-window truncation is
 * VFS-generic and out of the row group).
 */
FN_TEST(symlink_slow_form_readlink)
{
	static const struct {
		const char *name;
		size_t len;
	} slow[] = {
		{ "slow_256b_target", 256 },
		{ "slink_near_max", 4090 },
	};
	char expect[EROFS_MAX_TARGET_LEN];
	char buf[EROFS_MAX_TARGET_LEN + 2];
	struct stat st;
	char path[512];
	size_t i, j;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(slow); i++) {
		snprintf(path, sizeof(path), "%s/symlink/%s", EROFS_INIT_MNT,
			 slow[i].name);
		/* Expected bytes mechanically regenerated (S01 sec. 3.0). */
		for (j = 0; j < slow[i].len; j++)
			expect[j] = (char)ero_symlink_byte(j);
		TEST_SUCC(lstat(path, &st));
		TEST_RES(st.st_mode & S_IFMT, _ret == S_IFLNK);
		TEST_RES((size_t)st.st_size, _ret == slow[i].len);
		memset(buf, '@', sizeof(buf));
		TEST_RES(readlink(path, buf, slow[i].len + 1),
			 _ret == (ssize_t)slow[i].len);
		TEST_RES(memcmp(buf, expect, slow[i].len), _ret == 0);
		TEST_RES(buf[slow[i].len], _ret == '@');
		TEST_RES(buf[slow[i].len + 1], _ret == '@');
	}
	/* Exact-size window anchor on slow_256b_target (256 B). */
	memset(buf, '#', sizeof(buf));
	TEST_RES(readlink(EROFS_INIT_MNT "/symlink/slow_256b_target", buf, 256),
		 _ret == 256);
	for (j = 0; j < 256; j++)
		expect[j] = (char)ero_symlink_byte(j);
	TEST_RES(memcmp(buf, expect, 256), _ret == 0);
	TEST_RES(buf[256], _ret == '#');
}
END_TEST()

/*
 * Matrix sec. 3.3 L1-L6 row, fifth-entry accounting (anti-silent-
 * regression face): slink_empty is ABSENT from every staged image
 * (T-018/S03 sec. 3 removal; Linux symlink(2) fails at getname on an
 * empty oldpath, so the material cannot be built by any standard
 * syscall). Its empty-form coverage (L4: i_size = 0 -> empty readlink
 * output stays legal) rides FX-INODE on the ktest half; the ENOENT
 * here doubles as the anti-silent-regression assertion for that
 * ledger, in the same shape as namei.c's absent-255 face.
 */
FN_TEST(symlink_removed_empty_absent)
{
	struct stat st;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_ERRNO(lstat(EROFS_INIT_MNT "/symlink/slink_empty", &st), ENOENT);
}
END_TEST()
