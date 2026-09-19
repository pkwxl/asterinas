// SPDX-License-Identifier: MPL-2.0

/*
 * erofs readdir/getdents healthy-face assertions (T-020/S12; matrix
 * sec. 3.5 healthy half -- S05 sec. 3 file #10): R basic face (read(2)
 * on a directory -> EISDIR, getdents on a non-Dir fd -> ENOTDIR),
 * emit-order contract (no reorder / no dedup / no alphabetical
 * assumption: exact row count + set equality + order stability across
 * two independent passes), cookie seven-element face (d_off monotone
 * progression, exhaustion d_off == i_size, seekdir/telldir resume at
 * natural cookies, roundup(12) resume equivalence), G-N06 dir-fd
 * SEEK_END == i_size + SEEK_SET resume alignment, G-N07 readdir does
 * not update atime, W-N05 zero-record tiny buffer -> Ok(0), W-N09
 * llseek whence faces, W-N10 getdents on a non-inode-handle fd.
 *
 * Carrier: MNT only (the persistent /erofs mount point; under the
 * canonical single-run complement it carries x7/C2 base_cpt, errata
 * T-020/S01). Every test starts with the init-mount guard
 * EROFS_SKIP_IF_NO_INIT_MNT() (mount-success evidence, S05 sec. 6
 * extension 2), which keeps the non-erofs run form and the
 * attached-but-unimplemented state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists. Registered-difference assertions carry their
 * Linux baseline inline (marked "登记差异"); all other assertions are
 * parity. Never adjust an expected value to match observed behavior --
 * go back to the matrix instead.
 *
 * Sources (never re-derive locally): matrix sec. 3.5 rows 1-2 quoting
 * T-003 sec. 4.1 (R1-R14), sec. 4.2 (cookie/offset dual view, llseek
 * face), sec. 4.3 (zero filtering / atime note) and sec. 3.4 (dots are
 * ordinary on-disk dirents, no synthesis); materials from T-016/S01
 * sec. 3.2 (dirs/ family; many_entries = 200 bulk names of exactly
 * 40 B, "bulk_" + "%03d" + "_" + 'a' pad, template regenerated
 * mechanically below, never stored as a table; >= 3 directory blocks).
 *
 * Fact alignment note (for S17 reconciliation, no authority
 * revision): S01 sec. 3.2 annotates empty_dir as "零 dirent 落盘
 * (readdir 仅合成 . ..)". Both halves of that parenthetical drift
 * from the behavior authority: T-003 sec. 3.4/4.3 (quoted by matrix
 * sec. 3.4) prove the kernel synthesizes nothing -- the dot rows come
 * from mkfs-written on-disk dirents -- and the T-018 staged image
 * carries empty_dir with exactly the two dot rows on disk (i_size 27;
 * dump.erofs --ls, docs/T-018/S07/index.md sec. 2 anchor ④ records
 * the same listing shape). The "空目录 i_size=0 恒空" item of matrix
 * sec. 3.5 row 1 describes the i_size == 0 crafted form (T-003
 * R3 tags it 畸形; its zero-row enumeration rides FX-DIRENT on the
 * ktest half). The healthy empty_dir face therefore asserts: exactly
 * two rows, the set { ".", ".." }, each DT_DIR, and st_size > 0 (the
 * dots-on-disk discriminator).
 *
 * Face boundaries (no overlap with sibling files): the dot-row ino
 * identity (stat ino comparison) belongs to #8 namei.c; the full
 * statx field faces (including the three-times-identical X8 face
 * that atime non-update pairs with) belong to #7 inode_stat.c;
 * crafted d_type >= 8 / nid = 0 / nameoff geometry / embedded NUL /
 * out-of-order images ride FX-DIRENT / FX-NAME on the ktest half
 * (S05 sec. 3 #10 "ktest 余半边"); the write-family EROFS negative
 * belongs to #14 write_ero_fs.c. The d_type one-to-one FT -> DT
 * mapping (R8) is pinned here on healthy entries of every type
 * (DIR/REG via many_entries, LNK via symlink/, CHR/BLK/FIFO/SOCK via
 * special/), consuming the enumeration face S11's downstream pointer
 * assigned to this file.
 */

#include "erofs_common.h"

#include <dirent.h>
#include <limits.h>
#include <linux/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * getdents64 UAPI shape along the in-tree precedent
 * fs/procfs/getdents.c (this host's glibc ships no usable wrapper).
 */
struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

#define ERO_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Healthy image family block size (G-M08 pins blkszbits = 12). */
#define EROFS_IMG_BS 4096u

/* S01 sec. 3.2 / sec. 4.2-2 material constants. */
#define EROFS_MANY_ENTRIES 200
#define EROFS_BULK_NAME_LEN 40

/*
 * Width of one stored name column (NAME_MAX + NUL). The glibc-pass
 * helper stores readdir(3) d_name strings, which may legally be up to
 * 255 bytes long, so a bulk-name-width column would make the snprintf
 * copy provably truncatable (-Wformat-truncation). Sizing at NAME_MAX
 * also removes the silent-truncation false-pass risk; name-content
 * correctness stays pinned by the exact strcmp against the template.
 *
 * AUTO-DECISION: widen the glibc-pass name column 48 -> 256 instead of
 * suppressing -Wformat-truncation (<stdio.h> copies of unknown-length
 * names must never be provably truncatable; no expected value moves).
 *
 * S18 late compile fix (same philosophy, raw-getdents half): the two
 * copies of a raw getdents64 d_name -- a flexible array riding the
 * 4096 B syscall buffer, provably up to 4076 B under the optimizing
 * official build -- are precision-bounded to their destination
 * ("%.*s"), which -Wformat-truncation proves non-truncatable. Output
 * is byte-identical for every legal <= 255 B name; no expected value
 * moves.
 */
#define EROFS_NAME_COL 256

/* many_entries enumerates 200 bulk rows + the two on-disk dot rows. */
#define EROFS_MANY_TOTAL (EROFS_MANY_ENTRIES + 2)
#define EROFS_ENUM_MAX (EROFS_MANY_TOTAL + 8)

#define EROFS_DIR_MANY EROFS_INIT_MNT "/dirs/many_entries"
#define EROFS_DIR_EMPTY EROFS_INIT_MNT "/dirs/empty_dir"
#define EROFS_DIR_SYMLINK EROFS_INIT_MNT "/symlink"
#define EROFS_DIR_SPECIAL EROFS_INIT_MNT "/special"

struct ero_rec {
	char name[EROFS_NAME_COL];
	unsigned char type;
	int64_t off;
	unsigned short reclen;
};

/* S01 sec. 4.2-2 template: "bulk_" + %03d + "_" + 'a' pad to 40 B. */
static void ero_bulk_name(char out[EROFS_BULK_NAME_LEN + 1], int i)
{
	int n = snprintf(out, EROFS_BULK_NAME_LEN + 1, "bulk_%03d_", i);

	memset(out + n, 'a', EROFS_BULK_NAME_LEN - n);
	out[EROFS_BULK_NAME_LEN] = '\0';
}

/* Drain fd through getdents64, collecting every record. -1 on error. */
static int ero_read_dir_fd(int fd, struct ero_rec *recs, int max)
{
	char buf[4096];
	int count = 0;

	for (;;) {
		ssize_t n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		size_t pos;

		if (n < 0)
			return -1;
		if (n == 0)
			return count;
		for (pos = 0; pos < (size_t)n;) {
			struct linux_dirent64 *d =
				(struct linux_dirent64 *)(buf + pos);

			if (count >= max) {
				errno = EOVERFLOW;
				return -1;
			}
			snprintf(recs[count].name, sizeof(recs[count].name),
				 "%.*s", (int)sizeof(recs[count].name) - 1,
				 d->d_name);
			recs[count].type = d->d_type;
			recs[count].off = d->d_off;
			recs[count].reclen = d->d_reclen;
			count++;
			pos += d->d_reclen;
		}
	}
}

/* Open path, fstat into *st, drain, close. Returns the row count. */
static int ero_enumerate(const char *path, struct ero_rec *recs, int max,
			 struct stat *st)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	int rc;

	if (fd < 0)
		return -1;
	if (fstat(fd, st) < 0) {
		close(fd);
		return -1;
	}
	rc = ero_read_dir_fd(fd, recs, max);
	close(fd);
	return rc;
}

/* glibc readdir(3) pass: collect the name sequence, return count. */
static int ero_readdir_seq(const char *path, char names[][EROFS_NAME_COL],
			   int max)
{
	DIR *dp = opendir(path);
	struct dirent *ent;
	int count = 0;

	if (dp == NULL)
		return -1;
	while ((ent = readdir(dp)) != NULL) {
		if (count >= max) {
			closedir(dp);
			errno = EOVERFLOW;
			return -1;
		}
		snprintf(names[count], EROFS_NAME_COL, "%s", ent->d_name);
		count++;
	}
	closedir(dp);
	return count;
}

/*
 * One getdents64 call on fd; return its first record name (and
 * reclen/reclen-sized record when asked). 0 on success, -1 on error
 * or non-positive syscall result.
 */
static int ero_first_name(int fd, char *out, size_t outsz,
			  unsigned short *reclen)
{
	char buf[4096];
	ssize_t n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
	struct linux_dirent64 *d;

	if (n <= 0)
		return -1;
	d = (struct linux_dirent64 *)buf;
	snprintf(out, outsz, "%.*s", (int)outsz - 1, d->d_name);
	if (reclen != NULL)
		*reclen = d->d_reclen;
	return 0;
}

static int ero_find(const struct ero_rec *recs, int n, const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(recs[i].name, name) == 0)
			return i;
	return -1;
}

/* statx along fs/statx/btime.c / inode_stat.c (raw syscall form). */
static int ero_statx(const char *path, unsigned int mask, struct statx *stx)
{
	memset(stx, 0, sizeof(*stx));
	return (int)syscall(SYS_statx, AT_FDCWD, path, 0, mask, stx);
}

/*
 * Matrix sec. 3.5 row 3, R1/R2 guards (parity) + W-N10 (registered
 * difference): read(2) on a directory fd -> EISDIR (R2, both ends);
 * getdents64 on a regular-file fd -> ENOTDIR (R1, the Dir-inode guard
 * at the syscall layer, parity); getdents64 on a socket fd ->
 * EINVAL, because a socket is not an inode handle in the aster
 * framework while Linux answers ENOTDIR through f_op->iterate_shared
 * absence.
 */
FN_TEST(readdir_read_and_fd_guards)
{
	char buf[4096];
	int dfd, ffd, sv[2];

	EROFS_SKIP_IF_NO_INIT_MNT();
	dfd = TEST_SUCC(open(EROFS_DIR_MANY, O_RDONLY | O_DIRECTORY));
	/* R2 parity: read(2) on a directory fd. */
	TEST_ERRNO(read(dfd, buf, 1), EISDIR);
	TEST_SUCC(close(dfd));

	/* R1 parity: non-Dir (REG) fd getdents guard. */
	ffd = TEST_SUCC(open(EROFS_INIT_MNT "/regular/file_1b.bin", O_RDONLY));
	TEST_ERRNO(syscall(SYS_getdents64, ffd, buf, sizeof(buf)), ENOTDIR);
	TEST_SUCC(close(ffd));

	/* W-N10: socket(2) fd is not an inode handle.
	 * 登记差异(W-N10): Linux 基线为 ENOTDIR。 */
	TEST_SUCC(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	TEST_ERRNO(syscall(SYS_getdents64, sv[0], buf, sizeof(buf)), EINVAL);
	TEST_SUCC(close(sv[0]));
	TEST_SUCC(close(sv[1]));
}
END_TEST()

/*
 * Matrix sec. 3.5 row 1, empty-dir healthy face: the empty dir
 * enumerates as empty -- exactly the two on-disk dot rows, nothing
 * else, both DT_DIR (see the header fact-alignment note for the S01
 * sec. 3.2 annotation drift; the i_size == 0 zero-row crafted form
 * rides FX-DIRENT on the ktest half).
 */
FN_TEST(readdir_empty_dir_only_dots)
{
	struct ero_rec recs[8];
	struct stat st;
	int n, i, dot = 0, dotdot = 0, bad = 0;

	EROFS_SKIP_IF_NO_INIT_MNT();
	n = TEST_RES(ero_enumerate(EROFS_DIR_EMPTY, recs, ERO_ARRAY_SIZE(recs),
				   &st),
		     _ret == 2);
	/* Dots are on-disk dirents (matrix sec. 3.4) => i_size > 0. */
	TEST_RES((unsigned long long)st.st_size, _ret > 0);
	for (i = 0; i < n; i++) {
		if (strcmp(recs[i].name, ".") == 0) {
			dot++;
			if (recs[i].type != DT_DIR)
				bad++;
		} else if (strcmp(recs[i].name, "..") == 0) {
			dotdot++;
			if (recs[i].type != DT_DIR)
				bad++;
		} else {
			bad++;
		}
	}
	TEST_RES(dot, _ret == 1);
	TEST_RES(dotdot, _ret == 1);
	TEST_RES(bad, _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 3.5 rows 1-2, emit-order contract + full-set face on
 * many_entries (multi-block, S01 sec. 3.2 ">= 3 blocks"): exact row
 * count 200 + 2 dots (no dedup / no loss), every name matches the
 * regenerated 40 B template exactly once, d_off strictly increases
 * (cookie elements ①③⑦: headers advance, block tails fold forward),
 * the final d_off equals st_size (element ④: exhaustion = i_size),
 * d_type maps FT_DIR/FT_REG one-to-one (R8), and a second pass
 * through glibc readdir(3) produces the identical sequence (emit
 * order = stable disk slot order; WHICH order is a fixture fact and
 * deliberately not frozen here).
 */
FN_TEST(readdir_many_entries_full_pass)
{
	static struct ero_rec recs[EROFS_ENUM_MAX];
	static char seq_b[EROFS_ENUM_MAX][EROFS_NAME_COL];
	static int seen[EROFS_MANY_ENTRIES];
	struct stat st;
	char expect[EROFS_BULK_NAME_LEN + 1];
	int n, m, i, dot = 0, dotdot = 0, bad = 0, mono = 1, same;
	long idx;
	char *end;

	EROFS_SKIP_IF_NO_INIT_MNT();
	n = TEST_RES(ero_enumerate(EROFS_DIR_MANY, recs, EROFS_ENUM_MAX, &st),
		     _ret == EROFS_MANY_TOTAL);
	m = TEST_RES(ero_readdir_seq(EROFS_DIR_MANY, seq_b, EROFS_ENUM_MAX),
		     _ret == EROFS_MANY_TOTAL);
	if (n != EROFS_MANY_TOTAL || m != EROFS_MANY_TOTAL) {
		/* Record the breakage once more, then stop indexing. */
		TEST_RES(n == EROFS_MANY_TOTAL && m == EROFS_MANY_TOTAL,
			 _ret == 1);
		__TEST_SUMMARY();
		return;
	}
	/* S01 sec. 3.2: the material exists to span >= 3 blocks. */
	TEST_RES((unsigned long long)st.st_size, _ret > 2 * EROFS_IMG_BS);
	for (i = 1; i < n; i++)
		if (recs[i].off <= recs[i - 1].off)
			mono = 0;
	TEST_RES(mono, _ret == 1);
	/* Cookie element ④: the last record's d_off = exhaustion pos. */
	TEST_RES(recs[n - 1].off, _ret == (int64_t)st.st_size);
	for (i = 0; i < n; i++) {
		if (strcmp(recs[i].name, ".") == 0) {
			dot++;
			if (recs[i].type != DT_DIR)
				bad++;
		} else if (strcmp(recs[i].name, "..") == 0) {
			dotdot++;
			if (recs[i].type != DT_DIR)
				bad++;
		} else {
			idx = strtol(recs[i].name + 5, &end, 10);
			ero_bulk_name(expect, (int)idx);
			if (strncmp(recs[i].name, "bulk_", 5) != 0 || idx < 0 ||
			    idx >= EROFS_MANY_ENTRIES || *end != '_' ||
			    strcmp(expect, recs[i].name) != 0 ||
			    recs[i].type != DT_REG)
				bad++;
			else
				seen[idx]++;
		}
	}
	TEST_RES(dot, _ret == 1);
	TEST_RES(dotdot, _ret == 1);
	TEST_RES(bad, _ret == 0);
	for (i = 0; i < EROFS_MANY_ENTRIES; i++)
		if (seen[i] != 1)
			bad++;
	TEST_RES(bad, _ret == 0);
	/* Order stability across the second, independent (glibc) pass. */
	same = 1;
	for (i = 0; i < n; i++)
		if (strcmp(recs[i].name, seq_b[i]) != 0)
			same = 0;
	TEST_RES(same, _ret == 1);
}
END_TEST()

/*
 * Matrix sec. 3.5 row 1, R8 d_type one-to-one mapping completion: the
 * FT_* -> DT_* table is pinned across every healthy entry type --
 * DT_LNK on the four symlink/ entries (S01 sec. 3.3 names verbatim;
 * the removed slink_empty stays absent from the count) and
 * DT_CHR/DT_BLK/DT_FIFO/DT_SOCK on the four special/ entries (S01
 * sec. 3.5), on top of DIR/REG from the faces above.
 */
FN_TEST(readdir_dtype_lnk_and_special)
{
	static struct ero_rec recs[16];
	static const struct {
		const char *name;
		unsigned char dtype;
	} symlink_rows[] = {
		{ "to_file_short", DT_LNK },
		{ "to_dir_short", DT_LNK },
		{ "slow_256b_target", DT_LNK },
		{ "slink_near_max", DT_LNK },
	};
	static const struct {
		const char *name;
		unsigned char dtype;
	} special_rows[] = {
		{ "chr_dev", DT_CHR },
		{ "blk_dev", DT_BLK },
		{ "fifo_entry", DT_FIFO },
		{ "sock_entry", DT_SOCK },
	};
	struct stat st;
	size_t i;
	int n, at, bad = 0;

	EROFS_SKIP_IF_NO_INIT_MNT();
	n = TEST_RES(ero_enumerate(EROFS_DIR_SYMLINK, recs,
				   ERO_ARRAY_SIZE(recs), &st),
		     _ret == (int)(ERO_ARRAY_SIZE(symlink_rows) + 2));
	for (i = 0; i < ERO_ARRAY_SIZE(symlink_rows); i++) {
		at = ero_find(recs, n, symlink_rows[i].name);
		if (at < 0 || recs[at].type != symlink_rows[i].dtype)
			bad++;
	}
	TEST_RES(bad, _ret == 0);

	n = TEST_RES(ero_enumerate(EROFS_DIR_SPECIAL, recs,
				   ERO_ARRAY_SIZE(recs), &st),
		     _ret == (int)(ERO_ARRAY_SIZE(special_rows) + 2));
	for (i = 0; i < ERO_ARRAY_SIZE(special_rows); i++) {
		at = ero_find(recs, n, special_rows[i].name);
		if (at < 0 || recs[at].type != special_rows[i].dtype)
			bad++;
	}
	TEST_RES(bad, _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 3.5 row 2, cookie seven elements -- seekdir/telldir
 * resume along the fs/ext2/readdir.c readdir_seekdir_resume sample
 * shape (material re-based onto the image-preset many_entries, matrix
 * sec. 1.4): telldir after full exhaustion equals st_size (element
 * ④), and resuming at the cookie taken after k consumed rows (early /
 * deep-inside / last row, so cross-block cookies are exercised,
 * element ③) continues with exactly row k and drains the identical
 * suffix -- no skip, no duplicate (elements ①②).
 */
FN_TEST(readdir_seekdir_telldir_resume)
{
	static char seq[EROFS_ENUM_MAX][EROFS_NAME_COL];
	static const int points[] = { 3, 100, EROFS_MANY_TOTAL - 1 };
	struct stat st;
	DIR *dp;
	struct dirent *ent;
	size_t p;
	int n, k, idx, ok;
	long cookie;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_SUCC(stat(EROFS_DIR_MANY, &st));
	n = TEST_RES(ero_readdir_seq(EROFS_DIR_MANY, seq, EROFS_ENUM_MAX),
		     _ret == EROFS_MANY_TOTAL);

	/* Element ④, DIR* view: exhausted telldir == i_size. */
	dp = TEST_SUCC(opendir(EROFS_DIR_MANY));
	while ((ent = readdir(dp)) != NULL)
		;
	TEST_RES(telldir(dp), _ret == (long)st.st_size);
	TEST_SUCC(closedir(dp));

	for (p = 0; p < ERO_ARRAY_SIZE(points); p++) {
		k = points[p];
		dp = TEST_SUCC(opendir(EROFS_DIR_MANY));
		for (idx = 0; idx < k; idx++) {
			ent = readdir(dp);
			TEST_RES(ent != NULL, _ret == 1);
		}
		cookie = telldir(dp);
		TEST_SUCC(closedir(dp));

		dp = TEST_SUCC(opendir(EROFS_DIR_MANY));
		seekdir(dp, cookie);
		ent = readdir(dp);
		TEST_RES(ent != NULL, _ret == 1);
		if (ent != NULL)
			TEST_RES(strcmp(ent->d_name, seq[k]), _ret == 0);
		ok = 1;
		idx = k + 1;
		while ((ent = readdir(dp)) != NULL) {
			if (idx >= n || strcmp(ent->d_name, seq[idx]) != 0)
				ok = 0;
			idx++;
		}
		TEST_RES(ok, _ret == 1);
		TEST_RES(idx, _ret == n);
		TEST_SUCC(closedir(dp));
	}
}
END_TEST()

/*
 * Matrix sec. 3.5 row 2 + G-N06 raw-syscall half: resuming at a
 * record's d_off (user-side "next entry" basis, T-003 sec. 4.2)
 * yields exactly the following record (SEEK_SET arbitrary-offset
 * resume alignment); element ⑤ -- resuming at cookie + 5 behaves
 * exactly as resuming at roundup(12) = cookie + 12, because the FS
 * rounds the within-block offset up to the next 12-byte slot before
 * filling (T-003 R7; both offsets are the same post-roundup state,
 * which holds regardless of where the block/name-area boundary sits
 * -- the geometry-dependent ⑥ face rides FX-DIRENT); element ② +
 * W-N05 -- a buffer that cannot hold even the record at pos returns
 * Ok(0) without consuming the position (retry the same record), and a
 * buffer of exactly one record's size stops after that record with
 * the next call continuing at the following one.
 */
FN_TEST(readdir_cookie_resume_and_small_buffer)
{
	static struct ero_rec recs[EROFS_ENUM_MAX];
	static char name_a[256], name_b[256];
	char buf[4096];
	struct stat st;
	unsigned short r0;
	int fd;
	ssize_t r;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_RES(ero_enumerate(EROFS_DIR_MANY, recs, EROFS_ENUM_MAX, &st),
		 _ret == EROFS_MANY_TOTAL);
	fd = TEST_SUCC(open(EROFS_DIR_MANY, O_RDONLY | O_DIRECTORY));

	/* G-N06 / element ①: d_off(N) = next-entry basis. */
	TEST_RES(lseek(fd, (off_t)recs[100].off, SEEK_SET),
		 _ret == (off_t)recs[100].off);
	TEST_RES(ero_first_name(fd, name_a, sizeof(name_a), NULL), _ret == 0);
	TEST_RES(strcmp(name_a, recs[101].name), _ret == 0);

	/* Element ⑤: cookie + 5 resumes exactly as cookie + 12. */
	TEST_RES(lseek(fd, (off_t)recs[100].off + 5, SEEK_SET),
		 _ret == (off_t)recs[100].off + 5);
	TEST_RES(ero_first_name(fd, name_a, sizeof(name_a), NULL), _ret == 0);
	TEST_RES(lseek(fd, (off_t)recs[100].off + 12, SEEK_SET),
		 _ret == (off_t)recs[100].off + 12);
	TEST_RES(ero_first_name(fd, name_b, sizeof(name_b), NULL), _ret == 0);
	TEST_RES(strcmp(name_a, name_b), _ret == 0);

	/* Record 0's reclen at a fresh position 0. */
	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	TEST_RES(ero_first_name(fd, name_a, sizeof(name_a), &r0), _ret == 0);
	TEST_RES(strcmp(name_a, recs[0].name), _ret == 0);

	/* W-N05: zero-record buffer -> Ok(0), position not consumed.
	 * 登记差异(W-N05): Linux 基线为 EINVAL(缓冲容不下一条记录)。 */
	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	TEST_RES(syscall(SYS_getdents64, fd, buf, (size_t)r0 - 1), _ret == 0);
	TEST_RES(ero_first_name(fd, name_a, sizeof(name_a), NULL), _ret == 0);
	TEST_RES(strcmp(name_a, recs[0].name), _ret == 0);

	/* Element ②: exactly-one-record buffer stops after record 0 and
	 * the next call continues with record 1. */
	TEST_RES(lseek(fd, 0, SEEK_SET), _ret == 0);
	r = TEST_RES(syscall(SYS_getdents64, fd, buf, (size_t)r0),
		     _ret == (ssize_t)r0);
	TEST_RES(r > 0 && strcmp(((struct linux_dirent64 *)buf)->d_name,
				 recs[0].name) == 0,
		 _ret == 1);
	TEST_RES(ero_first_name(fd, name_a, sizeof(name_a), NULL), _ret == 0);
	TEST_RES(strcmp(name_a, recs[1].name), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

/*
 * Matrix sec. 3.5 G-N06 + W-N09 + R3: dir-fd SEEK_END returns i_size
 * (G-N06 parity; the erofs Dir overrides seek_end, AR-S01-8
 * candidate ①); SEEK_DATA/SEEK_HOLE are not supported whences on the
 * aster lseek path and an oversized SEEK_SET offset succeeds (W-N09
 * framework-level registered differences); a position at or beyond
 * i_size enumerates as EOF (R3: pos >= i_size -> 0, both ends
 * identical).
 */
FN_TEST(readdir_llseek_whence_faces)
{
	char buf[4096];
	struct stat st;
	off_t beyond;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_SUCC(stat(EROFS_DIR_MANY, &st));
	fd = TEST_SUCC(open(EROFS_DIR_MANY, O_RDONLY | O_DIRECTORY));

	/* G-N06 parity: SEEK_END == i_size. */
	TEST_RES(lseek(fd, 0, SEEK_END), _ret == (off_t)st.st_size);
	/* W-N09: unsupported whences.
	 * 登记差异(W-N09): Linux 基线 SEEK_DATA 于 offset<i_size 返回
	 * offset、>=i_size 返 ENXIO;SEEK_HOLE 返回 i_size、>= 返 ENXIO。 */
	TEST_ERRNO(lseek(fd, 0, SEEK_DATA), EINVAL);
	TEST_ERRNO(lseek(fd, 0, SEEK_HOLE), EINVAL);
	/* W-N09: no s_maxbytes bound.
	 * 登记差异(W-N09): Linux 基线对 > MAX_LFS_FILESIZE 偏移返 EINVAL。 */
	TEST_RES(lseek(fd, LLONG_MAX, SEEK_SET), _ret == (off_t)LLONG_MAX);
	TEST_RES(syscall(SYS_getdents64, fd, buf, sizeof(buf)), _ret == 0);

	/* R3 parity: an explicit beyond-i_size position also hits EOF. */
	beyond = (off_t)st.st_size + (off_t)EROFS_IMG_BS;
	TEST_RES(lseek(fd, beyond, SEEK_SET), _ret == beyond);
	TEST_RES(syscall(SYS_getdents64, fd, buf, sizeof(buf)), _ret == 0);
	TEST_SUCC(close(fd));
}
END_TEST()

/*
 * Matrix sec. 3.5 G-N07 (parity + negative control): a full getdents
 * enumeration must not update the directory's atime -- Linux leaves
 * no persistent atime effect on a read-only mount (T-003 sec. 4.3),
 * and the ext2-aster readdir-after set_atime habit (ext2/inode/dir/
 * mod.rs:61) is exactly the miscode this pins against for erofs. The
 * three-times-identical X8 face itself belongs to inode_stat.c.
 */
FN_TEST(readdir_atime_unchanged)
{
	struct statx before, after;
	char buf[4096];
	int fd;
	ssize_t r;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_RES(ero_statx(EROFS_DIR_MANY, STATX_ATIME, &before), _ret == 0);
	fd = TEST_SUCC(open(EROFS_DIR_MANY, O_RDONLY | O_DIRECTORY));
	do {
		r = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		TEST_RES(r, _ret >= 0);
	} while (r > 0);
	TEST_SUCC(close(fd));
	TEST_RES(ero_statx(EROFS_DIR_MANY, STATX_ATIME, &after), _ret == 0);
	TEST_RES(before.stx_atime.tv_sec == after.stx_atime.tv_sec &&
			 before.stx_atime.tv_nsec == after.stx_atime.tv_nsec,
		 _ret == 1);
}
END_TEST()
