// SPDX-License-Identifier: MPL-2.0

/*
 * erofs lookup / namei healthy-face assertions (T-020/S10; matrix
 * sec. 3.4 healthy half -- the N1-N14 baseline row and the "./..
 * on-disk no-synthesis" row, S05 sec. 3 file #8).
 *
 * Carrier: MNT only (the persistent /erofs mount point; under the
 * canonical single-run complement it carries x7/C2 base_cpt, errata
 * T-020/S01). Every test starts with the init-mount guard
 * EROFS_SKIP_IF_NO_INIT_MNT() (mount-success evidence, S05 sec. 6
 * extension 2), which keeps the non-erofs run form and the
 * attached-but-unimplemented state SKIPped with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists, and every assertion in this file is a
 * parity assertion: the registered differences of the lookup group
 * (W-N04 lossy, W-N08 loop) live on the crafted/ktest half
 * (FX-NAME / FX-DIRENT, S05 sec. 3 #8 "ktest 余半边") and are not
 * representable on a healthy image. Sources: matrix sec. 3.4 quoting
 * T-003 sec. 1 (N1-N14) and sec. 3.4; material faces from T-016/S01
 * sec. 3.2 (case_variants / boundary_names / deep / small /
 * empty_dir) plus the digest-pinned stage truth of T-018 (the
 * many_entries bulk name template "bulk_%03d_" + 'a' x31 = 40 B,
 * erofs_stage.sh sec. 4.2; the n255_* removal -- mkfs.erofs 1.7.1
 * rejects 255-B dirent names, T-018/S04 sec. 3 -- whose absence is
 * asserted below as the anti-silent-regression face). Never adjust
 * an expected value to match observed behavior -- go back to the
 * matrix instead.
 *
 * Face boundaries (no overlap with sibling files): symlink content
 * faces (readlink bytes, lstat st_size, fast-path bounds) belong to
 * #9 symlink.c (L1-L6); the readdir-side dot provenance ("getdents
 * 点号来源 = 盘面条目") belongs to #10 readdir.c; write-family EROFS
 * negatives (creat / mkdir / link / unlink through the namei API)
 * are concentrated in #14 write_ero_fs.c (G-M20) -- the lookup face
 * itself has no write channel.
 */

#include "erofs_common.h"

#define ERO_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* S05 sec. 8: the single privilege-drop uid (nobody, 65534). */
#define EROFS_NOBODY_UID 65534

/* Stage truth: bulk names are exactly 40 bytes. */
#define ERO_BULK_NAME_LEN 40

/*
 * Boundary-name builder (S01 sec. 3.2: each name is exactly `total`
 * bytes, "n<total>_" + padding; the on-image padding is 'n'). This
 * mechanically regenerates the ADDRESS of a preset entry -- it is
 * not a fabricated fixture (S05 sec. 1-1).
 */
static void ero_boundary_name(char *buf, size_t total, char pad)
{
	size_t len = (size_t)snprintf(buf, total + 1, "n%zu_", total);

	memset(buf + len, pad, total - len);
	buf[total] = '\0';
}

/* many_entries bulk-name builder (stage truth, 40 B total). */
static void ero_bulk_name(char *buf, int idx, char pad)
{
	size_t len =
		(size_t)snprintf(buf, ERO_BULK_NAME_LEN + 1, "bulk_%03d_", idx);

	memset(buf + len, pad, ERO_BULK_NAME_LEN - len);
	buf[ERO_BULK_NAME_LEN] = '\0';
}

/*
 * Privilege-drop probe callbacks (S05 sec. 8 shape): return 0 on
 * success and the positive errno on failure (-1 stays reserved for
 * ero_run_as_uid construction failures). Tests run serially, so the
 * file-static probe state is race-free.
 */
static const char *ero_probe_path;
static int ero_probe_open_flags;

static int dropped_stat_probe(void)
{
	struct stat st;

	if (stat(ero_probe_path, &st) == 0)
		return 0;
	return errno;
}

static int dropped_open_probe(void)
{
	int fd = open(ero_probe_path, ero_probe_open_flags);

	if (fd >= 0) {
		close(fd);
		return 0;
	}
	return errno;
}

/*
 * Matrix sec. 3.4 N1-N14 baseline row (parity): preset-entry hits
 * across types, misses -> ENOENT (N10/N11 no candidate, N14), the
 * empty-directory miss (N4 zero-i_size short-circuit; the userland
 * result is ENOENT either way), and the negative-dentry face
 * (N14 (1): a repeated miss of the same name stays ENOENT -- the
 * cached negative entry is behaviorally indistinguishable). Symlink
 * traversal during the walk (N1 walk face): stat resolves to the
 * target inode, lstat addresses the link inode itself (content
 * faces belong to #9 symlink.c, not here).
 */
FN_TEST(namei_hit_miss_enoent)
{
	static const struct {
		const char *rel;
		unsigned int ifmt;
	} hits[] = {
		{ "/regular/file_1b.bin", S_IFREG },
		{ "/dirs/small/f1.dat", S_IFREG },
		{ "/special/fifo_entry", S_IFIFO },
		{ "/special/sock_entry", S_IFSOCK },
	};
	struct stat st, st_target;
	char path[512];
	ino_t link_ino;
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(hits); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT,
			 hits[i].rel);
		TEST_SUCC(stat(path, &st));
		TEST_RES(st.st_mode & S_IFMT, _ret == hits[i].ifmt);
	}
	/* Walk faces across symlinks (N1): follow vs no-follow. */
	TEST_SUCC(lstat(EROFS_INIT_MNT "/symlink/to_file_short", &st));
	TEST_RES(st.st_mode & S_IFMT, _ret == S_IFLNK);
	link_ino = st.st_ino;
	TEST_SUCC(
		stat(EROFS_INIT_MNT "/regular/content_anchor.txt", &st_target));
	TEST_RES(stat(EROFS_INIT_MNT "/symlink/to_file_short", &st),
		 st.st_ino == st_target.st_ino);
	TEST_RES(link_ino != st_target.st_ino, _ret);
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs", &st_target));
	TEST_RES(stat(EROFS_INIT_MNT "/symlink/to_dir_short", &st),
		 st.st_ino == st_target.st_ino);
	TEST_RES(st.st_mode & S_IFMT, _ret == S_IFDIR);
	/* Misses (N10/N11 -> N14): plain absent names. */
	TEST_ERRNO(stat(EROFS_INIT_MNT "/regular/absent_file.bin", &st),
		   ENOENT);
	/* N4 face: any lookup inside an empty directory misses. */
	TEST_ERRNO(stat(EROFS_INIT_MNT "/dirs/empty_dir/anything", &st),
		   ENOENT);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/absent_root_child", &st), ENOENT);
	/* N14 (1) negative-dentry face: the repeated miss stays ENOENT. */
	TEST_ERRNO(stat(EROFS_INIT_MNT "/regular/absent_file.bin", &st),
		   ENOENT);
}
END_TEST()

/*
 * Matrix sec. 3.4 N12 (parity, via the IMG-DIR case_variants
 * material): byte-exact, case-sensitive comparison with no
 * normalization -- all four preset variants coexist as distinct
 * entries (pairwise-distinct inodes), each carrying its 1-byte
 * material face (content = first character of the name, S01
 * sec. 3.2), and a near-miss matching none of them byte-exactly
 * is ENOENT.
 */
FN_TEST(namei_case_sensitivity)
{
	static const char *const variants[] = {
		"Alpha.txt",
		"alpha.txt",
		"ALPHA.txt",
		"aLPHA.txt",
	};
	struct stat st;
	char path[512], byte[1];
	ino_t inos[ERO_ARRAY_SIZE(variants)];
	size_t i, j;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the per-variant 1-byte
	 * content probe below reads the entry's material — the
	 * data-read face (T-025). The stat/ino arms would pass with
	 * T-024 alone; the frozen set rides together. SKIP until the
	 * data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	for (i = 0; i < ERO_ARRAY_SIZE(variants); i++) {
		snprintf(path, sizeof(path), "%s/dirs/case_variants/%s",
			 EROFS_INIT_MNT, variants[i]);
		TEST_SUCC(stat(path, &st));
		inos[i] = st.st_ino;
		fd = TEST_SUCC(open(path, O_RDONLY));
		TEST_RES(read(fd, byte, 1), _ret == 1);
		TEST_RES(byte[0], _ret == variants[i][0]);
		TEST_SUCC(close(fd));
	}
	/* No two variants collapse onto one entry (no case folding). */
	for (i = 0; i < ERO_ARRAY_SIZE(inos); i++)
		for (j = i + 1; j < ERO_ARRAY_SIZE(inos); j++)
			TEST_RES(inos[i] != inos[j], _ret);
	/* Byte-exact miss (N12). */
	snprintf(path, sizeof(path), "%s/dirs/case_variants/ALPha.txt",
		 EROFS_INIT_MNT);
	TEST_ERRNO(stat(path, &st), ENOENT);
}
END_TEST()

/*
 * Matrix sec. 3.4 N6-N11 healthy face (parity): lookup inside the
 * multi-block many_entries directory (200 x 40-B names, ~3 dirent
 * blocks) exercises the block-level binary search (N6/N10) and the
 * in-block search (N11) -- hits at spread indices (first / middle /
 * last of the 000-199 range, i.e. different dirent blocks) plus two
 * byte-exact misses (over-range index; right index, wrong padding).
 */
FN_TEST(namei_multi_block_dir_lookup)
{
	static const int hit_idx[] = { 0, 100, 199 };
	struct stat st;
	char name[ERO_BULK_NAME_LEN + 1], path[512];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(hit_idx); i++) {
		ero_bulk_name(name, hit_idx[i], 'a');
		snprintf(path, sizeof(path), "%s/dirs/many_entries/%s",
			 EROFS_INIT_MNT, name);
		TEST_SUCC(stat(path, &st));
		TEST_RES(st.st_ino, _ret != 0);
	}
	ero_bulk_name(name, 200, 'a');
	snprintf(path, sizeof(path), "%s/dirs/many_entries/%s", EROFS_INIT_MNT,
		 name);
	TEST_ERRNO(stat(path, &st), ENOENT);
	ero_bulk_name(name, 0, 'b');
	snprintf(path, sizeof(path), "%s/dirs/many_entries/%s", EROFS_INIT_MNT,
		 name);
	TEST_ERRNO(stat(path, &st), ENOENT);
}
END_TEST()

/*
 * Matrix sec. 3.4 N1 (2) (parity): a non-directory used as a path
 * component is rejected at the VFS front -- the FS lookup is never
 * consulted (the erofs non-DIR i_ops carry no .lookup member,
 * T-003 N1) -- with ENOTDIR. Constructions: a REG in mid-path, FIFO
 * and SOCK in mid-path, and a trailing slash on a REG (the same
 * errno family: the slash demands a directory).
 */
FN_TEST(namei_enotdir_vfs_front)
{
	struct stat st;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_ERRNO(stat(EROFS_INIT_MNT "/regular/file_1b.bin/sub", &st),
		   ENOTDIR);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/special/fifo_entry/sub", &st),
		   ENOTDIR);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/special/sock_entry/sub", &st),
		   ENOTDIR);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/regular/file_1b.bin/", &st), ENOTDIR);
}
END_TEST()

/*
 * Matrix sec. 3.4 N1 baseline row, EACCES half (parity): permission
 * checks sit in the VFS front of the walk/open chain, not in the FS
 * (EROFS registers no permission hooks). Constructed with the staged
 * mode faces: inline_64b.bin = 0600 root:root and dirs/small = 0711
 * root:root (S01 sec. 3.6 / erofs_stage.sh chmod). As uid 65534:
 * walking the 0755 tree stats the 0600 file fine (the walk needs
 * only search on the parents and stat needs no permission on the
 * entry) while opening it is EACCES; through the 0711 directory
 * (other = --x) a child stat still succeeds (search granted) while
 * reading the directory itself is denied.
 *
 * AUTO-DECISION: the walk-flavored EACCES (MAY_EXEC denied on a
 * directory component) is NOT constructible from the preset tree --
 * no directory material denies search to any uid class (S01 sec. 3
 * has no 0700-class directory) and in-test fabrication is forbidden
 * (S05 sec. 1-1); the open-permission EACCES above carries the
 * VFS-front semantics instead. Pointer: a walk-EACCES material would
 * need an S01 table extension through the authority-revision
 * channel -- registered for S17 reconciliation, not done here.
 */
FN_TEST(namei_eaccess_vfs_front)
{
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/* Root contrast: privilege bypasses the permission faces. */
	fd = TEST_SUCC(
		open(EROFS_INIT_MNT "/regular/inline_64b.bin", O_RDONLY));
	TEST_SUCC(close(fd));
	fd = TEST_SUCC(
		open(EROFS_INIT_MNT "/dirs/small", O_RDONLY | O_DIRECTORY));
	TEST_SUCC(close(fd));
	/* Dropped uid: walk allowed, open denied (0600 root:root). */
	ero_probe_path = EROFS_INIT_MNT "/regular/inline_64b.bin";
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_stat_probe),
		 _ret == 0);
	ero_probe_open_flags = O_RDONLY;
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_open_probe),
		 _ret == EACCES);
	/* Through the 0711 directory: search granted to other. */
	ero_probe_path = EROFS_INIT_MNT "/dirs/small/f1.dat";
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_stat_probe),
		 _ret == 0);
	/* Reading the 0711 directory itself is denied to other. */
	ero_probe_path = EROFS_INIT_MNT "/dirs/small";
	ero_probe_open_flags = O_RDONLY | O_DIRECTORY;
	TEST_RES(ero_run_as_uid(EROFS_NOBODY_UID, dropped_open_probe),
		 _ret == EACCES);
}
END_TEST()

/*
 * Matrix sec. 3.4 N1 (3) + N3 (parity, "名长 255 界 VFS 预检等价"):
 * the 253/254-byte preset names hit; the 255-byte name is ABSENT
 * from the image (mkfs.erofs 1.7.1 rejects 255-B dirent names,
 * T-018/S04 sec. 3 ledger -- the ENOENT here doubles as the
 * anti-silent-regression face for that removal); a 256-byte name is
 * ENAMETOOLONG (the length gate fires whichever layer owns it --
 * VFS precheck or FS N3 -- and it wins over existence); a
 * 253-byte miss with different padding stays ENOENT (the length
 * gate does not collapse byte addressing).
 */
FN_TEST(namei_name_length_boundary)
{
	struct stat st;
	char name[257], path[512];

	EROFS_SKIP_IF_NO_INIT_MNT();
	ero_boundary_name(name, 253, 'n');
	snprintf(path, sizeof(path), "%s/dirs/boundary_names/%s",
		 EROFS_INIT_MNT, name);
	TEST_SUCC(stat(path, &st));
	ero_boundary_name(name, 254, 'n');
	snprintf(path, sizeof(path), "%s/dirs/boundary_names/%s",
		 EROFS_INIT_MNT, name);
	TEST_SUCC(stat(path, &st));
	/*
	 * Absent-255 face (T-018/S04 sec. 3): present in the static
	 * tree, removed from every staged image; the 255-boundary
	 * crafted face itself rides FX (ktest).
	 */
	ero_boundary_name(name, 255, 'n');
	snprintf(path, sizeof(path), "%s/dirs/boundary_names/%s",
		 EROFS_INIT_MNT, name);
	TEST_ERRNO(stat(path, &st), ENOENT);
	/* 256 > NAME_MAX: ENAMETOOLONG (N3 face, 预检等价). */
	ero_boundary_name(name, 256, 'n');
	snprintf(path, sizeof(path), "%s/dirs/boundary_names/%s",
		 EROFS_INIT_MNT, name);
	TEST_ERRNO(stat(path, &st), ENAMETOOLONG);
	/* Same length, different bytes: a plain miss again. */
	ero_boundary_name(name, 253, 'x');
	snprintf(path, sizeof(path), "%s/dirs/boundary_names/%s",
		 EROFS_INIT_MNT, name);
	TEST_ERRNO(stat(path, &st), ENOENT);
}
END_TEST()

/*
 * Matrix sec. 3.4 N1 walk chain (parity, via the S01 sec. 3.2 deep
 * material): every level of the 8-deep chain is a directory, the
 * leaf file hits as S_IFREG, a mid-chain miss is ENOENT, and
 * stepping INTO the leaf file is ENOTDIR.
 */
FN_TEST(namei_deep_chain_walk)
{
	static const char *const chain[] = {
		"/dirs/deep/a",
		"/dirs/deep/a/b",
		"/dirs/deep/a/b/c",
		"/dirs/deep/a/b/c/d",
		"/dirs/deep/a/b/c/d/e",
		"/dirs/deep/a/b/c/d/e/f",
		"/dirs/deep/a/b/c/d/e/f/g",
	};
	struct stat st;
	char path[512];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	for (i = 0; i < ERO_ARRAY_SIZE(chain); i++) {
		snprintf(path, sizeof(path), "%s%s", EROFS_INIT_MNT, chain[i]);
		TEST_SUCC(stat(path, &st));
		TEST_RES(st.st_mode & S_IFMT, _ret == S_IFDIR);
	}
	snprintf(path, sizeof(path), "%s/dirs/deep/a/b/c/d/e/f/g/leaf.txt",
		 EROFS_INIT_MNT);
	TEST_SUCC(stat(path, &st));
	TEST_RES(st.st_mode & S_IFMT, _ret == S_IFREG);
	TEST_RES(st.st_ino, _ret != 0);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/dirs/deep/a/b/c/zzz", &st), ENOENT);
	TEST_ERRNO(stat(EROFS_INIT_MNT "/dirs/deep/a/b/c/d/e/f/g/leaf.txt/x",
			&st),
		   ENOTDIR);
}
END_TEST()

/*
 * Matrix sec. 3.4 "./.. 盘上写入无合成" row, healthy half (parity):
 * stat ino 对照 along the fs/ext2/readdir.c dot_dotdot_semantics
 * shape with the material swapped to preset entries -- "." resolves
 * to the directory itself and ".." to its parent. The walk itself
 * goes through the dcache tree (N1 (1) handle_dots) and is therefore
 * insensitive to the on-disk dot form; the readdir-side dot
 * provenance (点号来源 = 盘面条目) belongs to #10 readdir.c and the
 * crafted halves (missing "..", wrong-parent nid) to FX-DIRENT on
 * the ktest side (S05 sec. 3 #8 "ktest 余半边").
 */
FN_TEST(namei_dot_dotdot_stat_ino)
{
	struct stat st_child, st_parent, st_dot, st_dotdot;

	EROFS_SKIP_IF_NO_INIT_MNT();
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs/small", &st_child));
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs", &st_parent));
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/small/.", &st_dot),
		 st_dot.st_ino == st_child.st_ino);
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/small/..", &st_dotdot),
		 st_dotdot.st_ino == st_parent.st_ino);
	/* Empty directory: the dot faces hold with no children. */
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs/empty_dir", &st_child));
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/empty_dir/.", &st_dot),
		 st_dot.st_ino == st_child.st_ino);
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/empty_dir/..", &st_dotdot),
		 st_dotdot.st_ino == st_parent.st_ino);
	/* Deep-chain level: parent swap at depth. */
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs/deep/a/b", &st_child));
	TEST_SUCC(stat(EROFS_INIT_MNT "/dirs/deep/a", &st_parent));
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/deep/a/b/.", &st_dot),
		 st_dot.st_ino == st_child.st_ino);
	TEST_RES(stat(EROFS_INIT_MNT "/dirs/deep/a/b/..", &st_dotdot),
		 st_dotdot.st_ino == st_parent.st_ino);
}
END_TEST()
