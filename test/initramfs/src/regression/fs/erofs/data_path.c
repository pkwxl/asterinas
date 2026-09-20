// SPDX-License-Identifier: MPL-2.0

/*
 * erofs uncompressed data-path assertions (T-020/S13; matrix sec. 4.1-4.5
 * healthy halves + sec. 7.3 G-O06 + C11 main-only out-of-bounds EIO --
 * S05 sec. 3 file #11).
 *
 * Faces and carriers:
 *   - buffered-read faces on the persistent init mount MNT = /erofs
 *     (under the canonical single-run complement it carries x7/C2
 *     base_cpt, errata T-020/S01; same staged tree as C1, so content
 *     addressing is unaffected): the regular/ size gradient file by file
 *     against the S01 sec. 3.0 content formula, EOF truncation (M3
 *     read-side), zero-length read (Y1), the fixed-sentence content
 *     anchor, and the flat-carrier sparse file (solid zero blocks on a
 *     non-chunk image -- full 3-segment content compare allowed there,
 *     T-018/S07 sec. 8 item 1);
 *   - G-P02 last-page tail zero-fill via mmap (flat_4097b / flat_16k
 *     final pages; inline tail zero-fill rides inline_64b, 分歧行③);
 *   - F11 splice to a pipe -- REGISTERED DIFFERENCE (erratum
 *     T-025/S09): aster has no splice(2) syscall at all, so the
 *     case asserts ENOSYS with a never-advancing offset (full
 *     evidence chain in the case comment and
 *     docs/T-025/S09/index.md sec. 5.1);
 *   - G-P01 DIO alignment gate (SECTOR_SIZE = 512 constant, three-factor
 *     EINVAL) via O_DIRECT pread on an MNT file;
 *   - G-P03 fiemap/FIBMAP whole-face trim -> ENOTTY (registered
 *     difference) on an MNT REG fd and a DIR fd;
 *   - CHUNK_BASED layout content faces on self-mounted images: C12
 *     (4-byte entries, main-device global addresses) and D1 concat
 *     (8-byte entries; every data chunk is dev1/blob-local, so each read
 *     exercises the G-O06 mapped_blkaddr shift; C11 geometry per
 *     T-018/S08: main = 12 blocks, mapped = 12, blob = 13 blocks);
 *   - MD10/MD13: C11 main image mounted main-only -- metadata resolves
 *     from the 12-block main device while every data chunk shifts beyond
 *     its end -> data read EIO.
 *
 * Guards: MNT tests use EROFS_SKIP_IF_NO_INIT_MNT() (mount-success
 * evidence, S05 sec. 6 extension 2); C12/D1/C11 tests use the self-mount
 * class guard EROFS_SKIP_IF_NO_DEV() (device present AND erofs
 * registered, extension 1) and mount/umount the single self-mount point
 * serially inside the FN_TEST. The init mount point is never unmounted
 * or remounted.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists. Registered-difference assertions carry their
 * Linux baseline inline (marked "登记差异"); all other assertions are
 * parity. Never adjust an expected value to match observed behavior --
 * go back to the matrix instead.
 *
 * Erratum consumption (S05 sec. 3 #11 "vdq hole 读零" wording, adjusted
 * per docs/T-020/context.md risk 4 and docs/T-018/S07/index.md sec. 3):
 * mkfs 1.7.1 chunk-mode images distort the sparse FILE CONTENT (C12:
 * the tail 4K is swallowed by the hole unit; C11/D1: chunk0 spans 64
 * blocks beyond the device end), so sparse_hole.bin full-content
 * assertions run ONLY on MNT; on the chunk carriers the hole face is a
 * form assertion on the genuinely hole-marked range [262144, 397312)
 * plus the head-4K formula probe (the T-018/S07 sec. 2 anchor-② form
 * faces), never a full-file compare.
 *
 * Face boundaries (no overlap with sibling files): the statx DIOALIGN
 * non-advertising face (X14/W-N02/W-P03 same batch) belongs to
 * inode_stat.c; the llseek SEEK_DATA/HOLE/oversized-offset faces
 * (W-N09) belong to readdir.c; the write-family EROFS panorama belongs
 * to write_ero_fs.c (this file carries one face-inline open(O_WRONLY)
 * negative per the S05 sec. 7.2 sample); the crafted cross-block inline
 * image (EUCLEAN defense) rides FX-INODE on the ktest half.
 *
 * Sources (never re-derive locally): matrix sec. 4.1/4.2/4.3/4.4/4.5
 * and sec. 7.3 (docs/R-01/phase-docs/a-analysis/r1-baseline-matrix.md)
 * quoting T-004 sec. 1.2-1.4/1.8-1.11/1.14 and T-006 sec. 5 (MD7/MD8/
 * MD10/MD13); materials from T-016/S01 sec. 3.0/3.1 (content formula,
 * sentence anchor, size gradient, sparse 392 KiB = 4K head + 384K hole
 * + 4K tail); products from T-016/S02 sec. 2/5.1 (C11/C12/D1 mkfs
 * forms and deployment forms 甲/丙); C11 geometry and the digest-pinned
 * per-file chunkbits from docs/T-018/S08/index.md and
 * docs/T-018/S07/index.md sec. 3.
 */

#include "erofs_common.h"

#include <linux/fiemap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Healthy image block size (G-M08 pins blkszbits = 12) and page size of
 * the guest (both faces used by the mmap/last-page checks).
 */
#define EROFS_IMG_BS 4096u

/* S01 sec. 3.1 material sizes, frozen from the in-tree source files. */
#define EROFS_SIZE_ANCHOR 200u
#define EROFS_SIZE_16K_PLUS_100 16588u
#define EROFS_SPARSE_SIZE 401408u /* 392 KiB */
#define EROFS_SPARSE_HEAD 4096u /* leading formula run */
#define EROFS_SPARSE_TAIL_OFF 397312u /* trailing formula run start */

/*
 * Digest-pinned mkfs 1.7.1 per-file chunkbits for sparse_hole.bin:
 * 2^18 = 262144, i.e. unit0 = [0, 262144) is a data chunk and unit1 =
 * [262144, 401408) is the hole-marked (0xFFFFFFFF) entry on both the
 * 8-byte (C11/D1) and 4-byte (C12) chunk images
 * (docs/T-018/S07/index.md sec. 3; images are digest-anchored, so the
 * split is a stable fixture fact).
 */
#define EROFS_SPARSE_HOLE_UNIT 262144u

/* Fixed readable sentence anchor (S01 sec. 3.0): 44 B per line. */
#define EROFS_ANCHOR_SENTENCE "aster-fs erofs regression content anchor v1\n"

/*
 * AUTO-DECISION: FIBMAP is defined locally as _IO(0x00, 1) (its
 * linux/fs.h value) instead of including <linux/fs.h> -- pulling both
 * sys/mount.h and linux/fs.h in one TU walks into the historical
 * MS_*-style redefinition noise and the build runs -Werror. Identical
 * local value, zero header coupling. (Test-writing choice; no expected
 * value moves.)
 */
#ifndef FIBMAP
#define FIBMAP _IO(0x00, 1)
#endif

/*
 * AUTO-DECISION: the FIEMAP ioctl number is defined locally as
 * _IOWR('f', 11, struct fiemap) -- its exact value in linux/fs.h --
 * under the canonical name FS_IOC_FIEMAP. linux/fiemap.h only exports
 * struct fiemap + the FIEMAP_* flags (no ioctl macro at all), and the
 * macro's only header home, linux/fs.h, is off-limits per the FIBMAP
 * decision above (MS_* redefinition noise x -Werror). Guarded #ifndef
 * so a future header chain that does provide it stays conflict-free.
 * (Test-writing choice; no expected value moves.)
 */
#ifndef FS_IOC_FIEMAP
#define FS_IOC_FIEMAP _IOWR('f', 11, struct fiemap)
#endif

#define EROFS_REG_DIR EROFS_INIT_MNT "/regular"
#define EROFS_SELF_REG EROFS_SELF_MNT "/regular"

/*
 * Compare `len` bytes of `buf` against the content formula window
 * starting at absolute file offset `off`. 0 = full match.
 */
static int ero_buf_matches_formula(const char *buf, size_t len, size_t off)
{
	char expect[1024];
	size_t done = 0;

	while (done < len) {
		size_t want = len - done;

		if (want > sizeof(expect))
			want = sizeof(expect);
		ero_fill_content(expect, want, off + done);
		if (memcmp(buf + done, expect, want) != 0)
			return -1;
		done += want;
	}
	return 0;
}

/*
 * pread window [off, off + len) and compare against the formula.
 * 0 = match, -1 = short/error/mismatch.
 */
static int ero_check_window_fd(int fd, size_t off, size_t len)
{
	char buf[EROFS_IMG_BS];
	size_t done = 0;

	while (done < len) {
		size_t want = len - done;
		ssize_t n;

		if (want > sizeof(buf))
			want = sizeof(buf);
		n = pread(fd, buf, want, (off_t)(off + done));
		if (n <= 0)
			return -1;
		if (ero_buf_matches_formula(buf, (size_t)n, off + done) != 0)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

/* pread window [off, off + len) and require every byte to be zero. */
static int ero_check_zero_fd(int fd, size_t off, size_t len)
{
	char buf[EROFS_IMG_BS];
	size_t done = 0;

	while (done < len) {
		size_t want = len - done;
		ssize_t n;
		size_t i;

		if (want > sizeof(buf))
			want = sizeof(buf);
		n = pread(fd, buf, want, (off_t)(off + done));
		if (n <= 0)
			return -1;
		for (i = 0; i < (size_t)n; i++)
			if (buf[i] != 0)
				return -1;
		done += (size_t)n;
	}
	return 0;
}

/*
 * content_anchor.txt: the fixed sentence repeated and truncated at the
 * tree-pinned 200 B (S01 sec. 3.1 says "~200 B"; the in-tree source
 * file pins exactly 200, and 200 < one full 5th line, so the tail is a
 * truncated line -- the compare is modulo the sentence length).
 * 0 = match.
 */
static int ero_check_anchor_fd(int fd, size_t size)
{
	char buf[EROFS_IMG_BS];
	size_t done = 0;
	size_t sent = sizeof(EROFS_ANCHOR_SENTENCE) - 1;

	while (done < size) {
		size_t want = size - done;
		ssize_t n;
		size_t i;

		if (want > sizeof(buf))
			want = sizeof(buf);
		n = pread(fd, buf, want, (off_t)done);
		if (n <= 0)
			return -1;
		for (i = 0; i < (size_t)n; i++)
			if (buf[i] != EROFS_ANCHOR_SENTENCE[(done + i) % sent])
				return -1;
		done += (size_t)n;
	}
	return 0;
}

/*
 * Matrix sec. 4.1 (parity): the regular/ size-gradient family, file by
 * file -- stat size, full content against the formula (covers sec. 4.3
 * inline healthy half: file_1b/inline_64b content with the copy amount
 * truncated at i_size, observable as an exact-size read), EOF at
 * i_size (M3 read-side truncation), and the Y1 zero-length read.
 * closes with the three-element write negative of the S05 sec. 7.2
 * sample shape (panorama lives in write_ero_fs.c).
 */
FN_TEST(data_path_flat_size_gradient)
{
	static const struct {
		const char *name;
		size_t size;
	} rows[] = {
		{ "empty_file.bin", 0 },
		{ "file_1b.bin", 1 },
		{ "inline_64b.bin", 64 },
		{ "inline_4095b.bin", 4095 },
		{ "flat_4096b.bin", 4096 },
		{ "flat_4097b.bin", 4097 },
		{ "flat_16k_plus_100b.bin", EROFS_SIZE_16K_PLUS_100 },
	};
	struct stat st;
	char path[256];
	char buf[EROFS_IMG_BS];
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the assertions below
	 * read file CONTENT through the mounted tree (formula compares,
	 * EOF/Y1 probes) — the data-read face (T-025). The T-024 namei
	 * rewrite makes the paths reachable but read(2) stays
	 * EOPNOTSUPP; SKIP until the data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		int fd;

		snprintf(path, sizeof(path), "%s/%s", EROFS_REG_DIR,
			 rows[i].name);
		fd = TEST_SUCC(open(path, O_RDONLY));
		if (fd < 0)
			continue;
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size,
			 _ret == (unsigned long long)rows[i].size);
		/* Content == formula; the copy amount is cut at i_size. */
		TEST_RES(ero_check_content_fd(fd, rows[i].size), _ret == 0);
		/* M3 read-side EOF truncation: pread at i_size returns 0. */
		TEST_RES(pread(fd, buf, 1, (off_t)rows[i].size), _ret == 0);
		TEST_SUCC(close(fd));
	}

	/* EOF crossing: exactly the 1-byte tail of flat_4097b comes back. */
	{
		int fd = TEST_SUCC(
			open(EROFS_REG_DIR "/flat_4097b.bin", O_RDONLY));

		if (fd >= 0) {
			TEST_RES(pread(fd, buf, EROFS_IMG_BS,
				       (off_t)EROFS_IMG_BS),
				 _ret == 1);
			TEST_RES(buf[0] == (char)ero_content_byte(EROFS_IMG_BS),
				 _ret == 1);
			/* Y1: zero-length read returns 0 (both forms). */
			TEST_RES(pread(fd, buf, 0, 0), _ret == 0);
			TEST_RES(read(fd, buf, 0), _ret == 0);
			TEST_SUCC(close(fd));
		}
	}

	/* 要素③ write-family EROFS negative (sample shape, S05 sec. 7.2).
	 *
	 * Expected-value revision (T-024/S04): REGISTERED DIFFERENCE
	 * (docs/T-013/analysis.md sec. 9.1 row 3 / S07 sec. 4.2 F-3,
	 * assertion form OPN-09): aster's open chain carries no
	 * SB_RDONLY gate, so open(O_WRONLY) SUCCEEDS and the first
	 * refusal lands on write(2). Revised from the authority, never
	 * from observed behavior; the negative-control essence (no
	 * writable channel exists) is carried by the write refusal. */
	{
		int wfd = TEST_SUCC(
			open(EROFS_REG_DIR "/flat_4096b.bin", O_WRONLY));

		TEST_ERRNO(write(wfd, buf, 1), EROFS);
		TEST_SUCC(close(wfd));
	}
}
END_TEST()

/*
 * Matrix sec. 4.1 (parity): the two non-formula regular/ materials --
 * content_anchor.txt (fixed sentence, truncated at the tree-pinned
 * 200 B) and sparse_hole.bin on the FLAT carrier (MNT): head 4K and
 * tail 4K formula, the 384 KiB middle solid zeros (on a non-chunk
 * image the hole is stored as real zero blocks; full-file compare is
 * allowed ONLY here, T-018/S07 sec. 8 item 1).
 */
FN_TEST(data_path_anchor_and_sparse_content)
{
	struct stat st;
	char byte;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the assertions below
	 * read anchor and sparse-file CONTENT (sentence compare, head/
	 * tail formula windows) — the data-read face (T-025). SKIP
	 * until the data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();

	fd = TEST_SUCC(open(EROFS_REG_DIR "/content_anchor.txt", O_RDONLY));
	if (fd >= 0) {
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size,
			 _ret == EROFS_SIZE_ANCHOR);
		TEST_RES(ero_check_anchor_fd(fd, (size_t)st.st_size),
			 _ret == 0);
		TEST_RES(pread(fd, &byte, 0, (off_t)st.st_size), _ret == 0);
		TEST_SUCC(close(fd));
	}

	fd = TEST_SUCC(open(EROFS_REG_DIR "/sparse_hole.bin", O_RDONLY));
	if (fd >= 0) {
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size,
			 _ret == EROFS_SPARSE_SIZE);
		TEST_RES(ero_check_window_fd(fd, 0, EROFS_SPARSE_HEAD),
			 _ret == 0);
		TEST_RES(ero_check_zero_fd(fd, EROFS_SPARSE_HEAD,
					   EROFS_SPARSE_TAIL_OFF -
						   EROFS_SPARSE_HEAD),
			 _ret == 0);
		TEST_RES(ero_check_window_fd(fd, EROFS_SPARSE_TAIL_OFF,
					     EROFS_SPARSE_SIZE -
						     EROFS_SPARSE_TAIL_OFF),
			 _ret == 0);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

/*
 * Matrix sec. 4.2 (parity, candidate ① "no device residue"): the
 * last-page tail beyond i_size is zero-filled -- mmap the final page of
 * flat_4097b (1 data byte then 4095 zeros), of flat_16k_plus_100b (204
 * data bytes then the rest zeros), and page 0 of the INLINE file
 * inline_64b (64 bytes then zeros -- INLINE tail zero-fill, 分歧行③,
 * rides along). This is the exact face the ext2 current behavior
 * exposes device bytes for (matrix negative-control note).
 */
FN_TEST(data_path_tail_zerofill_mmap)
{
	static const struct {
		const char *name;
		off_t page_off;
		size_t data_len;
	} rows[] = {
		{ "flat_4097b.bin", 4096, 1 },
		{ "flat_16k_plus_100b.bin", 16384, 204 },
		{ "inline_64b.bin", 0, 64 },
	};
	size_t i;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the tail-zero-fill
	 * assertions read page CONTENT through mmap — the data face
	 * (T-025; the VMO channel itself may go live earlier with the
	 * T-024 page-cache rewrite, but the conservative data probe
	 * keeps this case SKIPped until read(2) is served too — a
	 * later activation, never a red window).
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		char path[256];
		char *p;
		size_t bad = 0;
		size_t k;
		int fd;

		snprintf(path, sizeof(path), "%s/%s", EROFS_REG_DIR,
			 rows[i].name);
		fd = TEST_SUCC(open(path, O_RDONLY));
		if (fd < 0)
			continue;
		p = mmap(NULL, EROFS_IMG_BS, PROT_READ, MAP_SHARED, fd,
			 rows[i].page_off);
		if (p == MAP_FAILED) {
			TEST_RES(p != MAP_FAILED, _ret == 1);
			close(fd);
			continue;
		}
		for (k = 0; k < EROFS_IMG_BS; k++) {
			char want =
				k < rows[i].data_len ?
					(char)ero_content_byte(
						(size_t)rows[i].page_off + k) :
					0;

			if (p[k] != want)
				bad++;
		}
		TEST_RES(bad, _ret == 0);
		TEST_SUCC(munmap(p, EROFS_IMG_BS));
		TEST_SUCC(close(fd));
	}
}
END_TEST()

/*
 * Matrix sec. 4.1 F11 (REGISTERED DIFFERENCE, erratum T-025/S09):
 * aster carries NO splice(2) syscall at all -- the syscall tables
 * (kernel/core/src/syscall/arch/) register no SYS_SPLICE, LTP
 * splice01-09 are disabled in the conformance list, the kselftest
 * blocklist masks the splice family, and kernel/core/src/syscall/
 * sendfile.rs notes that FileLike has no splice_read yet. The F11
 * parity registration (and the T-014/S07 sec. 7.2 assumption that
 * "aster splice goes through the generic FileLike read face")
 * predates that verified fact, so content preservation and offset
 * advance are unassertable here; revised per the erratum record
 * (docs/T-025/S09/index.md sec. 5.1), never from observed behavior.
 * Linux baseline: splice moves the bytes and advances the explicit
 * offset by the moved count. aster baseline: ENOSYS for every call,
 * the offset never advances, shape-identical on ext2 (whole-kernel
 * facility gap, same registration class as the G-P03 ENOTTY trim;
 * framework-side, erofs itself carries no splice face).
 * 登记差异(F11 勘误): Linux 基线 splice 移动字节并推进 off;aster
 * 整设施缺位 splice(2),一律 ENOSYS、off 零推进(erofs 与 ext2 同形)。
 */
FN_TEST(data_path_splice_pipe)
{
	int pfd[2];
	loff_t off = 0;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): unchanged -- the case
	 * still opens an MNT file through the served data face; only
	 * the splice expectation is revised (the 88/13 activation
	 * boundary itself does not move).
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	fd = TEST_SUCC(open(EROFS_REG_DIR "/flat_16k_plus_100b.bin", O_RDONLY));
	if (fd < 0)
		return;
	TEST_SUCC(pipe(pfd));

	/* 登记差异: both sizes ENOSYS; nothing is ever moved. */
	TEST_ERRNO(splice(fd, &off, pfd[1], NULL, EROFS_IMG_BS, 0), ENOSYS);
	TEST_ERRNO(splice(fd, &off, pfd[1], NULL, 1024, 0), ENOSYS);
	/* The explicit offset never advances (no bytes moved). */
	TEST_RES((unsigned long long)off, _ret == 0);

	TEST_SUCC(close(pfd[0]));
	TEST_SUCC(close(pfd[1]));
	TEST_SUCC(close(fd));
}
END_TEST()

/*
 * Matrix sec. 4.4 G-P01 (parity): the DIO alignment gate is the 512
 * constant (SECTOR_SIZE) plus the three alignment checks -- 512-aligned
 * O_DIRECT preads succeed with correct content; pos, count, and buffer
 * each individually misaligned -> EINVAL. (Y3 "no buffered fallback"
 * is pinned by the errno itself: a silent fallback would return
 * success instead of EINVAL.)
 */
FN_TEST(data_path_dio_alignment_gate)
{
	static char raw[EROFS_IMG_BS * 2 + 512];
	char *ali;
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the aligned O_DIRECT
	 * preads assert CONTENT against the formula — the data-read
	 * face (T-025). SKIP until the data face is served (the EINVAL
	 * three-factor half rides the same open fd).
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ali = (char *)(((uintptr_t)raw + 511u) & ~(uintptr_t)511u);
	fd = TEST_SUCC(open(EROFS_REG_DIR "/flat_16k_plus_100b.bin",
			    O_RDONLY | O_DIRECT));
	if (fd < 0)
		return;

	/* 512-aligned (not 4K-aligned) window succeeds. */
	TEST_RES(pread(fd, ali, 512, 0), _ret == 512);
	TEST_RES(ero_buf_matches_formula(ali, 512, 0), _ret == 0);
	/* 4K-aligned window succeeds too. */
	TEST_RES(pread(fd, ali, EROFS_IMG_BS, 2 * EROFS_IMG_BS),
		 _ret == (ssize_t)EROFS_IMG_BS);
	TEST_RES(ero_buf_matches_formula(ali, EROFS_IMG_BS, 2 * EROFS_IMG_BS),
		 _ret == 0);

	/* Factor 1: position not 512-aligned. */
	TEST_ERRNO(pread(fd, ali, 512, 513), EINVAL);
	/* Factor 2: count not 512-aligned. */
	TEST_ERRNO(pread(fd, ali, 513, 512), EINVAL);
	/* Factor 3: buffer not 512-aligned (pos/count fine). */
	TEST_ERRNO(pread(fd, ali + 1, 512, 2 * 512), EINVAL);

	TEST_SUCC(close(fd));
}
END_TEST()

/*
 * Matrix sec. 4.5 G-P03 (registered difference): the whole fiemap face
 * is trimmed -- FIEMAP on an MNT REG fd and on a DIR fd, and FIBMAP on
 * the REG fd, all return ENOTTY, matching the ext2/exfat shape.
 * 登记差异(G-P03): Linux 基线为 FIEMAP 输出 extent 记录、FIBMAP 返回
 * 物理块号;aster 整面裁剪,一律 ENOTTY。
 */
FN_TEST(data_path_fiemap_fibmap_enotty)
{
	struct fiemap fm;
	long lba = 0;
	int fd, dfd;

	EROFS_SKIP_IF_NO_INIT_MNT();
	fd = TEST_SUCC(open(EROFS_REG_DIR "/flat_4096b.bin", O_RDONLY));
	if (fd >= 0) {
		memset(&fm, 0, sizeof(fm));
		fm.fm_start = 0;
		fm.fm_length = FIEMAP_MAX_OFFSET;
		fm.fm_extent_count = 1;
		TEST_ERRNO(ioctl(fd, FS_IOC_FIEMAP, &fm), ENOTTY);
		TEST_ERRNO(ioctl(fd, FIBMAP, &lba), ENOTTY);
		TEST_SUCC(close(fd));
	}

	dfd = TEST_SUCC(open(EROFS_REG_DIR, O_RDONLY | O_DIRECTORY));
	if (dfd >= 0) {
		memset(&fm, 0, sizeof(fm));
		fm.fm_start = 0;
		fm.fm_length = FIEMAP_MAX_OFFSET;
		fm.fm_extent_count = 1;
		TEST_ERRNO(ioctl(dfd, FS_IOC_FIEMAP, &fm), ENOTTY);
		TEST_SUCC(close(dfd));
	}
}
END_TEST()

/*
 * Matrix sec. 4.1 (parity), 4-byte chunk face: C12 self-mounted -- the
 * cross-block file flat_16k_plus_100b (two 4-byte index entries,
 * main-device global addresses) and two single-entry probes read back
 * the formula byte-for-byte.
 */
FN_TEST(data_path_chunk4b_crossblk_content)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_CHUNK4B);
	/*
	 * Activation-boundary guard (T-023/S08): the content assertions
	 * below walk and read regular files through the mounted tree --
	 * the namei/lookup and chunked-data domains (T-024). SKIP until
	 * /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the chunked-content
	 * compares below READ through the self-mounted image — the
	 * chunk data face (T-025 map_blocks finalization; the T-024
	 * minimal backend answers CHUNK with EOPNOTSUPP by design).
	 * SKIP until the data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_CHUNK4B, EROFS_SELF_MNT, "erofs", 0, NULL));
	TEST_RES(ero_check_content_path(EROFS_SELF_REG
					"/flat_16k_plus_100b.bin",
					EROFS_SIZE_16K_PLUS_100),
		 _ret == 0);
	TEST_RES(ero_check_content_path(EROFS_SELF_REG "/flat_4096b.bin", 4096),
		 _ret == 0);
	TEST_RES(ero_check_content_path(EROFS_SELF_REG "/file_1b.bin", 1),
		 _ret == 0);
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 7.3 G-O06 (parity) + sec. 4.1 8-byte chunk face: D1
 * (concat) self-mounted WITHOUT any device= option (deployment form
 * 甲, T-016/S02 sec. 5.1) -- every data chunk entry is dev1/blob-local
 * and each read shifts by mapped_blkaddr (= 12) before hitting the
 * concatenated device, so content preservation on healthy files IS the
 * shifted-read assertion. flat_16k_plus_100b spans two 8-byte entries;
 * flat_4096b and content_anchor.txt are single-entry probes.
 */
FN_TEST(data_path_concat_shift_content)
{
	struct stat st;
	int fd;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_CONCAT);
	/*
	 * Activation-boundary guard (T-023/S08): the shifted-read
	 * assertions below open and read through the mounted tree --
	 * the namei/lookup and chunked-data domains (T-024). SKIP
	 * until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the shifted-read
	 * compares below READ through the self-mounted image — the
	 * chunk data face (T-025). SKIP until the data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_CONCAT, EROFS_SELF_MNT, "erofs", 0, NULL));
	TEST_RES(ero_check_content_path(EROFS_SELF_REG
					"/flat_16k_plus_100b.bin",
					EROFS_SIZE_16K_PLUS_100),
		 _ret == 0);
	TEST_RES(ero_check_content_path(EROFS_SELF_REG "/flat_4096b.bin", 4096),
		 _ret == 0);

	fd = TEST_SUCC(open(EROFS_SELF_REG "/content_anchor.txt", O_RDONLY));
	if (fd >= 0) {
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size,
			 _ret == EROFS_SIZE_ANCHOR);
		TEST_RES(ero_check_anchor_fd(fd, (size_t)st.st_size),
			 _ret == 0);
		TEST_SUCC(close(fd));
	}
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 4.2 整页洞 face, form assertion per the erratum (see the
 * file header): on D1 the sparse file's hole-marked trailing unit
 * [262144, 401408) reads as zeros without touching the device; the
 * probe window is narrowed to [262144, 397312) -- the semantically-hole
 * subrange -- so the assertion stays valid even if a future mkfs fix
 * stops swallowing the tail 4K into the hole unit. The head 4K
 * (chunk0 = dev1@2 -> concat block 14) reads the formula, pinning the
 * shifted read on the same file. No full-file content assertion runs
 * on any chunk carrier (T-018/S07 sec. 3 distortion).
 *
 * AUTO-DECISION: hole probe window = [262144, 397312) rather than the
 * full hole unit (robust to the mkfs tail-swallow being fixed later;
 * assertion target "hole entry reads zero" unchanged).
 */
FN_TEST(data_path_concat_sparse_hole_form_face)
{
	struct stat st;
	int fd;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_CONCAT);
	/*
	 * Activation-boundary guard (T-023/S08): the hole-form probes
	 * below open and read sparse_hole.bin through the mounted tree
	 * -- the namei/lookup and chunked-data domains (T-024). SKIP
	 * until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the hole-form probes
	 * below READ through the self-mounted image — the chunk data
	 * face (T-025). SKIP until the data face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_CONCAT, EROFS_SELF_MNT, "erofs", 0, NULL));
	fd = TEST_SUCC(open(EROFS_SELF_REG "/sparse_hole.bin", O_RDONLY));
	if (fd >= 0) {
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size,
			 _ret == EROFS_SPARSE_SIZE);
		/* Head 4K = formula through the shifted chunk0 read. */
		TEST_RES(ero_check_window_fd(fd, 0, EROFS_SPARSE_HEAD),
			 _ret == 0);
		/* Hole-marked unit interior: reads zero. */
		TEST_RES(ero_check_zero_fd(fd, EROFS_SPARSE_HOLE_UNIT,
					   EROFS_SPARSE_TAIL_OFF -
						   EROFS_SPARSE_HOLE_UNIT),
			 _ret == 0);
		TEST_SUCC(close(fd));
	}
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 7.3 MD10/MD13 (parity): C11 main image mounted main-only
 * (deployment form 丙, no device=): the mount itself succeeds and the
 * metadata path (root lookup, dirent, inode) resolves from the
 * 12-block main device -- open and fstat succeed -- while every data
 * chunk entry is dev1, shifting the read past the end of the main
 * device: the data read returns EIO.
 */
FN_TEST(data_path_main_only_data_eio)
{
	struct stat st;
	char buf[EROFS_IMG_BS];
	int fd;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_FLATDEV);
	/*
	 * Activation-boundary guard (T-023/S08): the metadata/data
	 * split assertions below open flat_4096b.bin through the
	 * mounted tree and expect the dev1 chunk read to shift past
	 * the main device -- the namei/lookup domain (T-024) plus the
	 * data-path map_blocks half (T-025). SKIP until /erofs content
	 * is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the split assertions
	 * below expect a DATA read whose EIO comes from the map-dev
	 * shift — the T-025 map_blocks error face. SKIP until the data
	 * face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_FLATDEV, EROFS_SELF_MNT, "erofs", 0, NULL));
	fd = TEST_SUCC(open(EROFS_SELF_REG "/flat_4096b.bin", O_RDONLY));
	if (fd >= 0) {
		/* Metadata resolves from the main device. */
		TEST_SUCC(fstat(fd, &st));
		TEST_RES((unsigned long long)st.st_size, _ret == 4096);
		/* Data chunk (dev1) shifts beyond the main device end. */
		TEST_ERRNO(read(fd, buf, sizeof(buf)), EIO);
		TEST_SUCC(close(fd));
	}
	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
