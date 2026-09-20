// SPDX-License-Identifier: MPL-2.0

/*
 * erofs xattr assertions (T-020/S14; matrix sec. 6.1/6.2/6.4/6.5/6.6
 * healthy halves -- S05 sec. 3 file #12).
 *
 * Faces and carriers:
 *   - get value matrix on the persistent init mount MNT = /erofs
 *     (under the canonical single-run complement it carries x7/C2
 *     base_cpt, errata T-020/S01; same staged tree as C1, so content
 *     addressing is unaffected): every S01 sec. 3.4 preset entry,
 *     name-for-name, value-for-value (matrix sec. 6.1 healthy half;
 *     this IS the bloom-on face -- MNT compat=0x7: existing names hit
 *     through the filter, absent names end in ENODATA either way);
 *   - get entry/value gates on MNT: X12 name length edges, X6 unknown
 *     prefix / no-dot bare name, W-X03 bare "user." (empty suffix)
 *     EINVAL, X26 value ERANGE judged-before-copied (zero-touch),
 *     exact-size buffer, and the size=0 two-phase length return;
 *   - visibility matrix under a privilege drop (fork + setresuid 65534,
 *     erofs_common.h runner): G-X08/X15 EACCES face and its exemption
 *     half, X14 trusted-no-cap ENODATA, X4/X5 non-root list faces,
 *     X34 same-inode root-vs-non-root list totals, the list
 *     no-permission-gate negative contrast, and the W-X08 check-order
 *     double-error samples (registered differences);
 *   - root list visibility on MNT: name sets and totals per host,
 *     X34 two-phase size=0 totals, X36 undersized-buffer ERANGE with
 *     whole-batch discard (zero-touch); the acl hosts' list faces ride
 *     here as the W-X02 state-B registered difference;
 *   - write family on MNT: W-X01 state-B EROFS for every resolvable
 *     name and flag form, F21 order negatives (flags/empty name/
 *     oversize value first), and the registered W-X05/W-X01 residues
 *     (lazy reader -> path error first; kernel-range value pointer;
 *     trusted-no-cap EPERM);
 *   - fd variant gates on MNT: EBADF, W-X04 pipe-fd EINVAL and
 *     O_PATH-fd EBADF (both registered differences);
 *   - nouser_xattr gate on a self-mounted BASE (X3 EOPNOTSUPP for
 *     user.*, trusted./security. unaffected, X4 list filtering);
 *   - form faces on self-mounted modulated images: C8 = -x0
 *     xattr_shared_all (every entry in the shared region: get/list
 *     fidelity), C9 = -x-1 xattr_none (whole-image zero xattrs +
 *     bloom off: every get ENODATA, every list empty), C10 =
 *     --xattr-prefix=user.erofs_test.lpx. (full-name get/list through
 *     the on-disk prefix table, XAT-17 initramfs half).
 *
 * Guards: MNT tests use EROFS_SKIP_IF_NO_INIT_MNT() (mount-success
 * evidence, S05 sec. 6 extension 2); the four self-mount tests use
 * EROFS_SKIP_IF_NO_DEV() (device present AND erofs registered,
 * extension 1) and mount/umount the single self-mount point serially
 * inside the FN_TEST. The init mount point is never unmounted or
 * remounted.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists. Registered-difference assertions carry their
 * Linux baseline inline (marked "登记差异"); all other assertions are
 * parity. Never adjust an expected value to match observed behavior --
 * go back to the matrix instead.
 *
 * Face boundaries (no overlap with sibling files): the acl value faces
 * (G-X07 state-two precise-name get, noacl variant, symlink own-gate)
 * belong to acl.c; the write-family EROFS panorama belongs to
 * write_ero_fs.c (this file carries the xattr-specific W-X01 face);
 * every crafted half rides the ktest FX-XATTR fixtures (T-015): entry
 * overrunning remaining, dead indexes, contradictory bloom, shared id
 * out of range, garbage prefix metadata, the XAT-17 prefix
 * concatenation negatives, and the E2BIG three-segment family (XAT-38,
 * no healthy-tree list is large enough); the G-X09 non-reg/dir half
 * (user.* on symlink/device/fifo/socket hosts carrying a user.* entry)
 * needs symlink-host xattr material absent from the S01 tree and is
 * degraded to FX-XATTR per S05 sec. 8 case B -- this file carries only
 * the reg/dir half; W-X06 non-UTF-8 names likewise need crafted
 * entries (the healthy UTF-8 hit half is the per-host get matrix).
 *
 * Sources (never re-derive locally): matrix sec. 6.1-6.6
 * (docs/R-01/phase-docs/a-analysis/r1-baseline-matrix.md) quoting
 * T-005 sec. 3.1-3.4 (get chain, 31-row table, X12-X28), sec. 4.1-4.5
 * (visibility matrix, X29-X38), sec. 5.3/5.4 (write chain, X47/X48),
 * sec. 6.2-6.4 (aster syscall chain, samples 1-18, D1-D12) and
 * sec. 7.4 F39/F46; assertion directions r1-scope sec. 1.2/2.2/2.4/
 * 3.2 (G-X08/G-X09 state A parity, W-X01/W-X03 state-B parity, W-X02
 * state B / W-X04 / W-X05 / W-X08 registered differences); materials
 * T-016/S01 sec. 3.4/3.6 (hosts, names, values, chmod/chown faces);
 * image variants T-016/S02 sec. 2 (C8/C9/C10 mkfs forms; digest-pinned
 * by T-018).
 */

#include "erofs_common.h"

#include <stdint.h>
#include <sys/mount.h>
#include <sys/xattr.h>

/* xattr_host/ under the init mount point and a self-mount point. */
#define XV_MNT EROFS_INIT_MNT "/xattr_host"
#define XV_SELF EROFS_SELF_MNT "/xattr_host"

/* Dropped-identity uid for the visibility matrix (S05 sec. 8). */
#define XV_NOBODY 65534

/*
 * AUTO-DECISION: XATTR_CREATE is defined locally as 1 (its linux
 * value) -- glibc's sys/xattr.h does not export the flag constants.
 * Identical value, zero header coupling (same shape as the FIBMAP/
 * FS_IOC_FIEMAP decisions in data_path.c).
 */
#define XV_XATTR_CREATE 1

/*
 * AUTO-DECISION: kernel-range value pointer for the F39 corner, spelled
 * as a uintptr_t cast (a plain integer-to-pointer cast of a 64-bit
 * literal trips -Wint-to-pointer-cast under -Werror on some toolchains;
 * the uintptr_t route is warning-free and arch-portable). Above
 * MAX_USERSPACE_VADDR on both x86_64 and riscv64.
 */
#define XV_KERNEL_PTR ((const void *)(uintptr_t)0xfffffffffffff000ULL)

/*
 * AUTO-DECISION: unmapped low value pointer for the W-X05 sample-15
 * residue, laundered through a volatile object. GCC folds the plain
 * uintptr_t cast back to the literal address and, with setxattr's
 * access(read_only, 3, 4) attribute, -Wstringop-overread rejects any
 * compiler-known constant low address as a read source (the F39
 * XV_KERNEL_PTR spelling above stays clean only because its size is
 * 0, i.e. no read at all). The volatile load hands the analyzer an
 * opaque pointer while keeping the address (0x10 is never mapped) and
 * the asserted observable identical.
 */
static const void *volatile xv_bad_ptr = (const void *)(uintptr_t)0x10;

/* Long-name material (S01 sec. 3.4): "user." + 'n' * 200 = 205 chars. */
#define XV_LONGNAME_TOTAL 205

/* Value kinds for the per-host entry table. */
enum xv_kind {
	XV_FILL, /* every byte == ch */
	XV_INC, /* value[i] = i % 256 (mid and long incremental values) */
	XV_SHAR, /* the 4-byte literal "SHAR" (0x53484152 via setfattr) */
};

/*
 * The S01 sec. 3.4 preset-entry table: host file, entry name, value
 * length, value kind. Every row is asserted identically on MNT and on
 * the -x0 all-shared image (C8); the prefix rows carry full plain
 * names on MNT/C8 and 0x80|k-encoded names on C10.
 */
static const struct xv_row {
	const char *host;
	const char *name;
	int vlen;
	int kind;
	char ch;
} xv_rows[] = {
	{ "xattr_user_short.bin", "user.v", 1, XV_FILL, 0x41 },
	{ "xattr_user_mid.bin", "user.v", 64, XV_INC, 0 },
	{ "xattr_user_long.bin", "user.v", 1024, XV_INC, 0 },
	{ "xattr_multi.bin", "user.a", 8, XV_FILL, 'A' },
	{ "xattr_multi.bin", "user.b", 8, XV_FILL, 'B' },
	{ "xattr_multi.bin", "user.c", 8, XV_FILL, 'C' },
	{ "xattr_shared_1.bin", "user.shared", 4, XV_SHAR, 0 },
	{ "xattr_shared_1.bin", "user.shared2", 16, XV_FILL, 's' },
	{ "xattr_shared_2.bin", "user.shared", 4, XV_SHAR, 0 },
	{ "xattr_shared_2.bin", "user.shared2", 16, XV_FILL, 's' },
	{ "xattr_shared_3.bin", "user.shared", 4, XV_SHAR, 0 },
	{ "xattr_shared_3.bin", "user.shared2", 16, XV_FILL, 's' },
	{ "xattr_trusted.bin", "trusted.t", 16, XV_FILL, 'T' },
	{ "xattr_security.bin", "security.s", 16, XV_FILL, 'S' },
	{ "prefix_lpx_1.bin", "user.erofs_test.lpx.alpha", 8, XV_FILL, 'P' },
	{ "prefix_lpx_1.bin", "user.erofs_test.lpx.beta", 8, XV_FILL, 'Q' },
	{ "prefix_lpx_2.bin", "user.erofs_test.lpx.alpha", 8, XV_FILL, 'P' },
	{ "prefix_lpx_2.bin", "user.erofs_test.lpx.beta", 8, XV_FILL, 'Q' },
};

/* Build the 205-char long name (NUL-terminated, buffer >= 206). */
static void xv_longname(char *out)
{
	memcpy(out, "user.", 5);
	memset(out + 5, 'n', XV_LONGNAME_TOTAL - 5);
	out[XV_LONGNAME_TOTAL] = '\0';
}

/* value[i] = i % 256, over len bytes. 0 = match. */
static int xv_matches_inc(const char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if ((unsigned char)buf[i] != (unsigned char)(i % 256))
			return -1;
	return 0;
}

/* Every byte == ch over len bytes. 0 = match. */
static int xv_matches_ch(const char *buf, size_t len, char ch)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (buf[i] != ch)
			return -1;
	return 0;
}

/*
 * Get every table row under `root` (an xattr_host/ directory path) and
 * compare name-for-name, value-for-value. Returns 0 when all rows hit
 * with exact lengths and values. Order = table order (foreach order is
 * never an assertion face).
 */
static int xv_check_all_entries(const char *root)
{
	char path[256];
	char buf[1024];
	size_t i;
	int bad = 0;

	for (i = 0; i < sizeof(xv_rows) / sizeof(xv_rows[0]); i++) {
		const struct xv_row *r = &xv_rows[i];
		ssize_t n;

		snprintf(path, sizeof(path), "%s/%s", root, r->host);
		n = getxattr(path, r->name, buf, sizeof(buf));
		if (n != r->vlen) {
			bad++;
			continue;
		}
		switch (r->kind) {
		case XV_FILL:
			if (xv_matches_ch(buf, (size_t)n, r->ch) != 0)
				bad++;
			break;
		case XV_INC:
			if (xv_matches_inc(buf, (size_t)n) != 0)
				bad++;
			break;
		case XV_SHAR:
			if (memcmp(buf, "SHAR", 4) != 0)
				bad++;
			break;
		}
	}
	return bad;
}

/*
 * Walk the NUL-terminated tokens of a listxattr buffer. Returns the
 * token count, or -1 on a malformed tail (no NUL before the end).
 */
static int xv_token_count(const char *buf, size_t len)
{
	size_t off = 0;
	int n = 0;

	while (off < len) {
		const char *nl = memchr(buf + off, '\0', len - off);

		if (nl == NULL)
			return -1;
		off += (size_t)(nl - (buf + off)) + 1;
		n++;
	}
	return n;
}

/* Is `name` present as one full token of the list buffer? */
static int xv_has_name(const char *buf, size_t len, const char *name)
{
	size_t off = 0;

	while (off < len) {
		const char *nl = memchr(buf + off, '\0', len - off);
		size_t tlen;

		if (nl == NULL)
			return 0;
		tlen = (size_t)(nl - (buf + off)) + 1;
		if (tlen == strlen(name) + 1 &&
		    memcmp(buf + off, name, tlen) == 0)
			return 1;
		off += tlen;
	}
	return 0;
}

/*
 * List `path` and require: total length == `total`, token count ==
 * `nnames`, and every expected name present as a full token.
 *
 * AUTO-DECISION: name-set semantics (order-free). The matrix pins name
 * sets and size=0 totals, never foreach emission order (X37 is a
 * continue-iteration structural face, not an ordering contract);
 * pinning order would freeze an on-disk layout detail the baseline
 * never promises.
 */
static int xv_check_list(const char *path, const char *const *names, int nnames,
			 int total)
{
	char list[512];
	ssize_t n;
	int i;
	int found = 0;

	n = listxattr(path, list, sizeof(list));
	if (n != total)
		return -1;
	if (total == 0)
		return 0;
	if (xv_token_count(list, (size_t)n) != nnames)
		return -1;
	for (i = 0; i < nnames; i++)
		found += xv_has_name(list, (size_t)n, names[i]);
	return found == nnames ? 0 : -1;
}

/*
 * Privilege-drop probe plumbing. The tests run as constructor-ordered
 * serial functions in a single-threaded binary, so single static
 * parameter slots are race-free.
 *
 * AUTO-DECISION: single static slot instead of an argument context
 * struct -- ero_run_as_uid takes a callback without a void *arg; the
 * alternatives (global struct, closure emulation) add no value here.
 */
static const char *xv_path;
static const char *xv_name;

/* errno of getxattr (0 on success); -1 stays reserved for the runner. */
static int xv_get_errno(void)
{
	char buf[64];

	return getxattr(xv_path, xv_name, buf, sizeof(buf)) < 0 ? errno : 0;
}

/* errno of setxattr (0 on success). */
static int xv_set_errno(void)
{
	const char val[] = "v";

	return setxattr(xv_path, xv_name, val, sizeof(val) - 1, 0) < 0 ? errno :
									 0;
}

/* errno of removexattr (0 on success). */
static int xv_remove_errno(void)
{
	return removexattr(xv_path, xv_name) < 0 ? errno : 0;
}

/*
 * listxattr length on success (>= 0, fits every healthy list), or
 * 1000 + errno on failure (kept away from both the success range and
 * the runner's -1).
 */
static int xv_list_len(void)
{
	char buf[256];
	ssize_t n = listxattr(xv_path, buf, sizeof(buf));

	return n < 0 ? 1000 + errno : (int)n;
}

/*
 * Matrix sec. 6.1 healthy half (parity): every preset entry of S01
 * sec. 3.4 -- value-size gradient (1B/64B/1024B), the 200-char name,
 * the same-host 3-entry chain, the identical-entry shared trio,
 * trusted./security., and the four prefix-trigger names stored as
 * plain names on this image. Plus the absent-name ENODATA (bloom-on
 * face), the host-level zero-entry control, and the G-X09 reg/dir
 * half: user.* passes the type gate on REG/DIR hosts (the ENODATA
 * answers below are absence, not type rejection; the non-reg/dir
 * discriminating half rides FX-XATTR, S05 sec. 8 case B).
 */
FN_TEST(xattr_get_host_value_matrix)
{
	char buf[1024];
	char name[XV_LONGNAME_TOTAL + 2];

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): every value/ENODATA
	 * assertion below queries the on-image xattrs — the xattr value
	 * face (T-026). The T-024 namei rewrite makes the hosts
	 * reachable but the framework get_xattr default still answers
	 * EOPNOTSUPP; SKIP until the xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();

	TEST_RES(xv_check_all_entries(XV_MNT), _ret == 0);

	/* Long-name entry: 205-char name, 4-byte value 'N' * 4. */
	xv_longname(name);
	TEST_RES(getxattr(XV_MNT "/xattr_user_longname.bin", name, buf,
			  sizeof(buf)),
		 _ret == 4);
	TEST_RES(xv_matches_ch(buf, 4, 'N'), _ret == 0);

	/* Absent name on a host with entries: ENODATA. */
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", "user.missing", buf,
			    sizeof(buf)),
		   ENODATA);

	/* Host-level zero-entry control (xattr_none.bin gets nothing). */
	TEST_ERRNO(getxattr(XV_MNT "/xattr_none.bin", "user.v", buf,
			    sizeof(buf)),
		   ENODATA);

	/* G-X09 dir half: a directory host passes the user.* type gate. */
	TEST_ERRNO(getxattr(XV_MNT "/acl_dir", "user.foo", buf, sizeof(buf)),
		   ENODATA);
}
END_TEST()

/*
 * Matrix sec. 6.1 entry and value gates (parity): X12 name-length
 * edges (empty -> ERANGE, 255 chars legal -> ENODATA, 256 chars ->
 * ERANGE), X6 unknown prefix and no-dot bare name -> EOPNOTSUPP, W-X03
 * bare "user." (empty suffix) -> EINVAL (per-FS patch parity), X26
 * value ERANGE judged before copying (zero-touch), exact-size buffer,
 * and the size=0 two-phase length return (F46-verified parity).
 */
FN_TEST(xattr_get_entry_and_value_gates)
{
	char buf[1024];
	char name[300];
	const char *host = XV_MNT "/xattr_user_long.bin";

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the ENODATA/X26 arms
	 * below need a real xattr layer (misses answer ENODATA, hits
	 * return the value) — the xattr value face (T-026). The
	 * syscall-layer parse arms (ERANGE/EOPNOTSUPP/EINVAL) would
	 * pass already; the frozen set rides together. SKIP until the
	 * xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();

	/* X12: empty name -> ERANGE before any xattr semantics. */
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", "", buf,
			    sizeof(buf)),
		   ERANGE);

	/* X12 boundary: 255 chars is a legal name (proceeds -> ENODATA). */
	memcpy(name, "user.", 5);
	memset(name + 5, 'x', 250);
	name[255] = '\0';
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", name, buf,
			    sizeof(buf)),
		   ENODATA);

	/* X12 boundary: 256 chars -> ERANGE. */
	memcpy(name, "user.", 5);
	memset(name + 5, 'x', 251);
	name[256] = '\0';
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", name, buf,
			    sizeof(buf)),
		   ERANGE);

	/* X6: unknown prefix / no-dot bare name -> EOPNOTSUPP. */
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", "lustre.x", buf,
			    sizeof(buf)),
		   EOPNOTSUPP);
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", "foo", buf,
			    sizeof(buf)),
		   EOPNOTSUPP);

	/* W-X03: bare prefix "user." (empty suffix) -> EINVAL. */
	TEST_ERRNO(getxattr(XV_MNT "/xattr_user_short.bin", "user.", buf,
			    sizeof(buf)),
		   EINVAL);

	/* X26: undersized buffer -> ERANGE with no partial copy. */
	memset(buf, 0x5A, sizeof(buf));
	TEST_ERRNO(getxattr(host, "user.v", buf, 16), ERANGE);
	TEST_RES(xv_matches_ch(buf, 16, 'Z'), _ret == 0);

	/* X26: exact-size buffer succeeds. */
	TEST_RES(getxattr(host, "user.v", buf, 1024), _ret == 1024);

	/* X26 two-phase: size=0 returns the value length. */
	TEST_RES(getxattr(host, "user.v", NULL, 0), _ret == 1024);
}
END_TEST()

/*
 * Matrix sec. 6.1 G-X08/X14/X15 + sec. 6.2 caller dimension + W-X08
 * samples 1/2/5/7, all under the uid-65534 privilege drop on MNT:
 * user.* and unknown-prefix names on a no-read host -> EACCES (X15,
 * sample 5 parity after the state-A carryover); security./trusted. are
 * exempt from the read gate (ENODATA from absence / from the cap gate,
 * never EACCES); readable hosts answer normally (positive half,
 * including the 65534-owned multi host); the list face has no
 * permission gate (0 names, no EACCES, on the 0600 host); root-vs-
 * non-root same-inode list totals differ through the trusted gate
 * (X34); and the W-X08 double-error samples show aster's checks
 * running before path lookup (registered differences: Linux answers
 * ENOENT from the path walk first).
 */
FN_TEST(xattr_visibility_priv_drop_matrix)
{
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the EACCES/ENODATA/
	 * list-total arms below need the erofs xattr read gate and
	 * value face (T-026). SKIP until the xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();

	/* X15 (sample 5, parity after G-X08 state A): user.* on the 0600
	 * host (regular/inline_64b.bin, S01 sec. 3.6) -> EACCES. */
	xv_path = EROFS_INIT_MNT "/regular/inline_64b.bin";
	xv_name = "user.x";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == EACCES);

	/* 登记差异(W-X08 order residue): the X15 unknown-prefix EACCES
	 * cell is shadowed on aster by the parse-first order -- Linux
	 * answers EACCES here, aster answers the parse EOPNOTSUPP. */
	xv_name = "lustre.x";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == EOPNOTSUPP);

	/* X15 exemption: security. skips the read gate -> plain ENODATA. */
	xv_name = "security.foo";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == ENODATA);

	/* X14 (sample 7, parity): trusted. without CAP_SYS_ADMIN ->
	 * ENODATA (the cap gate replaces the read gate). */
	xv_name = "trusted.t";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == ENODATA);

	/* Positive half: readable hosts answer the dropped uid. */
	xv_path = XV_MNT "/xattr_user_short.bin"; /* 0644 root:root */
	xv_name = "user.v";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == 0);
	xv_path = XV_MNT "/xattr_multi.bin"; /* owned 65534:65534, S01 3.6 */
	xv_name = "user.a";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == 0);

	/* W-X08 sample 1 (登记差异): trusted.x + missing path, no cap ->
	 * Linux ENOENT, aster ENODATA (namespace check first). */
	xv_path = EROFS_INIT_MNT "/no_such_entry";
	xv_name = "trusted.x";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_get_errno), _ret == ENODATA);

	/* W-X08 sample 2 (登记差异): unknown prefix + missing path ->
	 * Linux ENOENT, aster EOPNOTSUPP (parse first; root form). */
	TEST_ERRNO(getxattr(EROFS_INIT_MNT "/no_such_entry", "lustre.x", NULL,
			    0),
		   EOPNOTSUPP);

	/* List has no permission gate (negative contrast): the 0600 host
	 * lists fine (0 names) as the dropped uid -- a gate would surface
	 * EACCES here regardless of the entry count. */
	xv_path = EROFS_INIT_MNT "/regular/inline_64b.bin";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_list_len), _ret == 0);

	/* X4/X5 non-root list faces: user./security. visible, trusted.
	 * filtered -> the trusted-only host lists 0 (vs 10 as root: the
	 * X34 same-inode differing-total face). */
	xv_path = XV_MNT "/xattr_user_short.bin";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_list_len), _ret == 7);
	xv_path = XV_MNT "/xattr_security.bin";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_list_len), _ret == 11);
	xv_path = XV_MNT "/xattr_trusted.bin";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_list_len), _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 6.2 visibility matrix, root caller, on MNT (parity
 * unless marked): per-host name sets and totals (the root visible set
 * is user+trusted+security), X34 two-phase size=0 totals, X36
 * undersized-buffer ERANGE with whole-batch discard (zero-touch), the
 * 200-char name listed in full, and the zero-entry host control. The
 * acl hosts' list face is the W-X02 state-B registered difference.
 */
FN_TEST(xattr_list_visibility_root)
{
	char list[512];
	char name[XV_LONGNAME_TOTAL + 2];
	static const char *const user_v_names[] = { "user.v" };
	static const char *const multi_names[] = { "user.a", "user.b",
						   "user.c" };
	static const char *const trusted_names[] = { "trusted.t" };
	static const char *const security_names[] = { "security.s" };
	static const char *const shared_names[] = { "user.shared",
						    "user.shared2" };
	static const char *const prefix_names[] = {
		"user.erofs_test.lpx.alpha", "user.erofs_test.lpx.beta"
	};

	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the per-host list
	 * name sets and totals below need the erofs list_xattr face
	 * (T-026). SKIP until the xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();

	TEST_RES(xv_check_list(XV_MNT "/xattr_user_short.bin", user_v_names, 1,
			       7),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_multi.bin", multi_names, 3, 21),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_trusted.bin", trusted_names, 1,
			       10),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_security.bin", security_names, 1,
			       11),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_shared_1.bin", shared_names, 2,
			       25),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_shared_2.bin", shared_names, 2,
			       25),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/xattr_shared_3.bin", shared_names, 2,
			       25),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/prefix_lpx_1.bin", prefix_names, 2, 51),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/prefix_lpx_2.bin", prefix_names, 2, 51),
		 _ret == 0);

	/* The 200-char name is listed in full (X27 family: plain long
	 * names carry no prefix-table involvement). */
	xv_longname(name);
	{
		const char *const one[] = { name };

		TEST_RES(xv_check_list(XV_MNT "/xattr_user_longname.bin", one,
				       1, XV_LONGNAME_TOTAL + 1),
			 _ret == 0);
	}

	/* X34 two-phase: size=0 returns the would-write total. */
	TEST_RES(listxattr(XV_MNT "/xattr_multi.bin", NULL, 0), _ret == 21);

	/* X36: undersized buffer -> ERANGE, whole batch discarded. */
	memset(list, 0x5A, sizeof(list));
	TEST_ERRNO(listxattr(XV_MNT "/xattr_multi.bin", list, 5), ERANGE);
	TEST_RES(xv_matches_ch(list, 5, 'Z'), _ret == 0);

	/* Zero-entry host control. */
	TEST_RES(xv_check_list(XV_MNT "/xattr_none.bin", NULL, 0, 0),
		 _ret == 0);

	/*
	 * 登记差异(W-X02 态 B): Linux lists the acl precise names on
	 * the acl hosts (system.posix_acl_access = 24 total /
	 * system.posix_acl_default = 25); aster's single-namespace list
	 * workaround has no System enumeration channel, so both lists are
	 * empty. The acl VALUE faces are acl.c's; this is the list-side
	 * cell only.
	 */
	TEST_RES(xv_check_list(XV_MNT "/acl_file.bin", NULL, 0, 0), _ret == 0);
	TEST_RES(xv_check_list(XV_MNT "/acl_dir", NULL, 0, 0), _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 6.4 W-X01 (state-B parity + registered residues), on
 * MNT: setxattr/removexattr with a valid path answer EROFS for every
 * resolvable name (user./bare "user."/trusted. as root/security./
 * system.posix_acl_access) and for legal flag forms (F26: no explicit
 * -o ro needed); F21 order negatives return the syscall-layer errors
 * first (flags EINVAL / empty-name ERANGE / oversize-value E2BIG,
 * each ahead of both the path error and EROFS); and the registered
 * residues: the lazy value reader lets a missing path answer ENOENT
 * (W-X05 sample 15; Linux EFAULT), a kernel-range value pointer with
 * size=0 faults the reader (F39; Linux's 0-byte copy succeeds and
 * would proceed to EROFS), and trusted without cap answers EPERM
 * ahead of everything (sample 9; Linux EROFS).
 */
FN_TEST(xattr_write_erofs_and_order)
{
	const char *host = XV_MNT "/xattr_user_short.bin";
	const char *missing = EROFS_INIT_MNT "/no_such_entry";
	const char val[] = "v";
	/* E2BIG staging: the syscall size gate (> XATTR_SIZE_MAX 65536)
	 * fires before any copy, but the region handed over is made
	 * genuinely readable at the full size so -Wstringop-overread (it
	 * reads sizes, not intent) sees an in-bounds source. 70000 is the
	 * registered oversize value; sizeof() locks buffer and syscall
	 * size together by construction. */
	static char big[70000];

	EROFS_SKIP_IF_NO_INIT_MNT();

	/* W-X01 state B: any resolvable name, any legal flags -> EROFS. */
	TEST_ERRNO(setxattr(host, "user.new", val, 1, 0), EROFS);
	TEST_ERRNO(setxattr(host, "user.", val, 1, 0), EROFS);
	TEST_ERRNO(setxattr(host, "trusted.new", val, 1, 0), EROFS);
	TEST_ERRNO(setxattr(host, "security.new", val, 1, 0), EROFS);
	TEST_ERRNO(setxattr(host, "system.posix_acl_access", val, 1, 0), EROFS);
	TEST_ERRNO(setxattr(host, "user.new", val, 1, XV_XATTR_CREATE), EROFS);
	TEST_ERRNO(removexattr(host, "user.v"), EROFS);
	TEST_ERRNO(removexattr(host, "trusted.t"), EROFS);

	/*
	 * 登记差异(W-X08 write-side residue): unknown-prefix name +
	 * VALID path -> Linux EROFS (the RO gate precedes name
	 * resolution), aster EOPNOTSUPP (the parse gate precedes
	 * lookup). The same order family as the get-side sample 2.
	 */
	TEST_ERRNO(setxattr(host, "lustre.new", val, 1, 0), EOPNOTSUPP);

	/* F21 negatives: each syscall-layer gate fires before EROFS. */
	TEST_ERRNO(setxattr(missing, "user.x", val, 1, 5), EINVAL);
	TEST_ERRNO(setxattr(missing, "", val, 1, 0), ERANGE);
	TEST_ERRNO(setxattr(missing, "user.x", big, sizeof(big), 0), E2BIG);

	/* 登记差异(W-X05 sample 15): unmapped value pointer + missing
	 * path -> Linux EFAULT (value copy first), aster ENOENT (the
	 * lazy reader is only consulted after lookup). */
	TEST_ERRNO(setxattr(missing, "user.x", xv_bad_ptr, 16, 0), ENOENT);

	/* 登记差异(W-X05 F39 corner): kernel-range value pointer with
	 * size=0 -> aster EFAULT (the reader faults at construction);
	 * Linux's 0-byte copy succeeds and would proceed to EROFS. */
	TEST_ERRNO(setxattr(host, "user.x", XV_KERNEL_PTR, 0, 0), EFAULT);

	/* 登记差异(W-X01 D1 residue, sample 9): trusted set/remove
	 * without cap -> aster EPERM (the namespace-cap check precedes
	 * lookup and the FS's EROFS), Linux EROFS. */
	xv_path = host;
	xv_name = "trusted.new";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_set_errno), _ret == EPERM);
	xv_name = "trusted.v";
	TEST_RES(ero_run_as_uid(XV_NOBODY, xv_remove_errno), _ret == EPERM);
}
END_TEST()

/*
 * Matrix sec. 6.1 row 1 fd face + sec. 6.6 W-X04 (registered
 * differences), on MNT: an invalid fd answers EBADF (parity); a pipe
 * fd answers EINVAL where Linux answers EOPNOTSUPP (pipefs has no
 * s_xattr); an O_PATH fd on an erofs file answers EBADF where Linux
 * performs the get normally.
 */
FN_TEST(xattr_fd_variant_gates)
{
	char buf[64];
	int pfd[2];
	int fd;

	EROFS_SKIP_IF_NO_INIT_MNT();

	/* Entry row 1: invalid fd -> EBADF. */
	TEST_ERRNO(fgetxattr(-1, "user.x", buf, sizeof(buf)), EBADF);

	/* W-X04 sample 17 (登记差异): pipe fd -> EINVAL (Linux
	 * EOPNOTSUPP). */
	TEST_SUCC(pipe(pfd));
	TEST_ERRNO(fgetxattr(pfd[0], "user.x", buf, sizeof(buf)), EINVAL);
	TEST_SUCC(close(pfd[0]));
	TEST_SUCC(close(pfd[1]));

	/* W-X04 sample 18 (登记差异): O_PATH fd on an erofs file ->
	 * EBADF (Linux returns the value normally). */
	fd = TEST_SUCC(open(XV_MNT "/xattr_user_short.bin", O_PATH));
	if (fd >= 0) {
		TEST_ERRNO(fgetxattr(fd, "user.v", buf, sizeof(buf)), EBADF);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

/*
 * Matrix sec. 6.1 X3 + sec. 6.2 mount-option dimension: BASE
 * self-mounted with nouser_xattr -- user.* get answers EOPNOTSUPP
 * (the FS gate, NOT ENODATA); trusted./security. gets are unaffected
 * (root); user names silently disappear from the list while trusted.
 * stays (X4).
 */
FN_TEST(xattr_nouser_xattr_gate)
{
	char buf[64];
	char list[512];

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	/*
	 * Activation-boundary guard (T-023/S08): the X3/X4 probes below
	 * walk into the mounted tree and read on-image xattrs -- the
	 * namei/lookup domain (T-024) plus the xattr domain (T-026).
	 * SKIP until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the trusted./security.
	 * value reads and the list totals below need the erofs xattr
	 * value face (T-026). SKIP until the xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0,
			"nouser_xattr"));

	/* X3: user.* -> EOPNOTSUPP. */
	TEST_ERRNO(getxattr(XV_SELF "/xattr_user_short.bin", "user.v", buf,
			    sizeof(buf)),
		   EOPNOTSUPP);

	/* trusted./security. ride a different gate and still answer. */
	TEST_RES(getxattr(XV_SELF "/xattr_trusted.bin", "trusted.t", buf,
			  sizeof(buf)),
		 _ret == 16);
	TEST_RES(xv_matches_ch(buf, 16, 'T'), _ret == 0);
	TEST_RES(getxattr(XV_SELF "/xattr_security.bin", "security.s", buf,
			  sizeof(buf)),
		 _ret == 16);
	TEST_RES(xv_matches_ch(buf, 16, 'S'), _ret == 0);

	/* X4: user names are skipped from the list (not an error). */
	TEST_RES(listxattr(XV_SELF "/xattr_user_short.bin", list, sizeof(list)),
		 _ret == 0);
	TEST_RES(listxattr(XV_SELF "/xattr_trusted.bin", list, sizeof(list)),
		 _ret == 10);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 6.5 G-X06 form face: C8 (-x0) self-mounted -- every
 * entry of the tree rides the shared region (h_shared_count > 0,
 * index histogram empty), so the full per-host get matrix plus the
 * per-host lists double as shared-region decode fidelity. The
 * identical-entry shared trio keeps its values; the zero-entry host
 * stays empty.
 */
FN_TEST(xattr_shared_all_fidelity)
{
	static const char *const user_v_names[] = { "user.v" };
	static const char *const multi_names[] = { "user.a", "user.b",
						   "user.c" };
	static const char *const shared_names[] = { "user.shared",
						    "user.shared2" };
	static const char *const prefix_names[] = {
		"user.erofs_test.lpx.alpha", "user.erofs_test.lpx.beta"
	};

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_XSHARED);
	/*
	 * Activation-boundary guard (T-023/S08): the shared-region
	 * fidelity matrix below walks into the mounted tree and reads
	 * on-image xattrs -- the namei/lookup domain (T-024) plus the
	 * xattr domain (T-026). SKIP until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the shared-region get/
	 * list fidelity matrix below needs the erofs xattr value face
	 * over the shared store (T-026). SKIP until the xattr face is
	 * served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_XSHARED, EROFS_SELF_MNT, "erofs", 0, NULL));

	TEST_RES(xv_check_all_entries(XV_SELF), _ret == 0);

	TEST_RES(xv_check_list(XV_SELF "/xattr_user_short.bin", user_v_names, 1,
			       7),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_SELF "/xattr_multi.bin", multi_names, 3, 21),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_SELF "/xattr_shared_1.bin", shared_names, 2,
			       25),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_SELF "/prefix_lpx_1.bin", prefix_names, 2,
			       51),
		 _ret == 0);

	/* Zero-entry host control on the all-shared image. */
	TEST_ERRNO(getxattr(XV_SELF "/xattr_none.bin", "user.v", NULL, 0),
		   ENODATA);
	TEST_RES(xv_check_list(XV_SELF "/xattr_none.bin", NULL, 0, 0),
		 _ret == 0);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 6.5 C9 negative contrast: the -x-1 image carries zero
 * xattrs filesystem-wide and its bloom bit is off (compat 0x3) -- so
 * the hosts that hold entries on every other image answer ENODATA /
 * empty lists here. This pins that the healthy answers elsewhere come
 * from the on-image entries, not from any ambient state.
 */
FN_TEST(xattr_zero_xattr_negative)
{
	char buf[64];
	char list[512];

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_XNONE);
	/*
	 * Activation-boundary guard (T-023/S08): the negative-contrast
	 * probes below walk into the mounted tree and query xattrs --
	 * the namei/lookup domain (T-024) plus the xattr domain
	 * (T-026); pinning ENODATA presupposes the query reaching the
	 * xattr layer at all. SKIP until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the ENODATA/empty-list
	 * arms below need a real xattr layer (the framework default
	 * answers EOPNOTSUPP, not ENODATA) — T-026. SKIP until the
	 * xattr face is served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_XNONE, EROFS_SELF_MNT, "erofs", 0, NULL));

	TEST_ERRNO(getxattr(XV_SELF "/xattr_user_short.bin", "user.v", buf,
			    sizeof(buf)),
		   ENODATA);
	TEST_ERRNO(getxattr(XV_SELF "/xattr_user_long.bin", "user.v", buf,
			    sizeof(buf)),
		   ENODATA);
	TEST_ERRNO(getxattr(XV_SELF "/xattr_trusted.bin", "trusted.t", buf,
			    sizeof(buf)),
		   ENODATA);
	TEST_ERRNO(getxattr(XV_SELF "/xattr_security.bin", "security.s", buf,
			    sizeof(buf)),
		   ENODATA);

	TEST_RES(listxattr(XV_SELF "/xattr_user_short.bin", list, sizeof(list)),
		 _ret == 0);
	TEST_RES(listxattr(XV_SELF "/xattr_multi.bin", list, sizeof(list)),
		 _ret == 0);
	TEST_RES(listxattr(XV_SELF "/xattr_trusted.bin", list, sizeof(list)),
		 _ret == 0);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()

/*
 * Matrix sec. 6.5 G-X03 form face (XAT-17 initramfs half): C10
 * (--xattr-prefix=user.erofs_test.lpx.) self-mounted -- the four
 * trigger names are stored as 0x80|0 long-prefix entries referencing
 * the on-disk prefix table; get by the assembled full name and list
 * with the full names reassembled must be byte-identical to the
 * plain-storage answers on MNT. Plain entries coexist on the same
 * image (user.v hits normally). The concatenation NEGATIVES (infix /
 * total-length mismatch variants) need fixture queries and ride the
 * XAT-17 ktest half.
 */
FN_TEST(xattr_prefix_get_list_fidelity)
{
	static const char *const user_v_names[] = { "user.v" };
	static const char *const prefix_names[] = {
		"user.erofs_test.lpx.alpha", "user.erofs_test.lpx.beta"
	};
	char buf[64];

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_PREFIX);
	/*
	 * Activation-boundary guard (T-023/S08): the prefix-table
	 * fidelity probes below walk into the mounted tree and read
	 * on-image xattrs -- the namei/lookup domain (T-024) plus the
	 * xattr domain (T-026, prefix table included). SKIP until
	 * /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the prefix-table get/
	 * list fidelity probes below need the erofs xattr value face
	 * with prefix reassembly (T-026). SKIP until the xattr face is
	 * served.
	 */
	EROFS_SKIP_IF_NO_XATTR_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_PREFIX, EROFS_SELF_MNT, "erofs", 0, NULL));

	/* Full-name get through the prefix table, both hosts. */
	TEST_RES(getxattr(XV_SELF "/prefix_lpx_1.bin",
			  "user.erofs_test.lpx.alpha", buf, sizeof(buf)),
		 _ret == 8);
	TEST_RES(xv_matches_ch(buf, 8, 'P'), _ret == 0);
	TEST_RES(getxattr(XV_SELF "/prefix_lpx_1.bin",
			  "user.erofs_test.lpx.beta", buf, sizeof(buf)),
		 _ret == 8);
	TEST_RES(xv_matches_ch(buf, 8, 'Q'), _ret == 0);
	TEST_RES(getxattr(XV_SELF "/prefix_lpx_2.bin",
			  "user.erofs_test.lpx.alpha", buf, sizeof(buf)),
		 _ret == 8);
	TEST_RES(xv_matches_ch(buf, 8, 'P'), _ret == 0);
	TEST_RES(getxattr(XV_SELF "/prefix_lpx_2.bin",
			  "user.erofs_test.lpx.beta", buf, sizeof(buf)),
		 _ret == 8);
	TEST_RES(xv_matches_ch(buf, 8, 'Q'), _ret == 0);

	/* List reassembles the full names (26 + 25 = 51 total). */
	TEST_RES(xv_check_list(XV_SELF "/prefix_lpx_1.bin", prefix_names, 2,
			       51),
		 _ret == 0);
	TEST_RES(xv_check_list(XV_SELF "/prefix_lpx_2.bin", prefix_names, 2,
			       51),
		 _ret == 0);

	/* Plain entries coexist on the same image. */
	TEST_RES(getxattr(XV_SELF "/xattr_user_short.bin", "user.v", buf,
			  sizeof(buf)),
		 _ret == 1);
	TEST_RES(xv_check_list(XV_SELF "/xattr_user_short.bin", user_v_names, 1,
			       7),
		 _ret == 0);

	/* Absent tail of the registered prefix family -> ENODATA (the
	 * discriminating concatenation negatives are XAT-17's ktest
	 * half). */
	TEST_ERRNO(getxattr(XV_SELF "/prefix_lpx_1.bin",
			    "user.erofs_test.lpx.gamma", buf, sizeof(buf)),
		   ENODATA);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
