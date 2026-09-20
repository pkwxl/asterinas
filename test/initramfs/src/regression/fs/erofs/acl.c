// SPDX-License-Identifier: MPL-2.0

/*
 * erofs POSIX ACL read-channel assertions (T-020/S15; matrix sec. 6.3
 * G-X07 state-two healthy half -- S05 sec. 3 file #13).
 *
 * Faces and carriers:
 *   - precise-name get on the persistent init mount MNT = /erofs
 *     (under the canonical single-run complement it carries x7/C2
 *     base_cpt, errata T-020/S01; same staged tree as C1, so content
 *     addressing is unaffected): the two stored ACLs read back
 *     byte-exact in the canonical POSIX ACL wire format;
 *   - absence faces on MNT: the access name on the default-only
 *     directory and the default name on the access-only file (F25
 *     corner: the get side carries no type gate, a non-directory
 *     answers plain ENODATA), plus the zero-xattr host (matrix row 4
 *     healthy form: init isize==0 -> ENODATA);
 *   - non-exact system.* names on MNT: X42 -> EOPNOTSUPP for the
 *     documented near-miss forms, including the trailing-dot name
 *     that trips ext2's From<System> suffix strip into EINVAL
 *     (anti-copy negative: Linux never produces EINVAL at the name
 *     layer);
 *   - symlink own-gate on MNT: both precise names -> EOPNOTSUPP
 *     (matrix row 3; NOT the ENODATA a user.* name gets);
 *   - buffer protocol on MNT: size=0 returns real_size = 4+8n
 *     (44/36), an undersized buffer answers ERANGE with the
 *     userspace buffer untouched (the protocol is isomorphic to
 *     X26's judge-before-copy, T-005 S05 sec. 1.2), an exact-size
 *     buffer succeeds;
 *   - noacl variant on a self-mounted BASE: both precise names ->
 *     EOPNOTSUPP (matrix row 2; the noacl equivalent is never
 *     ENODATA -- the two codes must not be interchanged), with a
 *     user.* positive contrast pinning the EOPNOTSUPP to the acl
 *     gate (visibility matrix noacl column: root keeps user/
 *     trusted/security, only the acl cell drops).
 *
 * Guards: MNT tests use EROFS_SKIP_IF_NO_INIT_MNT() (mount-success
 * evidence, S05 sec. 6 extension 2); the noacl test uses
 * EROFS_SKIP_IF_NO_DEV() (device present AND erofs registered,
 * extension 1) and mounts/umounts the single self-mount point inside
 * the FN_TEST. The init mount point is never unmounted or remounted.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists; every assertion here is parity (the one
 * registered difference of this row group rides xattr.c's list
 * face, not this file). Never adjust an expected value to match
 * observed behavior -- go back to the matrix instead.
 *
 * Face boundaries (no overlap with sibling files): the acl LIST
 * faces are xattr.c's W-X02 state-B registered difference (acl
 * hosts list 0 vs Linux 24/25); the acl-name WRITE face (setxattr
 * of "system.posix_acl_access" -> EROFS; the acl write dispatch
 * stays unreachable behind the RO gate, W-X01/X47) is xattr.c's;
 * the value-parse family (a_version != 2 -> EOPNOTSUPP, malformed
 * values -> EINVAL, pure 4-byte header -> ENODATA, index-2/3
 * entries with e_name_len > 0, empty values, the isize == 12 init
 * state) needs crafted entries and rides the ktest FX-XATTR
 * fixtures (T-015) per the S05 sec. 3 #13 remainder column; the
 * shared-region half of matrix row 8 rides C8, xattr.c's carrier.
 *
 * Sources (never re-derive locally): matrix sec. 6.3
 * (docs/R-01/phase-docs/a-analysis/r1-baseline-matrix.md) quoting
 * T-005 S05 sec. 1.1/1.2/1.3 (the X42/X46/X43 chain) and sec. 2
 * (the 16-row visible-behavior matrix); assertion direction
 * r1-scope AR-S01-7 (G-X07 state two); materials T-016/S01 sec. 3.4
 * (the setfacl text forms below are the single source of the
 * expected bytes, mechanically re-encoded through the wire layout).
 */

#include "erofs_common.h"

#include <sys/mount.h>
#include <sys/xattr.h>

/* xattr_host/ under the init mount point and the self-mount point. */
#define AC_MNT EROFS_INIT_MNT "/xattr_host"
#define AC_SELF EROFS_SELF_MNT "/xattr_host"

/* The two acl hosts (S01 sec. 3.4). */
#define AC_FILE AC_MNT "/acl_file.bin"
#define AC_DIR AC_MNT "/acl_dir"

/* The two precise names (X42 exact strcmp; T-005 S05 sec. 1.1). */
#define AC_ACCESS "system.posix_acl_access"
#define AC_DEFAULT "system.posix_acl_default"

/*
 * POSIX ACL xattr wire format (Linux UAPI): a little-endian 4-byte
 * a_version == POSIX_ACL_XATTR_VERSION (2) header, then 8-byte
 * entries of le16 e_tag, le16 e_perm, le32 e_id, with e_id =
 * ACL_UNDEFINED_ID (0xffffffff) for the unqualified tags. The
 * channel round-trips through the in-memory posix_acl (parse
 * validates the canonical tag order, serialize re-emits it) and the
 * staged blobs are setfacl's canonical output, so the value read
 * back equals the encoding of the S01 sec. 3.4 text forms below,
 * byte for byte (T-005 S05 sec. 1.2: the round-trip is NOT a byte
 * passthrough -- the assertion pins the canonical form).
 */
#define AC_VERSION 2
#define AC_ID_UNDEF 0xffffffffU

/* e_tag values (include/uapi/linux/posix_acl.h). */
#define AC_TAG_USER_OBJ 0x01
#define AC_TAG_USER 0x02
#define AC_TAG_GROUP_OBJ 0x04
#define AC_TAG_MASK 0x10
#define AC_TAG_OTHER 0x20

struct ac_ent {
	unsigned int tag;
	unsigned int perm;
	unsigned int id;
};

/*
 * acl_file.bin access ACL, mechanically encoded from the S01 sec. 3.4
 * staged form: setfacl -m u::rw-,g::r--,o::r--,m::rw-,u:1000:r--.
 * Canonical order: USER_OBJ, USER (by id), GROUP_OBJ, MASK, OTHER.
 */
static const struct ac_ent ac_access_ents[] = {
	{ AC_TAG_USER_OBJ, 6, AC_ID_UNDEF }, /* u:: rw- */
	{ AC_TAG_USER, 4, 1000 }, /* u:1000 r-- */
	{ AC_TAG_GROUP_OBJ, 4, AC_ID_UNDEF }, /* g:: r-- */
	{ AC_TAG_MASK, 6, AC_ID_UNDEF }, /* m:: rw- */
	{ AC_TAG_OTHER, 4, AC_ID_UNDEF }, /* o:: r-- */
};

/* acl_dir default ACL: setfacl -d -m u::rwx,g::rx,o::r--,m::rwx. */
static const struct ac_ent ac_default_ents[] = {
	{ AC_TAG_USER_OBJ, 7, AC_ID_UNDEF }, /* u:: rwx */
	{ AC_TAG_GROUP_OBJ, 5, AC_ID_UNDEF }, /* g:: rx */
	{ AC_TAG_MASK, 7, AC_ID_UNDEF }, /* m:: rwx */
	{ AC_TAG_OTHER, 4, AC_ID_UNDEF }, /* o:: r-- */
};

/* real_size = 4 + 8n (X46): 5 entries / 4 entries. */
#define AC_ACCESS_LEN 44
#define AC_DEFAULT_LEN 36

#define AC_ENTS_N(a) (sizeof(a) / sizeof((a)[0]))

/* Encode `ents` into `buf` (wire format); returns the byte count. */
static size_t ac_encode(char *buf, const struct ac_ent *ents, size_t n)
{
	size_t off = 0;
	size_t i;

	buf[off++] = (char)AC_VERSION;
	buf[off++] = 0;
	buf[off++] = 0;
	buf[off++] = 0;
	for (i = 0; i < n; i++) {
		unsigned int v;

		v = ents[i].tag;
		buf[off++] = (char)(v & 0xff);
		buf[off++] = (char)((v >> 8) & 0xff);
		v = ents[i].perm;
		buf[off++] = (char)(v & 0xff);
		buf[off++] = (char)((v >> 8) & 0xff);
		v = ents[i].id;
		buf[off++] = (char)(v & 0xff);
		buf[off++] = (char)((v >> 8) & 0xff);
		buf[off++] = (char)((v >> 16) & 0xff);
		buf[off++] = (char)((v >> 24) & 0xff);
	}
	return off;
}

/*
 * 0 = the acl `name` at `path` reads back exactly the canonical
 * encoding of `ents` (`len` bytes). -1 = wrong errno, wrong length,
 * or wrong bytes.
 */
static int ac_check_value(const char *path, const char *name,
			  const struct ac_ent *ents, size_t n, size_t len)
{
	char expect[64];
	char actual[64];
	ssize_t ret;

	if (ac_encode(expect, ents, n) != len)
		return -1;
	ret = getxattr(path, name, actual, sizeof(actual));
	if (ret < 0 || (size_t)ret != len)
		return -1;
	return memcmp(expect, actual, len) == 0 ? 0 : -1;
}

/*
 * Matrix sec. 6.3 G-X07 state two, T-005 S05 sec. 2 rows 14-15
 * healthy halves (parity): the two stored ACLs read back through
 * the precise names byte-exact in the canonical wire format -- 44
 * bytes (5 entries) for the access ACL of acl_file.bin, 36 bytes
 * (4 entries) for the default ACL of acl_dir.
 */
FN_TEST(acl_precise_name_get_value)
{
	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_RES(ac_check_value(AC_FILE, AC_ACCESS, ac_access_ents,
				AC_ENTS_N(ac_access_ents), AC_ACCESS_LEN),
		 _ret == 0);
	TEST_RES(ac_check_value(AC_DIR, AC_DEFAULT, ac_default_ents,
				AC_ENTS_N(ac_default_ents), AC_DEFAULT_LEN),
		 _ret == 0);
}
END_TEST()

/*
 * Matrix sec. 6.3 healthy absence faces (parity): the access name on
 * the default-only directory and the default name on the access-only
 * file -- the F25 corner carries no type gate on the get side, so a
 * non-directory answers plain ENODATA (never EOPNOTSUPP/EINVAL);
 * and the zero-xattr host is the healthy form of matrix row 4
 * (init isize==0 -> ENODATA).
 */
FN_TEST(acl_absence_faces)
{
	char buf[64];

	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_ERRNO(getxattr(AC_DIR, AC_ACCESS, buf, sizeof(buf)), ENODATA);
	TEST_ERRNO(getxattr(AC_FILE, AC_DEFAULT, buf, sizeof(buf)), ENODATA);
	TEST_ERRNO(getxattr(AC_MNT "/xattr_none.bin", AC_ACCESS, buf,
			    sizeof(buf)),
		   ENODATA);
	TEST_ERRNO(getxattr(AC_MNT "/xattr_none.bin", AC_DEFAULT, buf,
			    sizeof(buf)),
		   ENODATA);
}
END_TEST()

/*
 * Matrix sec. 6.3 X42 (parity): only the two precise names take the
 * acl channel; every non-exact system.* name answers EOPNOTSUPP --
 * "system.foo" (S05 sec. 3 #13 row) and the near-miss forms of
 * T-005 S05 sec. 1.1 ("system.posix_acl_access.x",
 * "system.posix_acl"), plus the trailing-dot form as the anti-copy
 * negative: ext2's From<System> suffix strip fails into EINVAL
 * there, but Linux never produces EINVAL at the name layer.
 */
FN_TEST(acl_nonexact_name_gates)
{
	char buf[64];

	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_ERRNO(getxattr(AC_FILE, "system.foo", buf, sizeof(buf)),
		   EOPNOTSUPP);
	TEST_ERRNO(getxattr(AC_FILE, "system.posix_acl_access.x", buf,
			    sizeof(buf)),
		   EOPNOTSUPP);
	TEST_ERRNO(getxattr(AC_FILE, "system.posix_acl", buf, sizeof(buf)),
		   EOPNOTSUPP);
	/* anti-strip negative: EOPNOTSUPP, NOT the ext2-style EINVAL */
	TEST_ERRNO(getxattr(AC_FILE, "system.posix_acl_access.", buf,
			    sizeof(buf)),
		   EOPNOTSUPP);
}
END_TEST()

/*
 * Matrix sec. 6.3 X43 symlink own-gate (parity): both precise names
 * on a symlink answer EOPNOTSUPP -- the gate's own code, NOT the
 * ENODATA a user.* name gets on a symlink (X13 is xattr.c's face).
 */
FN_TEST(acl_symlink_own_gate)
{
	char buf[64];

	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_ERRNO(getxattr(EROFS_INIT_MNT "/symlink/to_file_short", AC_ACCESS,
			    buf, sizeof(buf)),
		   EOPNOTSUPP);
	TEST_ERRNO(getxattr(EROFS_INIT_MNT "/symlink/to_file_short", AC_DEFAULT,
			    buf, sizeof(buf)),
		   EOPNOTSUPP);
}
END_TEST()

/*
 * Matrix sec. 6.3 X46 (parity): size=0 returns real_size = 4+8n
 * (44 access / 36 default); a buffer one byte short answers ERANGE
 * with the userspace buffer left untouched (the two-phase/ERANGE
 * protocol is isomorphic to X26's judge-before-copy, T-005 S05
 * sec. 1.2); an exact-size buffer succeeds. E2BIG is unreachable
 * for acl values (real_size <= 4+8*8191 < 65536) -- no assertion.
 */
FN_TEST(acl_buffer_protocol)
{
	char buf[64];

	EROFS_SKIP_IF_NO_INIT_MNT();

	TEST_RES(getxattr(AC_FILE, AC_ACCESS, NULL, 0), _ret == 44);
	TEST_RES(getxattr(AC_DIR, AC_DEFAULT, NULL, 0), _ret == 36);

	memset(buf, 0x5A, sizeof(buf));
	TEST_ERRNO(getxattr(AC_FILE, AC_ACCESS, buf, AC_ACCESS_LEN - 1),
		   ERANGE);
	TEST_RES(memcmp(buf, "ZZZZ", 4), _ret == 0);
	memset(buf, 0x5A, sizeof(buf));
	TEST_ERRNO(getxattr(AC_DIR, AC_DEFAULT, buf, AC_DEFAULT_LEN - 1),
		   ERANGE);
	TEST_RES(memcmp(buf, "ZZZZ", 4), _ret == 0);

	TEST_RES(getxattr(AC_FILE, AC_ACCESS, buf, AC_ACCESS_LEN),
		 _ret == AC_ACCESS_LEN);
}
END_TEST()

/*
 * Matrix sec. 6.3 X43 noacl gate (parity): BASE self-mounted with
 * noacl -- both precise names answer EOPNOTSUPP; the noacl
 * equivalent is never ENODATA (the two codes must not be
 * interchanged). The user.* positive contrast pins the code to the
 * acl gate rather than any blanket xattr switch: the visibility
 * matrix noacl column keeps user./trusted./security. visible for
 * root (matrix sec. 6.2), so user.v still reads its 1-byte value
 * under the very same mount.
 */
FN_TEST(acl_noacl_variant_gate)
{
	char buf[64];

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	/*
	 * Activation-boundary guard (T-023/S08): the gate probes below
	 * walk into the mounted tree and query on-image xattrs (ACL
	 * names ride the xattr namespace) -- the namei/lookup domain
	 * (T-024) plus the xattr/ACL domain (T-026). SKIP until
	 * /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	ero_ensure_self_mnt();

	TEST_SUCC(mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, "noacl"));

	TEST_ERRNO(getxattr(AC_SELF "/acl_file.bin", AC_ACCESS, buf,
			    sizeof(buf)),
		   EOPNOTSUPP);
	TEST_ERRNO(getxattr(AC_SELF "/acl_dir", AC_DEFAULT, buf, sizeof(buf)),
		   EOPNOTSUPP);

	TEST_RES(getxattr(AC_SELF "/xattr_user_short.bin", "user.v", buf,
			  sizeof(buf)),
		 _ret == 1);
	TEST_RES(memcmp(buf, "A", 1), _ret == 0);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
