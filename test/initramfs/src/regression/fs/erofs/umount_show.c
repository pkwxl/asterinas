// SPDX-License-Identifier: MPL-2.0

/*
 * erofs umount + /proc mounts display assertions (T-020/S07; matrix sec.
 * 2.6 sysfs-excepted, S05 sec. 3 file #5).
 *
 * Carrier: BASE (EROFS_DEV_BASE, slot x5 / image C1) self-mounted at the
 * single self-mount point EROFS_SELF_MNT, mounted and unmounted serially
 * inside each FN_TEST. This file carries:
 *   - the umount basic face (umount success / non-mount-point EINVAL),
 *   - W-M11 (no busy check: umount with a preset file still open
 *     succeeds and the fd stays readable),
 *   - G-M20 (umount2 flags negative control: MNT_FORCE/MNT_DETACH/
 *     MNT_EXPIRE/UMOUNT_NOFOLLOW and combinations behave the same as a
 *     plain umount),
 *   - W-M04/W-M08 (rw-requested mount read back through /proc/mounts and
 *     /proc/self/mountinfo),
 *   - the RM13 remount,rw display half deferred from statfs_remount.c
 *     (docs/T-020/S06/index.md sec. 7-5).
 *
 * Guard: self-mount class, EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE) -- the
 * device node is present AND erofs is registered, so both the non-erofs
 * run form and the attached-but-unimplemented state SKIP with exit 0.
 *
 * Expected values are frozen from the baseline BEFORE the erofs
 * implementation exists (matrix sec. 2.6 rows quoting T-002 sec. 5.1/5.2
 * (WO1/WO2, facts M22/M23), sec. 6.3 O1 and sec. 7.5 umount(2) face
 * (facts T8/T9, umount.rs flag set); r1-scope sec. 3.2 W-M04).
 * Registered-difference assertions carry their Linux baseline inline
 * (marked "登记差异"). Never adjust an expected value to match observed
 * behavior -- go back to the matrix instead.
 */

#include "erofs_common.h"

#include <sys/mount.h>

/*
 * umount2 flag numbers, shared by both trees (UAPI values; aster umount.rs
 * UmountFlags accepts exactly these four and rejects any other bit). The
 * guest toolchain's <sys/mount.h> ships the first three but not
 * necessarily UMOUNT_NOFOLLOW, hence the guards.
 */
#ifndef MNT_FORCE
#define MNT_FORCE 1
#endif
#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#ifndef MNT_EXPIRE
#define MNT_EXPIRE 4
#endif
#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW 8
#endif

/* The common shape: BASE self-mounted with a rw request (no MS_RDONLY),
 * no option string. */
static int mount_base_default(void)
{
	return mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", 0, NULL);
}

/* remount,rw on the self-mounted BASE instance (RM13: MS_REMOUNT without
 * MS_RDONLY; the syscall-return/EROFS/statfs faces live in
 * statfs_remount.c, only the display faces are consumed here). */
static int remount_base_rw(void)
{
	return mount(EROFS_DEV_BASE, EROFS_SELF_MNT, "erofs", MS_REMOUNT, NULL);
}

/*
 * Read a whole (small) proc file into buf (NUL-terminated). Returns the
 * total length, or -1 when open/read failed (errno then set by the raw
 * syscall -- an unexpected path that TEST_RES reports as-is). The
 * expected paths keep errno at 0.
 */
static long umnt_read_proc(const char *path, char *buf, size_t bufsz)
{
	ssize_t total = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	while (total < (ssize_t)bufsz - 1) {
		ssize_t n = read(fd, buf + total, bufsz - 1 - (size_t)total);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		total += n;
	}
	close(fd);
	buf[total] = '\0';
	return total;
}

/* Locate the idx-th (0-based) whitespace-separated field of `line`;
 * returns its start and length, or NULL when the line has no such
 * field. Pure string scan, errno untouched. */
static const char *umnt_field(const char *line, int idx, size_t *len)
{
	const char *p = line;
	const char *start;
	int i;

	for (i = 0; i <= idx; i++) {
		while (*p == ' ' || *p == '\t')
			p++;
		start = p;
		while (*p != '\0' && *p != '\n' && *p != ' ' && *p != '\t')
			p++;
		if (start == p)
			return NULL; /* line exhausted */
		if (i == idx) {
			*len = (size_t)(p - start);
			return start;
		}
	}
	return NULL;
}

static int umnt_field_eq(const char *f, size_t len, const char *s)
{
	return strlen(s) == len && strncmp(f, s, len) == 0;
}

/* 1 iff the comma-separated options field contains `tok` as an exact
 * token. */
static int umnt_has_token(const char *field, size_t len, const char *tok)
{
	size_t toklen = strlen(tok);
	size_t i = 0;

	while (i < len) {
		size_t j = i;

		while (j < len && field[j] != ',')
			j++;
		if (j - i == toklen && strncmp(field + i, tok, toklen) == 0)
			return 1;
		i = j + 1;
	}
	return 0;
}

/*
 * /proc/mounts: find the line of the "erofs" mount at `mnt` (fields:
 * source mount_point fs_type options dump pass). On success return 0 and
 * fill the options (4th) field; -1 when no such line.
 */
static int umnt_mounts_opts(const char *buf, const char *mnt,
			    const char **start, size_t *len)
{
	const char *p = buf;

	while (*p != '\0') {
		const char *line = p;
		const char *end = strchrnul(p, '\n');
		const char *f;
		size_t fl;

		p = (*end == '\n') ? end + 1 : end;

		f = umnt_field(line, 1, &fl);
		if (f == NULL || !umnt_field_eq(f, fl, mnt))
			continue;
		f = umnt_field(line, 2, &fl);
		if (f == NULL || !umnt_field_eq(f, fl, "erofs"))
			continue;
		*start = umnt_field(line, 3, len);
		return (*start != NULL) ? 0 : -1;
	}
	return -1;
}

/*
 * /proc/self/mountinfo: find the line of the "erofs" mount at `mnt`
 * (fields: id parent major:minor root mount_point mount_flags
 * [optional...] - fs_type source fs_flags). On success return 0 and fill
 * the mount-flag field (always the 6th, right after the mount point --
 * optional fields, when present, come later before the "-" separator)
 * and the fs-flags field (the last one behind " - "). -1 when absent.
 */
static int umnt_mountinfo_fields(const char *buf, const char *mnt,
				 const char **mflags, size_t *mflags_len,
				 const char **fsflags, size_t *fsflags_len)
{
	const char *p = buf;

	while (*p != '\0') {
		const char *line = p;
		const char *end = strchrnul(p, '\n');
		const char *f;
		const char *fst;
		const char *last = NULL;
		size_t fl;
		size_t lastlen = 0;
		int i;
		int sep_idx = -1;

		p = (*end == '\n') ? end + 1 : end;

		f = umnt_field(line, 4, &fl);
		if (f == NULL || !umnt_field_eq(f, fl, mnt))
			continue;
		for (i = 5;; i++) {
			const char *t = umnt_field(line, i, &fl);

			if (t == NULL)
				break;
			if (umnt_field_eq(t, fl, "-")) {
				sep_idx = i;
				break;
			}
		}
		if (sep_idx < 0)
			continue;
		fst = umnt_field(line, sep_idx + 1, &fl);
		if (fst == NULL || !umnt_field_eq(fst, fl, "erofs"))
			continue;
		f = umnt_field(line, 5, mflags_len);
		if (f == NULL)
			continue;
		for (i = sep_idx + 2;; i++) {
			const char *t = umnt_field(line, i, &fl);

			if (t == NULL)
				break;
			last = t;
			lastlen = fl;
		}
		if (last == NULL)
			continue;
		*mflags = f;
		*fsflags = last;
		*fsflags_len = lastlen;
		return 0;
	}
	return -1;
}

/*
 * Matrix sec. 2.6 row 1 (umount basic face, parity): umount succeeds on
 * the self-mounted instance and takes effect; umounting the now-plain
 * directory is the non-mount-point EINVAL face (fact T8: aster
 * non-mount-root unmount is EINVAL, same as Linux).
 */
FN_TEST(umount_show_basic_face)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	/*
	 * Activation-boundary guard (T-023/S08): the mount-effect
	 * witness below resolves SELF_MNT "/regular" through the erofs
	 * root -- the namei/lookup domain (T-024); the T-023
	 * transitional inode set answers lookup with EOPNOTSUPP. SKIP
	 * until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	ero_ensure_self_mnt();

	TEST_SUCC(mount_base_default());
	/* 挂载生效: 预置条目经挂载点可达(要素①: 条目名 S01 §2/§3.1 逐字)。 */
	TEST_SUCC(access(EROFS_SELF_MNT "/regular", F_OK));
	TEST_SUCC(umount(EROFS_SELF_MNT));
	/* 卸载生效: 同一条目不再可达。 */
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);
	/* 非挂载点 EINVAL: 目录在场、其上已无挂载(对等)。 */
	TEST_ERRNO(umount(EROFS_SELF_MNT), EINVAL);
}
END_TEST()

/*
 * Matrix sec. 2.6 row 2 (W-M11, registered difference): aster's umount
 * has no busy check -- a self-mounted instance with a preset file still
 * open unmounts fine, and the open fd stays readable (the instance lives
 * on through its references until they close).
 */
FN_TEST(umount_show_open_fd_no_busy_check)
{
	int fd;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	/*
	 * Activation-boundary guard (T-023/S08): the open fd and the
	 * follow-up content check walk regular/inline_64b.bin through
	 * the mounted tree -- the namei/lookup and data domains
	 * (T-024). SKIP until /erofs content is reachable.
	 */
	EROFS_SKIP_IF_NO_INIT_MNT();
	/*
	 * Activation-boundary guard (T-024/S04): the still-open fd's
	 * 64-byte content check below reads through the unmounted
	 * instance — the data-read face (T-025). SKIP until the data
	 * face is served.
	 */
	EROFS_SKIP_IF_NO_DATA_FACE();
	ero_ensure_self_mnt();

	TEST_SUCC(mount_base_default());
	fd = TEST_SUCC(
		open(EROFS_SELF_MNT "/regular/inline_64b.bin", O_RDONLY));
	/* 要素③: 写族 EROFS 负对照,面内随行(全景归 write_ero_fs.c)。
	 *
	 * Expected-value revision (T-024/S04): REGISTERED DIFFERENCE
	 * (docs/T-013/analysis.md sec. 9.1 row 3 / S07 sec. 4.2 F-3,
	 * assertion form OPN-09): aster's open chain carries no
	 * SB_RDONLY gate, so open(O_WRONLY) SUCCEEDS and the first
	 * refusal lands on write(2). Revised from the authority, never
	 * from observed behavior. */
	{
		int wfd = TEST_SUCC(open(
			EROFS_SELF_MNT "/regular/inline_64b.bin", O_WRONLY));

		TEST_ERRNO(write(wfd, "x", 1), EROFS);
		TEST_SUCC(close(wfd));
	}
	/*
	 * 登记差异(W-M11): Linux 基线对被打开文件占用的挂载点 umount
	 * 返回 EBUSY;aster 无 busy 检查,直接卸载成功(实例经 Arc 存活
	 * 到引用闭合)。
	 */
	TEST_SUCC(umount(EROFS_SELF_MNT));
	/* fd 仍可读: 64 字节内容公式逐字节对照(矩阵行文「fd 继续读写」
	 * 的可构造半边;fd 为只读打开,写半边即写族 EROFS 负对照)。 */
	TEST_RES(ero_check_content_fd(fd, 64), _ret == 0);
	TEST_SUCC(close(fd));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);
}
END_TEST()

/*
 * Matrix sec. 2.6 row 3 (G-M20, negative control): the four supported
 * umount2 flag bits do not change the umount result -- every flag form
 * behaves as a plain umount (rc 0 and the mount actually gone). The
 * umount.rs accepted-flag set is exactly {MNT_FORCE, MNT_DETACH,
 * MNT_EXPIRE, UMOUNT_NOFOLLOW} (T-002 sec. 7.5); the inline notes mark
 * where the Linux baseline differs.
 */
FN_TEST(umount_show_flags_negative_control)
{
	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	/* MNT_FORCE: parity -- erofs has no umount_begin op and the Linux
	 * call site guards on it (fs/namespace.c do_umount), so the flag is
	 * ignored; same result here. */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, MNT_FORCE));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);

	/* MNT_DETACH: parity -- a non-busy mount detaches (and unmounts)
	 * just the same. */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, MNT_DETACH));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);

	/*
	 * 登记差异(G-M20): Linux 基线 MNT_EXPIRE 首调只打过期标记、
	 * 不卸载(fs/namespace.c do_umount EXPIRE 分支);aster 四 flags
	 * 全接受、行为无差,即常规卸载。
	 */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, MNT_EXPIRE));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);

	/* UMOUNT_NOFOLLOW: parity -- the target is a plain directory, so
	 * the no-follow resolution difference is unobservable. */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, UMOUNT_NOFOLLOW));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);

	/* FORCE|DETACH 组合: Linux 亦允许该组合,结果相同(对等)。 */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, MNT_FORCE | MNT_DETACH));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);

	/*
	 * 登记差异(G-M20): Linux 基线 MNT_EXPIRE 与 MNT_FORCE/MNT_DETACH
	 * 组合返回 EINVAL(fs/namespace.c:1868-1871);aster 接受且行为
	 * 无差。
	 */
	TEST_SUCC(mount_base_default());
	TEST_SUCC(umount2(EROFS_SELF_MNT, MNT_EXPIRE | MNT_DETACH));
	TEST_ERRNO(access(EROFS_SELF_MNT "/regular", F_OK), ENOENT);
}
END_TEST()

/*
 * Matrix sec. 2.6 row 5 (W-M04 + W-M08, registered differences): display
 * of a rw-requested erofs mount. On Linux /proc/mounts renders ro/rw via
 * __mnt_is_readonly = MNT_READONLY | sb_rdonly -- an erofs mount is
 * sb-read-only, so the row reads "ro" -- and appends the show_options
 * tail ",user_xattr,acl" (WO1/WO2). aster's display layer carries
 * per-mount flags only (facts M22/M23): the row reads "rw" and carries
 * no show_options tail. /proc/self/mountinfo splits the two domains on
 * both sides (mount-flag field per-mount only, fs domain behind " - "
 * from the fs-stored flags), so its two domains are parity faces.
 */
FN_TEST(umount_show_rw_request_display)
{
	char buf[8192];
	const char *opts = NULL;
	const char *mflags = NULL;
	const char *fsflags = NULL;
	size_t opts_len = 0;
	size_t mflags_len = 0;
	size_t fsflags_len = 0;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_base_default());
	TEST_RES(umnt_read_proc("/proc/mounts", buf, sizeof(buf)), _ret > 0);
	TEST_RES(umnt_mounts_opts(buf, EROFS_SELF_MNT, &opts, &opts_len),
		 _ret == 0);
	/*
	 * 登记差异(W-M04): Linux 基线 /proc/mounts 的 ro/rw 取
	 * MNT_READONLY ∨ sb_rdonly,erofs 恒 "ro";aster 显示层仅
	 * per-mount 旗标,rw 请求下显示 "rw"。
	 */
	TEST_RES(umnt_has_token(opts, opts_len, "rw"), _ret == 1);
	TEST_RES(umnt_has_token(opts, opts_len, "ro"), _ret == 0);
	/*
	 * 登记差异(W-M08): Linux 基线默认挂载回显选项尾
	 * ",user_xattr,acl"(WO1/WO2);aster 无 show_options 挂钩,选项域
	 * 只有 per-mount 旗标。
	 */
	TEST_RES(umnt_has_token(opts, opts_len, "user_xattr"), _ret == 0);
	TEST_RES(umnt_has_token(opts, opts_len, "acl"), _ret == 0);
	/*
	 * mountinfo 两域拆分与 Linux 逐域一致(事实 M22/M23、T-002 §6.3
	 * O1): 挂载旗标域仅 per-mount(rw 请求 → "rw");" - " 后 fs 域取
	 * fs 存储位(erofs 存 FsFlags::RDONLY,SF11/RM13 权威链 → "ro")。
	 */
	TEST_RES(umnt_read_proc("/proc/self/mountinfo", buf, sizeof(buf)),
		 _ret > 0);
	TEST_RES(umnt_mountinfo_fields(buf, EROFS_SELF_MNT, &mflags,
				       &mflags_len, &fsflags, &fsflags_len),
		 _ret == 0);
	TEST_RES(umnt_has_token(mflags, mflags_len, "rw"), _ret == 1);
	TEST_RES(umnt_has_token(fsflags, fsflags_len, "ro"), _ret == 1);
	TEST_RES(umnt_has_token(fsflags, fsflags_len, "rw"), _ret == 0);

	TEST_SUCC(umount(EROFS_SELF_MNT));
	/* 卸载后展示行随之消失(行随挂载集合生灭,M22 枚举语义)。 */
	TEST_RES(umnt_read_proc("/proc/mounts", buf, sizeof(buf)), _ret > 0);
	TEST_RES(umnt_mounts_opts(buf, EROFS_SELF_MNT, &opts, &opts_len),
		 _ret == -1);
}
END_TEST()

/*
 * Matrix sec. 2.5 row 2 display half (RM13 "mountinfo fs 域 ro",
 * deferred from statfs_remount.c by docs/T-020/S06/index.md sec. 7-5):
 * a remount,rw request returns 0 and the fs stays read-only; the three
 * display domains then read exactly as in the fresh-mount form above.
 *
 * The instance is CREATED with a rw request so the mount-flag-domain
 * "rw" assertion holds regardless of whether aster's remount updates
 * PerMountFlags::RDONLY -- that per-mount clearing question is frozen
 * by no authority row and is left unasserted (the ro-created +
 * remount,rw form would hinge on it).
 */
FN_TEST(umount_show_remount_rw_display)
{
	char buf[8192];
	const char *opts = NULL;
	const char *mflags = NULL;
	const char *fsflags = NULL;
	size_t opts_len = 0;
	size_t mflags_len = 0;
	size_t fsflags_len = 0;

	EROFS_SKIP_IF_NO_DEV(EROFS_DEV_BASE);
	ero_ensure_self_mnt();

	TEST_SUCC(mount_base_default());
	/* remount,rw = MS_REMOUNT without MS_RDONLY(RM13)。 */
	TEST_SUCC(remount_base_rw());
	TEST_RES(umnt_read_proc("/proc/mounts", buf, sizeof(buf)), _ret > 0);
	TEST_RES(umnt_mounts_opts(buf, EROFS_SELF_MNT, &opts, &opts_len),
		 _ret == 0);
	/* 登记差异(W-M04): Linux 基线 remount,rw 后 /proc/mounts 仍
	 * "ro"(sb_rdonly);aster 显示层仅 per-mount 旗标 → "rw"。 */
	TEST_RES(umnt_has_token(opts, opts_len, "rw"), _ret == 1);
	TEST_RES(umnt_has_token(opts, opts_len, "ro"), _ret == 0);
	/* 登记差异(W-M08): 选项尾 ",user_xattr,acl" 同缺失。 */
	TEST_RES(umnt_has_token(opts, opts_len, "user_xattr"), _ret == 0);
	TEST_RES(umnt_has_token(opts, opts_len, "acl"), _ret == 0);
	/* mountinfo 两域(O1): 挂载旗标域 "rw"、fs 域 "ro"(fs 恒存
	 * FsFlags::RDONLY,RM13)。 */
	TEST_RES(umnt_read_proc("/proc/self/mountinfo", buf, sizeof(buf)),
		 _ret > 0);
	TEST_RES(umnt_mountinfo_fields(buf, EROFS_SELF_MNT, &mflags,
				       &mflags_len, &fsflags, &fsflags_len),
		 _ret == 0);
	TEST_RES(umnt_has_token(mflags, mflags_len, "rw"), _ret == 1);
	TEST_RES(umnt_has_token(fsflags, fsflags_len, "ro"), _ret == 1);
	TEST_RES(umnt_has_token(fsflags, fsflags_len, "rw"), _ret == 0);

	TEST_SUCC(umount(EROFS_SELF_MNT));
}
END_TEST()
