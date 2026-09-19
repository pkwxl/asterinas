#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# T-018.S03 erofs stage 补全脚本(docs/T-016/S01/index.md §4 逐命令蓝本直译)
# ----------------------------------------------------------------------------
# 职责: 把静态源树 erofs_tree/ 全量复制到 build/erofs_tree_stage/ 副本,在
# 副本上补全 git 不可承载 / 机械批量的形态(两空目录、many_entries、
# special 七型、sparse、symlink 边界、xattr/acl、stat 多样性)。此后一切
# mkfs.erofs 调用一律以 stage 目录为 srcdir(S01 §6),永不直接消费
# erofs_tree/。
#
# 接口(S01 §4.0): erofs_stage.sh [src] [dst]
#   缺省 src = <本脚本所在目录>/erofs_tree
#   缺省 dst = <本脚本所在目录>/build/erofs_tree_stage(= Makefile BUILD_DIR
#   下落点;Makefile 调用形态见 T-016/S03 §3.1: erofs_stage.sh <src> <dst>)
#
# 纪律(S01 §4.0 / T-018 约束 7):
#   - 幂等: 每次执行 rm -rf "$dst" 全量重建;
#   - 永不写 src(源树保持 git 干净;含 src/dst 交叉包含防护);
#   - §4.1 五项前置自检任一失败硬停,不软降级(断言面不随环境缩水);
#   - 任一补全命令失败立即退出非零,无吞错。
#
# 版本门(T-016/S03 §6.1): 自检 #1 绑定 erofs-utils 1.7.1(mkfs 拼写逐字
# 绑定该版本);异版硬停,须按 T-009 探针方法重核参数面后再放行,
# 不得「先放行后补核」。
#
# 退出码: 0 = stage 完成(尾检对账全过);非 0 = 硬停(附 STAGE-FAIL 行)。
# ============================================================================
set -euo pipefail
export LC_ALL=C

EROFS_UTILS_EXPECTED="1.7.1"          # mkfs 拼写逐字绑定的版本(T-018 约束 1)
SPARSE_SIZE=401408                    # 392 KiB = 首 4K 公式 + 洞 384 KiB(393216B)+ 尾 4K
                                      # (S01 §3.1 规格表为尺寸单源;§4.2 字面
                                      #   "truncate -s 393216" 与 §3.1 总尺寸自相矛盾,
                                      #   393216 = 洞尺寸;口径闭合见 docs/T-018/S03)
MANY_COUNT=200                        # S01 §3.2 many_entries 条数
MANY_NAMELEN=40                       # S01 §4.2 步骤 2: 名长恰 40B
NEAR_MAX_LEN=4090                     # S01 §3.3 slink_near_max 目标长
FORMULA='abcdefghijklmnopqrstuvwxyz'  # 内容公式 content[i] = 'a' + (i % 26)

die() { printf 'STAGE-FAIL: %s\n' "$*" >&2; exit 1; }
section() { printf '\n========== %s ==========\n' "$1"; }
note() { printf '  %s\n' "$1"; }

repeat() { # repeat <string> <count>: 纯 bash 定长重复(构造公式/pattern 串)
  local out='' i
  for ((i = 0; i < $2; i++)); do out+="$1"; done
  printf '%s' "$out"
}

# ---------- 参数与路径防护(S01 §4.0: 永不写 src) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$SCRIPT_DIR/erofs_tree}"
DST="${2:-$SCRIPT_DIR/build/erofs_tree_stage}"
[ "$#" -le 2 ] || die "用法: erofs_stage.sh [src] [dst](多余参数: $*)"

[ -d "$SRC" ] || die "src 不存在或非目录: $SRC"
for d in regular dirs symlink xattr_host; do
  [ -d "$SRC/$d" ] || die "src 静态树缺区目录 $d/(S02 五区产物不完整): $SRC"
done
# special/ 不在 src 断言之列: 其目录与全部条目由本脚本步骤 3 创建(S01 §3.5)。
mkdir -p "$(dirname "$DST")"
SRC_REAL="$(cd "$SRC" && pwd -P)"
DST_REAL="$(cd "$(dirname "$DST")" && pwd -P)/$(basename "$DST")"
[ "$DST_REAL" != "/" ] || die "dst 解析为根目录,拒绝执行"
[ "$SRC_REAL" != "$DST_REAL" ] || die "src 与 dst 相同: $SRC_REAL"
case "$DST_REAL" in "$SRC_REAL"/*) die "dst($DST_REAL)位于 src($SRC_REAL)之内";; esac
case "$SRC_REAL" in "$DST_REAL"/*) die "src($SRC_REAL)位于 dst($DST_REAL)之内 — rm -rf dst 将毁源树";; esac
note "src: $SRC_REAL"
note "dst: $DST_REAL"

PROBE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/erofs_stage.XXXXXXXX")"
trap 'rm -rf "$PROBE_DIR"' EXIT

# ================= §4.1 前置自检(顺序执行,任一失败硬停) =================
section "§4.1 自检 #1/5: mkfs.erofs 版本门(无参 usage 尾行解析;--version/-V 不被识别)"
command -v mkfs.erofs >/dev/null 2>&1 || die "自检#1: mkfs.erofs ABSENT(erofs-utils 未安装)"
set +e
USAGE_OUT="$(mkfs.erofs 2>&1)"
USAGE_RC=$?
set -e
[ "$USAGE_RC" -ne 0 ] || die "自检#1: mkfs.erofs 无参调用 rc=0(预期非 0,输出 usage)"
USAGE_TAIL="$(printf '%s\n' "$USAGE_OUT" | sed -e '/^[[:space:]]*$/d' | tail -n 1)"
VERSION_FOUND="$(printf '%s' "$USAGE_TAIL" | grep -oE '[0-9]+([.][0-9]+)+' | tail -n 1 || true)"
case "$VERSION_FOUND" in
  "$EROFS_UTILS_EXPECTED"*)
    note "PASS: usage 尾行版本 '$VERSION_FOUND'(绑定 $EROFS_UTILS_EXPECTED)";;
  *)
    die "自检#1: 版本 '${VERSION_FOUND:-<尾行未解析>}' 异于 $EROFS_UTILS_EXPECTED — 须按实际版本重核 mkfs 参数面(docs/T-016/S02 §2 实例化表;方法 = T-009 探针)后再放行,不得先放行后补核(T-016/S03 §6.1 异版流程)";;
esac

section "§4.1 自检 #2/5: setfattr/getfattr/setfacl 存在性"
for t in setfattr getfattr setfacl; do
  command -v "$t" >/dev/null 2>&1 || die "自检#2: $t ABSENT(宿主缺 attr/acl 包)"
done
note "PASS: setfattr/getfattr/setfacl 全 PRESENT"

section "§4.1 自检 #3/5: trusted./security. 试写探测(需 CAP_SYS_ADMIN)"
: > "$PROBE_DIR/f"
setfattr -n trusted.probe  -v stage "$PROBE_DIR/f" || die "自检#3: setfattr trusted.probe 失败 — 需 CAP_SYS_ADMIN(标准 docker --privileged 容器可过)"
setfattr -n security.probe -v stage "$PROBE_DIR/f" || die "自检#3: setfattr security.probe 失败 — 需 CAP_SYS_ADMIN"
note "PASS: trusted./security. 试写成功"

section "§4.1 自检 #4/5: mknod 试探测(dst 下造后删;需 CAP_MKNOD)"
mkdir -p "$DST"
mknod "$DST/.mknod_probe" c 1 3 || die "自检#4: mknod c 1 3 失败 — 需 CAP_MKNOD"
rm -f "$DST/.mknod_probe"
note "PASS: mknod 试探成功(残留已删;步骤 1 将整建 dst)"

section "§4.1 自检 #5/5: python3 存在性(sock_entry 唯一可靠造法 = AF_UNIX bind)"
command -v python3 >/dev/null 2>&1 || die "自检#5: python3 ABSENT — socket 条目无可靠替代造法(socat 更不可靠;跳过 = 七型缺一)"
note "PASS: python3 PRESENT ($(python3 --version 2>&1))"

# ================= §4.2 补全步骤(自检全过后顺序执行) =================
section "§4.2 步骤 1/8: 全量重建副本 + 两空目录补建"
rm -rf "$DST"
mkdir -p "$DST"
cp -a "$SRC"/. "$DST"/
mkdir -p "$DST/dirs/empty_dir" "$DST/xattr_host/acl_dir"
note "cp -a 完成(保 symlink 与静态 mode);dirs/empty_dir、xattr_host/acl_dir 显式 mkdir -p(git 不追踪空目录,全新 clone 下为常态路径 — S08 修订①)"

section "§4.2 步骤 2/8: many_entries(${MANY_COUNT} × ${MANY_NAMELEN}B 名,机械批量)"
mkdir -p "$DST/dirs/many_entries"
PAD="$(repeat a 31)"
i=0
while [ "$i" -lt "$MANY_COUNT" ]; do
  NAME="$(printf 'bulk_%03d_' "$i")$PAD"      # bulk_ + %03d + _ + 'a'×31 = 40B
  # 名长逐条自检: 规格形态 stat -c %n | wc -c 回显的是完整路径(非 dirent 名),
  # 故构造期用字符串长度,dirent 真值由循环后 find -printf '%f' 聚合复核
  [ "${#NAME}" -eq "$MANY_NAMELEN" ] || die "步骤2: 名长 ${#NAME} != $MANY_NAMELEN($NAME)"
  printf 'a' > "$DST/dirs/many_entries/$NAME" # 1B 公式字节 content[0]='a'
  i=$((i + 1))
done
BAD_NAMES="$(find "$DST/dirs/many_entries" -mindepth 1 -maxdepth 1 -printf '%f\n' \
  | awk -v n="$MANY_NAMELEN" 'length($0) != n { print }')"
[ -z "$BAD_NAMES" ] || die "步骤2: dirent 名长 != ${MANY_NAMELEN}B: $BAD_NAMES"
MANY_N="$(find "$DST/dirs/many_entries" -mindepth 1 | wc -l)"
[ "$MANY_N" -eq "$MANY_COUNT" ] || die "步骤2: many_entries 条目数 $MANY_N != $MANY_COUNT"
note "$MANY_COUNT 条 × 名长 ${MANY_NAMELEN}B 逐条自检通过(目录预期跨 3 块以上,dirent ≈ 200×54B)"

section "§4.2 步骤 3/8: special/(chr/blk/fifo/sock,git 不可承载)"
mkdir "$DST/special"
mknod "$DST/special/chr_dev" c 1 3   || die "步骤3: mknod chr_dev c 1 3 失败"
mknod "$DST/special/blk_dev" b 7 200 || die "步骤3: mknod blk_dev b 7 200 失败"
mkfifo "$DST/special/fifo_entry"     || die "步骤3: mkfifo fifo_entry 失败"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
  "$DST/special/sock_entry"          || die "步骤3: AF_UNIX bind sock_entry 失败"
[ "$(stat -c %F "$DST/special/chr_dev")" = 'character special file' ] || die "步骤3: chr_dev 型别异常"
[ "$(stat -c '%t %T' "$DST/special/chr_dev")" = '1 3' ]               || die "步骤3: chr_dev rdev != (1,3)"
[ "$(stat -c %F "$DST/special/blk_dev")" = 'block special file' ]     || die "步骤3: blk_dev 型别异常"
[ "$(stat -c '%t %T' "$DST/special/blk_dev")" = '7 c8' ]              || die "步骤3: blk_dev rdev != (7,200)"
[ -p "$DST/special/fifo_entry" ] || die "步骤3: fifo_entry 非 FIFO"
[ -S "$DST/special/sock_entry" ] || die "步骤3: sock_entry 非 socket"
note "special 四条落位并复核: chr(1,3) blk(7,200) fifo sock"

section "§4.2 步骤 4/8: sparse_hole.bin(392KiB = 首 4K 公式 + 洞 384KiB + 尾 4K 公式)"
SP="$DST/regular/sparse_hole.bin"
F4K="$(repeat "$FORMULA" 158)"; F4K="${F4K:0:4096}"          # 26×158=4108 → 截 4096: content[0..4095]
PHASE=$(( (SPARSE_SIZE - 4096) % 26 ))
ROT="${FORMULA:$PHASE}${FORMULA:0:$PHASE}"                   # 相位旋转: 尾段首字节 = content[SPARSE_SIZE-4096]
T4K="$(repeat "$ROT" 158)"; T4K="${T4K:0:4096}"
printf '%s' "$F4K" > "$SP"
truncate -s "$SPARSE_SIZE" "$SP" || die "步骤4: truncate -s $SPARSE_SIZE 失败"
printf '%s' "$T4K" | dd of="$SP" bs=4096 seek=$(( (SPARSE_SIZE - 4096) / 4096 )) \
  conv=notrunc status=none || die "步骤4: 尾 4K dd 写入失败"
[ "$(stat -c %s "$SP")" -eq "$SPARSE_SIZE" ] || die "步骤4: 尺寸 != $SPARSE_SIZE"
SP_BLK="$(stat -c %b "$SP")"
SP_LIM=$(( SPARSE_SIZE / 512 ))                              # 784
[ "$SP_BLK" -lt "$SP_LIM" ] || die "步骤4: 物理 sparse 不成立(blocks=$SP_BLK >= $SP_LIM)"
note "size=$SPARSE_SIZE blocks(512B)=$SP_BLK < $SP_LIM — 中段 $((SPARSE_SIZE - 8192))B(384KiB)为洞"

section "§4.2 步骤 5/8: symlink 边界(空目标 + 4090B 近 PATH_MAX 目标)"
ln -s '' "$DST/symlink/slink_empty" || die "步骤5: ln -s ''(空目标)失败"
PATTERN='0123456789abcdef'
BIG="$(repeat "$PATTERN" 256)"                               # 16×256 = 4096B
NEAR="${BIG:0:$NEAR_MAX_LEN}"                                # 同 pattern 截 4090
ln -s "$NEAR" "$DST/symlink/slink_near_max" || die "步骤5: ln -s ${NEAR_MAX_LEN}B 目标失败"
T="$(readlink "$DST/symlink/slink_empty")"
[ "${#T}" -eq 0 ] || die "步骤5: slink_empty 目标非空(长 ${#T})"
T="$(readlink "$DST/symlink/slink_near_max")"
[ "$T" = "$NEAR" ] || die "步骤5: slink_near_max 目标回读不符(长 ${#T} != $NEAR_MAX_LEN)"
note "slink_empty(0B)/slink_near_max(${NEAR_MAX_LEN}B)落位并回读复核"

section "§4.2 步骤 6/8: xattr/acl(S01 §3.4 表逐条;setfattr + setfacl,getfattr 复核)"
X="$DST/xattr_host"
MID_HEX="$(printf '%02x' {0..63})"                                  # 0x00..0x3F 递增 64B
LONG_HEX="$(printf '%02x' {0..255} {0..255} {0..255} {0..255})"     # (i mod 256) 递增 1024B
LN_NAME="user.$(repeat n 200)"                                      # 'user.' + n×200 = 205B 名
sx() { setfattr -n "$2" -v "$3" "$1" || die "步骤6: setfattr $2 -> $1 失败"; }
sx "$X/xattr_user_short.bin"    user.v       0x41                   # 1B 值
sx "$X/xattr_user_mid.bin"      user.v       "0x$MID_HEX"           # 64B 值
sx "$X/xattr_user_long.bin"     user.v       "0x$LONG_HEX"          # 1024B 值
sx "$X/xattr_user_longname.bin" "$LN_NAME"   'NNNN'                 # 200B 名 = 'N'×4
sx "$X/xattr_multi.bin"         user.a       'AAAAAAAA'             # 同宿主 3 条目
sx "$X/xattr_multi.bin"         user.b       'BBBBBBBB'
sx "$X/xattr_multi.bin"         user.c       'CCCCCCCC'
for h in 1 2 3; do                                                  # 三宿主完全相同 entry 集 → 共享形态
  sx "$X/xattr_shared_$h.bin"   user.shared  0x53484152             # 4B "SHAR"(LE 注记见 S01 §3.4)
  sx "$X/xattr_shared_$h.bin"   user.shared2 "$(repeat s 16)"
done
sx "$X/xattr_trusted.bin"       trusted.t    "$(repeat T 16)"       # 需 CAP_SYS_ADMIN(自检 #3 已过)
sx "$X/xattr_security.bin"      security.s   "$(repeat S 16)"       # 需 CAP_SYS_ADMIN
sx "$X/prefix_lpx_1.bin"        user.erofs_test.lpx.alpha "$(repeat P 8)"   # 前缀表引用条目 ×4
sx "$X/prefix_lpx_1.bin"        user.erofs_test.lpx.beta  "$(repeat Q 8)"
sx "$X/prefix_lpx_2.bin"        user.erofs_test.lpx.alpha "$(repeat P 8)"
sx "$X/prefix_lpx_2.bin"        user.erofs_test.lpx.beta  "$(repeat Q 8)"
setfacl -m 'u::rw-,g::r--,o::r--,m::rw-,u:1000:r--' "$X/acl_file.bin" \
  || die "步骤6: setfacl(access)失败 → system.posix_acl_access 未生成"
setfacl -d -m 'u::rwx,g::rx,o::r--,m::rwx' "$X/acl_dir" \
  || die "步骤6: setfacl -d(default)失败 → system.posix_acl_default 未生成"
# 复核: 逐宿主条目计数(getfattr -m- 全命名空间)
xc() { getfattr --absolute-names -d -m- "$1" 2>/dev/null | grep -c '="' || true; }
xv() { # <path> <期望条目数>
  local c; c="$(xc "$1")"
  [ "$c" -eq "$2" ] || die "步骤6复核: ${1#$DST/} xattr 条目数 $c != $2"
  note "$(printf '%-28s %s 条' "${1##*/}" "$c")"
}
xv "$X/xattr_none.bin"        0
xv "$X/xattr_user_short.bin"  1
xv "$X/xattr_user_mid.bin"    1
xv "$X/xattr_user_long.bin"   1
xv "$X/xattr_user_longname.bin" 1
xv "$X/xattr_multi.bin"       3
xv "$X/xattr_shared_1.bin"    2
xv "$X/xattr_shared_2.bin"    2
xv "$X/xattr_shared_3.bin"    2
xv "$X/xattr_trusted.bin"     1
xv "$X/xattr_security.bin"    1
xv "$X/acl_file.bin"          1
xv "$X/acl_dir"               1
xv "$X/prefix_lpx_1.bin"      2
xv "$X/prefix_lpx_2.bin"      2
# 复核: acl 两精确名 + 代表性值逐字节回读
getfattr --absolute-names --only-values -n system.posix_acl_access "$X/acl_file.bin" >/dev/null 2>&1 \
  || die "步骤6复核: acl_file 未生成 system.posix_acl_access"
getfattr --absolute-names --only-values -n system.posix_acl_default "$X/acl_dir" >/dev/null 2>&1 \
  || die "步骤6复核: acl_dir 未生成 system.posix_acl_default"
vr() { # <path> <name> <期望值>: 值逐字节回读比对
  local v
  v="$(getfattr --absolute-names --only-values -n "$2" "$1" 2>/dev/null)" \
    || die "步骤6复核: $2 回读失败(${1##*/})"
  [ "$v" = "$3" ] || die "步骤6复核: $2 回读值不符(${1##*/})"
}
vr "$X/xattr_user_short.bin" user.v 'A'
vr "$X/xattr_user_longname.bin" "$LN_NAME" 'NNNN'
vr "$X/xattr_shared_1.bin"   user.shared  'SHAR'
vr "$X/xattr_shared_2.bin"   user.shared2 "$(repeat s 16)"
vr "$X/xattr_trusted.bin"    trusted.t    "$(repeat T 16)"
vr "$X/xattr_security.bin"   security.s   "$(repeat S 16)"
vr "$X/prefix_lpx_1.bin"     user.erofs_test.lpx.alpha "$(repeat P 8)"
note "14 宿主 / 21 条目复核通过(xattr_none 零条目对照);acl 两精确名 + 代表值逐字节回读一致"

section "§4.2 步骤 7/8: stat 多样性(S01 §3.6 表逐条 chmod/chown)"
chmod 0600 "$DST/regular/inline_64b.bin"       || die "步骤7: chmod 0600 inline_64b 失败"
chmod 0444 "$DST/regular/flat_4096b.bin"       || die "步骤7: chmod 0444 flat_4096b 失败"
chmod 0711 "$DST/dirs/small"                   || die "步骤7: chmod 0711 dirs/small 失败"
chown 1000:1000 "$DST/regular/flat_4097b.bin"  || die "步骤7: chown 1000:1000 flat_4097b 失败"
chown 65534:65534 "$DST/xattr_host/xattr_multi.bin" || die "步骤7: chown 65534:65534 xattr_multi 失败"
[ "$(stat -c %a "$DST/regular/inline_64b.bin")" = '600' ] || die "步骤7复核: inline_64b mode != 0600"
[ "$(stat -c %a "$DST/regular/flat_4096b.bin")" = '444' ] || die "步骤7复核: flat_4096b mode != 0444"
[ "$(stat -c %a "$DST/dirs/small")" = '711' ]              || die "步骤7复核: dirs/small mode != 0711"
[ "$(stat -c '%u %g' "$DST/regular/flat_4097b.bin")" = '1000 1000' ] || die "步骤7复核: flat_4097b owner != 1000:1000"
[ "$(stat -c '%u %g' "$DST/xattr_host/xattr_multi.bin")" = '65534 65534' ] || die "步骤7复核: xattr_multi owner != 65534:65534"
note "mode 600/444/711 + owner 1000:1000、65534:65534 落位并复核"

section "§4.2 步骤 8/8: 尾检摘要与对账(计数硬停,防静默缩面)"
REG_N="$(find "$DST" -type f | wc -l)"
LNK_N="$(find "$DST" -type l | wc -l)"
DIR_N="$(find "$DST" -mindepth 1 -type d | wc -l)"
CHR_N="$(find "$DST" -type c | wc -l)"
BLK_N="$(find "$DST" -type b | wc -l)"
FIFO_N="$(find "$DST" -type p | wc -l)"
SOCK_N="$(find "$DST" -type s | wc -l)"
[ "$REG_N"  -eq 235 ] || die "尾检: REG $REG_N != 235(34 静态 + 200 bulk + 1 sparse)"
[ "$DIR_N"  -eq 19  ] || die "尾检: DIR $DIR_N != 19(15 静态 + empty_dir/many_entries/acl_dir/special)"
[ "$LNK_N"  -eq 5   ] || die "尾检: LNK $LNK_N != 5(3 静态 + slink_empty/slink_near_max)"
[ "$CHR_N"  -eq 1   ] || die "尾检: CHR $CHR_N != 1"
[ "$BLK_N"  -eq 1   ] || die "尾检: BLK $BLK_N != 1"
[ "$FIFO_N" -eq 1   ] || die "尾检: FIFO $FIFO_N != 1"
[ "$SOCK_N" -eq 1   ] || die "尾检: SOCK $SOCK_N != 1"
for n in 253 254 255; do
  M="$(find "$DST/dirs/boundary_names" -maxdepth 1 -name "n${n}_*" -type f)"
  [ -n "$M" ] || die "尾检: boundary_names 缺 n${n}_*"
  NB="$(find "$DST/dirs/boundary_names" -maxdepth 1 -name "n${n}_*" -type f -printf '%f' | wc -c)"
  [ "$NB" -eq "$n" ] || die "尾检: n${n}_* dirent 名长 $NB != $n"
done
[ -z "$(ls -A "$DST/dirs/empty_dir")" ]     || die "尾检: dirs/empty_dir 非空"
[ -z "$(ls -A "$DST/xattr_host/acl_dir")" ] || die "尾检: xattr_host/acl_dir 非空(仅 default ACL,无 dirent)"
TOTAL=$((REG_N + DIR_N + LNK_N + CHR_N + BLK_N + FIFO_N + SOCK_N))
note "REG=$REG_N DIR=$DIR_N LNK=$LNK_N CHR=$CHR_N BLK=$BLK_N FIFO=$FIFO_N SOCK=$SOCK_N(七型齐备,total=$TOTAL)"
note "many_entries=$MANY_N(名长 ${MANY_NAMELEN}B)|boundary 名 253/254/255|sparse ${SPARSE_SIZE}B(blocks=$SP_BLK)|xattr 14 宿主/21 条目"
printf 'STAGE-VERDICT: OK dst=%s reg=%d dir=%d lnk=%d chr=%d blk=%d fifo=%d sock=%d xattr_hosts=14 xattr_entries=21 many=%d sparse=%dB\n' \
  "$DST_REAL" "$REG_N" "$DIR_N" "$LNK_N" "$CHR_N" "$BLK_N" "$FIFO_N" "$SOCK_N" "$MANY_COUNT" "$SPARSE_SIZE"
