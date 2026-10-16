#!/system/bin/sh

EXPECTED_SERIAL="<DEVICE_SERIAL>"
EXPECTED_PRODUCT="xaga"
EXPECTED_KERNEL="5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928"
EXPECTED_SLOT="_b"
STOCK_LK_HASH="02b3c717e0406e288b05c6ffb75749ec9d00bd490365c189461953a1ae7e910d"
STOCK_TEE_HASH="07fa53c253d1d9c77c8f2808ac880bf60f919b75b7b7b9bbdb0a8733be5aa5e7"
PATCHED_LK_HASH="f65358f6345782b7f95c2d4e9b2c4d9445fd459501ec6e23e776c26e41bb9fad"
PATCHED_TEE_HASH="9ef85ac32d213ca34d01e30157acaaf4edb42d48f8774bbce459b884d7ec9960"
LK_SIZE="8388608"
TEE_SIZE="5242880"

INPUT_LK="/data/local/tmp/xaga_lk_b_stock_full.img"
INPUT_TEE="/data/local/tmp/xaga_tee_b_stock_full.img"
LK_A="/dev/block/by-name/lk_a"
LK_B="/dev/block/by-name/lk_b"
TEE_A="/dev/block/by-name/tee_a"
TEE_B="/dev/block/by-name/tee_b"
OUT="/data/local/tmp/xaga_stage1_rollback_result"

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

fatal() {
  echo "FATAL: $*" >&2
  chmod -R a+rX "$OUT" 2>/dev/null || true
  exit 90
}

rm -rf "$OUT"
mkdir -p "$OUT" || exit 80
chmod 0755 "$OUT"
exec >"$OUT/回滚日志.txt" 2>"$OUT/回滚错误.txt"

echo "XAGA_STAGE1_ROLLBACK_START"
date
id
id -Z 2>/dev/null || true
getenforce 2>/dev/null || true

[ "$(id -u)" = 0 ] || fatal "not uid 0"
[ "$(getprop ro.serialno)" = "$EXPECTED_SERIAL" ] || fatal "serial mismatch"
[ "$(getprop ro.product.vendor.device)" = "$EXPECTED_PRODUCT" ] || fatal "product mismatch"
[ "$(uname -r)" = "$EXPECTED_KERNEL" ] || fatal "kernel mismatch"
[ "$(getprop ro.boot.slot_suffix)" = "$EXPECTED_SLOT" ] || fatal "active slot is not _b"
[ "$(stat -c %s "$INPUT_LK")" = "$LK_SIZE" ] || fatal "stock LK size mismatch"
[ "$(stat -c %s "$INPUT_TEE")" = "$TEE_SIZE" ] || fatal "stock TEE size mismatch"
[ "$(hash_file "$INPUT_LK")" = "$STOCK_LK_HASH" ] || fatal "stock LK hash mismatch"
[ "$(hash_file "$INPUT_TEE")" = "$STOCK_TEE_HASH" ] || fatal "stock TEE hash mismatch"
[ "$(hash_file "$LK_A")" = "$STOCK_LK_HASH" ] || fatal "lk_a is not stock"
[ "$(hash_file "$TEE_A")" = "$STOCK_TEE_HASH" ] || fatal "tee_a is not stock"

current_lk=$(hash_file "$LK_B")
current_tee=$(hash_file "$TEE_B")
echo "current_lk_b=$current_lk"
echo "current_tee_b=$current_tee"
case "$current_lk" in
  "$PATCHED_LK_HASH"|"$STOCK_LK_HASH") ;;
  *) fatal "unexpected lk_b hash" ;;
esac
case "$current_tee" in
  "$PATCHED_TEE_HASH"|"$STOCK_TEE_HASH") ;;
  *) fatal "unexpected tee_b hash" ;;
esac

# Stock TEE under patched LK is bootable, so restore TEE before restoring LK.
dd if="$INPUT_TEE" of="$TEE_B" bs=1048576 || fatal "restore tee_b failed"
sync
[ "$(hash_file "$TEE_B")" = "$STOCK_TEE_HASH" ] || fatal "tee_b rollback hash mismatch"

dd if="$INPUT_LK" of="$LK_B" bs=1048576 || fatal "restore lk_b failed"
sync
[ "$(hash_file "$LK_B")" = "$STOCK_LK_HASH" ] || fatal "lk_b rollback hash mismatch"
[ "$(hash_file "$LK_A")" = "$STOCK_LK_HASH" ] || fatal "lk_a changed"
[ "$(hash_file "$TEE_A")" = "$STOCK_TEE_HASH" ] || fatal "tee_a changed"

echo "XAGA_STAGE1_ROLLBACK_VERIFIED"
chmod -R a+rX "$OUT"
sync
while true; do
  sleep 3600
done
