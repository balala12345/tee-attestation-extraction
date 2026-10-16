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

INPUT_LK="/data/local/tmp/xaga_lk_b_fenrir_full.img"
INPUT_TEE="/data/local/tmp/xaga_tee_b_keybox_full.img"
LK_A="/dev/block/by-name/lk_a"
LK_B="/dev/block/by-name/lk_b"
TEE_A="/dev/block/by-name/tee_a"
TEE_B="/dev/block/by-name/tee_b"
OUT="/data/local/tmp/xaga_stage1_deploy_result"
WROTE_PARTITION=0

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

rollback_written_partitions() {
  echo "ROLLBACK_START"
  dd if="$OUT/lk_b_写前完整备份.img" of="$LK_B" bs=1048576 || true
  dd if="$OUT/tee_b_写前完整备份.img" of="$TEE_B" bs=1048576 || true
  sync
  echo "rollback_lk_b=$(hash_file "$LK_B")"
  echo "rollback_tee_b=$(hash_file "$TEE_B")"
  echo "ROLLBACK_END"
}

fatal() {
  echo "FATAL: $*" >&2
  if [ "$WROTE_PARTITION" = 1 ]; then
    rollback_written_partitions >&2
  fi
  chmod -R a+rX "$OUT" 2>/dev/null || true
  exit 90
}

rm -rf "$OUT"
mkdir -p "$OUT" || exit 80
chmod 0755 "$OUT"
exec >"$OUT/部署日志.txt" 2>"$OUT/部署错误.txt"

echo "XAGA_STAGE1_DEPLOY_START"
date
id
id -Z 2>/dev/null || true
getenforce 2>/dev/null || true

[ "$(id -u)" = 0 ] || fatal "not uid 0"
[ "$(getprop ro.serialno)" = "$EXPECTED_SERIAL" ] || fatal "serial mismatch"
[ "$(getprop ro.product.vendor.device)" = "$EXPECTED_PRODUCT" ] || fatal "product mismatch"
[ "$(uname -r)" = "$EXPECTED_KERNEL" ] || fatal "kernel mismatch"
[ "$(getprop ro.boot.slot_suffix)" = "$EXPECTED_SLOT" ] || fatal "active slot is not _b"

for node in "$LK_A" "$LK_B" "$TEE_A" "$TEE_B"; do
  [ -b "$node" ] || fatal "missing block device $node"
done
[ "$(blockdev --getsize64 "$LK_B")" = "$LK_SIZE" ] || fatal "lk_b size mismatch"
[ "$(blockdev --getsize64 "$TEE_B")" = "$TEE_SIZE" ] || fatal "tee_b size mismatch"
[ "$(stat -c %s "$INPUT_LK")" = "$LK_SIZE" ] || fatal "input LK size mismatch"
[ "$(stat -c %s "$INPUT_TEE")" = "$TEE_SIZE" ] || fatal "input TEE size mismatch"
[ "$(hash_file "$INPUT_LK")" = "$PATCHED_LK_HASH" ] || fatal "input LK hash mismatch"
[ "$(hash_file "$INPUT_TEE")" = "$PATCHED_TEE_HASH" ] || fatal "input TEE hash mismatch"

before_lk_a=$(hash_file "$LK_A")
before_lk_b=$(hash_file "$LK_B")
before_tee_a=$(hash_file "$TEE_A")
before_tee_b=$(hash_file "$TEE_B")
echo "before_lk_a=$before_lk_a"
echo "before_lk_b=$before_lk_b"
echo "before_tee_a=$before_tee_a"
echo "before_tee_b=$before_tee_b"
[ "$before_lk_a" = "$STOCK_LK_HASH" ] || fatal "lk_a is not exact stock"
[ "$before_lk_b" = "$STOCK_LK_HASH" ] || fatal "lk_b is not exact stock"
[ "$before_tee_a" = "$STOCK_TEE_HASH" ] || fatal "tee_a is not exact stock"
[ "$before_tee_b" = "$STOCK_TEE_HASH" ] || fatal "tee_b is not exact stock"

dd if="$LK_B" of="$OUT/lk_b_写前完整备份.img" bs=1048576 || fatal "backup lk_b failed"
dd if="$TEE_B" of="$OUT/tee_b_写前完整备份.img" bs=1048576 || fatal "backup tee_b failed"
sync
[ "$(hash_file "$OUT/lk_b_写前完整备份.img")" = "$STOCK_LK_HASH" ] || fatal "LK backup hash mismatch"
[ "$(hash_file "$OUT/tee_b_写前完整备份.img")" = "$STOCK_TEE_HASH" ] || fatal "TEE backup hash mismatch"

echo "WRITE_LK_B_START"
WROTE_PARTITION=1
dd if="$INPUT_LK" of="$LK_B" bs=1048576 || fatal "write lk_b failed"
sync
after_lk_b=$(hash_file "$LK_B")
echo "after_lk_b=$after_lk_b"
[ "$after_lk_b" = "$PATCHED_LK_HASH" ] || fatal "lk_b readback hash mismatch"

echo "WRITE_TEE_B_START"
dd if="$INPUT_TEE" of="$TEE_B" bs=1048576 || fatal "write tee_b failed"
sync
after_tee_b=$(hash_file "$TEE_B")
echo "after_tee_b=$after_tee_b"
[ "$after_tee_b" = "$PATCHED_TEE_HASH" ] || fatal "tee_b readback hash mismatch"

[ "$(hash_file "$LK_A")" = "$STOCK_LK_HASH" ] || fatal "untouched lk_a changed"
[ "$(hash_file "$TEE_A")" = "$STOCK_TEE_HASH" ] || fatal "untouched tee_a changed"

WROTE_PARTITION=0
echo "slot_a_remains_stock=yes"
echo "slot_b_lk_patched=yes"
echo "slot_b_tee_patched=yes"
echo "XAGA_STAGE1_DEPLOY_VERIFIED"
chmod -R a+rX "$OUT"
sync

while true; do
  sleep 3600
done
