#!/system/bin/sh

EXPECTED_SERIAL="<DEVICE_SERIAL>"
EXPECTED_PRODUCT="xaga"
EXPECTED_KERNEL="5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928"
EXPECTED_SLOT="_b"
STOCK_TA_HASH="0fafcb889813891dca764f36627691a839345105d8dcbb7fbdc82d9178f0e52f"
PATCHED_TA_HASH="97e1c1b34d8da376df44f820fc32cdff6e9fac312a0d603d99116aebd572b2f5"
CLIENT_HASH="15ce4229efe32697cee4268332447b6de8b1b5bfa5992f1dfa3217db4cd01e71"
TEE_LIBRARY_HASH="815ea6ca64fafd92456cb5cf041272237a0eb390cf62def72394fd288f8a3202"

PATCHED_TA="/data/local/tmp/d91f322ad5a441d5955110eda3272fc0_patched.ta"
CLIENT="/data/local/tmp/xaga_keybox_readonly"
TEE_LIBRARY="/data/local/tmp/libTEECommon_xaga.so"
VENDOR_TA="/vendor/thh/ta/d91f322ad5a441d5955110eda3272fc0.ta"
OUT="/data/local/tmp/xaga_keybox_extraction_result"

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
exec >"$OUT/提取流程日志.txt" 2>"$OUT/提取错误日志.txt"

echo "XAGA_KEYBOX_EXTRACTION_START"
date
id
id -Z 2>/dev/null || true
getenforce 2>/dev/null || true

[ "$(id -u)" = 0 ] || fatal "not uid 0"
[ "$(getprop ro.serialno)" = "$EXPECTED_SERIAL" ] || fatal "serial mismatch"
[ "$(getprop ro.product.vendor.device)" = "$EXPECTED_PRODUCT" ] || fatal "product mismatch"
[ "$(uname -r)" = "$EXPECTED_KERNEL" ] || fatal "kernel mismatch"
[ "$(getprop ro.boot.slot_suffix)" = "$EXPECTED_SLOT" ] || fatal "active slot is not _b"
[ -f "$PATCHED_TA" ] || fatal "patched TA missing"
[ -x "$CLIENT" ] || fatal "client missing or not executable"
[ -f "$TEE_LIBRARY" ] || fatal "TEE client library missing"
[ "$(hash_file "$PATCHED_TA")" = "$PATCHED_TA_HASH" ] || fatal "patched TA hash mismatch"
[ "$(hash_file "$CLIENT")" = "$CLIENT_HASH" ] || fatal "client hash mismatch"
[ "$(hash_file "$TEE_LIBRARY")" = "$TEE_LIBRARY_HASH" ] || fatal "TEE library hash mismatch"

vendor_hash_before=$(hash_file "$VENDOR_TA") || fatal "cannot hash stock vendor TA"
echo "vendor_ta_before=$vendor_hash_before"
[ "$vendor_hash_before" = "$STOCK_TA_HASH" ] || fatal "vendor TA is not exact stock"

echo "STOP_KEYMINT_HAL"
stop vendor.keymint-beanpod 2>/dev/null || true
for count in 1 2 3 4 5; do
  [ "$(getprop init.svc.vendor.keymint-beanpod)" = "stopped" ] && break
  sleep 1
done
echo "keymint_service=$(getprop init.svc.vendor.keymint-beanpod)"
ps -AZ | grep -i -E 'keymint|beanpod|teei' >"$OUT/覆盖前相关进程.txt" 2>&1 || true

echo "BIND_MOUNT_PATCHED_TA"
mount --bind "$PATCHED_TA" "$VENDOR_TA" || fatal "bind mount patched TA failed"
vendor_hash_after=$(hash_file "$VENDOR_TA") || fatal "cannot hash mounted TA"
echo "vendor_ta_after=$vendor_hash_after"
[ "$vendor_hash_after" = "$PATCHED_TA_HASH" ] || fatal "mounted TA hash mismatch"
cat /proc/mounts | grep 'd91f322ad5a441d5955110eda3272fc0' >"$OUT/TA覆盖挂载记录.txt" || true

dmesg >"$OUT/调用前_dmesg.txt" 2>&1 || true
logcat -d >"$OUT/调用前_logcat.txt" 2>&1 || true

echo "INVOKE_READ_ONLY_COMMAND_0x64"
XAGA_TEE_LIBRARY="$TEE_LIBRARY" "$CLIENT" "$OUT/客户端输出" \
  >"$OUT/客户端标准输出.txt" 2>&1
client_rc=$?
echo "client_rc=$client_rc"

dmesg >"$OUT/调用后_dmesg.txt" 2>&1 || true
logcat -d >"$OUT/调用后_logcat.txt" 2>&1 || true
ps -AZ | grep -i -E 'keymint|beanpod|teei' >"$OUT/调用后相关进程.txt" 2>&1 || true

if [ "$client_rc" = 0 ] && [ -s "$OUT/客户端输出/keybox_原始载荷.bin" ]; then
  echo "XAGA_KEYBOX_EXTRACTION_VERIFIED"
  sha256sum "$OUT/客户端输出"/* >"$OUT/客户端输出_SHA256SUMS.txt"
else
  echo "XAGA_KEYBOX_EXTRACTION_FAILED rc=$client_rc" >&2
fi

chmod -R a+rX "$OUT"
sync
while true; do
  sleep 3600
done
