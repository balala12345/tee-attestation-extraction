#!/bin/sh
set -eu

SERIAL="${1:-${ADB_SERIAL:-}}"
if [ -z "$SERIAL" ]; then
  printf '%s\n' '用法: 00_设备预检_Nothing2A.sh <adb序列号>' >&2
  exit 2
fi

ADB="adb -s $SERIAL"
command -v adb >/dev/null || { echo 'FAIL: 未找到 adb' >&2; exit 2; }

prop() { $ADB shell getprop "$1" | tr -d '\n'; }
device="$(prop ro.product.vendor.device)"
product="$(prop ro.product.name)"
model="$(prop ro.product.model)"
fingerprint="$(prop ro.build.fingerprint)"
root_id="$($ADB shell su -c id 2>/dev/null || true)"
tee_state="$(prop init.svc.tee-1-1)"

printf 'serial=<TARGET_SERIAL>' \
  "$SERIAL" "$device" "$product" "$model" "$fingerprint" "$tee_state" "$root_id"

[ "$device" = "Pacman" ] || { echo 'STOP: 不是 Nothing 2a/Pacman'; exit 3; }
[ "$model" = "A142" ] || { echo 'STOP: 型号不是 A142'; exit 3; }
printf '%s' "$root_id" | grep -q 'uid=0' || { echo 'STOP: 当前没有授权 root'; exit 3; }
[ "$tee_state" = "running" ] || { echo 'STOP: tee-1-1 未运行；不要继续'; exit 3; }

echo 'PASS: Nothing 2a 设备门禁通过。后续仅使用本包内与 Pacman U2.5 匹配的输入。'
