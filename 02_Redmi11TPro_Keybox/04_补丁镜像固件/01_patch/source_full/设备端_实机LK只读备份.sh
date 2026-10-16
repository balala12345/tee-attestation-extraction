#!/system/bin/sh

EXPECTED_PRODUCT="xaga"
EXPECTED_KERNEL="5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928"
OUT="/data/local/tmp/xaga_lk_readonly_20260826"

if [ "$(id -u)" != "0" ]; then
  echo "FATAL: collector is not uid 0" >&2
  exit 20
fi
if [ "$(getprop ro.product.vendor.device)" != "$EXPECTED_PRODUCT" ]; then
  echo "FATAL: unexpected product" >&2
  exit 21
fi
if [ "$(uname -r)" != "$EXPECTED_KERNEL" ]; then
  echo "FATAL: unexpected kernel" >&2
  exit 22
fi

mkdir -p "$OUT"
chmod 0755 "$OUT"
exec >"$OUT/采集日志.txt" 2>"$OUT/采集错误.txt"

echo "XAGA_LK_READONLY_BACKUP_START"
date
id
id -Z 2>/dev/null || true
getenforce 2>/dev/null || true
echo "slot_suffix=$(getprop ro.boot.slot_suffix)"

for part in lk_a lk_b; do
  source="/dev/block/by-name/$part"
  if [ ! -e "$source" ]; then
    echo "FATAL: missing $source" >&2
    exit 23
  fi
  size=$(blockdev --getsize64 "$source") || exit 24
  echo "$part size=$size source=$source"
  dd if="$source" of="$OUT/$part.img" bs=1048576 || exit 25
  chmod 0644 "$OUT/$part.img"
done

(cd "$OUT" && sha256sum lk_a.img lk_b.img > SHA256SUMS.txt)
chmod 0644 "$OUT"/*.txt
sync
echo "XAGA_LK_READONLY_BACKUP_COMPLETE"

while true; do
  sleep 3600
done
