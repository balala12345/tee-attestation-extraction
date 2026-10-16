#!/bin/sh
set -eu
set -o pipefail 2>/dev/null || true

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SERIAL="${1:-${ADB_SERIAL:-}}"
[ -n "$SERIAL" ] || { echo '用法: 01_运行_Keybox_采集.sh <adb序列号>' >&2; exit 2; }
ADB="adb -s $SERIAL"
TA="$ROOT/03_patch与二进制/patched_binaries/0706000000000000000000000000004d.dumpkeybox.tlbin"
CLIENT="$ROOT/02_脚本/keymint_tee_client/kmtee_probe"
RUN="$ROOT/04_结果/现场运行/Nothing2A_Keybox_$(date +%Y%m%d_%H%M%S)"
REMOTE_TAG="nothing2a_keybox_$(date +%Y%m%d_%H%M%S)"

[ -f "$TA" ] || { echo "FAIL: missing $TA" >&2; exit 2; }
[ -x "$CLIENT" ] || { echo "FAIL: missing/executable bit $CLIENT" >&2; exit 2; }
mkdir -p "$RUN/raw" "$RUN/解析验证结果"

$ADB push "$CLIENT" /data/local/tmp/kmtee_probe >/dev/null
$ADB push "$TA" /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin >/dev/null
$ADB shell su -c "chmod 0755 /data/local/tmp/kmtee_probe; if [ -d /data/local/tmp/kmtee_out ]; then mv /data/local/tmp/kmtee_out /data/local/tmp/kmtee_out_${REMOTE_TAG}; fi; LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin" \
  2>&1 | tee "$RUN/device_run.txt"
$ADB exec-out su -c 'cd /data/local/tmp/kmtee_out && tar -cf - .' | tar -C "$RUN/raw" -xf -

python3 "$ROOT/02_脚本/解析_Keybox_包内.py" \
  "$RUN/raw/attest_keybox_buf_after.bin" \
  "$RUN/解析验证结果"
printf 'KEYBOX_RUN=%s\n' "$RUN"
