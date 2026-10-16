#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SERIAL="${1:-${ADB_SERIAL:-}}"
[ -n "$SERIAL" ] || { echo '用法: 03_提取_RKP_CDI_seed.sh <adb序列号>' >&2; exit 2; }
export ADB_SERIAL="$SERIAL"
export RKP_DIRECT_TA="$ROOT/03_patch与二进制/patched_binaries/patched_ta/0706000000000000000000000000004d.rkp_bcc_kdf_keygenleak.tlbin"
export RKP_DIRECT_KEY_COUNT=1
export RKP_DIRECT_TEST_MODE=0
export RKP_DIRECT_SENSITIVE_OUTPUT=1
export RKP_DIRECT_RUN_ID="Nothing2A_rkp_bcc_km_$(date +%Y%m%d_%H%M%S)"

python3 "$ROOT/02_脚本/rkp_research/run_direct_csr_batch.py"
RUN="$ROOT/04_结果/outputs/$RKP_DIRECT_RUN_ID"
python3 "$ROOT/02_脚本/提取_rkp_bcc_km_seed.py" "$RUN"
printf 'RKP_CDI_RUN=%s\n' "$RUN"
