#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SEED="${1:-$ROOT/06_离线_google-rkp-sw/ctf_artifacts/ctf_seed.bin}"
[ -f "$SEED" ] || { echo "FAIL: seed not found: $SEED" >&2; exit 2; }

SIZE="$(wc -c < "$SEED" | tr -d ' ')"
SHA="$(shasum -a 256 "$SEED" | awk '{print $1}')"
printf 'seed_file=%s\nseed_length=%s\nseed_sha256=%s\n' "$SEED" "$SIZE" "$SHA"
[ "$SIZE" = 32 ] || { echo 'FAIL: 不是 32 字节 rkp_bcc_km 材料' >&2; exit 3; }

REPORT_DIR="$ROOT/04_结果/离线验收/RKP_CDI_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"
python3 - "$SEED" "$REPORT_DIR" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

seed = Path(sys.argv[1]).read_bytes()
out = Path(sys.argv[2])
out.mkdir(mode=0o700, parents=True, exist_ok=True)
report = {
    "status": "PASS" if len(seed) == 32 else "FAIL",
    "seed_length": len(seed),
    "seed_sha256": hashlib.sha256(seed).hexdigest(),
    "raw_secret_printed": False,
    "meaning": "Nothing 2a rkp_bcc_km 32-byte material; this package does not relabel it as universal UDS/CDI root",
}
(out / "seed_audit.json").write_text(json.dumps(report, indent=2) + "\n")
os.chmod(out / "seed_audit.json", 0o600)
print(json.dumps(report, indent=2))
PY
printf 'OFFLINE_AUDIT=%s\n' "$REPORT_DIR"
