#!/usr/bin/env python3
"""Extract and validate the 32-byte rkp_bcc_km output from a saved run.

The patched TA writes the KDF output at private_out+0x400, the KDF return
code at +0x420, and a non-secret pointer marker at +0x424. This parser never
prints the seed; it writes it with mode 0600 and records only its SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--expected-sha256", default="e0e2617b3156d12a0b7108b71340484c3e4ae965ae686d7360c8032f2d82a7c3")
    args = parser.parse_args()

    raw = args.run_dir / "raw"
    src = raw / "rkp_gen_prod_00_priv_full.bin"
    if not src.is_file():
        raise SystemExit(f"missing {src}")
    blob = src.read_bytes()
    if len(blob) < 0x444:
        raise SystemExit(f"short private buffer: {len(blob)} bytes")

    seed = blob[0x400:0x420]
    status = int.from_bytes(blob[0x420:0x424], "little")
    marker = int.from_bytes(blob[0x424:0x428], "little")
    digest = hashlib.sha256(seed).hexdigest()
    out_dir = args.run_dir / "rkp_bcc_km_seed"
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    seed_path = out_dir / "rkp_bcc_km_seed.bin"
    seed_path.write_bytes(seed)
    os.chmod(seed_path, 0o600)
    report = {
        "status": "PASS" if status == 0 and len(seed) == 32 and digest == args.expected_sha256 else "FAIL",
        "source": str(src),
        "seed_length": len(seed),
        "kdf_status": status,
        "pointer_marker": marker,
        "seed_sha256": digest,
        "expected_sha256": args.expected_sha256,
        "secret_value_printed": False,
    }
    (out_dir / "seed_report.json").write_text(json.dumps(report, indent=2) + "\n")
    os.chmod(out_dir / "seed_report.json", 0o600)
    print(json.dumps(report, indent=2))
    print(f"SEED_FILE={seed_path}")
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
