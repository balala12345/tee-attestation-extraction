#!/usr/bin/env python3
"""Generate a stock-HAL CSR for direct sideleak MacedPublicKeys via Binder."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "rkp_research/rkp_binder_csr_client"
DEFAULT_GEEK = ROOT / "rkp_research/geek_fetch_20260815_165246/geek_curve_2.cbor"
DEFAULT_CHALLENGE = ROOT / "rkp_research/geek_fetch_20260815_165246/challenge.bin"
DEV_BASE = "/data/local/tmp/rkp_binder_csr"
SERVICE = "android.hardware.security.keymint.IRemotelyProvisionedComponent/default"
HAL_PATH = "/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic"
TA_PATH = "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
STOCK_TA_SHA256 = "ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2"
STOCK_HAL_SHA256 = "bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a"


def run(cmd: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def adb_shell(script: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return run(["adb", "shell", "su", "-c", "sh"], input_bytes=script.encode(), check=check)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def key_paths(raw: Path, key_count: int, prefix: str) -> list[Path]:
    paths = [raw / f"{prefix}_{i:02d}_pub_len.bin" for i in range(key_count)]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError("missing key files: " + ", ".join(missing))
    return paths


def main() -> None:
    default_key_run = ROOT / "rkp_research/LATEST_DIRECT_CSR_BATCH.txt"
    key_run = Path(os.environ.get("RKP_BINDER_CSR_KEY_RUN", default_key_run.read_text().strip()))
    geek = Path(os.environ.get("RKP_BINDER_CSR_GEEK", str(DEFAULT_GEEK)))
    challenge = Path(os.environ.get("RKP_BINDER_CSR_CHALLENGE", str(DEFAULT_CHALLENGE)))
    key_count = int(os.environ.get("RKP_BINDER_CSR_KEY_COUNT", "12"))
    prefix = os.environ.get("RKP_BINDER_CSR_KEY_PREFIX", "rkp_gen_prod")
    run_id = os.environ.get("RKP_BINDER_CSR_RUN_ID", "binder_csr_from_direct_" + time.strftime("%Y%m%d_%H%M%S"))
    run_dir = ROOT / "rkp_research" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    raw = key_run / "raw"
    if not raw.is_dir():
        raw = key_run
    keys = key_paths(raw, key_count, prefix)

    dev_in = f"{DEV_BASE}_in"
    dev_out = f"{DEV_BASE}_out"
    dev_tar = f"/data/local/tmp/{run_id}.tar"
    adb_shell(f"rm -rf {dev_in} {dev_out} {dev_tar}; mkdir -p {dev_in} {dev_out}; chmod 777 {dev_in} {dev_out}\n")
    pushes: list[str] = []
    for src, dst in [(CLIENT, f"{dev_in}/rkp_binder_csr_client"), (geek, f"{dev_in}/geek_curve_2.cbor"), (challenge, f"{dev_in}/challenge.bin")]:
        cp = run(["adb", "push", str(src), dst])
        pushes.append(cp.stdout.decode(errors="replace") + cp.stderr.decode(errors="replace"))
    for i, src in enumerate(keys):
        cp = run(["adb", "push", str(src), f"{dev_in}/key_{i:02d}.bin"])
        pushes.append(cp.stdout.decode(errors="replace") + cp.stderr.decode(errors="replace"))
    (run_dir / "adb_push.txt").write_text("\n".join(pushes))

    key_args = " ".join(f"{dev_in}/key_{i:02d}.bin" for i in range(key_count))
    cmd = f"""
set -x
sha256sum '{HAL_PATH}' '{TA_PATH}' > {dev_out}/stock_hashes.txt
service check '{SERVICE}' > {dev_out}/service_check.txt 2>&1
chmod 755 {dev_in}/rkp_binder_csr_client
logcat -c
{dev_in}/rkp_binder_csr_client {dev_out} {dev_in}/geek_curve_2.cbor {dev_in}/challenge.bin {key_args} > {dev_out}/client.stdout 2> {dev_out}/client.stderr
echo $? > {dev_out}/client.status
logcat -d -v time > {dev_out}/logcat.txt
tar -cf {dev_tar} -C /data/local/tmp {Path(dev_out).name}
"""
    cp = adb_shell(cmd, check=False)
    (run_dir / "device_shell.txt").write_bytes(cp.stdout + cp.stderr)
    pull = run(["adb", "pull", dev_tar, str(run_dir / f"{run_id}.tar")], check=False)
    (run_dir / "adb_pull_tar.txt").write_bytes(pull.stdout + pull.stderr)
    with tarfile.open(run_dir / f"{run_id}.tar") as tf:
        tf.extractall(run_dir)
    out = run_dir / Path(dev_out).name
    pulled = run_dir / "raw"
    if pulled.exists():
        shutil.rmtree(pulled)
    out.rename(pulled)

    status = (pulled / "client.status").read_text(errors="replace").strip()
    stdout = (pulled / "client.stdout").read_text(errors="replace")
    stderr = (pulled / "client.stderr").read_text(errors="replace")
    hashes = (pulled / "stock_hashes.txt").read_text(errors="replace")
    summary = {
        "key_run": str(key_run),
        "raw_dir": str(raw),
        "geek": str(geek),
        "challenge": str(challenge),
        "key_count": key_count,
        "key_prefix": prefix,
        "client_status": status,
        "client_stdout": stdout.strip().splitlines()[-10:],
        "client_stderr": stderr.strip().splitlines()[-20:],
        "stock_hal_hash_ok": STOCK_HAL_SHA256 in hashes,
        "stock_ta_hash_ok": STOCK_TA_SHA256 in hashes,
        "artifacts": {},
    }
    for name in ["csr_maced_keys_len.bin", "csr_device_info_len.bin", "csr_protected_data_len.bin"]:
        p = pulled / name
        if p.exists():
            b = p.read_bytes()
            summary["artifacts"][name] = {
                "len": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
                "first16": b[:16].hex(),
            }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (ROOT / "rkp_research/LATEST_BINDER_CSR_FROM_DIRECT.txt").write_text(str(run_dir) + "\n")
    print(f"HOST_RUN={run_dir}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
