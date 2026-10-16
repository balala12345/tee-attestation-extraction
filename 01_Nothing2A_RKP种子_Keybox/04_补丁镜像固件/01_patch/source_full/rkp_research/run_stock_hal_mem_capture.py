#!/usr/bin/env python3
"""
Capture stock HAL memory around a successful RKPD provisioning run.

The goal is to observe normal-world residue from the stock KeyMint HAL without
patching the production TA. It clears RKPD, triggers stock provisioning, scans
the HAL process for TCI command signatures and known GEEK bytes, then pulls the
RKPD database and logs.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

from run_system_sideleak_memscan import adb_exec_out, adb_shell, adb_su, pull_rkpd_data

ROOT = Path(__file__).resolve().parents[1]
TA_PATH = "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
HAL_PATH = "/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic"
INIT_SERVICE = "vendor.keymint-trustonic"
SERVICE = "android.hardware.security.keymint@2.0-service.trustonic"
STOCK_TA_SHA256 = "ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2"
STOCK_HAL_SHA256 = "bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a"


def read_mem(pid: str, addr: int, size: int) -> bytes:
    cmd = f"dd if=/proc/{pid}/mem bs=4096 iflag=skip_bytes,count_bytes skip={hex(addr)} count={size} status=none"
    return adb_exec_out(cmd, check=False)


def parse_rw_maps(pid: str) -> list[dict]:
    maps = adb_su(f"cat /proc/{pid}/maps")
    regions = []
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        rng, perms = parts[0], parts[1]
        path = parts[5] if len(parts) > 5 else ""
        if "r" not in perms or "w" not in perms:
            continue
        start_s, end_s = rng.split("-", 1)
        start, end = int(start_s, 16), int(end_s, 16)
        size = end - start
        if size <= 0 or size > 64 * 1024 * 1024:
            continue
        regions.append({"start": start, "end": end, "perms": perms, "path": path})
    return regions


def trigger_stock(dev_run: str) -> None:
    adb_shell(
        f"""
set -x
DEV_RUN='{dev_run}'
mkdir -p "$DEV_RUN/logs" "$DEV_RUN/backup"
umount '{TA_PATH}' 2> "$DEV_RUN/logs/pre_umount.err"
sha256sum '{HAL_PATH}' '{TA_PATH}' > "$DEV_RUN/logs/stock_hashes_before.txt"
stop {INIT_SERVICE}
sleep 1
start {INIT_SERVICE}
sleep 5
getprop init.svc.{INIT_SERVICE} > "$DEV_RUN/logs/keymint_after_stock_restart.txt"
pidof {SERVICE} > "$DEV_RUN/logs/keymint_pid_after_stock_restart.txt"
logcat -c
pm clear com.android.rkpdapp > "$DEV_RUN/logs/pm_clear.out" 2> "$DEV_RUN/logs/pm_clear.err"
am broadcast -n com.android.rkpdapp/.BootReceiver -a android.intent.action.BOOT_COMPLETED > "$DEV_RUN/logs/bootreceiver.out" 2> "$DEV_RUN/logs/bootreceiver.err"
cmd jobscheduler run -f com.android.rkpdapp 26 > "$DEV_RUN/logs/force_jobs_26.txt" 2>&1
true >> "$DEV_RUN/logs/force_jobs_26.txt"
cmd jobscheduler run -f com.android.rkpdapp 27 > "$DEV_RUN/logs/force_jobs_27.txt" 2>&1
true >> "$DEV_RUN/logs/force_jobs_27.txt"
"""
    )


def summarize_db(db: Path) -> dict:
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "select count(*), min(length(key_blob)), max(length(key_blob)), "
            "min(length(public_key)), max(length(public_key)) from provisioned_keys"
        ).fetchone()
        pubs = [r[0] for r in con.execute("select public_key from provisioned_keys order by rowid").fetchall()]
    finally:
        con.close()
    return {
        "count": row[0],
        "key_blob_len_min": row[1],
        "key_blob_len_max": row[2],
        "public_key_len_min": row[3],
        "public_key_len_max": row[4],
        "public_keys": [p.hex() for p in pubs],
    }


def pattern_defs() -> list[tuple[str, bytes]]:
    patterns = [
        ("tci_cmd_50402", bytes.fromhex("02040580")),
        ("tci_cmd_50401", bytes.fromhex("01040580")),
        ("cose_mac0_p256_key_prefix", bytes.fromhex("8443a10105a0")),
        ("geek_curve2_prefix", bytes.fromhex("828443a10127")),
    ]
    geek = ROOT / "rkp_research/geek_fetch_20260815_165246/geek_curve_2.cbor"
    if geek.exists():
        patterns.append(("geek_curve2_full_20260815", geek.read_bytes()))
    return patterns


def scan_hal_memory(run_dir: Path, pid: str) -> dict:
    scan_dir = run_dir / "hal_mem_capture"
    scan_dir.mkdir(exist_ok=True)
    patterns = pattern_defs()
    hits = []
    regions = parse_rw_maps(pid)
    for idx, region in enumerate(regions):
        start, end = region["start"], region["end"]
        data = read_mem(pid, start, end - start)
        if not data:
            continue
        for name, pat in patterns:
            pos = 0
            while True:
                hit = data.find(pat, pos)
                if hit < 0:
                    break
                abs_addr = start + hit
                context_start = max(0, hit - 256)
                context_end = min(len(data), hit + max(len(pat), 320) + 256)
                ctx = data[context_start:context_end]
                out_name = f"{len(hits):04d}_{name}_r{idx:03d}_{abs_addr:x}.bin"
                (scan_dir / out_name).write_bytes(ctx)
                item = {
                    "pattern": name,
                    "region_index": idx,
                    "addr": hex(abs_addr),
                    "region_start": hex(start),
                    "region_end": hex(end),
                    "perms": region["perms"],
                    "path": region["path"],
                    "context_file": str(scan_dir / out_name),
                    "context_addr": hex(start + context_start),
                    "context_sha256": hashlib.sha256(ctx).hexdigest(),
                }
                if name.startswith("tci_cmd") and hit + 64 <= len(data):
                    tci = data[hit : hit + 320]
                    tci_name = out_name.replace(".bin", "_tci320.bin")
                    (scan_dir / tci_name).write_bytes(tci)
                    item["tci_file"] = str(scan_dir / tci_name)
                    item["tci_u32_first16"] = [
                        int.from_bytes(tci[i : i + 4], "little") for i in range(0, 64, 4)
                    ]
                hits.append(item)
                pos = hit + 1
    summary = {
        "pid": pid,
        "regions_scanned": len(regions),
        "patterns": [{"name": n, "len": len(p), "sha256": hashlib.sha256(p).hexdigest()} for n, p in patterns],
        "hits": hits,
    }
    (scan_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> None:
    run_id = "stock_hal_mem_capture_" + time.strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / "rkp_research" / run_id
    dev_run = f"/data/local/tmp/{run_id}"
    (run_dir / "device_logs").mkdir(parents=True)
    (run_dir / "RUN_ID.txt").write_text(run_id + "\n")
    (run_dir / "DEV_RUN.txt").write_text(dev_run + "\n")

    trigger_stock(dev_run)
    time.sleep(8)
    pid = adb_su(f"pidof {SERVICE}").strip()
    scan_summary = scan_hal_memory(run_dir, pid)
    time.sleep(80)
    db = pull_rkpd_data(run_dir, dev_run, "rkpdapp_data_after_stock_hal_capture.tar")
    db_summary = summarize_db(db)
    hashes = (run_dir / "raw" / run_id / "logs" / "stock_hashes_before.txt").read_text(errors="replace")
    result = {
        "stock_hal_hash_ok": STOCK_HAL_SHA256 in hashes,
        "stock_ta_hash_ok": STOCK_TA_SHA256 in hashes,
        "pid": pid,
        "db": db_summary,
        "memscan": {
            "regions_scanned": scan_summary["regions_scanned"],
            "hit_count": len(scan_summary["hits"]),
            "hit_patterns": sorted({h["pattern"] for h in scan_summary["hits"]}),
        },
    }
    (run_dir / "result_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "rkp_research/LATEST_STOCK_HAL_MEM_CAPTURE.txt").write_text(str(run_dir) + "\n")
    print(f"HOST_RUN={run_dir}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
