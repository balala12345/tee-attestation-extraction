#!/usr/bin/env python3
"""
Restore the device to a stock RKPD key pool.

This does not bind-mount or patch anything. It verifies stock TA/HAL hashes,
restarts KeyMint, clears RKPD app data, triggers provisioning, pulls the RKPD
database, and writes a small summary.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from run_system_sideleak_memscan import adb_shell, pull_rkpd_data

ROOT = Path(__file__).resolve().parents[1]
TA_PATH = "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
HAL_PATH = "/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic"
INIT_SERVICE = "vendor.keymint-trustonic"
SERVICE = "android.hardware.security.keymint@2.0-service.trustonic"
STOCK_TA_SHA256 = "ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2"
STOCK_HAL_SHA256 = "bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a"
WAIT_SECONDS = int(os.environ.get("RKP_STOCK_RESTORE_WAIT_SECONDS", "150"))


def trigger_stock(dev_run: str) -> None:
    adb_shell(
        f"""
set -x
DEV_RUN='{dev_run}'
TA_PATH='{TA_PATH}'
HAL_PATH='{HAL_PATH}'
mkdir -p "$DEV_RUN/logs" "$DEV_RUN/backup"
umount "$TA_PATH" 2> "$DEV_RUN/logs/pre_umount.err"
sha256sum "$HAL_PATH" "$TA_PATH" > "$DEV_RUN/logs/stock_hashes_before.txt"
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
            "min(length(public_key)), max(length(public_key)), "
            "min(expiration_time), max(expiration_time) from provisioned_keys"
        ).fetchone()
    finally:
        con.close()
    return {
        "count": row[0],
        "key_blob_len_min": row[1],
        "key_blob_len_max": row[2],
        "public_key_len_min": row[3],
        "public_key_len_max": row[4],
        "expiration_time_min": row[5],
        "expiration_time_max": row[6],
    }


def main() -> None:
    run_id = "stock_restore_rkpd_" + time.strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / "rkp_research" / run_id
    dev_run = f"/data/local/tmp/{run_id}"
    (run_dir / "device_logs").mkdir(parents=True)
    (run_dir / "RUN_ID.txt").write_text(run_id + "\n")
    (run_dir / "DEV_RUN.txt").write_text(dev_run + "\n")

    trigger_stock(dev_run)
    time.sleep(WAIT_SECONDS)
    db = pull_rkpd_data(run_dir, dev_run, "rkpdapp_data_after_stock_restore.tar")
    summary = summarize_db(db)

    hashes = (run_dir / "raw" / run_id / "logs" / "stock_hashes_before.txt").read_text(errors="replace")
    summary["stock_hashes_before"] = hashes.strip().splitlines()
    summary["stock_hal_hash_ok"] = STOCK_HAL_SHA256 in hashes
    summary["stock_ta_hash_ok"] = STOCK_TA_SHA256 in hashes
    (run_dir / "result_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (ROOT / "rkp_research/LATEST_STOCK_RESTORE_RKPD.txt").write_text(str(run_dir) + "\n")

    print(f"HOST_RUN={run_dir}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
