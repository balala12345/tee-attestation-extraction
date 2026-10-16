#!/usr/bin/env python3
"""
Run a loaded-TA control for the RKP keygen hook.

This mounts the recopy-stock TA patch with a readable vendor context, restarts
KeyMint so the patched TA is actually loaded, triggers RKPD provisioning, then
pulls the RKPD DB and restores stock TA/service state.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from run_system_sideleak_memscan import adb_shell, adb_su, pull_rkpd_data, restore, run

ROOT = Path(__file__).resolve().parents[1]
TA_LOCAL = Path(
    os.environ.get(
        "RKP_CONTROL_TA_LOCAL",
        str(ROOT / "patched_ta/0706000000000000000000000000004d.rkp_recopy_stock.tlbin"),
    )
)
TA_DEV = f"/data/local/tmp/{TA_LOCAL.name}"
RUN_PREFIX = os.environ.get("RKP_CONTROL_RUN_PREFIX", "system_recopy_restart_control")
TA_PATH = "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
HAL_PATH = "/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic"
INIT_SERVICE = "vendor.keymint-trustonic"
SERVICE = "android.hardware.security.keymint@2.0-service.trustonic"
WAIT_SECONDS = 120


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


def summarize_db(db: Path) -> dict:
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "select count(*), min(length(key_blob)), max(length(key_blob)), "
            "min(length(public_key)), max(length(public_key)) from provisioned_keys"
        ).fetchone()
    finally:
        con.close()
    return {
        "count": row[0],
        "key_blob_len_min": row[1],
        "key_blob_len_max": row[2],
        "public_key_len_min": row[3],
        "public_key_len_max": row[4],
    }


def main() -> None:
    run_id = RUN_PREFIX + "_" + time.strftime("%Y%m%d_%H%M%S")
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

        trigger_provisioning(dev_run)
        time.sleep(WAIT_SECONDS)
        db = pull_rkpd_data(run_dir, dev_run, "rkpdapp_data_after_recopy_restart_control.tar")
        summary = summarize_db(db)
        summary["keymint_pid_after_ta_restart"] = (
            run_dir / "raw" / run_id / "logs" / "keymint_pid_after_ta_restart.txt"
        ).read_text(errors="replace").strip()
        (run_dir / "result_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        restore(dev_run)
        final_pull = run(["adb", "pull", f"/data/local/tmp/{run_id}.tar", str(run_dir / f"{run_id}.tar")], check=False)
        (run_dir / "device_logs/final_adb_pull_run_tar.txt").write_bytes(final_pull.stdout + final_pull.stderr)
        (ROOT / f"rkp_research/LATEST_{RUN_PREFIX.upper()}.txt").write_text(str(run_dir) + "\n")

    print(f"HOST_RUN={run_dir}")
    print(json.dumps(json.loads((run_dir / "result_summary.json").read_text()), indent=2))


if __name__ == "__main__":
    main()
