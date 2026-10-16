#!/usr/bin/env python3
"""
Run direct RKP keygen+CSR with a configurable key batch size.

This is used to test the stock HAL observation that production CSR succeeds
with 12 MacedPublicKey entries. For sideleak-patched direct TAs, it also checks
whether the object copied at private_out+0x400 contains a scalar matching the
generated public key.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_rkp_sideleak import mul  # noqa: E402

TARGET_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
PROBE = SCRIPT_DIR / "rkp_tee_probe_csr"
ADB_SERIAL = os.environ.get("ADB_SERIAL", "")
MCCLIENT = (
    TARGET_ROOT
    / "05_输入与支撑材料/source_binaries/vendor_lib64/libMcClient.so"
)
DEFAULT_TA = (
    TARGET_ROOT
    / "03_patch与二进制/patched_binaries/patched_ta/"
    "0706000000000000000000000000004e.rkp_sideleak.tlbin"
)
DEFAULT_GEEK = (
    TARGET_ROOT
    / "05_输入与支撑材料/rkp_research_full副本/"
    "geek_fetch_20260815_165246/geek_curve_2.cbor"
)
DEFAULT_CHALLENGE = (
    TARGET_ROOT
    / "05_输入与支撑材料/rkp_research_full副本/"
    "geek_fetch_20260815_165246/challenge.bin"
)
DEV_OUT = "/data/local/tmp/rkptee_csr_out"
SIG = bytes.fromhex("3c000000070000000a00001001000000")
SCALAR_OFFSET = 0x400 + 0x98
KEYMINT_INIT_SERVICE = "vendor.keymint-trustonic"
KEYMINT_PROCESS = "android.hardware.security.keymint@2.0-service.trustonic"


def run(cmd: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def adb_cmd(*args: str) -> list[str]:
    prefix = ["adb"]
    if ADB_SERIAL:
        prefix += ["-s", ADB_SERIAL]
    return prefix + list(args)


def adb_shell(cmd: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return run(adb_cmd("shell", "su", "-c", "sh"), input_bytes=cmd.encode(), check=check)


def parse_tci(tci: bytes) -> dict:
    def u32(off: int) -> int:
        return struct.unpack_from("<I", tci, off)[0]

    return {
        "cmd": hex(u32(0)),
        "ret": hex(u32(4)),
        "testMode": tci[12],
        "keys_addr": hex(u32(13)),
        "keys_len": u32(17),
        "endpoint_addr": hex(u32(21)),
        "endpoint_len": u32(25),
        "challenge_addr": hex(u32(29)),
        "challenge_len": u32(33),
        "device_addr": hex(u32(37)),
        "device_len": u32(41),
        "protected_addr": hex(u32(45)),
        "protected_len": u32(49),
        "maced_addr": hex(u32(53)),
        "maced_len": u32(57),
    }


def public_xy_from_maced_public_key(blob: bytes) -> bytes | None:
    idx = blob.find(bytes.fromhex("215820"))
    if idx < 0 or idx + 35 > len(blob):
        return None
    x = blob[idx + 3 : idx + 35]
    j = blob.find(bytes.fromhex("225820"), idx + 35)
    if j < 0 or j + 35 > len(blob):
        return None
    y = blob[j + 3 : j + 35]
    return x + y


def summarize_key(raw: Path, tag: str) -> dict:
    pub = (raw / f"{tag}_pub_len.bin").read_bytes()
    priv_full = (raw / f"{tag}_priv_full.bin").read_bytes()
    priv_len = (raw / f"{tag}_priv_len.bin").read_bytes()
    scalar = priv_full[SCALAR_OFFSET : SCALAR_OFFSET + 32]
    public_xy = public_xy_from_maced_public_key(pub)
    derived_xy = None
    scalar_matches = False
    if len(scalar) == 32:
        k = int.from_bytes(scalar, "big")
        point = mul(k)
        if point:
            x, y = point
            derived_xy = x.to_bytes(32, "big") + y.to_bytes(32, "big")
            scalar_matches = public_xy == derived_xy
    return {
        "tag": tag,
        "pub_len": len(pub),
        "priv_len_file_len": len(priv_len),
        "priv_first16": priv_len[:16].hex(),
        "sideleak_sig_at_0x400": priv_full[0x400 : 0x400 + len(SIG)].hex() == SIG.hex(),
        "scalar_sha256": hashlib.sha256(scalar).hexdigest(),
        "public_xy_sha256": hashlib.sha256(public_xy).hexdigest() if public_xy else None,
        "derived_public_matches": scalar_matches,
    }


def main() -> None:
    ta = Path(os.environ.get("RKP_DIRECT_TA", str(DEFAULT_TA)))
    geek = Path(os.environ.get("RKP_DIRECT_GEEK", str(DEFAULT_GEEK)))
    challenge = Path(os.environ.get("RKP_DIRECT_CHALLENGE", str(DEFAULT_CHALLENGE)))
    test_mode = int(os.environ.get("RKP_DIRECT_TEST_MODE", "0"))
    key_count = int(os.environ.get("RKP_DIRECT_KEY_COUNT", "12"))
    stop_keymint = os.environ.get("RKP_DIRECT_STOP_KEYMINT", "1") != "0"
    sensitive_output = os.environ.get("RKP_DIRECT_SENSITIVE_OUTPUT", "0") == "1"
    run_id = os.environ.get("RKP_DIRECT_RUN_ID", "direct_csr_batch_" + time.strftime("%Y%m%d_%H%M%S"))
    run_dir = TARGET_ROOT / "04_结果/outputs" / run_id
    raw = run_dir / "raw"
    run_dir.mkdir(parents=True, exist_ok=True)

    dev_probe = "/data/local/tmp/rkp_tee_probe_csr"
    dev_ta = f"/data/local/tmp/{ta.name}"
    dev_geek = f"/data/local/tmp/{geek.name}"
    dev_challenge = f"/data/local/tmp/{challenge.name}"

    pushes = []
    for src, dst in [(PROBE, dev_probe), (MCCLIENT, "/data/local/tmp/libMcClient.so"), (ta, dev_ta), (geek, dev_geek), (challenge, dev_challenge)]:
        adb_shell(f"rm -f {dst}\n", check=False)
        cp = run(adb_cmd("push", str(src), dst))
        pushes.append(cp.stdout.decode(errors="replace") + cp.stderr.decode(errors="replace"))
    (run_dir / "adb_push.txt").write_text("\n".join(pushes))

    stop_block = ""
    start_block = ""
    if stop_keymint:
        stop_block = (
            f"stop {KEYMINT_INIT_SERVICE}; "
            "sleep 1; "
        )
        start_block = (
            f"start {KEYMINT_INIT_SERVICE}; "
            "sleep 4; "
        )
    shell = (
        f"rm -rf {DEV_OUT}; mkdir -p {DEV_OUT}; chmod 755 {dev_probe}; cd /data/local/tmp; "
        f"getprop init.svc.{KEYMINT_INIT_SERVICE} > {DEV_OUT}/keymint_before.txt; "
        f"pidof {KEYMINT_PROCESS} > {DEV_OUT}/keymint_pid_before.txt 2>&1; true; "
        f"{stop_block}"
        f"getprop init.svc.{KEYMINT_INIT_SERVICE} > {DEV_OUT}/keymint_after_stop.txt; "
        f"pidof {KEYMINT_PROCESS} > {DEV_OUT}/keymint_pid_after_stop.txt 2>&1; true; "
        f"LD_LIBRARY_PATH=/data/local/tmp:/vendor/lib64 ./rkp_tee_probe_csr {dev_ta} {dev_geek} {dev_challenge} {test_mode} {key_count}; "
        f"STATUS=$?; echo shell_status=$STATUS; echo $STATUS > {DEV_OUT}/probe_status.txt; "
        f"{start_block}"
        f"getprop init.svc.{KEYMINT_INIT_SERVICE} > {DEV_OUT}/keymint_after_restart.txt; "
        f"pidof {KEYMINT_PROCESS} > {DEV_OUT}/keymint_pid_after_restart.txt 2>&1; true; "
        f"tar -cf /data/local/tmp/{run_id}.tar -C /data/local/tmp rkptee_csr_out; "
        "exit $STATUS"
    )
    cp = adb_shell(shell, check=False)
    (run_dir / "device_run.txt").write_bytes(cp.stdout + cp.stderr)
    pull = run(adb_cmd("pull", f"/data/local/tmp/{run_id}.tar", str(run_dir / f"{run_id}.tar")), check=False)
    (run_dir / "adb_pull_tar.txt").write_bytes(pull.stdout + pull.stderr)
    raw.mkdir(exist_ok=True)
    with tarfile.open(run_dir / f"{run_id}.tar") as tf:
        tf.extractall(run_dir)
    out = run_dir / "rkptee_csr_out"
    if raw.exists():
        shutil.rmtree(raw)
    out.rename(raw)

    summary = {
        "ta": str(ta),
        "ta_sha256": hashlib.sha256(ta.read_bytes()).hexdigest(),
        "geek_len": geek.stat().st_size,
        "challenge_len": challenge.stat().st_size,
        "test_mode": test_mode,
        "key_count": key_count,
        "stop_keymint": stop_keymint,
        "sensitive_output_redacted": sensitive_output,
        "device_run_tail": (run_dir / "device_run.txt").read_text(errors="replace").splitlines()[-20:],
    }
    csr_tci = raw / "csr_tci.bin"
    if csr_tci.exists():
        summary["csr_tci"] = parse_tci(csr_tci.read_bytes())
    summary["keys"] = []
    prefix = "rkp_gen_test" if test_mode else "rkp_gen_prod"
    for i in range(key_count):
        tag = f"{prefix}_{i:02d}"
        if (raw / f"{tag}_pub_len.bin").exists():
            summary["keys"].append(summarize_key(raw, tag))
    for name in ["csr_device_info_len.bin", "csr_protected_data_len.bin", "csr_maced_keys_len.bin", "csr_input_combined.bin"]:
        p = raw / name
        if p.exists():
            b = p.read_bytes()
            item = {"len": len(b), "sha256": hashlib.sha256(b).hexdigest()}
            if not sensitive_output:
                item["first16"] = b[:16].hex()
            summary[name] = item
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (SCRIPT_DIR / "LATEST_DIRECT_CSR_BATCH.txt").write_text(str(run_dir) + "\n")
    print(f"HOST_RUN={run_dir}")
    print(json.dumps({k: v for k, v in summary.items() if k != "keys"}, indent=2))
    print("keys", len(summary["keys"]), "scalar_matches", sum(1 for k in summary["keys"] if k["derived_public_matches"]))


if __name__ == "__main__":
    main()
