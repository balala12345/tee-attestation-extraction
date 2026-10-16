#!/usr/bin/env python3
"""One-shot google-rkp-sw issuance from a stock MiTEE-log capture.

This consumer understands only ``stock_mitee_log_v1`` capture contracts.  It
does not fabricate the legacy patched-TA/restore/latch fields consumed by the
older portable wrapper.  Run ``--preflight-only`` first.  A real attempt then
requires the unchanged, exclusive preflight report plus
``--execute-google-once``.  Every failure after attempt reservation is burned
and is never retried automatically.

The core, allowlisted ``rkp_sw.py`` gate-v7 implementation performs the sole
network invocation.  This wrapper independently rechecks its one P-256 key,
one returned chain, certificate signatures, trusted Google root, and complete
ProvisioningInfo policy before publishing SUCCESS.  Private bytes are never
printed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse


HERE = Path(__file__).resolve().parent
WORKSPACE_ROOT = HERE.parent.parent
VENV_PYTHON = WORKSPACE_ROOT / "third_party/google-rkp-sw/.venv/bin/python"
PORTABLE_WRAPPER = HERE / "rkp_sw_portable.py"
PROFILE_HELPER = HERE / "k70e_portable_profile.py"
EXTRACTOR = HERE / "extract_k70e_cdi_leaf_from_mitee_log.py"
EXPECTED_VENV_PYTHON_REALPATH = Path(
    "/Library/Developer/CommandLineTools/Library/Frameworks/"
    "Python3.framework/Versions/3.9/bin/python3.9"
)
EXPECTED_VENV_PYTHON_SIZE = 102_352
EXPECTED_VENV_PYTHON_SHA256 = (
    "9ea22c79baac7ee6906d807799f351ae5de25b74be3ead66370714ea5348ca9f"
)
EXPECTED_PROFILE_HELPER_SIZE = 134_026
EXPECTED_PROFILE_HELPER_SHA256 = (
    "724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57"
)
EXPECTED_PORTABLE_WRAPPER_SIZE = 76_113
EXPECTED_PORTABLE_WRAPPER_SHA256 = (
    "0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c"
)
IOREG_PATH = "/usr/sbin/ioreg"
EXPECTED_FASTBOOT_SIZE = 5_152_256
EXPECTED_FASTBOOT_SHA256 = (
    "549420b5b6b843efd78bfcd47765bb4b581fa23093693bb65648fab9eaa5de7a"
)
REFERENCE_USB_VENDOR_ID = 10_007
REFERENCE_USB_PRODUCT_ID = 65_288
REFERENCE_USB_VENDOR_NAME = "Xiaomi"
REFERENCE_USB_PRODUCT_NAME = "<DEVICE_SERIAL>"
FORBIDDEN_PIXEL_USB_SERIAL = "<DEVICE_SERIAL>"


def _early_read_regular(path: Path, *, label: str) -> bytes:
    """Freeze a trusted runtime component before executing project code."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise SystemExit(f"SAFE_ABORT: required {label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"SAFE_ABORT: {label} must be a non-symlink regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise SystemExit(f"SAFE_ABORT: {label} changed before freeze")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(opened, field) != getattr(after, field) for field in fields):
        raise SystemExit(f"SAFE_ABORT: {label} changed during freeze")
    raw = b"".join(chunks)
    if len(raw) != after.st_size:
        raise SystemExit(f"SAFE_ABORT: {label} size changed during freeze")
    return raw


def _freeze_trusted_runtime() -> tuple[bytes, bytes, bytes]:
    try:
        python_realpath = VENV_PYTHON.resolve(strict=True)
    except OSError as exc:
        raise SystemExit("SAFE_ABORT: canonical RKP venv Python is unavailable") from exc
    if python_realpath != EXPECTED_VENV_PYTHON_REALPATH:
        raise SystemExit("SAFE_ABORT: canonical RKP venv Python realpath drifted")
    python_raw = _early_read_regular(python_realpath, label="venv Python entity")
    if (
        len(python_raw) != EXPECTED_VENV_PYTHON_SIZE
        or hashlib.sha256(python_raw).hexdigest() != EXPECTED_VENV_PYTHON_SHA256
    ):
        raise SystemExit("SAFE_ABORT: canonical RKP venv Python bytes drifted")
    current_realpath = Path(sys.executable).resolve(strict=True)
    expected_prefix = VENV_PYTHON.parent.parent.resolve(strict=True)
    if current_realpath != python_realpath or Path(sys.prefix).resolve() != expected_prefix:
        if os.environ.get("K70E_STOCK_LOG_RKP_VENV") == "1":
            raise SystemExit("SAFE_ABORT: canonical RKP venv re-exec did not take effect")
        environment = dict(os.environ)
        environment["K70E_STOCK_LOG_RKP_VENV"] = "1"
        os.execve(
            str(VENV_PYTHON),
            [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]],
            environment,
        )

    helper_raw = _early_read_regular(PROFILE_HELPER, label="profile helper")
    if (
        len(helper_raw) != EXPECTED_PROFILE_HELPER_SIZE
        or hashlib.sha256(helper_raw).hexdigest() != EXPECTED_PROFILE_HELPER_SHA256
    ):
        raise SystemExit("SAFE_ABORT: current profile helper bytes drifted")
    portable_raw = _early_read_regular(PORTABLE_WRAPPER, label="portable RKP wrapper")
    if (
        len(portable_raw) != EXPECTED_PORTABLE_WRAPPER_SIZE
        or hashlib.sha256(portable_raw).hexdigest() != EXPECTED_PORTABLE_WRAPPER_SHA256
    ):
        raise SystemExit("SAFE_ABORT: portable RKP wrapper bytes drifted")
    return python_raw, helper_raw, portable_raw


_PYTHON_ENTITY_RAW, _PROFILE_HELPER_RAW, _PORTABLE_WRAPPER_RAW = (
    _freeze_trusted_runtime()
)

try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        ec,
        ed25519,
        ed448,
        padding,
        rsa,
    )
except ModuleNotFoundError as exc:
    raise SystemExit(f"missing dependency {exc.name!r}; expected {VENV_PYTHON}") from exc

# Execute exactly the frozen portable-wrapper bytes.  It independently freezes
# its helper; equality below proves it executed the same helper bytes that this
# consumer verified before importing any project code.
portable = types.ModuleType("k70e_stock_log_portable_snapshot")
portable.__file__ = str(PORTABLE_WRAPPER)
portable.__package__ = ""
sys.modules[portable.__name__] = portable
exec(compile(_PORTABLE_WRAPPER_RAW, str(PORTABLE_WRAPPER), "exec"), portable.__dict__)
if portable.PROFILE_HELPER_RAW != _PROFILE_HELPER_RAW:
    raise SystemExit("SAFE_ABORT: portable wrapper executed a different profile helper")


profile_lib = portable.profile_lib
OFFICIAL_SERVER_URL = portable.OFFICIAL_SERVER_URL
CAPTURE_CONTRACT_SCHEMA = "k70e-rkp-ctf-stock-mitee-log-capture-contract-v1"
PREFLIGHT_SCHEMA = "k70e-rkp-ctf-stock-log-provision-preflight-v1"
LIVE_CHECK_SCHEMA = "k70e-rkp-ctf-stock-log-live-check-v1"
ATTEMPT_SCHEMA = "k70e-rkp-ctf-stock-log-issuance-attempt-v1"
NETWORK_SCHEMA = "k70e-rkp-ctf-stock-log-network-start-v1"
BURN_SCHEMA = "k70e-rkp-ctf-stock-log-issuance-burn-v1"
SUCCESS_SCHEMA = "k70e-rkp-ctf-stock-log-issuance-success-v1"
STRICT_AUDIT_SCHEMA = "k70e-rkp-ctf-stock-log-issued-output-audit-v1"
CORE_DURABILITY_PATCH_SCHEMA = "k70e-rkp-ctf-core-durability-patch-v2"
CORE_RKP_GATE_VERSION = portable.REQUIRED_RKP_ISSUANCE_GATE_VERSION
if type(CORE_RKP_GATE_VERSION) is not int or CORE_RKP_GATE_VERSION != 7:
    raise SystemExit("SAFE_ABORT: portable wrapper did not enforce core gate v7")
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
TRUSTED_GOOGLE_ROOT_DER_SHA256 = frozenset(
    {"6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"}
)
TRUSTED_GOOGLE_ROOT_SPKI_SHA256 = frozenset(
    {"3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"}
)
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
USB_SERIAL_RE = re.compile(r"[A-Za-z0-9._-]{4,128}")
REMOTE_CAPTURE_RE = re.compile(r"/data/local/tmp/k70e_stock_cdi_log_once_[0-9a-f]{32}")
MAX_INPUT_BYTES = 64 * 1024 * 1024
STOCK_LK_A_SIZE = 16_777_216
STOCK_LK_A_SHA256 = (
    "9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35"
)
STOCK_PRELOADER_RAW_A_SIZE = 4_190_208
STOCK_PRELOADER_RAW_A_SHA256 = (
    "33ef65d9560e92990e5d6bbf7dc8e161e57346e7f9434082b59d31366a638d1f"
)
APPROVED_A_SLOT_RAW_PARTITIONS = (
    (
        "vbmeta_a",
        8_388_608,
        "c38281042cd2581421c4589ee2ccaf349e929d1e6a1390b915133c3bb2291ce0",
    ),
    (
        "vbmeta_system_a",
        8_388_608,
        "b3fa87e82361a8f6efc0a3b170ae9fe75111681e64e184405bd36d0c426503ee",
    ),
    (
        "vbmeta_vendor_a",
        8_388_608,
        "ec0f5244b94798dae89875d91afea7e0651064dc1dcfdd5f4e5738158dbbbe5e",
    ),
    (
        "boot_a",
        67_108_864,
        "8a7f406b56e6db22a910eef5370e9f2cbcf08a3e7e5be8fff6fbbe19a42058b8",
    ),
    (
        "vendor_boot_a",
        67_108_864,
        "501ec32cb585c60c4db9245266c16469eb42b31f7b4fb37b8f8f6d1c7d45d9c9",
    ),
    (
        "dtbo_a",
        8_388_608,
        "6def7656d2a130bff752754647d37d2003416f2277d4c8cce79c954fadd83336",
    ),
    (
        "gz_a",
        33_554_432,
        "21ebe0bbc10e0ddd6632b989840ef1adab29ae3e4da09133880d47a6fbf5a177",
    ),
)
KNOWN_GOOD_HLOS_PROVENANCE_SENTINEL = {
    "vbmeta_size": "13184",
    "vbmeta_digest": (
        "acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"
    ),
    "build_host": "<BUILD_HOST>",
    "crypto_state": "encrypted",
    "control_privapp_permissions": "enforce",
    "miui_build_region": "cn",
    "product_locale": "zh-CN",
}


class SafeAbort(RuntimeError):
    """A deliberately non-secret, user-facing rejection."""


class ProvisioningInfoRejected(SafeAbort):
    """The burned Google result cannot be accepted or retried."""


@dataclass(frozen=True)
class FrozenCapture:
    root: Path
    profile: dict[str, Any]
    profile_raw: bytes
    evidence: dict[str, bytes]
    scalar: bytes
    identity_spki: bytes
    csr: bytes
    challenge: bytes
    config: bytes
    report: dict[str, Any]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_core_durability_patch(rkp: Any) -> dict[str, Any]:
    """Add directory-entry durability without changing the pinned core logic."""
    prior = getattr(rkp, "_k70e_stock_log_durability_patch", None)
    if prior is not None:
        if not isinstance(prior, dict) or prior.get("schema") != CORE_DURABILITY_PATCH_SCHEMA:
            raise SafeAbort("core durability patch state is ambiguous")
        return dict(prior)
    original_atomic = getattr(rkp, "_atomic_write_bytes", None)
    original_create = getattr(rkp, "_create_run_dir", None)
    if not callable(original_atomic) or not callable(original_create):
        raise SafeAbort("pinned core lacks the audited durable-write hook points")

    def durable_atomic_write(path: Path, data: bytes) -> None:
        original_atomic(path, data)
        parent = Path(path).parent
        fsync_directory(parent)
        fsync_directory(parent.parent)

    def durable_create_run_dir(output_dir: str | None, command: str) -> Path:
        run_dir = Path(original_create(output_dir, command))
        fsync_directory(run_dir)
        fsync_directory(run_dir.parent)
        return run_dir

    durable_atomic_write._k70e_original = original_atomic  # type: ignore[attr-defined]
    durable_create_run_dir._k70e_original = original_create  # type: ignore[attr-defined]
    rkp._atomic_write_bytes = durable_atomic_write
    rkp._create_run_dir = durable_create_run_dir
    report = {
        "schema": CORE_DURABILITY_PATCH_SCHEMA,
        "version": 2,
        "installed_after_allowlisted_core_load": True,
        "core_gate_version": CORE_RKP_GATE_VERSION,
        "atomic_write_payload_semantics_unchanged": True,
        "atomic_write_parent_fsync_added": True,
        "atomic_write_grandparent_fsync_added": True,
        "create_run_directory_fsync_added": True,
        "create_run_parent_fsync_added": True,
        "approval_or_parser_logic_changed": False,
    }
    rkp._k70e_stock_log_durability_patch = dict(report)
    return report


def require_core_durability_patch(rkp: Any) -> dict[str, Any]:
    report = getattr(rkp, "_k70e_stock_log_durability_patch", None)
    required_true = (
        "installed_after_allowlisted_core_load",
        "atomic_write_payload_semantics_unchanged",
        "atomic_write_parent_fsync_added",
        "atomic_write_grandparent_fsync_added",
        "create_run_directory_fsync_added",
        "create_run_parent_fsync_added",
    )
    if (
        not isinstance(report, dict)
        or report.get("schema") != CORE_DURABILITY_PATCH_SCHEMA
        or report.get("version") != 2
        or type(report.get("core_gate_version")) is not int
        or report.get("core_gate_version") != CORE_RKP_GATE_VERSION
        or report.get("approval_or_parser_logic_changed") is not False
        or any(report.get(field) is not True for field in required_true)
        or not callable(getattr(rkp, "_atomic_write_bytes", None))
        or not callable(getattr(rkp, "_create_run_dir", None))
        or not hasattr(rkp._atomic_write_bytes, "_k70e_original")
        or not hasattr(rkp._create_run_dir, "_k70e_original")
    ):
        raise SafeAbort("core durability patch is absent or incomplete")
    return dict(report)


def read_regular_nofollow(
    path: Path, *, label: str, limit: int = MAX_INPUT_BYTES
) -> bytes:
    """Freeze one regular file through a single O_NOFOLLOW descriptor."""
    expanded = path.expanduser()
    try:
        before = expanded.lstat()
    except FileNotFoundError as exc:
        raise SafeAbort(f"required {label} is missing") from exc
    if stat.S_ISLNK(before.st_mode):
        raise SafeAbort(f"{label} must not be a symlink")
    descriptor = os.open(expanded, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SafeAbort(f"{label} was replaced before it could be frozen")
        if not stat.S_ISREG(metadata.st_mode):
            raise SafeAbort(f"{label} is not a regular file")
        if metadata.st_size > limit:
            raise SafeAbort(f"{label} exceeds its safety limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise SafeAbort(f"{label} exceeds its safety limit")
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(metadata, field) != getattr(after, field) for field in stable_fields):
            raise SafeAbort(f"{label} changed while it was being frozen")
        if len(data) != after.st_size:
            raise SafeAbort(f"{label} changed size while it was being frozen")
        return data
    finally:
        os.close(descriptor)


def capture_path(root: Path, relative: str) -> Path:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise SafeAbort("capture contract contains an unsafe relative path")
    cursor = root
    for part in parts[:-1]:
        cursor = cursor / part
        metadata = cursor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise SafeAbort("capture evidence parent is not a real directory")
    return root.joinpath(*parts)


def read_capture_file(root: Path, relative: str, *, label: str) -> bytes:
    return read_regular_nofollow(capture_path(root, relative), label=label)


def decode_json(raw: bytes, *, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SafeAbort(f"{label} has a duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise SafeAbort(f"{label} contains a non-finite JSON value")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafeAbort(f"{label} is not strict UTF-8 JSON") from exc


def json_map(raw: bytes, *, label: str) -> dict[str, Any]:
    value = decode_json(raw, label=label)
    if not isinstance(value, dict):
        raise SafeAbort(f"{label} is not a JSON map")
    return value


def write_exclusive_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    try:
        parent_metadata = path.parent.lstat()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
        parent_metadata = path.parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        raise SafeAbort("private output parent must be a real directory")
    os.chmod(path.parent, 0o700)
    if stat.S_IMODE(path.parent.lstat().st_mode) != 0o700:
        raise SafeAbort("private output parent could not be fixed at mode 0700")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.link(temporary, path, follow_symlinks=False)
        fsync_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def write_exclusive_json(path: Path, value: dict[str, Any]) -> bytes:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_exclusive_bytes(path, raw)
    return raw


def load_profile_snapshot(profile_path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_nofollow(profile_path, label="current target profile")
    with tempfile.TemporaryDirectory(prefix="k70e_stock_log_profile_") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        snapshot = root / "TARGET_PROFILE.json"
        portable.profile_lib.atomic_write(snapshot, raw, 0o600)
        profile = portable.profile_lib.load_profile(snapshot)
    if profile.get("schema") != profile_lib.SCHEMA:
        raise SafeAbort("profile is not the current schema-v4 format")
    if profile.get("compatibility", {}).get("classification") != "EXACT_REFERENCE_FAST_PATH":
        raise SafeAbort("profile is not the exact audited K70E reference")
    approval = profile.get("approval_baseline", {})
    if (
        approval.get("matches_recognized_stock_reference") is not True
        or approval.get("eligible_as_network_comparison_baseline") is not True
        or not isinstance(approval.get("checks"), dict)
        or not approval["checks"]
        or not all(value is True for value in approval["checks"].values())
    ):
        raise SafeAbort("profile is not bound to the approved stock environment")
    return profile, raw


def load_live_check_profile_readonly(profile_path: Path, serial: str) -> dict[str, Any]:
    """Validate the V5 profile without snapshots, capture files, or private bytes."""
    if USB_SERIAL_RE.fullmatch(serial) is None or ":" in serial:
        raise SafeAbort("serial must be one exact USB ADB serial")
    before = read_regular_nofollow(profile_path, label="current live-check profile")
    decoded = json_map(before, label="current live-check profile")
    profile = profile_lib.load_profile(
        profile_path.expanduser(),
        verify_files=True,
        required_artifacts={"adb_client"},
    )
    after = read_regular_nofollow(profile_path, label="current live-check profile")
    if not hmac.compare_digest(before, after):
        raise SafeAbort("live-check profile changed while it was being validated")
    if not profile_lib.typed_equal(decoded, profile):
        raise SafeAbort("live-check profile bytes differ from the validated profile")
    if (
        profile.get("schema") != profile_lib.SCHEMA
        or profile.get("toolchain", {}).get("id")
        != profile_lib.TOOLCHAIN_ALLOWLIST_ID
        or profile.get("compatibility", {}).get("classification")
        != "EXACT_REFERENCE_FAST_PATH"
        or profile.get("compatibility", {}).get("ready_for_automated_build") is not True
        or profile.get("target", {}).get("serial") != serial
        or profile.get("target", {}).get("product") != "duchamp"
        or profile.get("target", {}).get("slot_suffix") != "_a"
        or profile.get("safety", {}).get("profile_mode") != "stock-log-only"
        or profile.get("safety", {}).get("requires_attended_device_run") is not True
    ):
        raise SafeAbort("live-check profile is not the exact V5 stock-log target")
    approval = profile.get("approval_baseline", {})
    if (
        approval.get("matches_recognized_stock_reference") is not True
        or approval.get("eligible_as_network_comparison_baseline") is not True
        or not isinstance(approval.get("checks"), dict)
        or not approval["checks"]
        or not all(value is True for value in approval["checks"].values())
    ):
        raise SafeAbort("live-check profile lost its approved stock baseline")
    return profile


def exact_hash_record(raw: bytes) -> dict[str, Any]:
    return {"size": len(raw), "sha256": sha256(raw)}


def validate_capture_contract(
    root: Path,
    profile: dict[str, Any],
    evidence: dict[str, bytes],
) -> dict[str, Any]:
    contract = json_map(evidence["capture_evidence_contract.json"], label="capture contract")
    summary = json_map(evidence["capture_run_summary.json"], label="capture summary")
    run_summary = json_map(evidence["run_summary.json"], label="run summary")
    device = json_map(evidence["device_preflight.json"], label="capture device preflight")
    match = json_map(evidence["portable_profile_match.json"], label="capture profile match")
    native = json_map(
        evidence["native_identity_verification.json"], label="native identity verification"
    )
    identity = json_map(evidence["identity_validation.json"], label="identity validation")
    invocation = json_map(evidence["zero_key_invocation.json"], label="zero-key invocation")
    cleanup = json_map(evidence["remote_cleanup.json"], label="remote cleanup")
    inventory = json_map(
        evidence["parser_runtime_inventory.json"], label="parser runtime inventory"
    )
    selection = json_map(
        evidence["parser_input_selection.json"], label="parser input selection"
    )
    parser_execution = json_map(
        evidence["parser_execution.json"], label="parser execution"
    )
    parser_report = json_map(evidence["parser_report.json"], label="parser report")

    profile_sha = profile["profile_sha256"]
    serial = target["serial"]
    boot_id = str(contract.get("capture_boot_id", "")).lower()
    exact_contract_paths = {
        "same_run_native_csr": "native_trigger_csr.cbor",
        "same_run_challenge": "native_trigger_challenge.bin",
        "device_preflight": "device_preflight.json",
        "profile_match": "portable_profile_match.json",
        "identity_scalar": "identity/google_rkp_sw_cdi_leaf_p256_scalar.bin",
        "identity_public_spki": "identity/cdi_leaf_public_spki.der",
    }
    if (
        contract.get("schema") != CAPTURE_CONTRACT_SCHEMA
        or contract.get("status") != "PASS"
        or contract.get("capture_method") != "stock_mitee_log_v1"
        or contract.get("profile_sha256") != profile_sha
        or contract.get("serial") != serial
        or BOOT_ID_RE.fullmatch(boot_id) is None
        or any(contract.get(key) != value for key, value in exact_contract_paths.items())
        or type(contract.get("zero_key_binder_invocations")) is not int
        or contract.get("zero_key_binder_invocations") != 1
        or type(contract.get("keys_to_sign_count")) is not int
        or contract.get("keys_to_sign_count") != 0
        or contract.get("stock_approval_environment") != "ELIGIBLE"
        or contract.get("legacy_capture_contract_compatible") is not False
        or contract.get("network_submitted") is not False
        or contract.get("private_material_printed") is not False
    ):
        raise SafeAbort("stock MiTEE-log capture contract is invalid")
    if evidence["capture_run_summary.json"] != evidence["run_summary.json"]:
        raise SafeAbort("capture summary copies differ")
    if (
        summary.get("schema") != "k70e-stock-cdi-log-capture-v1"
        or summary.get("status") != "PASS"
        or summary.get("capture_method") != "stock_mitee_log_v1"
        or summary.get("profile_sha256") != profile_sha
        or summary.get("serial") != serial
        or str(summary.get("boot_id", "")).lower() != boot_id
        or type(summary.get("zero_key_binder_invocations")) is not int
        or summary.get("zero_key_binder_invocations") != 1
        or type(summary.get("keys_to_sign_count")) is not int
        or summary.get("keys_to_sign_count") != 0
        or summary.get("stock_approval_environment") != "ELIGIBLE"
        or summary.get("scalar_matches_same_run_leaf") is not True
        or summary.get("network_submitted") is not False
        or summary.get("private_material_printed") is not False
    ):
        raise SafeAbort("capture summary does not prove one successful stock-log identity run")

    artifacts = profile["artifacts"]
    target = profile["target"]
    if (
        device.get("schema") != "k70e-stock-mitee-log-device-preflight-v1"
        or device.get("status") != "PASS"
        or device.get("capture_method") != "stock_mitee_log_v1"
        or device.get("profile_sha256") != profile_sha
        or device.get("serial") != serial
        or device.get("product") != target["product"]
        or device.get("slot") != target["slot_suffix"]
        or device.get("build_fingerprint") != target["build_fingerprint"]
        or str(device.get("boot_id", "")).lower() != boot_id
        or device.get("tee_disk_sha256") != artifacts["stock_tee"]["sha256"]
        or device.get("tee_disk_size") != artifacts["stock_tee"]["size"]
        or device.get("init_boot_disk_sha256") != artifacts["source_init_boot"]["sha256"]
        or device.get("init_boot_disk_size") != artifacts["source_init_boot"]["size"]
        or device.get("lk_a_sha256") != STOCK_LK_A_SHA256
        or device.get("lk_a_size") != STOCK_LK_A_SIZE
        or device.get("preloader_raw_a_sha256") != STOCK_PRELOADER_RAW_A_SHA256
        or device.get("preloader_raw_a_size") != STOCK_PRELOADER_RAW_A_SIZE
        or device.get("stock_early_boot_partitions_match_approved_baseline") is not True
        or device.get("global_ta_sha256") != artifacts["stock_ta"]["sha256"]
        or device.get("namespace_ta_sha256") != artifacts["stock_ta"]["sha256"]
        or device.get("services_ready") is not True
        or not isinstance(device.get("hlos_boot_properties"), dict)
        or device["hlos_boot_properties"].get("authoritative_for_approval") is not False
        or device.get("hlos_boot_properties_used_as_approval_gate") is not False
        or device.get("full_signed_environment_recheck_pending_zero_key_csr") is not True
        or device.get("private_material_printed") is not False
        or device.get("network_submitted") is not False
    ):
        raise SafeAbort("capture device preflight is not the exact stock environment")

    if (
        match.get("status") != "PASS"
        or match.get("profile_sha256") != profile_sha
        or match.get("capture_method") != "stock_mitee_log_v1"
        or match.get("same_run_zero_key_csr") is not True
        or match.get("network_issuance_allowed") is not True
        or match.get("approval_environment", {}).get("eligible") is not True
        or match.get("verdicts", {}).get("approval_environment") != "ELIGIBLE"
    ):
        raise SafeAbort("capture profile match is not network-eligible")
    if (
        native.get("schema") != "k70e-stock-mitee-log-native-identity-verification-v1"
        or native.get("status") != "PASS"
        or native.get("capture_method") != "stock_mitee_log_v1"
        or native.get("profile_sha256") != profile_sha
        or native.get("serial") != serial
        or str(native.get("capture_boot_id", "")).lower() != boot_id
        or native.get("keys_to_sign_count") != 0
        or native.get("dice_signatures_verified") != 5
        or native.get("outer_csr_signature_verified") is not True
        or native.get("stock_approval_environment") != "ELIGIBLE"
        or native.get("network_issuance_allowed_without_scalar") is not False
        or native.get("network_submitted") is not False
        or native.get("private_material_printed") is not False
    ):
        raise SafeAbort("native identity verification is invalid")
    if (
        identity.get("schema") != "k70e-stock-cdi-log-parser-validation-v1"
        or identity.get("status") != "PASS"
        or identity.get("profile_sha256") != profile_sha
        or identity.get("identity_length") != 32
        or identity.get("scalar_matches_same_run_leaf") is not True
        or identity.get("approval_environment_eligible") is not True
        or identity.get("network_issuance_allowed_by_relationship_gate") is not True
        or identity.get("network_submitted") is not False
        or identity.get("private_material_printed") is not False
    ):
        raise SafeAbort("parser identity validation is invalid")

    if (
        invocation.get("schema") != "k70e-stock-cdi-zero-key-invocation-v1"
        or invocation.get("state") != "INVOKED_ONCE"
        or invocation.get("profile_sha256") != profile_sha
        or invocation.get("serial") != serial
        or str(invocation.get("boot_id", "")).lower() != boot_id
        or invocation.get("requested_keys_to_sign_count") != 0
        or invocation.get("maximum_invocations_for_this_output") != 1
        or invocation.get("observed_invocation_count") != 1
        or invocation.get("client_returncode") != 0
        or invocation.get("client_timed_out") is not False
        or invocation.get("network_submitted") is not False
        or invocation.get("private_material_printed") is not False
    ):
        raise SafeAbort("zero-key invocation evidence is invalid")
    if (
        cleanup.get("removed") is not True
        or cleanup.get("invocation_dispatched_or_uncertain") is not True
        or cleanup.get("contained_only_public_challenge_csr_and_client") is not True
        or REMOTE_CAPTURE_RE.fullmatch(str(cleanup.get("remote_path", ""))) is None
        or "cleanup_error" in cleanup
    ):
        raise SafeAbort("capture remote cleanup is incomplete")

    parser_record = inventory.get("parser")
    auditor_record = inventory.get("profile_auditor")
    if (
        inventory.get("schema") != "k70e-stock-cdi-parser-runtime-v1"
        or inventory.get("parser_available") is not True
        or not isinstance(parser_record, dict)
        or not isinstance(auditor_record, dict)
        or inventory.get("private_material_present") is not False
        or inventory.get("network_access") is not False
        or contract.get("parser_source_snapshot") != parser_record
        or contract.get("profile_auditor_source_snapshot") != auditor_record
    ):
        raise SafeAbort("parser runtime inventory is invalid")
    if (
        parser_record.get("sha256") != sha256(evidence["parser_runtime/extract_k70e_cdi_leaf_from_mitee_log.py"])
        or parser_record.get("size") != len(evidence["parser_runtime/extract_k70e_cdi_leaf_from_mitee_log.py"])
        or auditor_record.get("sha256") != sha256(evidence["parser_runtime/k70e_portable_profile.py"])
        or auditor_record.get("size") != len(evidence["parser_runtime/k70e_portable_profile.py"])
    ):
        raise SafeAbort("parser runtime hashes do not match their snapshots")
    current_extractor = read_regular_nofollow(EXTRACTOR, label="current stock-log parser")
    current_auditor = read_regular_nofollow(PROFILE_HELPER, label="current profile auditor")
    if evidence["parser_runtime/extract_k70e_cdi_leaf_from_mitee_log.py"] != current_extractor:
        raise SafeAbort("capture parser snapshot is not the current audited parser")
    if evidence["parser_runtime/k70e_portable_profile.py"] != current_auditor:
        raise SafeAbort("capture profile-auditor snapshot is not current")

    selected_increment = str(selection.get("selected_increment", ""))
    selected_path = Path(selected_increment)
    try:
        selected_relative = selected_path.relative_to(root)
    except ValueError as exc:
        raise SafeAbort("selected parser increment is outside the capture") from exc
    if not selected_relative.parts[:2] == ("logs", "delta"):
        raise SafeAbort("selected parser increment is outside logs/delta")
    selected_raw = read_capture_file(root, str(selected_relative), label="selected log increment")
    if (
        selection.get("schema") != "k70e-stock-cdi-parser-input-selection-v1"
        or selection.get("status") != "READY"
        or selection.get("parser_invocations_planned") != 1
        or selection.get("rerun_zero_key_forbidden") is not True
        or selection.get("network_submitted") is not False
        or selection.get("private_log_bytes_printed") is not False
        or selection.get("selected_increment_sha256") != sha256(selected_raw)
        or parser_execution.get("schema") != "k70e-stock-cdi-log-parser-execution-v1"
        or parser_execution.get("returncode") != 0
        or parser_execution.get("parser_sha256") != parser_record["sha256"]
        or parser_execution.get("profile_auditor_sha256") != auditor_record["sha256"]
        or parser_execution.get("selected_increment_sha256") != sha256(selected_raw)
        or parser_execution.get("private_parser_output_printed") is not False
    ):
        raise SafeAbort("parser selection/execution evidence is invalid")
    if parser_report.get("schema") != "k70e-cdi-leaf-mitee-log-extract-v1" or parser_report.get("status") != "PASS":
        raise SafeAbort("parser report is invalid")
    if evidence["parser_report.json"] != evidence["parser_extraction/extraction_report.json"]:
        raise SafeAbort("parser report copies differ")

    return {
        "contract": contract,
        "summary": summary,
        "device": device,
        "match": match,
        "native": native,
        "identity": identity,
        "invocation": invocation,
        "cleanup": cleanup,
        "parser_execution": parser_execution,
        "parser_report": parser_report,
        "selected_increment_relative": str(selected_relative),
        "selected_increment_sha256": sha256(selected_raw),
    }


def capture_evidence_files(root: Path) -> dict[str, bytes]:
    required = (
        "capture_evidence_contract.json",
        "capture_run_summary.json",
        "run_summary.json",
        "device_preflight.json",
        "portable_profile_match.json",
        "native_identity_verification.json",
        "identity_validation.json",
        "zero_key_invocation.json",
        "remote_cleanup.json",
        "parser_runtime_inventory.json",
        "parser_input_selection.json",
        "parser_execution.json",
        "parser_report.json",
        "native_trigger_csr.cbor",
        "native_trigger_challenge.bin",
        "identity/google_rkp_sw_cdi_leaf_p256_scalar.bin",
        "identity/cdi_leaf_public_spki.der",
        "parser_runtime/extract_k70e_cdi_leaf_from_mitee_log.py",
        "parser_runtime/k70e_portable_profile.py",
        "parser_extraction/extraction_report.json",
        "parser_extraction/cdi_leaf_scalar.bin",
        "parser_extraction/cdi_leaf_public_spki.der",
    )
    return {relative: read_capture_file(root, relative, label=relative) for relative in required}


def build_preflight(profile_path: Path, capture_dir: Path, serial: str) -> tuple[FrozenCapture, Any]:
    if USB_SERIAL_RE.fullmatch(serial) is None or ":" in serial:
        raise SafeAbort("serial must be one exact USB ADB serial")
    candidate = capture_dir.expanduser()
    metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SafeAbort("capture directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SafeAbort("capture directory must be mode 0700")
    root = candidate.resolve(strict=True)
    profile, profile_raw = load_profile_snapshot(profile_path)
    if profile["target"]["serial"] != serial:
        raise SafeAbort("explicit serial does not match the current profile")
    evidence = capture_evidence_files(root)
    capture = validate_capture_contract(root, profile, evidence)

    scalar = evidence["identity/google_rkp_sw_cdi_leaf_p256_scalar.bin"]
    identity_spki = evidence["identity/cdi_leaf_public_spki.der"]
    csr = evidence["native_trigger_csr.cbor"]
    challenge = evidence["native_trigger_challenge.bin"]
    if scalar != evidence["parser_extraction/cdi_leaf_scalar.bin"]:
        raise SafeAbort("canonical and parser-extraction scalar copies differ")
    if identity_spki != evidence["parser_extraction/cdi_leaf_public_spki.der"]:
        raise SafeAbort("canonical and parser-extraction public SPKI copies differ")
    scalar_value = int.from_bytes(scalar, "big")
    if len(scalar) != 32 or not 1 <= scalar_value < P256_ORDER:
        raise SafeAbort("captured identity is not a legal P-256 scalar")
    derived_spki = ec.derive_private_key(scalar_value, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(derived_spki, identity_spki):
        raise SafeAbort("captured scalar does not derive the saved identity SPKI")

    audit = profile_lib.audit_authenticated_request(
        csr, challenge, expected_keys_to_sign_count=0
    )
    with tempfile.TemporaryDirectory(prefix="k70e_stock_log_preflight_") as directory:
        freeze = Path(directory)
        os.chmod(freeze, 0o700)
        scalar_path = freeze / "identity.bin"
        csr_path = freeze / "source.cbor"
        config_path = freeze / "device.conf"
        profile_lib.atomic_write(scalar_path, scalar, 0o600)
        profile_lib.atomic_write(csr_path, csr, 0o600)
        config_record = profile["artifacts"]["device_config"]
        config = read_regular_nofollow(Path(config_record["path"]), label="device config")
        if exact_hash_record(config) != {
            "size": config_record["size"],
            "sha256": config_record["sha256"],
        }:
            raise SafeAbort("device config changed from the current profile")
        profile_lib.atomic_write(config_path, config, 0o600)
        relationship = profile_lib.compare_audit_to_profile(
            audit, profile, scalar_path
        )
        if (
            relationship.get("status") != "PASS"
            or relationship.get("network_issuance_allowed") is not True
            or relationship.get("approval_environment", {}).get("eligible") is not True
            or relationship.get("verdicts", {}).get("approval_environment") != "ELIGIBLE"
        ):
            raise SafeAbort("same-run identity does not match the approved stock profile")

        # This call is mandatory: it verifies the allowlisted source and exact
        # gate-v7 version/capabilities, then returns an immutable source snapshot.
        rkp = portable.load_pinned_rkp(profile)
        if (
            getattr(rkp, "K70E_PORTABLE_ISSUANCE_GATE_VERSION", None) != 7
            or getattr(rkp, "K70E_PORTABLE_ISSUANCE_GATE_CAPABILITIES", None)
            != portable.REQUIRED_RKP_ISSUANCE_GATE_CAPABILITIES
        ):
            raise SafeAbort("core rkp_sw gate-v7 contract is unavailable")
        durability_patch = install_core_durability_patch(rkp)
        seed = rkp.resolve_p256_identity_scalar_file(str(scalar_path))
        keys = rkp.DeviceKeys(seed, curve="p256")
        chain, uds_certs, signed_device_info, dice_audit = rkp.load_verified_dice_chain(
            str(csr_path),
            keys,
            approval_expectations=(
                profile_lib.approval_expectations_from_loaded_profile(profile)
            ),
        )
        if (
            len(chain) != 6
            or uds_certs != {}
            or dice_audit.get("dice_signatures_verified") != 5
            or dice_audit.get("outer_source_signature_verified") is not True
            or dice_audit.get("source_keys_to_sign_count") != 0
        ):
            raise SafeAbort("core gate-v7 rejected the five-entry zero-key source")
        configured = rkp.load_device_config(str(config_path))
        if set(configured) != set(signed_device_info):
            raise SafeAbort("device config fields differ from signed DeviceInfo")
        for field, value in signed_device_info.items():
            if not profile_lib.typed_equal(configured.get(field), value):
                raise SafeAbort("device config differs from signed DeviceInfo")
        fingerprint = rkp.get_fingerprint(str(config_path))
        if fingerprint != profile["target"]["build_fingerprint"]:
            raise SafeAbort("device config fingerprint differs from the profile")

    evidence_hashes = {
        relative: exact_hash_record(raw) for relative, raw in sorted(evidence.items())
    }
    contract_sha = sha256(evidence["capture_evidence_contract.json"])
    report = {
        "schema": PREFLIGHT_SCHEMA,
        "status": "PASS",
        "checked_at": utc_now(),
        "profile_sha256": profile["profile_sha256"],
        "profile_file_sha256": sha256(profile_raw),
        "run_id": profile["run"]["run_id"],
        "serial": serial,
        "capture_method": "stock_mitee_log_v1",
        "capture_boot_id": capture["contract"]["capture_boot_id"],
        "capture_contract_sha256": contract_sha,
        "capture_evidence": evidence_hashes,
        "identity_file_sha256": sha256(scalar),
        "identity_public_spki_sha256": sha256(identity_spki),
        "source_request_sha256": audit["source_file_sha256"],
        "source_challenge_sha256": audit["challenge_sha256"],
        "source_uds_spki_sha256": audit["uds_spki_sha256"],
        "source_cdi_leaf_spki_sha256": audit["cdi_leaf_spki_sha256"],
        "dice_entry_count": audit["entry_count"],
        "dice_signatures_verified": audit["dice_signatures_verified"],
        "source_keys_to_sign_count": audit["keys_to_sign_count"],
        "scalar_matches_same_run_leaf": sha256(identity_spki)
        == audit["cdi_leaf_spki_sha256"],
        "approval_environment": relationship["approval_environment"],
        "profile_checks": relationship["checks"],
        "profile_verdicts": relationship["verdicts"],
        "network_issuance_allowed": relationship["network_issuance_allowed"],
        "core_rkp_gate_version": CORE_RKP_GATE_VERSION,
        "core_rkp_gate_capabilities": list(
            portable.REQUIRED_RKP_ISSUANCE_GATE_CAPABILITIES
        ),
        "core_rkp_sha256": profile["artifacts"]["rkp_sw"]["sha256"],
        "core_runtime_durability_patch": durability_patch,
        "consumer_runtime": {
            "python_realpath": str(EXPECTED_VENV_PYTHON_REALPATH),
            "python_size": len(_PYTHON_ENTITY_RAW),
            "python_sha256": sha256(_PYTHON_ENTITY_RAW),
            "profile_helper_size": len(_PROFILE_HELPER_RAW),
            "profile_helper_sha256": sha256(_PROFILE_HELPER_RAW),
            "portable_wrapper_size": len(_PORTABLE_WRAPPER_RAW),
            "portable_wrapper_sha256": sha256(_PORTABLE_WRAPPER_RAW),
        },
        "device_config_sha256": sha256(config),
        "fingerprint": fingerprint,
        "signed_dice_device_info_is_approval_authority": True,
        "hlos_boot_properties_used_as_approval_gate": False,
        "official_server_url": OFFICIAL_SERVER_URL,
        "requested_software_key_count": 1,
        "expected_certificate_chain_count": 1,
        "host_attempt_path": str(attempt_directory(root, profile, contract_sha)),
        "device_issuance_latch_path": profile["run"]["issuance_latch"],
        "network_access": False,
        "private_material_printed": False,
    }
    frozen = FrozenCapture(
        root=root,
        profile=profile,
        profile_raw=profile_raw,
        evidence=evidence,
        scalar=scalar,
        identity_spki=identity_spki,
        csr=csr,
        challenge=challenge,
        config=config,
        report=report,
    )
    return frozen, rkp


def attempt_directory(root: Path, profile: dict[str, Any], contract_sha: str) -> Path:
    return root / (
        f".stock_log_google_attempt_{profile['run']['run_id']}_{contract_sha[:12]}"
    )


def semantic_report(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("checked_at", None)
    return result


def require_official_url(url: str) -> str:
    if url != OFFICIAL_SERVER_URL:
        raise SafeAbort("only the official Google RKP endpoint is permitted")
    return url


def build_rkp_argv(
    rkp_path: Path,
    scalar_path: Path,
    config_path: Path,
    csr_path: Path,
    output_dir: Path,
    server_url: str,
) -> list[str]:
    require_official_url(server_url)
    return [
        str(rkp_path),
        "provision",
        "--seed-file",
        str(scalar_path),
        "--curve",
        "p256",
        "--config",
        str(config_path),
        "--dice-chain-file",
        str(csr_path),
        "--num-keys",
        "1",
        "--output-dir",
        str(output_dir),
        "--server-url",
        OFFICIAL_SERVER_URL,
    ]


def dispatch_after_network_marker(
    network_path: Path,
    network_value: dict[str, Any],
    invoke_once: Callable[[], Any],
    *,
    marker_writer: Callable[[Path, dict[str, Any]], bytes] = write_exclusive_json,
) -> Any:
    """The only dispatch primitive: durable marker first, exactly one call."""
    marker_writer(network_path, network_value)
    return invoke_once()


def parse_key_value_lines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key and key not in result:
                result[key] = value.strip()
    return result


def normalize_exact_shell_stdout(text: str) -> str:
    """Remove exactly one LF without hiding any other boundary byte."""
    if (
        not isinstance(text, str)
        or not text.endswith("\n")
        or text.endswith("\n\n")
        or "\n" in text
        or any(
            ord(character) > 0x7F
            or (ord(character) < 0x20 and character != "\n")
            or ord(character) == 0x7F
            for character in text
        )
    ):
        raise SafeAbort("live shell stdout lacks one exact terminal LF")
    body = text[:-1]
    if not body or body != body.strip(" \t\n\v\f"):
        raise SafeAbort("live shell stdout has forbidden boundary whitespace")
    return body


def parse_strict_key_value_inventory(
    text: str, *, expected_keys: tuple[str, ...]
) -> dict[str, str]:
    """Parse a closed, injection-resistant shell inventory contract."""
    if (
        not expected_keys
        or len(expected_keys) != len(set(expected_keys))
        or any(
            re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            for key in expected_keys
        )
    ):
        raise SafeAbort("live stock inventory parser contract is malformed")
    if (
        not text
        or "\n" in text
        or any(
            ord(character) > 0x7F
            or (ord(character) < 0x20 and character != "\n")
            or ord(character) == 0x7F
            for character in text
        )
    ):
        raise SafeAbort("live stock inventory is not strict ASCII text")
    lines = text.split("\n")
    if len(lines) != len(expected_keys):
        raise SafeAbort("live stock inventory key set is incomplete")
    observed: dict[str, str] = {}
    for line, expected_key in zip(lines, expected_keys):
        if (
            not line
            or line != line.strip()
            or line.count("=") != 1
        ):
            raise SafeAbort("live stock inventory line is malformed")
        key, value = line.split("=", 1)
        if (
            key != expected_key
            or re.fullmatch(r"[A-Za-z0-9._:/+-]+", value) is None
        ):
            raise SafeAbort("live stock inventory key or value is malformed")
        observed[key] = value
    return observed


def is_allowed_dummy_sink_default(route: str, *, family: int) -> bool:
    """Accept only the two observed netd dummy0 sink grammars."""
    tokens = route.split()
    if not tokens or tokens[0] != "default" or family not in {4, 6}:
        return False
    if any(token in {"via", "nexthop", "nhid", "encap"} for token in tokens):
        return False
    if tokens.count("dev") != 1 or tokens.count("table") != 1:
        return False
    base = ["default", "dev", "dummy0", "table", "1002"]
    if tokens == base:
        return True
    if family == 4:
        return tokens == base + ["proto", "static", "scope", "link"]
    return (
        len(tokens) == 11
        and tokens[:8] == base + ["proto", "static", "metric"]
        and re.fullmatch(r"[0-9]+", tokens[8]) is not None
        and tokens[9:] == ["pref", "medium"]
    )


IPV4_DUMMY_SINK_AWK = (
    '$1 == "default" { '
    'base=($2 == "dev" && $3 == "dummy0" && $4 == "table" && $5 == "1002"); '
    'sink=(base && NF == 5) || (base && NF == 9 && '
    '$6 == "proto" && $7 == "static" && $8 == "scope" && $9 == "link"); '
    'for (i=1; i<=NF; i++) if ($i == "via" || $i == "nexthop" || '
    '$i == "nhid" || $i == "encap") sink=0; if (!sink) bad=1 } '
    'END { exit bad ? 1 : 0 }'
)
IPV6_DUMMY_SINK_AWK = (
    '$1 == "default" { '
    'base=($2 == "dev" && $3 == "dummy0" && $4 == "table" && $5 == "1002"); '
    'sink=(base && NF == 5) || (base && NF == 11 && '
    '$6 == "proto" && $7 == "static" && $8 == "metric" && '
    '$9 ~ /^[0-9]+$/ && $10 == "pref" && $11 == "medium"); '
    'for (i=1; i<=NF; i++) if ($i == "via" || $i == "nexthop" || '
    '$i == "nhid" || $i == "encap") sink=0; if (!sink) bad=1 } '
    'END { exit bad ? 1 : 0 }'
)


def phone_offline_gate(shell: Callable[[str], str]) -> dict[str, Any]:
    """Prove the phone cannot route a concurrent RKP request."""
    raw = shell(
        "echo airplane=$(/system/bin/settings get global airplane_mode_on); "
        "echo wifi=$(/system/bin/settings get global wifi_on); "
        "echo ipv4_routes_begin; "
        "/system/bin/ip -4 route show table all 2>/dev/null; "
        "ipv4_route_rc=$?; echo ipv4_routes_end; "
        "echo ipv4_route_rc=$ipv4_route_rc; "
        "echo ipv6_routes_begin; "
        "/system/bin/ip -6 route show table all 2>/dev/null; "
        "ipv6_route_rc=$?; echo ipv6_routes_end; "
        "echo ipv6_route_rc=$ipv6_route_rc"
    )
    lines = raw.splitlines()
    values = parse_key_value_lines(raw)

    def route_block(family: int) -> list[str]:
        begin = f"ipv{family}_routes_begin"
        end = f"ipv{family}_routes_end"
        if lines.count(begin) != 1 or lines.count(end) != 1:
            raise SafeAbort("live phone offline proof was malformed")
        start_index = lines.index(begin) + 1
        end_index = lines.index(end)
        if end_index < start_index:
            raise SafeAbort("live phone offline proof had invalid route delimiters")
        return [line.strip() for line in lines[start_index:end_index] if line.strip()]

    ipv4_routes = route_block(4)
    ipv6_routes = route_block(6)
    route_rc_lines = {
        family: [line for line in lines if line.startswith(f"ipv{family}_route_rc=")]
        for family in (4, 6)
    }
    if any(
        route_rc_lines[family] != [f"ipv{family}_route_rc=0"]
        for family in (4, 6)
    ):
        raise SafeAbort("live phone route query failed")
    default_routes = [
        (family, line)
        for family, routes in ((4, ipv4_routes), (6, ipv6_routes))
        for line in routes
        if line.split()[:1] == ["default"]
    ]
    dummy_sink_routes = [
        (family, line)
        for family, line in default_routes
        if is_allowed_dummy_sink_default(line, family=family)
    ]
    forwarding_default_routes = [
        item for item in default_routes if item not in dummy_sink_routes
    ]
    if values.get("airplane") != "1":
        raise SafeAbort("phone airplane mode must remain enabled before issuance")
    if values.get("wifi") not in {"0", "null"}:
        raise SafeAbort("phone Wi-Fi must remain disabled before issuance")
    if forwarding_default_routes:
        raise SafeAbort("phone gained a forwarding default IP route before issuance")
    return {
        "status": "PASS",
        "airplane_mode_on": True,
        "wifi_disabled": True,
        "ipv4_route_query_succeeded": True,
        "ipv6_route_query_succeeded": True,
        "forwarding_default_route_count": 0,
        "ignored_dummy_sink_default_route_count": len(dummy_sink_routes),
        "route_inventory_sha256": sha256(
            "\n".join(
                [f"ipv4:{line}" for line in ipv4_routes]
                + [f"ipv6:{line}" for line in ipv6_routes]
            ).encode("utf-8")
        ),
    }


def run_host_raw(
    arguments: list[str], *, timeout: int = 300
) -> subprocess.CompletedProcess[bytes]:
    """Run without TextIOWrapper so CR bytes reach the strict validators."""
    return subprocess.run(
        arguments,
        text=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def decode_raw_ascii(data: bytes, *, label: str) -> str:
    if type(data) is not bytes:
        raise SafeAbort(f"{label} was not captured as raw bytes")
    try:
        return data.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise SafeAbort(f"{label} is not strict ASCII") from exc


def decode_raw_utf8(data: bytes, *, label: str) -> str:
    if type(data) is not bytes:
        raise SafeAbort(f"{label} was not captured as raw bytes")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SafeAbort(f"{label} is not strict UTF-8") from exc


def validate_unique_adb_inventory(text: str, serial: str) -> dict[str, Any]:
    """Require one well-formed ``adb devices -l`` record for the target."""
    if any(
        ord(character) > 0x7F
        or (ord(character) < 0x20 and character not in "\t\n")
        or ord(character) == 0x7F
        for character in text
    ):
        raise SafeAbort("ADB inventory is not strict ASCII")
    if "\n" in text.replace("\n", ""):
        raise SafeAbort("ADB inventory has malformed line endings")
    lines = text.replace("\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if len(lines) != 2 or lines[0] != "List of devices attached":
        raise SafeAbort("ADB inventory must contain exactly one device record")
    record = lines[1]
    if not record or record != record.strip():
        raise SafeAbort("ADB device record is malformed")
    fields = re.split(r"[ \t]+", record)
    if len(fields) < 2 or fields[0] != serial or fields[1] != "device":
        raise SafeAbort("the sole ADB record must be the pinned serial in state=device")
    details: dict[str, str] = {}
    for token in fields[2:]:
        key, separator, value = token.partition(":")
        if (
            separator != ":"
            or re.fullmatch(r"[A-Za-z0-9_.-]+", key) is None
            or not value
            or key in details
        ):
            raise SafeAbort("ADB device detail record is malformed")
        details[key] = value
    return {"serial": serial, "state": "device", "details": details}


def validate_unique_ioreg_android_transport(text: str, serial: str) -> dict[str, Any]:
    """Require one physical Android USB interface: the pinned K70E in ADB mode."""
    try:
        raw = text.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise SafeAbort("IORegistry inventory is not strict UTF-8") from exc
    if len(raw) > 8 * 1024 * 1024:
        raise SafeAbort("IORegistry inventory exceeds its safety limit")
    try:
        value = plistlib.loads(raw)
    except Exception as exc:
        raise SafeAbort("IORegistry USB-interface inventory is malformed") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SafeAbort("IORegistry USB-interface inventory has an unexpected shape")

    android: list[dict[str, Any]] = []
    for item in value:
        if item.get("USB Serial Number") == FORBIDDEN_PIXEL_USB_SERIAL:
            raise SafeAbort("forbidden Pixel remains physically present in IORegistry")
        if item.get("bInterfaceClass") != 255 or item.get("bInterfaceSubClass") != 66:
            continue
        protocol = item.get("bInterfaceProtocol")
        if type(protocol) is not int or protocol not in {1, 3}:
            raise SafeAbort("IORegistry contains an unknown Android USB transport")
        usb_serial = item.get("USB Serial Number")
        if (
            not isinstance(usb_serial, str)
            or USB_SERIAL_RE.fullmatch(usb_serial) is None
            or ":" in usb_serial
            or not usb_serial.isascii()
        ):
            raise SafeAbort("IORegistry Android USB serial is malformed")
        integer_fields = ("idVendor", "idProduct", "locationID", "IORegistryEntryID")
        if any(type(item.get(field)) is not int for field in integer_fields):
            raise SafeAbort("IORegistry Android USB identity is incomplete")
        for field in ("USB Vendor Name", "USB Product Name", "IORegistryEntryName"):
            field_value = item.get(field)
            if (
                not isinstance(field_value, str)
                or not field_value
                or not field_value.isascii()
            ):
                raise SafeAbort("IORegistry Android USB identity is malformed")
        android.append(
            {
                "serial": usb_serial,
                "protocol": protocol,
                "id_vendor": item["idVendor"],
                "id_product": item["idProduct"],
                "location_id": item["locationID"],
                "registry_entry_id": item["IORegistryEntryID"],
                "vendor_name": item["USB Vendor Name"],
                "product_name": item["USB Product Name"],
                "interface_name": item["IORegistryEntryName"],
            }
        )
    if len(android) != 1:
        raise SafeAbort("IORegistry must contain exactly one Android USB transport")
    observed = android[0]
    if (
        observed["serial"] != serial
        or observed["protocol"] != 1
        or observed["id_vendor"] != REFERENCE_USB_VENDOR_ID
        or observed["id_product"] != REFERENCE_USB_PRODUCT_ID
        or observed["vendor_name"] != REFERENCE_USB_VENDOR_NAME
        or observed["product_name"] != REFERENCE_USB_PRODUCT_NAME
        or observed["interface_name"] != "ADB Interface"
    ):
        raise SafeAbort("the sole physical Android USB transport is not the pinned K70E ADB interface")
    return observed


def validate_empty_fastboot_inventory(text: str) -> None:
    if any(
        ord(character) > 0x7F
        or (ord(character) < 0x20 and character not in "\t\n")
        or ord(character) == 0x7F
        for character in text
    ):
        raise SafeAbort("Fastboot inventory is not strict ASCII")
    if "\n" in text.replace("\n", ""):
        raise SafeAbort("Fastboot inventory has malformed line endings")
    if text.strip():
        raise SafeAbort("Fastboot must contain no transport while the pinned K70E is in ADB mode")


def strict_live_transport_inventory(profile: dict[str, Any], serial: str) -> dict[str, Any]:
    """Check physical USB, global ADB, and global Fastboot before any shell."""
    ioreg = run_host_raw(
        [IOREG_PATH, "-a", "-r", "-c", "IOUSBHostInterface", "-l"],
        timeout=30,
    )
    if ioreg.returncode != 0 or ioreg.stderr:
        raise SafeAbort("IORegistry Android USB inventory failed")
    physical = validate_unique_ioreg_android_transport(
        decode_raw_utf8(ioreg.stdout, label="IORegistry inventory"), serial
    )

    adb_path = profile["artifacts"]["adb_client"]["path"]
    adb = run_host_raw([adb_path, "devices", "-l"], timeout=30)
    if adb.returncode != 0 or adb.stderr:
        raise SafeAbort("ADB inventory failed during read-only live check")
    adb_record = validate_unique_adb_inventory(
        decode_raw_ascii(adb.stdout, label="ADB inventory"), serial
    )

    fastboot_path = Path(adb_path).with_name("fastboot")
    fastboot_raw = read_regular_nofollow(
        fastboot_path,
        label="pinned platform-tools fastboot",
        limit=16 * 1024 * 1024,
    )
    if exact_hash_record(fastboot_raw) != {
        "size": EXPECTED_FASTBOOT_SIZE,
        "sha256": EXPECTED_FASTBOOT_SHA256,
    }:
        raise SafeAbort("platform-tools fastboot bytes drifted")
    fastboot = run_host_raw([str(fastboot_path), "devices", "-l"], timeout=30)
    if fastboot.returncode != 0 or fastboot.stderr:
        raise SafeAbort("Fastboot inventory failed during read-only live check")
    validate_empty_fastboot_inventory(
        decode_raw_ascii(fastboot.stdout, label="Fastboot inventory")
    )
    return {
        "physical_android_usb": physical,
        "adb": adb_record,
        "fastboot_transport_count": 0,
        "fastboot_sha256": EXPECTED_FASTBOOT_SHA256,
    }


def live_stock_preflight_for_profile(
    profile: dict[str, Any],
    *,
    expected_boot_id: str | None,
) -> dict[str, Any]:
    target, artifacts = profile["target"], profile["artifacts"]
    adb_path = artifacts["adb_client"]["path"]
    serial = target["serial"]
    inventory = run_host_raw([adb_path, "devices", "-l"])
    if inventory.returncode != 0 or inventory.stderr:
        raise SafeAbort("ADB inventory failed before real issuance")
    validate_unique_adb_inventory(
        decode_raw_ascii(inventory.stdout, label="live ADB inventory"), serial
    )

    def shell(command: str, *, root: bool = False) -> str:
        remote = (
            f"{shlex.quote(target['magisk_path'])} su -c {shlex.quote(command)}"
            if root
            else command
        )
        result = run_host_raw([adb_path, "-s", serial, "shell", remote])
        if result.returncode != 0 or result.stderr:
            raise SafeAbort("live stock device check failed")
        return normalize_exact_shell_stdout(
            decode_raw_ascii(result.stdout, label="live stock shell stdout")
        )

    if shell("getprop ro.product.device") != target["product"]:
        raise SafeAbort("live product changed")
    if shell("getprop ro.boot.slot_suffix") != target["slot_suffix"]:
        raise SafeAbort("live slot changed")
    if shell("getprop ro.build.fingerprint") != target["build_fingerprint"]:
        raise SafeAbort("live build fingerprint changed")
    if shell("getprop sys.boot_completed") != "1":
        raise SafeAbort("live device is not boot-complete")
    if "uid=0" not in shell("id", root=True):
        raise SafeAbort("profile-pinned root is unavailable")
    offline = phone_offline_gate(shell)
    tee_part = target["tee_partition"]
    init_part = target["init_boot_partition"]
    ta_path = target["ta_path"]
    if any(
        not isinstance(partition, str)
        or re.fullmatch(r"[A-Za-z0-9._-]+", partition) is None
        for partition in (tee_part, init_part)
    ):
        raise SafeAbort("profile partition name is unsafe for the live shell")
    approved_partition_commands = "".join(
        f"echo {name}=$(/system/bin/sha256sum /dev/block/by-name/{name} | "
        "/system/bin/awk '{print $1}'); "
        f"echo {name}_size=$(/system/bin/blockdev --getsize64 "
        f"/dev/block/by-name/{name}); "
        for name, _size, _digest in APPROVED_A_SLOT_RAW_PARTITIONS
    )
    raw = shell(
        f"echo tee=$(/system/bin/sha256sum /dev/block/by-name/{tee_part} | /system/bin/awk '{{print $1}}'); "
        f"echo tee_size=$(/system/bin/blockdev --getsize64 /dev/block/by-name/{tee_part}); "
        f"echo init=$(/system/bin/sha256sum /dev/block/by-name/{init_part} | /system/bin/awk '{{print $1}}'); "
        f"echo init_size=$(/system/bin/blockdev --getsize64 /dev/block/by-name/{init_part}); "
        "echo lk_a=$(/system/bin/sha256sum /dev/block/by-name/lk_a | /system/bin/awk '{print $1}'); "
        "echo lk_a_size=$(/system/bin/blockdev --getsize64 /dev/block/by-name/lk_a); "
        "echo preloader_raw_a=$(/system/bin/sha256sum /dev/block/by-name/preloader_raw_a | /system/bin/awk '{print $1}'); "
        "echo preloader_raw_a_size=$(/system/bin/blockdev --getsize64 /dev/block/by-name/preloader_raw_a); "
        + approved_partition_commands
        + f"echo global_ta=$(/system/bin/sha256sum {shlex.quote(ta_path)} | /system/bin/awk '{{print $1}}'); "
        "pid=$(/system/bin/pidof tee-supplicant); "
        "case \"$pid\" in ''|*[!0123456789]*) exit 75 ;; esac; echo pid=$pid; "
        f"echo namespace_ta=$(/system/bin/nsenter -t \"$pid\" -m -- /system/bin/sha256sum {shlex.quote(ta_path)} | /system/bin/awk '{{print $1}}'); "
        "echo keymint=$(/system/bin/getprop init.svc.vendor.keymint-mitee); "
        "echo tee_supplicant=$(/system/bin/getprop init.svc.tee-supplicant); "
        "echo teefs=$(/system/bin/getprop vendor.teefs_state); "
        "echo boot_id=$(/system/bin/cat /proc/sys/kernel/random/boot_id); "
        "echo vb_state=$(/system/bin/getprop ro.boot.verifiedbootstate); "
        "echo bootloader_state=$(/system/bin/getprop ro.boot.vbmeta.device_state); "
        "echo vbmeta_size=$(/system/bin/getprop ro.boot.vbmeta.size); "
        "echo vbmeta_digest=$(/system/bin/getprop ro.boot.vbmeta.digest); "
        "echo build_host=<BUILD_HOST> ro.build.host); "
        "echo crypto_state=$(/system/bin/getprop ro.crypto.state); "
        "echo control_privapp_permissions=$(/system/bin/getprop ro.control_privapp_permissions); "
        "echo miui_build_region=$(/system/bin/getprop ro.miui.build.region); "
        "echo product_locale=$(/system/bin/getprop ro.product.locale)",
        root=True,
    )
    expected = {
        "tee": artifacts["stock_tee"]["sha256"],
        "tee_size": str(artifacts["stock_tee"]["size"]),
        "init": artifacts["source_init_boot"]["sha256"],
        "init_size": str(artifacts["source_init_boot"]["size"]),
        "lk_a": STOCK_LK_A_SHA256,
        "lk_a_size": str(STOCK_LK_A_SIZE),
        "preloader_raw_a": STOCK_PRELOADER_RAW_A_SHA256,
        "preloader_raw_a_size": str(STOCK_PRELOADER_RAW_A_SIZE),
        "global_ta": artifacts["stock_ta"]["sha256"],
        "namespace_ta": artifacts["stock_ta"]["sha256"],
        "keymint": "running",
        "tee_supplicant": "running",
        "teefs": "ready",
        **{
            key: value
            for key, value in KNOWN_GOOD_HLOS_PROVENANCE_SENTINEL.items()
        },
    }
    for name, size, digest in APPROVED_A_SLOT_RAW_PARTITIONS:
        expected[name] = digest
        expected[f"{name}_size"] = str(size)
    approved_partition_keys = tuple(
        key
        for name, _size, _digest in APPROVED_A_SLOT_RAW_PARTITIONS
        for key in (name, f"{name}_size")
    )
    observed = parse_strict_key_value_inventory(
        raw,
        expected_keys=(
            "tee",
            "tee_size",
            "init",
            "init_size",
            "lk_a",
            "lk_a_size",
            "preloader_raw_a",
            "preloader_raw_a_size",
            *approved_partition_keys,
            "global_ta",
            "pid",
            "namespace_ta",
            "keymint",
            "tee_supplicant",
            "teefs",
            "boot_id",
            "vb_state",
            "bootloader_state",
            *KNOWN_GOOD_HLOS_PROVENANCE_SENTINEL,
        ),
    )
    if expected_boot_id is not None:
        expected["boot_id"] = expected_boot_id
    if any(observed.get(key) != value for key, value in expected.items()):
        reason = (
            "live stock hashes or services differ from the profile"
            if expected_boot_id is None
            else "live stock hashes, services, or boot ID differ from capture"
        )
        raise SafeAbort(reason)
    if re.fullmatch(r"[0-9]+", observed.get("pid", "")) is None:
        raise SafeAbort("tee-supplicant must have exactly one ASCII-decimal PID")
    boot_id = str(observed.get("boot_id", "")).lower()
    if BOOT_ID_RE.fullmatch(boot_id) is None:
        raise SafeAbort("live kernel boot ID is malformed")
    return {
        "status": "PASS",
        "serial": serial,
        "boot_id": boot_id,
        "profile_sha256": profile["profile_sha256"],
        "stock_hashes_match": True,
        "lk_a_sha256": observed["lk_a"],
        "lk_a_size": int(observed["lk_a_size"]),
        "preloader_raw_a_sha256": observed["preloader_raw_a"],
        "preloader_raw_a_size": int(observed["preloader_raw_a_size"]),
        "stock_early_boot_partitions_match_approved_baseline": True,
        "approved_a_slot_raw_partitions_match": True,
        "approved_a_slot_raw_partitions": {
            name: {
                "sha256": observed[name],
                "size": int(observed[f"{name}_size"]),
            }
            for name, _size, _digest in APPROVED_A_SLOT_RAW_PARTITIONS
        },
        "services_ready": True,
        "remote_provisioning_command_ready": None,
        "remote_provisioning_command_probed": False,
        "phone_offline_gate": offline,
        "hlos_boot_properties": {
            "vb_state": observed.get("vb_state"),
            "bootloader_state": observed.get("bootloader_state"),
            "vbmeta_size": observed["vbmeta_size"],
            "vbmeta_digest": observed.get("vbmeta_digest"),
            "build_host": observed["build_host"],
            "crypto_state": observed["crypto_state"],
            "control_privapp_permissions": observed[
                "control_privapp_permissions"
            ],
            "miui_build_region": observed["miui_build_region"],
            "product_locale": observed["product_locale"],
            "known_good_provenance_sentinel_match": True,
            "used_only_as_negative_environment_exclusion_gate": True,
            "authoritative_for_approval": False,
            "cannot_replace_same_run_signed_deviceinfo_or_dice": True,
        },
        "hlos_boot_properties_used_as_approval_gate": False,
        "hlos_boot_properties_used_as_negative_environment_exclusion_gate": True,
        "private_material_printed": False,
    }


def live_stock_preflight(frozen: FrozenCapture) -> dict[str, Any]:
    return live_stock_preflight_for_profile(
        frozen.profile,
        expected_boot_id=frozen.report["capture_boot_id"],
    )


def execute_live_check_only(profile_path: Path, serial: str) -> dict[str, Any]:
    """Perform only repeatable inventories and read-only live environment checks."""
    profile = load_live_check_profile_readonly(profile_path, serial)
    transport_before = strict_live_transport_inventory(profile, serial)
    live = live_stock_preflight_for_profile(profile, expected_boot_id=None)
    transport_after = strict_live_transport_inventory(profile, serial)
    if not profile_lib.typed_equal(transport_before, transport_after):
        raise SafeAbort("physical, ADB, or Fastboot inventory drifted during live check")
    return {
        "schema": LIVE_CHECK_SCHEMA,
        "status": "PASS",
        "serial": serial,
        "profile_sha256": profile["profile_sha256"],
        "transport_inventory": transport_after,
        "live_stock_preflight": live,
        "capture_read": False,
        "private_key_read": False,
        "private_key_generated": False,
        "device_write_performed": False,
        "binder_invoked": False,
        "network_access": False,
        "one_shot_state_created": False,
        "private_material_printed": False,
    }


def exact_device_latch_paths(profile: dict[str, Any]) -> tuple[str, str]:
    run = profile["run"]
    run_id = run["run_id"]
    expected_state = f"/metadata/watchdog/k70e_cdi_leaf_{run_id}"
    expected_latch = f"{expected_state}/google_issuance_used_{run_id}"
    if (
        run.get("state_dir") != expected_state
        or run.get("issuance_latch") != expected_latch
        or PurePosixPath(expected_state).parent != PurePosixPath("/metadata/watchdog")
        or PurePosixPath(expected_latch).parent != PurePosixPath(expected_state)
    ):
        raise SafeAbort("profile device issuance latch paths are not exactly derived")
    return expected_state, expected_latch


def prepare_device_latch_parent(frozen: FrozenCapture) -> dict[str, Any]:
    """Idempotently prepare only the fresh run's parent, before point-of-no-return."""
    profile = frozen.profile
    target, artifacts = profile["target"], profile["artifacts"]
    adb_path = artifacts["adb_client"]["path"]
    serial = target["serial"]
    state_dir, latch = exact_device_latch_paths(profile)
    boot_id = frozen.report["capture_boot_id"]
    command = (
        "set -eu; umask 077; "
        f"[ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" = {shlex.quote(boot_id)} ]; "
        "[ -d /metadata/watchdog ]; [ ! -L /metadata/watchdog ]; "
        f"if [ -e {shlex.quote(state_dir)} ] || [ -L {shlex.quote(state_dir)} ]; then "
        f"[ -d {shlex.quote(state_dir)} ]; [ ! -L {shlex.quote(state_dir)} ]; "
        f"else /system/bin/mkdir {shlex.quote(state_dir)}; fi; "
        f"/system/bin/chmod 0700 {shlex.quote(state_dir)}; "
        f"[ \"$(/system/bin/stat -c %a {shlex.quote(state_dir)})\" = 700 ]; "
        f"[ ! -e {shlex.quote(latch)} ]; [ ! -L {shlex.quote(latch)} ]; "
        "/system/bin/sync; echo STOCK_LOG_STATE_DIR_READY"
    )
    remote = f"{shlex.quote(target['magisk_path'])} su -c {shlex.quote(command)}"
    result = run_host_raw([adb_path, "-s", serial, "shell", remote])
    try:
        success_stdout = normalize_exact_shell_stdout(
            decode_raw_ascii(result.stdout, label="device state-dir shell stdout")
        )
    except SafeAbort as exc:
        raise SafeAbort("fresh stock-log state directory returned malformed stdout") from exc
    if (
        result.returncode != 0
        or result.stderr
        or success_stdout != "STOCK_LOG_STATE_DIR_READY"
    ):
        raise SafeAbort("fresh stock-log device state directory could not be prepared")
    return {
        "status": "PASS",
        "serial": serial,
        "boot_id": boot_id,
        "state_dir": state_dir,
        "state_dir_mode": "0700",
        "issuance_latch_path": latch,
        "issuance_latch_absent": True,
        "issuance_latch_created": False,
        "point_of_no_return_consumed": False,
        "private_material_printed": False,
    }


def device_latch_contract(frozen: FrozenCapture) -> dict[str, Any]:
    """Return the deterministic successful device-latch commitment."""
    profile = frozen.profile
    _, latch = exact_device_latch_paths(profile)
    return {
        "device_latch_consumed": True,
        "device_latch_path": latch,
        "device_latch_profile_sha256": profile["profile_sha256"],
        "device_latch_run_id": profile["run"]["run_id"],
        "device_latch_capture_boot_id": frozen.report["capture_boot_id"],
        "device_latch_capture_contract_sha256": frozen.report[
            "capture_contract_sha256"
        ],
    }


def reserve_device_latch(
    frozen: FrozenCapture, *, expected_transport_inventory: dict[str, Any]
) -> dict[str, Any]:
    profile = frozen.profile
    target, artifacts, run = profile["target"], profile["artifacts"], profile["run"]
    serial = target["serial"]
    transport_inventory = strict_live_transport_inventory(profile, serial)
    if not profile_lib.typed_equal(
        expected_transport_inventory, transport_inventory
    ):
        raise SafeAbort(
            "physical, ADB, or Fastboot inventory drifted before device latch"
        )
    adb_path = artifacts["adb_client"]["path"]
    state_dir, latch = exact_device_latch_paths(profile)
    boot_id = frozen.report["capture_boot_id"]
    contract_sha = frozen.report["capture_contract_sha256"]
    tee_part = target["tee_partition"]
    init_part = target["init_boot_partition"]
    ta_path = target["ta_path"]
    if any(
        not isinstance(partition, str)
        or re.fullmatch(r"[A-Za-z0-9._-]+", partition) is None
        for partition in (tee_part, init_part)
    ):
        raise SafeAbort("profile partition name is unsafe for the latch shell")
    approved_partition_assertions = "".join(
        f"[ \"$(/system/bin/sha256sum /dev/block/by-name/{name} | "
        f"/system/bin/awk '{{print $1}}')\" = {shlex.quote(digest)} ]; "
        f"[ \"$(/system/bin/blockdev --getsize64 /dev/block/by-name/{name})\" "
        f"= {size} ]; "
        for name, size, digest in APPROVED_A_SLOT_RAW_PARTITIONS
    )
    provenance_assertions = "".join(
        f"[ \"$(/system/bin/getprop {property_name})\" = "
        f"{shlex.quote(KNOWN_GOOD_HLOS_PROVENANCE_SENTINEL[key])} ]; "
        for key, property_name in (
            ("vbmeta_size", "ro.boot.vbmeta.size"),
            ("vbmeta_digest", "ro.boot.vbmeta.digest"),
            ("build_host", "ro.build.host"),
            ("crypto_state", "ro.crypto.state"),
            (
                "control_privapp_permissions",
                "ro.control_privapp_permissions",
            ),
            ("miui_build_region", "ro.miui.build.region"),
            ("product_locale", "ro.product.locale"),
        )
    )
    command = (
        "set -eu; umask 077; "
        f"[ \"$(/system/bin/cat /proc/sys/kernel/random/boot_id)\" = {shlex.quote(boot_id)} ]; "
        f"[ -d {shlex.quote(state_dir)} ]; [ ! -L {shlex.quote(state_dir)} ]; "
        f"[ \"$(/system/bin/stat -c %a {shlex.quote(state_dir)})\" = 700 ]; "
        f"[ \"$(/system/bin/sha256sum /dev/block/by-name/{tee_part} | /system/bin/awk '{{print $1}}')\" = {artifacts['stock_tee']['sha256']} ]; "
        f"[ \"$(/system/bin/blockdev --getsize64 /dev/block/by-name/{tee_part})\" = {artifacts['stock_tee']['size']} ]; "
        f"[ \"$(/system/bin/sha256sum /dev/block/by-name/{init_part} | /system/bin/awk '{{print $1}}')\" = {artifacts['source_init_boot']['sha256']} ]; "
        f"[ \"$(/system/bin/blockdev --getsize64 /dev/block/by-name/{init_part})\" = {artifacts['source_init_boot']['size']} ]; "
        f"[ \"$(/system/bin/blockdev --getsize64 /dev/block/by-name/lk_a)\" = {STOCK_LK_A_SIZE} ]; "
        f"[ \"$(/system/bin/sha256sum /dev/block/by-name/lk_a | /system/bin/awk '{{print $1}}')\" = {STOCK_LK_A_SHA256} ]; "
        f"[ \"$(/system/bin/blockdev --getsize64 /dev/block/by-name/preloader_raw_a)\" = {STOCK_PRELOADER_RAW_A_SIZE} ]; "
        f"[ \"$(/system/bin/sha256sum /dev/block/by-name/preloader_raw_a | /system/bin/awk '{{print $1}}')\" = {STOCK_PRELOADER_RAW_A_SHA256} ]; "
        + approved_partition_assertions
        + f"[ \"$(/system/bin/sha256sum {shlex.quote(ta_path)} | /system/bin/awk '{{print $1}}')\" = {artifacts['stock_ta']['sha256']} ]; "
        "pid=$(/system/bin/pidof tee-supplicant); "
        "case \"$pid\" in ''|*[!0123456789]*) exit 75 ;; esac; "
        f"[ \"$(/system/bin/nsenter -t \"$pid\" -m -- /system/bin/sha256sum {shlex.quote(ta_path)} | /system/bin/awk '{{print $1}}')\" = {artifacts['stock_ta']['sha256']} ]; "
        "[ \"$(/system/bin/getprop init.svc.vendor.keymint-mitee)\" = running ]; "
        "[ \"$(/system/bin/getprop init.svc.tee-supplicant)\" = running ]; "
        "[ \"$(/system/bin/getprop vendor.teefs_state)\" = ready ]; "
        + provenance_assertions
        + "[ \"$(/system/bin/settings get global airplane_mode_on)\" = 1 ]; "
        "wifi=$(/system/bin/settings get global wifi_on); "
        "case \"$wifi\" in 0|null) ;; *) exit 72 ;; esac; "
        "routes4=$(/system/bin/ip -4 route show table all 2>/dev/null) || exit 73; "
        "routes6=$(/system/bin/ip -6 route show table all 2>/dev/null) || exit 74; "
        f"/system/bin/printf '%s\\n' \"$routes4\" | /system/bin/awk {shlex.quote(IPV4_DUMMY_SINK_AWK)} || exit 73; "
        f"/system/bin/printf '%s\\n' \"$routes6\" | /system/bin/awk {shlex.quote(IPV6_DUMMY_SINK_AWK)} || exit 74; "
        "/system/bin/cmd remote_provisioning help >/dev/null; "
        f"/system/bin/mkdir {shlex.quote(latch)}; /system/bin/chmod 0700 {shlex.quote(latch)}; "
        f"/system/bin/printf '%s\\n' {shlex.quote(profile['profile_sha256'])} > {shlex.quote(latch + '/PROFILE_SHA256')}; "
        f"/system/bin/printf '%s\\n' {shlex.quote(run['run_id'])} > {shlex.quote(latch + '/RUN_ID')}; "
        f"/system/bin/printf '%s\\n' {shlex.quote(boot_id)} > {shlex.quote(latch + '/CAPTURE_BOOT_ID')}; "
        f"/system/bin/printf '%s\\n' {shlex.quote(contract_sha)} > {shlex.quote(latch + '/CAPTURE_CONTRACT_SHA256')}; "
        f"/system/bin/printf '%s\\n' stock_mitee_log_v1 > {shlex.quote(latch + '/CAPTURE_METHOD')}; "
        "/system/bin/sync; echo STOCK_LOG_GOOGLE_ISSUANCE_LATCH_CONSUMED"
    )
    remote = f"{shlex.quote(target['magisk_path'])} su -c {shlex.quote(command)}"
    result = run_host_raw([adb_path, "-s", serial, "shell", remote])
    try:
        success_stdout = normalize_exact_shell_stdout(
            decode_raw_ascii(result.stdout, label="device latch shell stdout")
        )
    except SafeAbort as exc:
        raise SafeAbort(
            "device issuance latch returned malformed stdout; attempt is burned"
        ) from exc
    if (
        result.returncode != 0
        or result.stderr
        or success_stdout != "STOCK_LOG_GOOGLE_ISSUANCE_LATCH_CONSUMED"
    ):
        raise SafeAbort("device issuance latch could not be consumed; attempt is burned")
    return device_latch_contract(frozen)


def reserve_host_attempt(frozen: FrozenCapture, output_dir: Path) -> tuple[Path, bytes]:
    attempt = Path(frozen.report["host_attempt_path"])
    if os.path.lexists(attempt):
        raise SafeAbort("this stock-log capture already has an issuance attempt; retry forbidden")
    os.mkdir(attempt, 0o700)
    fsync_directory(attempt.parent)
    device_latch = device_latch_contract(frozen)
    device_latch_snapshot = attempt / "DEVICE_LATCH.json"
    device_latch_raw = (
        json.dumps(device_latch, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    marker = {
        "schema": ATTEMPT_SCHEMA,
        "status": "BURNED_ON_RESERVATION",
        "reserved_at": utc_now(),
        "profile_sha256": frozen.profile["profile_sha256"],
        "run_id": frozen.profile["run"]["run_id"],
        "capture_contract_sha256": frozen.report["capture_contract_sha256"],
        "capture_boot_id": frozen.report["capture_boot_id"],
        "serial": frozen.profile["target"]["serial"],
        "requested_software_key_count": 1,
        "expected_certificate_chain_count": 1,
        "server_url": OFFICIAL_SERVER_URL,
        "output_dir": str(output_dir),
        "device_latch_snapshot_path": str(device_latch_snapshot.resolve()),
        "device_latch_snapshot_sha256": sha256(device_latch_raw),
        **device_latch,
        "retry_allowed": False,
        "private_material_printed": False,
    }
    raw = write_exclusive_json(attempt / "ATTEMPT.json", marker)
    return attempt, raw


def invoke_pinned_rkp(rkp: Any, argv: list[str]) -> tuple[bytes, bytes]:
    stdout, stderr = io.StringIO(), io.StringIO()
    saved_argv = sys.argv
    try:
        sys.argv = argv
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                result = rkp.main()
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise SafeAbort("core google-rkp-sw failed after attempt burn") from exc
                result = 0
        if result not in (None, 0):
            raise SafeAbort("core google-rkp-sw returned failure after attempt burn")
    finally:
        sys.argv = saved_argv
    return stdout.getvalue().encode("utf-8"), stderr.getvalue().encode("utf-8")


def verify_certificate_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    public = issuer.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        public.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm,
        )
    elif isinstance(public, ec.EllipticCurvePublicKey):
        public.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    elif isinstance(public, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public.verify(child.signature, child.tbs_certificate_bytes)
    else:
        raise SafeAbort("Google chain uses an unsupported signature key")


def strict_output_tree(root: Path) -> None:
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SafeAbort("provision output is not a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SafeAbort("provision output root is not mode 0700")
    for path in root.rglob("*"):
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode):
            raise SafeAbort("provision output contains a symlink")
        if stat.S_ISDIR(item.st_mode):
            if stat.S_IMODE(item.st_mode) != 0o700:
                raise SafeAbort("provision output contains a non-0700 directory")
        elif stat.S_ISREG(item.st_mode):
            if stat.S_IMODE(item.st_mode) != 0o600:
                raise SafeAbort("provision output contains a non-0600 file")
        else:
            raise SafeAbort("provision output contains a special file")


def output_file(root: Path, relative: str, label: str) -> bytes:
    return read_regular_nofollow(capture_path(root, relative), label=label)


def http_record(root: Path, body_name: str, metadata_name: str) -> tuple[bytes, dict[str, Any]]:
    body = output_file(root, body_name, body_name)
    metadata = json_map(output_file(root, metadata_name, metadata_name), label=metadata_name)
    if (
        metadata.get("status") != 200
        or metadata.get("response_len") != len(body)
        or metadata.get("body_sha256") != sha256(body)
    ):
        raise SafeAbort("saved Google HTTP response metadata is inconsistent")
    return body, metadata


def enforce_ctf_provisioning_info_policy(pi: dict[str, Any]) -> bool:
    """Enforce the event rule while reporting Android's independent verdict."""
    if (
        pi.get("schema") != "google-rkp-provisioning-info-chain-audit-v2"
        or pi.get("ctf_no_not_approved") is not True
    ):
        raise ProvisioningInfoRejected(
            "Google result has rejected ProvisioningInfo; attempt is burned and retry forbidden"
        )
    # Historical accepted Xiaomi leaves use {1: 8, 3: "Xiaomi"} and therefore
    # legitimately report false for the separate current Android CDDL check.
    # That diagnostic must never be substituted for the CTF rule above.
    return pi.get("android_schema_current_strict") is True


def audit_issued_output(
    rkp: Any, frozen: FrozenCapture, output: Path
) -> dict[str, Any]:
    strict_output_tree(output)
    key_dirs = sorted(path.name for path in output.glob("key_*") if path.is_dir())
    chain_dirs = sorted(path.name for path in output.glob("chain_*") if path.is_dir())
    if key_dirs != ["key_00"] or chain_dirs != ["chain_00"]:
        raise SafeAbort("issuance did not produce exactly one key and one chain")

    private_pem = output_file(output, "key_00/private_key_pkcs8.pem", "software private key")
    public_spki = output_file(output, "key_00/public_key_spki.der", "software public key")
    private = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
        private.curve, ec.SECP256R1
    ):
        raise SafeAbort("generated software key is not P-256")
    derived_public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(derived_public, public_spki):
        raise SafeAbort("saved software public key does not match its private key")
    if hmac.compare_digest(public_spki, frozen.identity_spki):
        raise SafeAbort("software key must be distinct from the CDI identity")
    key_summary = json_map(
        output_file(output, "key_00/key_summary.json", "software key summary"),
        label="software key summary",
    )
    if (
        key_summary.get("private_key_sha256") != sha256(private_pem)
        or key_summary.get("public_key_sha256") != sha256(public_spki)
    ):
        raise SafeAbort("software key summary is inconsistent")

    fetch_body, fetch_meta = http_record(
        output, "fetch_eek_response.cbor", "fetch_eek_response_http.json"
    )
    fetch_url = urlparse(str(fetch_meta.get("url", "")))
    if (
        fetch_url.scheme,
        fetch_url.netloc,
        fetch_url.path,
        fetch_url.query,
        fetch_url.fragment,
    ) != ("https", "remoteprovisioning.googleapis.com", "/v1:fetchEekChain", "", ""):
        raise SafeAbort("fetchEekChain did not use the exact official endpoint")
    fetch_value = profile_lib.decode_one_cbor(fetch_body)
    if isinstance(fetch_value, list) and len(fetch_value) == 1 and isinstance(fetch_value[0], list):
        fetch_value = fetch_value[0]
    if not (
        isinstance(fetch_value, list)
        and len(fetch_value) >= 2
        and isinstance(fetch_value[1], bytes)
    ):
        raise SafeAbort("fetchEekChain response has no challenge")
    fresh_challenge = fetch_value[1]

    request = output_file(output, "certificate_request.cbor", "software certificate request")
    request_audit = profile_lib.audit_authenticated_request(
        request, fresh_challenge, expected_keys_to_sign_count=1
    )
    with tempfile.TemporaryDirectory(prefix="k70e_stock_log_output_audit_") as directory:
        scalar_path = Path(directory) / "identity.bin"
        profile_lib.atomic_write(scalar_path, frozen.scalar, 0o600)
        relationship = profile_lib.compare_audit_to_profile(
            request_audit, frozen.profile, scalar_path
        )
    if relationship.get("network_issuance_allowed") is not True:
        raise SafeAbort("software request lost the approved stock environment")
    request_value = profile_lib.decode_one_cbor(request)
    source_value = profile_lib.decode_one_cbor(frozen.csr)
    if not profile_lib.typed_equal(request_value[1], source_value[1]) or not profile_lib.typed_equal(
        request_value[2], source_value[2]
    ):
        raise SafeAbort("software request changed the verified source DICE chain")
    if request_audit.get("keys_to_sign_spki_sha256") != [sha256(public_spki)]:
        raise SafeAbort("software request does not contain exactly the generated public key")
    request_preflight = json_map(
        output_file(
            output,
            "request_preflight_verification.json",
            "request preflight verification",
        ),
        label="request preflight verification",
    )
    if (
        request_preflight.get("status") != "PASS"
        or request_preflight.get("request_sha256") != sha256(request)
        or request_preflight.get("fresh_challenge_sha256") != sha256(fresh_challenge)
        or request_preflight.get("keys_to_sign_count") != 1
        or request_preflight.get("all_private_keys_match") is not True
        or request_preflight.get("source_dice_chain_exact_match") is not True
        or request_preflight.get("source_uds_certs_exact_match") is not True
        or request_preflight.get("source_device_info_exact_match") is not True
    ):
        raise SafeAbort("core request preflight is incomplete")

    sign_body, sign_meta = http_record(
        output,
        "response.cbor",
        "response_http.json",
    )
    sign_url = urlparse(str(sign_meta.get("url", "")))
    if (
        sign_url.scheme,
        sign_url.netloc,
        sign_url.path,
        sign_url.fragment,
    ) != ("https", "remoteprovisioning.googleapis.com", "/v1:signCertificates", ""):
        raise SafeAbort("signCertificates did not use the exact official endpoint")
    try:
        sign_query = parse_qs(sign_url.query, strict_parsing=True)
    except ValueError as exc:
        raise SafeAbort("signCertificates query is malformed") from exc
    expected_challenge = base64.urlsafe_b64encode(fresh_challenge).decode("ascii")
    if (
        set(sign_query) != {"challenge", "request_id"}
        or sign_query.get("challenge") != [expected_challenge]
        or len(sign_query.get("request_id", [])) != 1
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            sign_query["request_id"][0],
            re.IGNORECASE,
        )
        is None
    ):
        raise SafeAbort("signCertificates URL is not exactly challenge-bound")

    server_chain = output_file(
        output, "chain_00/certificate_chain.der", "server certificate chain"
    )
    ordered_chain = output_file(
        output, "chain_00/ordered_certificate_chain.der", "ordered certificate chain"
    )
    server_certs = rkp.parse_der_cert_chain(server_chain)
    certs = rkp.parse_der_cert_chain(ordered_chain)
    if len(certs) != 4 or len(server_certs) != 4:
        raise SafeAbort("Google response is not the expected four-certificate chain")
    if b"".join(cert.public_bytes(serialization.Encoding.DER) for cert in certs) != ordered_chain:
        raise SafeAbort("ordered certificate chain has trailing or omitted bytes")
    if sorted(sha256(cert.public_bytes(serialization.Encoding.DER)) for cert in certs) != sorted(
        sha256(cert.public_bytes(serialization.Encoding.DER)) for cert in server_certs
    ):
        raise SafeAbort("server and ordered certificate chains differ")
    sign_value = profile_lib.decode_one_cbor(sign_body)
    if isinstance(sign_value, list) and len(sign_value) == 1 and isinstance(sign_value[0], list):
        sign_value = sign_value[0]
    if not (
        isinstance(sign_value, list)
        and len(sign_value) == 2
        and isinstance(sign_value[0], bytes)
        and isinstance(sign_value[1], list)
        and len(sign_value[1]) == 1
        and isinstance(sign_value[1][0], bytes)
        and sign_value[1][0] + sign_value[0] == server_chain
    ):
        raise SafeAbort("raw signCertificates response does not encode the saved one chain")
    leaf_spki = certs[0].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if not hmac.compare_digest(leaf_spki, public_spki):
        raise SafeAbort("Google leaf certificate does not match the software private key")
    for child, issuer in zip(certs, certs[1:]):
        if child.issuer != issuer.subject:
            raise SafeAbort("Google certificate issuer/subject linkage is broken")
        verify_certificate_signature(child, issuer)
    if certs[-1].issuer != certs[-1].subject:
        raise SafeAbort("Google root certificate is not self-issued")
    verify_certificate_signature(certs[-1], certs[-1])
    root_der = certs[-1].public_bytes(serialization.Encoding.DER)
    root_spki = certs[-1].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if sha256(root_der) not in TRUSTED_GOOGLE_ROOT_DER_SHA256 or sha256(
        root_spki
    ) not in TRUSTED_GOOGLE_ROOT_SPKI_SHA256:
        raise SafeAbort("certificate chain does not terminate at the pinned Google root")

    pi = rkp.audit_provisioning_info_chain(certs)
    android_schema_current_strict = enforce_ctf_provisioning_info_policy(pi)
    chain_summary = json_map(
        output_file(output, "chain_00/chain_summary.json", "chain summary"),
        label="chain summary",
    )
    if (
        chain_summary.get("certificate_count") != 4
        or chain_summary.get("leaf_public_matches_private_public") is not True
        or chain_summary.get("all_der_bytes_consumed") is not True
        or chain_summary.get("signature_links_valid") is not True
        or chain_summary.get("root_self_signature_valid") is not True
        or chain_summary.get("ordered_chain_sha256") != sha256(ordered_chain)
        or chain_summary.get("provisioning_info_audit") != pi
    ):
        raise SafeAbort("core chain summary differs from independent validation")
    summary_raw = output_file(output, "run_summary.json", "provision run summary")
    summary = json_map(summary_raw, label="provision run summary")
    if (
        summary.get("status") != "complete"
        or summary.get("requested_key_count") != 1
        or summary.get("received_chain_count") != 1
        or summary.get("server_url") != OFFICIAL_SERVER_URL
        or summary.get("dice_chain_mode") != "verified_native_proper_chain"
        or summary.get("device_info_source") != "native_authenticated_request"
        or summary.get("request_sha256") != sha256(request)
        or summary.get("ctf_no_not_approved") is not True
        or type(summary.get("android_schema_current_strict")) is not bool
        or summary.get("android_schema_current_strict")
        is not android_schema_current_strict
    ):
        raise SafeAbort("core run summary is not one complete approved issuance")
    return {
        "schema": STRICT_AUDIT_SCHEMA,
        "status": "PASS",
        "audited_at": utc_now(),
        "profile_sha256": frozen.profile["profile_sha256"],
        "capture_contract_sha256": frozen.report["capture_contract_sha256"],
        "official_server_url": OFFICIAL_SERVER_URL,
        "requested_software_key_count": 1,
        "received_certificate_chain_count": 1,
        "software_key_is_p256": True,
        "software_private_public_match": True,
        "software_request_one_key_verified": True,
        "proper_dice_source_preserved": True,
        "certificate_count": 4,
        "certificate_signatures_verified": True,
        "trusted_google_root_verified": True,
        "leaf_matches_software_private_key": True,
        "provisioning_info_ctf_no_not_approved": True,
        "provisioning_info_android_schema_current_strict": android_schema_current_strict,
        "identity_scalar_sha256": sha256(frozen.scalar),
        "identity_public_spki_sha256": sha256(frozen.identity_spki),
        "source_zero_key_csr_sha256": sha256(frozen.csr),
        "source_zero_key_challenge_sha256": sha256(frozen.challenge),
        "source_cdi_leaf_spki_sha256": frozen.report["source_cdi_leaf_spki_sha256"],
        "identity_scalar_derives_public_spki": True,
        "identity_public_spki_matches_source_cdi_leaf": True,
        "software_private_key_pkcs8_sha256": sha256(private_pem),
        "software_public_spki_sha256": sha256(public_spki),
        "ordered_chain_sha256": sha256(ordered_chain),
        "provision_run_summary_sha256": sha256(summary_raw),
        "private_material_printed": False,
    }


SUCCESS_REQUIRED_TRUE = (
    "software_key_is_p256",
    "software_private_public_match",
    "software_request_one_key_verified",
    "proper_dice_source_preserved",
    "certificate_signatures_verified",
    "trusted_google_root_verified",
    "leaf_matches_software_private_key",
    "provisioning_info_ctf_no_not_approved",
    "identity_scalar_derives_public_spki",
    "identity_public_spki_matches_source_cdi_leaf",
)


def commit_success_markers(
    attempt_success: Path,
    output_success: Path,
    *,
    frozen: FrozenCapture,
    strict_audit: dict[str, Any],
    attempt_raw: bytes,
    network_raw: bytes,
) -> bytes:
    if (
        strict_audit.get("schema") != STRICT_AUDIT_SCHEMA
        or strict_audit.get("status") != "PASS"
        or strict_audit.get("official_server_url") != OFFICIAL_SERVER_URL
        or strict_audit.get("requested_software_key_count") != 1
        or strict_audit.get("received_certificate_chain_count") != 1
        or type(strict_audit.get("provisioning_info_android_schema_current_strict"))
        is not bool
        or strict_audit.get("identity_scalar_sha256") != sha256(frozen.scalar)
        or strict_audit.get("identity_public_spki_sha256")
        != sha256(frozen.identity_spki)
        or strict_audit.get("source_zero_key_csr_sha256") != sha256(frozen.csr)
        or strict_audit.get("source_zero_key_challenge_sha256")
        != sha256(frozen.challenge)
        or strict_audit.get("source_cdi_leaf_spki_sha256")
        != sha256(frozen.identity_spki)
        or any(strict_audit.get(field) is not True for field in SUCCESS_REQUIRED_TRUE)
    ):
        raise ProvisioningInfoRejected(
            "independent chain/key/ProvisioningInfo audit did not authorize SUCCESS"
        )
    marker = {
        "schema": SUCCESS_SCHEMA,
        "status": "SUCCESS",
        "completed_at": utc_now(),
        "profile_sha256": frozen.profile["profile_sha256"],
        "run_id": frozen.profile["run"]["run_id"],
        "capture_contract_sha256": frozen.report["capture_contract_sha256"],
        "capture_boot_id": frozen.report["capture_boot_id"],
        "server_url": OFFICIAL_SERVER_URL,
        "requested_software_key_count": 1,
        "received_certificate_chain_count": 1,
        "attempt_sha256": sha256(attempt_raw),
        "network_started_sha256": sha256(network_raw),
        "strict_audit_sha256": sha256(
            (json.dumps(strict_audit, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ),
        "provisioning_info_ctf_no_not_approved": True,
        "provisioning_info_android_schema_current_strict": strict_audit[
            "provisioning_info_android_schema_current_strict"
        ],
        "identity_scalar_sha256": strict_audit["identity_scalar_sha256"],
        "identity_public_spki_sha256": strict_audit["identity_public_spki_sha256"],
        "source_zero_key_csr_sha256": strict_audit["source_zero_key_csr_sha256"],
        "source_zero_key_challenge_sha256": strict_audit[
            "source_zero_key_challenge_sha256"
        ],
        "source_cdi_leaf_spki_sha256": strict_audit[
            "source_cdi_leaf_spki_sha256"
        ],
        "identity_scalar_path": "identity/google_rkp_sw_cdi_leaf_p256_scalar.bin",
        "identity_public_spki_path": "identity/cdi_leaf_public_spki.der",
        "source_zero_key_csr_path": "identity/native_zero_key_csr.cbor",
        "source_zero_key_challenge_path": "identity/native_zero_key_challenge.bin",
        "software_private_key_path": "key_00/private_key_pkcs8.pem",
        "software_private_key_pkcs8_sha256": strict_audit[
            "software_private_key_pkcs8_sha256"
        ],
        "software_public_spki_path": "key_00/public_key_spki.der",
        "software_public_spki_sha256": strict_audit["software_public_spki_sha256"],
        "ordered_certificate_chain_path": "chain_00/ordered_certificate_chain.der",
        "ordered_certificate_chain_sha256": strict_audit["ordered_chain_sha256"],
        "identity_scalar_derives_public_spki": True,
        "identity_public_spki_matches_source_cdi_leaf": True,
        "retry_allowed": False,
        "private_material_printed": False,
    }
    raw = write_exclusive_json(attempt_success, marker)
    write_exclusive_bytes(output_success, raw)
    return raw


def mark_burned(attempt: Path, frozen: FrozenCapture, reason: str) -> None:
    path = attempt / "BURNED.json"
    if os.path.lexists(path):
        return
    try:
        write_exclusive_json(
            path,
            {
                "schema": BURN_SCHEMA,
                "status": "BURNED_NO_RETRY",
                "burned_at": utc_now(),
                "profile_sha256": frozen.profile["profile_sha256"],
                "capture_contract_sha256": frozen.report["capture_contract_sha256"],
                "reason": reason,
                "retry_allowed": False,
                "private_material_printed": False,
            },
        )
    except OSError:
        pass


def validate_output_target(path: Path, frozen: FrozenCapture) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink() or os.path.lexists(candidate):
        raise SafeAbort("provision output must be a new non-symlink path")
    parent = candidate.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_dir():
        raise SafeAbort("provision output parent must be a real directory")
    if shutil.disk_usage(parent).free < 64 * 1024 * 1024:
        raise SafeAbort("provision output volume has less than 64 MiB free")
    output = parent / candidate.name
    attempt = Path(frozen.report["host_attempt_path"])
    if output == frozen.root or frozen.root in output.parents or output in frozen.root.parents:
        raise SafeAbort("provision output must not overlap the capture")
    if output == attempt or attempt in output.parents or output in attempt.parents:
        raise SafeAbort("provision output must not overlap the attempt latch")
    descriptor, probe_name = tempfile.mkstemp(prefix=".stock_log_rkp_probe_", dir=parent)
    try:
        os.write(descriptor, b"K70E\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        Path(probe_name).unlink()
    fsync_directory(parent)
    return output


def execute_google_once(
    frozen: FrozenCapture,
    rkp: Any,
    saved_report_raw: bytes,
    preflight_report_path: Path,
    output: Path,
) -> dict[str, Any]:
    require_core_durability_patch(rkp)
    transport_inventory = strict_live_transport_inventory(
        frozen.profile, frozen.profile["target"]["serial"]
    )
    # Physical transport and stock state are read before any device shell that
    # can mutate state.  After host reservation execute rechecks it explicitly;
    # reserve_device_latch() closes the remaining race with one final inventory
    # immediately before its atomic boot/hash/service/provenance shell.
    live = live_stock_preflight(frozen)
    prepared = prepare_device_latch_parent(frozen)
    attempt, attempt_raw = reserve_host_attempt(frozen, output)
    scalar_path = attempt / "identity_scalar.frozen.bin"
    csr_path = attempt / "native_request.frozen.cbor"
    config_path = attempt / "device_config.frozen.conf"
    runtime_profile_path = attempt / "runtime_profile.frozen.json"
    approval_evidence_path = attempt / "approval_evidence.frozen.json"
    profile_helper_path = attempt / "k70e_portable_profile.frozen.py"
    approval_evidence_raw = (
        json.dumps(
            frozen.profile["approval_baseline"]["evidence"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    try:
        write_exclusive_bytes(scalar_path, frozen.scalar)
        write_exclusive_bytes(csr_path, frozen.csr)
        write_exclusive_bytes(config_path, frozen.config)
        write_exclusive_bytes(runtime_profile_path, frozen.profile_raw)
        write_exclusive_bytes(approval_evidence_path, approval_evidence_raw)
        write_exclusive_bytes(profile_helper_path, _PROFILE_HELPER_RAW)
        write_exclusive_json(attempt / "LIVE_STOCK_PREFLIGHT.json", live)
        write_exclusive_json(attempt / "DEVICE_STATE_DIR_PREPARED.json", prepared)
        transport_recheck = strict_live_transport_inventory(
            frozen.profile, frozen.profile["target"]["serial"]
        )
        if not profile_lib.typed_equal(
            transport_inventory, transport_recheck
        ):
            raise SafeAbort(
                "physical, ADB, or Fastboot inventory drifted before device latch"
            )
        device_latch = reserve_device_latch(
            frozen, expected_transport_inventory=transport_inventory
        )
        device_latch_path = attempt / "DEVICE_LATCH.json"
        device_latch_raw = write_exclusive_json(device_latch_path, device_latch)
        network_path = attempt / "NETWORK_STARTED.json"
        network_value = {
            "schema": NETWORK_SCHEMA,
            "status": "STARTING",
            "created_at": utc_now(),
            "profile_sha256": frozen.profile["profile_sha256"],
            "run_id": frozen.profile["run"]["run_id"],
            "capture_contract_sha256": frozen.report["capture_contract_sha256"],
            "capture_boot_id": frozen.report["capture_boot_id"],
            "preflight_report_sha256": sha256(saved_report_raw),
            "identity_file_sha256": sha256(frozen.scalar),
            "source_request_sha256": sha256(frozen.csr),
            "device_config_sha256": sha256(frozen.config),
            "runtime_profile_snapshot_path": str(runtime_profile_path.resolve()),
            "runtime_profile_file_sha256": sha256(frozen.profile_raw),
            "approval_evidence_snapshot_path": str(
                approval_evidence_path.resolve()
            ),
            "approval_evidence_snapshot_sha256": sha256(approval_evidence_raw),
            "profile_helper_snapshot_path": str(profile_helper_path.resolve()),
            "profile_helper_sha256": sha256(_PROFILE_HELPER_RAW),
            "device_latch_snapshot_path": str(device_latch_path.resolve()),
            "device_latch_snapshot_sha256": sha256(device_latch_raw),
            **device_latch,
            "requested_software_key_count": 1,
            "expected_certificate_chain_count": 1,
            "server_url": OFFICIAL_SERVER_URL,
            "network_issuance_allowed": True,
            "attempt_marker_sha256": sha256(attempt_raw),
            "output_dir": str(output),
            "retry_allowed": False,
            "meaning": "durably written before the sole core rkp_sw.main invocation",
            "private_material_printed": False,
        }
        argv = build_rkp_argv(
            Path(rkp.__file__),
            scalar_path,
            config_path,
            csr_path,
            output,
            OFFICIAL_SERVER_URL,
        )

        def invoke() -> tuple[bytes, bytes]:
            network_raw = read_regular_nofollow(
                network_path, label="stock-log network STARTING marker"
            )
            rkp._arm_k70e_profile_bound_dispatch_once(
                output_dir=str(output),
                seed_file=str(scalar_path),
                dice_chain_file=str(csr_path),
                config_path=str(config_path),
                server_url=OFFICIAL_SERVER_URL,
                num_keys=1,
                network_marker_path=str(network_path),
                network_marker_sha256=sha256(network_raw),
                attempt_marker_path=str(attempt / "ATTEMPT.json"),
                attempt_marker_sha256=sha256(attempt_raw),
                preflight_report_path=str(preflight_report_path),
                preflight_report_sha256=sha256(saved_report_raw),
                runtime_profile_snapshot_path=str(runtime_profile_path),
                runtime_profile_file_sha256=sha256(frozen.profile_raw),
                approval_evidence_snapshot_path=str(approval_evidence_path),
                approval_evidence_snapshot_sha256=sha256(
                    approval_evidence_raw
                ),
                profile_helper_snapshot_path=str(profile_helper_path),
                profile_helper_sha256=sha256(_PROFILE_HELPER_RAW),
                device_latch_snapshot_path=str(device_latch_path),
                device_latch_snapshot_sha256=sha256(device_latch_raw),
                profile_sha256=frozen.profile["profile_sha256"],
                run_id=frozen.profile["run"]["run_id"],
                dispatch_contract="stock-log",
            )
            return invoke_pinned_rkp(rkp, argv)

        stdout, stderr = dispatch_after_network_marker(
            network_path, network_value, invoke
        )
        write_exclusive_bytes(attempt / "rkp_stdout.private.txt", stdout)
        write_exclusive_bytes(attempt / "rkp_stderr.private.txt", stderr)
        if output.is_dir():
            portable.durably_sync_output_tree(output)
        if not output.is_dir():
            raise SafeAbort("core provisioning did not create its output directory")
        strict_audit = audit_issued_output(rkp, frozen, output)
        strict_raw = write_exclusive_json(
            output / "stock_log_strict_issuance_audit.json", strict_audit
        )
        write_exclusive_bytes(
            output / "identity/google_rkp_sw_cdi_leaf_p256_scalar.bin",
            frozen.scalar,
        )
        write_exclusive_bytes(
            output / "identity/cdi_leaf_public_spki.der", frozen.identity_spki
        )
        write_exclusive_bytes(
            output / "identity/native_zero_key_csr.cbor", frozen.csr
        )
        write_exclusive_bytes(
            output / "identity/native_zero_key_challenge.bin", frozen.challenge
        )
        write_exclusive_bytes(output / "stock_log_preflight_used.json", saved_report_raw)
        write_exclusive_bytes(output / "stock_log_capture_contract_used.json", frozen.evidence["capture_evidence_contract.json"])
        write_exclusive_bytes(output / "stock_log_runtime_profile_used.json", frozen.profile_raw)
        write_exclusive_bytes(
            output / "rkp_sw_used.py",
            read_regular_nofollow(Path(rkp.__file__), label="pinned core rkp snapshot"),
        )
        strict_output_tree(output)
        portable.durably_sync_output_tree(output)
        network_raw = read_regular_nofollow(network_path, label="network-start marker")
        commit_success_markers(
            attempt / "SUCCESS.json",
            output / "stock_log_issuance_success.json",
            frozen=frozen,
            strict_audit=strict_audit,
            attempt_raw=attempt_raw,
            network_raw=network_raw,
        )
        portable.durably_sync_output_tree(output)
        del strict_raw
        return {
            "status": "SUCCESS",
            "output_dir": str(output),
            "requested_software_key_count": 1,
            "received_certificate_chain_count": 1,
            "server_url": OFFICIAL_SERVER_URL,
            "retry_allowed": False,
            "private_material_printed": False,
        }
    except BaseException as exc:
        if output.is_dir():
            try:
                portable.durably_sync_output_tree(output)
            except BaseException:
                pass
        mark_burned(attempt, frozen, type(exc).__name__)
        raise
    finally:
        if not scalar_path.is_symlink() and scalar_path.is_file():
            scalar_path.unlink()
            fsync_directory(attempt)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--preflight-report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--server-url", default=OFFICIAL_SERVER_URL)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--live-check-only", action="store_true")
    parser.add_argument("--execute-google-once", action="store_true")
    parser.add_argument("--attended", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    os.umask(0o077)
    selected_modes = sum(
        bool(value)
        for value in (
            arguments.live_check_only,
            arguments.preflight_only,
            arguments.execute_google_once,
        )
    )
    if selected_modes != 1:
        raise SafeAbort(
            "choose exactly one of --live-check-only, --preflight-only, "
            "or --execute-google-once"
        )
    if arguments.live_check_only:
        if arguments.attended:
            raise SafeAbort("--live-check-only must not claim attended authorization")
        if any(
            value is not None
            for value in (
                arguments.capture_dir,
                arguments.preflight_report,
                arguments.output_dir,
            )
        ):
            raise SafeAbort(
                "--live-check-only does not accept capture, preflight-report, or output paths"
            )
        require_official_url(arguments.server_url)
        result = execute_live_check_only(arguments.profile, arguments.serial)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.execute_google_once and not arguments.attended:
        raise SafeAbort("real issuance requires --attended")
    if arguments.preflight_only and arguments.attended:
        raise SafeAbort("--attended is valid only with --execute-google-once")
    if arguments.capture_dir is None:
        raise SafeAbort("preflight and issuance modes require --capture-dir")
    require_official_url(arguments.server_url)
    frozen, rkp = build_preflight(
        arguments.profile, arguments.capture_dir, arguments.serial
    )
    report_candidate = (
        arguments.preflight_report.expanduser()
        if arguments.preflight_report is not None
        else frozen.root / "stock_log_provision_preflight.json"
    )
    if report_candidate.is_symlink():
        raise SafeAbort("preflight report must not be a symlink")
    report_path = report_candidate.absolute()
    if report_path.parent != frozen.root or report_path.suffix != ".json":
        raise SafeAbort("preflight report must be a direct JSON child of capture-dir")
    if arguments.preflight_only:
        if arguments.output_dir is not None:
            raise SafeAbort("--preflight-only does not accept --output-dir")
        write_exclusive_json(report_path, frozen.report)
        print(json.dumps(frozen.report, indent=2, sort_keys=True))
        return 0

    if arguments.output_dir is None:
        raise SafeAbort("real issuance requires --output-dir")
    saved_report_raw = read_regular_nofollow(
        report_path, label="exclusive stock-log preflight report"
    )
    saved_report = json_map(saved_report_raw, label="exclusive stock-log preflight report")
    if saved_report.get("schema") != PREFLIGHT_SCHEMA or saved_report.get("status") != "PASS":
        raise SafeAbort("saved preflight report is invalid")
    if not profile_lib.typed_equal(
        semantic_report(saved_report), semantic_report(frozen.report)
    ):
        raise SafeAbort("saved preflight report no longer matches frozen inputs")
    if saved_report.get("network_issuance_allowed") is not True:
        raise SafeAbort("saved preflight does not authorize network issuance")
    output = validate_output_target(arguments.output_dir, frozen)
    if os.path.lexists(Path(frozen.report["host_attempt_path"])):
        raise SafeAbort("capture already has a burned or completed issuance attempt")
    result = execute_google_once(
        frozen, rkp, saved_report_raw, report_path, output
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        SafeAbort,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        message = str(exc) if isinstance(exc, SafeAbort) else type(exc).__name__
        print(f"SAFE_ABORT: {message}", file=sys.stderr)
        raise SystemExit(1)
