#!/usr/bin/env python3
"""Host-only audit of the K70E KeyMint begin/update/finish Binder ABI.

This file deliberately does *not* open a device, talk to adb/fastboot, attach
with ptrace, or invoke a KeyMint operation.  It reads the archived stock
service, the archived V3 stable-AIDL support library, the SDK generated Java
sources, and (optionally) the row03 opaque key blob.  The output is a compact
protocol/frame specification that can be reviewed before somebody chooses to
run a separately gated client on a device.

The important distinction is between the Binder frame and the internal
MiTEE/keymaster frame.  Binder transaction 10 returns an IKeyMintOperation
strong binder.  The returned object owns the internal uint64 operation handle;
the handle is not a field supplied by update/finish Binder callers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import re
import struct
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).resolve()
K70_ROOT = SCRIPT.parents[1]
WORK_ROOT = K70_ROOT.parent
DEFAULT_BLOB = (
    K70_ROOT
    / "03_提取结果/K70E_HAL单把密钥期间内存采样_20260829_02/keygen_all"
    / "rkp_03_private_key_blob.bin"
)
DEFAULT_SERVICE = (
    K70_ROOT
    / "03_提取结果/K70E_stock只读运行备份_20260829_当前/device_vendor"
    / "android.hardware.security.keymint@3.0-service.mitee"
)
DEFAULT_NDK = WORK_ROOT / "out/k70e_vendor/extracted_stock/lib64/android.hardware.security.keymint-V3-ndk.so"
DEFAULT_AIDL_DEVICE = Path(
    "<HOST_SDK>/Android/sdk/sources/android-36"
    "/android/hardware/security/keymint/IKeyMintDevice.java"
)
DEFAULT_AIDL_OPERATION = Path(
    "<HOST_SDK>/Android/sdk/sources/android-36"
    "/android/hardware/security/keymint/IKeyMintOperation.java"
)


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def align4(value: int) -> int:
    return (value + 3) & ~3


def byte_array_size(length: int | None) -> int:
    """AParcel/Parcel byte[] footprint, excluding the implicit Binder header."""

    # A negative length is the nullable-array marker and has no payload.
    if length is None or length < 0:
        return 4
    return 4 + align4(length)


def typed_object_size(body_size: int | None) -> int:
    """Nullable typed-object footprint (presence int + body if present)."""

    return 4 if body_size is None else 4 + body_size


def key_parameter_body_size(value_kind: str = "digest") -> int:
    """Generated KeyParameter parcelable size for one scalar union value.

    KeyParameter.writeToParcel writes: size(4), tag(4), typed-value marker(4),
    then KeyParameterValue's union tag/value (8 for all scalar enum/int kinds).
    """

    if value_kind not in {"digest", "integer", "algorithm", "purpose"}:
        raise ValueError(value_kind)
    return 4 + 4 + 4 + 4 + 4


def frame_layout(blob_len: int, message_len: int = 32) -> dict[str, Any]:
    """Return Binder argument footprints and field offsets.

    The NDK stable-AIDL transaction header is intentionally not included: it is
    platform-owned and is inserted by AIBinder_prepareTransaction after the
    binder has been associated with its interface class.
    """

    begin_empty = [
        ("purpose:int32", 4),
        (f"keyBlob:byte[{blob_len}]", byte_array_size(blob_len)),
        ("params:typed_array[0]", 4),
        ("authToken:null", typed_object_size(None)),
    ]
    one_param = 4 + key_parameter_body_size("digest")  # array element marker + body
    begin_digest = [
        ("purpose:int32", 4),
        (f"keyBlob:byte[{blob_len}]", byte_array_size(blob_len)),
        ("params:typed_array[1]", 4 + one_param),
        ("authToken:null", typed_object_size(None)),
    ]
    update = [
        (f"input:byte[{message_len}]", byte_array_size(message_len)),
        ("authToken:null", typed_object_size(None)),
        ("timeStampToken:null", typed_object_size(None)),
    ]
    finish = [
        (f"input:byte[{message_len}]", byte_array_size(message_len)),
        ("signature:null", byte_array_size(None)),
        ("authToken:null", typed_object_size(None)),
        ("timeStampToken:null", typed_object_size(None)),
        ("confirmationToken:null", byte_array_size(None)),
    ]

    def annotate(items: list[tuple[str, int]]) -> dict[str, Any]:
        pos = 0
        fields = []
        for name, size in items:
            fields.append({"field": name, "offset": pos, "size": size})
            pos += size
        return {"fields": fields, "body_size_without_header": pos}

    return {
        "header_note": "AIBinder_prepareTransaction inserts the stable-AIDL interface header; do not hand-code it.",
        "begin_txn_10_empty_params": annotate(begin_empty),
        "begin_txn_10_one_digest_none_param": annotate(begin_digest),
        "update_txn_2_input_len_32": annotate(update),
        "finish_txn_3_input_len_32_null_signature": annotate(finish),
        "abort_txn_4_body": {"fields": [], "body_size_without_header": 0},
        "key_parameter_digest_none": {
            "tag": "Tag.DIGEST = 0x20000005",
            "union_tag": 4,
            "union_value": 0,
            "parcelable_body_size": key_parameter_body_size("digest"),
            "array_element_size_including_presence": one_param,
        },
    }


def extract_debug_elf(path: Path) -> bytes | None:
    """Decompress an ELF .gnu_debugdata section, if present."""

    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return None
    if not path.is_file():
        return None
    with path.open("rb") as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(".gnu_debugdata")
        if section is None:
            return None
        try:
            return lzma.decompress(section.data())
        except lzma.LZMAError:
            return None


def symbol_map(elf_bytes: bytes | None) -> dict[str, tuple[int, int]]:
    if not elf_bytes:
        return {}
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return {}
    from io import BytesIO

    result: dict[str, tuple[int, int]] = {}
    with BytesIO(elf_bytes) as f:
        elf = ELFFile(f)
        for section_name in (".symtab", ".dynsym"):
            section = elf.get_section_by_name(section_name)
            if section is None:
                continue
            for sym in section.iter_symbols():
                if sym.name:
                    result[sym.name] = (int(sym["st_value"]), int(sym["st_size"]))
    return result


def load_text(path: Path) -> tuple[bytes, int]:
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return b"", 0
    with path.open("rb") as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(".text")
        if section is None:
            return b"", 0
        return section.data(), int(section["sh_addr"])


def disasm_instructions(path: Path, start: int, size: int) -> list[Any]:
    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    except Exception:
        return []
    text, text_va = load_text(path)
    if not text or start < text_va or start - text_va >= len(text):
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return list(md.disasm(text[start - text_va : start - text_va + size], start))


def instruction_at(path: Path, address: int) -> dict[str, Any] | None:
    ins = disasm_instructions(path, address, 4)
    if not ins:
        return None
    i = ins[0]
    return {"address": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str, "bytes": i.bytes.hex()}


def service_audit(path: Path) -> dict[str, Any]:
    symbols = symbol_map(extract_debug_elf(path))
    wanted = {
        "device_begin": "MiteeKeyMintDevice5begin",
        "operation_update": "MiteeKeyMintOperation6update",
        "operation_finish": "MiteeKeyMintOperation6finish",
        "operation_abort": "MiteeKeyMintOperation5abort",
        "operation_ctor": "MiteeKeyMintOperationC1",
    }
    found: dict[str, Any] = {}
    for label, needle in wanted.items():
        matches = [(name, value[0], value[1]) for name, value in symbols.items() if needle in name]
        found[label] = [
            {"symbol": name, "va": hex(value), "size": size}
            for name, value, size in sorted(matches, key=lambda x: x[1])
        ]

    # Call sites and the ctor store are stable in the archived stock build.
    call_checks = {
        # The begin body performs cleanup/argument setup immediately before
        # the wrapper call at 0xEECC.  0xEDCC is only `mov x0, x24`.
        "begin_to_mitee_cmd_0x04": (0xEECC, 0xB5F0),
        "update_to_mitee_cmd_0x08": (0x11E68, 0xB670),
        "finish_to_mitee_cmd_0x0c": (0x1227C, 0xB6F0),
        "abort_to_mitee_cmd_0x10": (0x12498, 0xB770),
    }
    calls: dict[str, Any] = {}
    for label, (address, expected_target) in call_checks.items():
        ins = disasm_instructions(path, address, 4)
        actual = None
        if ins and ins[0].mnemonic == "bl":
            match = re.search(r"#0x([0-9a-f]+)", ins[0].op_str)
            if match:
                actual = int(match.group(1), 16)
        calls[label] = {
            "instruction": instruction_at(path, address),
            "expected_target": hex(expected_target),
            "decoded_target": hex(actual) if actual is not None else None,
            "match": actual == expected_target,
        }

    ctor_store = instruction_at(path, 0x117EC)
    return {
        "path": str(path),
        "sha256": sha256(path),
        "debug_symbols": found,
        "internal_command_calls": calls,
        "operation_handle": {
            "constructor_store_instruction": ctor_store,
            "field_offset": "this+0x60",
            "field_type": "uint64 operation_handle",
            "note": "update/finish requests copy this field; Binder callers never supply it",
        },
    }


def ndk_audit(path: Path) -> dict[str, Any]:
    symbols = symbol_map(path.read_bytes() if path.is_file() else None)
    needles = {
        "bp_device_begin": "BpKeyMintDevice5begin",
        "bp_operation_update": "BpKeyMintOperation6update",
        "bp_operation_finish": "BpKeyMintOperation6finish",
        "bp_operation_abort": "BpKeyMintOperation5abort",
        "begin_result_read": "BeginResult14readFromParcel",
        "begin_result_write": "BeginResult13writeToParcel",
        "key_parameter_write": "KeyParameter13writeToParcel",
    }
    found: dict[str, Any] = {}
    for label, needle in needles.items():
        matches = [(name, value[0], value[1]) for name, value in symbols.items() if needle in name]
        found[label] = [
            {"symbol": name, "va": hex(value), "size": size}
            for name, value, size in sorted(matches, key=lambda x: x[1])
        ]

    # These are the generated Bp call-site transaction immediates in the stock
    # V3 support library.  They independently verify 10/2/3/4.
    call_checks = {
        "begin": (0xF104, 10),
        "update": (0x13594, 2),
        "finish": (0x1386C, 3),
        "abort": (0x13A78, 4),
    }
    calls: dict[str, Any] = {}
    for label, (address, expected) in call_checks.items():
        ins = disasm_instructions(path, address, 4)
        actual = None
        if ins:
            match = re.search(r"#(-?0x[0-9a-f]+|[0-9]+)", ins[0].op_str)
            if match:
                token = match.group(1)
                actual = int(token, 0)
        calls[label] = {
            "instruction": instruction_at(path, address),
            "expected_transaction": expected,
            "decoded_immediate": actual,
            "match": actual == expected,
        }
    return {"path": str(path), "sha256": sha256(path), "symbols": found, "transaction_calls": calls}


def aidl_audit(device_path: Path, operation_path: Path) -> dict[str, Any]:
    device = device_path.read_text(encoding="utf-8", errors="replace") if device_path.is_file() else ""
    operation = operation_path.read_text(encoding="utf-8", errors="replace") if operation_path.is_file() else ""

    def tx(text: str, name: str) -> int | None:
        match = re.search(
            rf"TRANSACTION_{re.escape(name)}\s*=\s*\(android\.os\.IBinder\.FIRST_CALL_TRANSACTION\s*\+\s*(\d+)\)",
            text,
        )
        return 1 + int(match.group(1)) if match else None

    return {
        "device": {
            "path": str(device_path),
            "sha256": sha256(device_path),
            "descriptor": "android.hardware.security.keymint.IKeyMintDevice",
            "transactions": {"begin": tx(device, "begin"), "getKeyCharacteristics": tx(device, "getKeyCharacteristics")},
            "begin_proxy_sequence": [
                "writeInterfaceToken (NDK header is automatic)",
                "writeInt(purpose)",
                "writeByteArray(keyBlob)",
                "writeTypedArray(params)",
                "writeTypedObject(authToken)",
                "transact(begin=10)",
                "readException/readStatusHeader",
                "readTypedObject(BeginResult)",
            ],
        },
        "operation": {
            "path": str(operation_path),
            "sha256": sha256(operation_path),
            "descriptor": "android.hardware.security.keymint.IKeyMintOperation",
            "transactions": {
                "updateAad": tx(operation, "updateAad"),
                "update": tx(operation, "update"),
                "finish": tx(operation, "finish"),
                "abort": tx(operation, "abort"),
            },
            "update_proxy_sequence": [
                "writeByteArray(input)",
                "writeTypedObject(authToken=null)",
                "writeTypedObject(timeStampToken=null)",
                "transact(update=2)",
                "readException/readStatusHeader + createByteArray",
            ],
            "finish_proxy_sequence": [
                "writeByteArray(input)",
                "writeByteArray(signature=null)",
                "writeTypedObject(authToken=null)",
                "writeTypedObject(timestampToken=null)",
                "writeByteArray(confirmationToken=null)",
                "transact(finish=3)",
                "readException/readStatusHeader + createByteArray",
            ],
            "abort_proxy_sequence": ["transact(abort=4)", "readException/readStatusHeader"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", type=Path, default=DEFAULT_BLOB)
    parser.add_argument("--service", type=Path, default=DEFAULT_SERVICE)
    parser.add_argument("--ndk", type=Path, default=DEFAULT_NDK)
    parser.add_argument("--aidl-device", type=Path, default=DEFAULT_AIDL_DEVICE)
    parser.add_argument("--aidl-operation", type=Path, default=DEFAULT_AIDL_OPERATION)
    parser.add_argument("--out", type=Path, default=None, help="JSON output; stdout if omitted")
    args = parser.parse_args()

    blob_len = 0
    blob_hash = None
    if args.blob.is_file():
        blob_len = args.blob.stat().st_size
        blob_hash = sha256(args.blob)

    report: dict[str, Any] = {
        "schema": "k70e-keymint-begin-frames-hostonly-v2",
        "device_access": False,
        "writes_device": False,
        "source_files": {
            "row03_blob": {"path": str(args.blob), "present": args.blob.is_file(), "length": blob_len, "sha256": blob_hash},
            "service": {"path": str(args.service), "present": args.service.is_file(), "sha256": sha256(args.service)},
            "ndk_v3": {"path": str(args.ndk), "present": args.ndk.is_file(), "sha256": sha256(args.ndk)},
        },
        "aidl": aidl_audit(args.aidl_device, args.aidl_operation),
        "service_static": service_audit(args.service) if args.service.is_file() else {},
        "ndk_static": ndk_audit(args.ndk) if args.ndk.is_file() else {},
        "frames": frame_layout(blob_len or 275),
        "dynamic_plan": {
            "required_object_flow": [
                "associate device Binder with IKeyMintDevice class",
                "begin(SIGN=2, row03 blob, empty params, null auth)",
                "read BeginResult and retain returned IKeyMintOperation strong Binder",
                "abort() transaction 4 immediately; do not call update/finish",
            ],
            "semantic_expectation": {
                "row03_origin": "GenerateRkpKey/attestation-key KeyMint blob; opaque handle, not host private scalar",
                "aosp_rkp_authorization_hint": "AOSP RKP ECDSA P-256 template uses TAG_PURPOSE=ATTEST_KEY and TAG_DIGEST=SHA_2_256; this is a hint, not proof of this vendor blob's complete authorization list",
                "likely_negative_statuses_for_sign": [
                    "UNSUPPORTED_PURPOSE (-2)",
                    "INCOMPATIBLE_PURPOSE (-3)",
                    "INCOMPATIBLE_DIGEST (-13)",
                    "INVALID_KEY_BLOB (-33)",
                ],
                "interpretation": "A non-OK begin status with no BeginResult is a semantic authorization result, not evidence that transaction code or parcel framing is wrong",
                "optional_followup": "Only if an authorized operator explicitly requests it, repeat the same begin->abort gate with one DIGEST=SHA_2_256 KeyParameter; never infer or fabricate a private scalar from the blob",
            },
            "guard": "This report does not execute the dynamic plan; any future client must be separately gated and reviewed.",
            "persistent_write_claim": "none expected from begin/abort; stop on any unexpected status and never continue to update/finish",
        },
    }

    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
