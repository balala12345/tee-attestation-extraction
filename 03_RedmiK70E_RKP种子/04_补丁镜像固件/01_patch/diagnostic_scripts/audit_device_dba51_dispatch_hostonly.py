#!/usr/bin/env python3
"""Static, host-only audit of the stock dba51 KeyMint dispatcher.

This script deliberately works on the archived ELF only.  It does not open
adb/fastboot, attach to a process, invoke a TA, or emit a device payload.  The
report contains addresses, instruction/call metadata, lengths, and hashes;
raw request, key, and scalar bytes are never copied to the report.

The dba51 wire command is the Android Keymaster command enum value itself
(multiples of four in the stock service), not an array index divided by four.
The dispatcher indexes a 16-bit table with the command word directly.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any, Iterable

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_IMM, Cs


SCRIPT = Path(__file__).resolve()
K70_ROOT = SCRIPT.parents[1]
DEFAULT_ELF = (
    K70_ROOT
    / "02_脚本与补丁/duchamp_Mitee_TA_ELF分析_20260828"
    / "dba51a17-0563-11e7-93b16fa7b0071a51.elf"
)
DEFAULT_OUT = K70_ROOT / "03_提取结果/K70E_dba51_dispatch_hostonly_20260904"

DISPATCHER_VA = 0xC7670
TABLE_VA = 0x1E940
TABLE_BASE_VA = 0xC771C
DEFAULT_TARGET_VA = 0xCBD10
ACTIVE_MAX_COMMAND = 0x90
# The first active handler contains the alternate high-command branch after
# this address.  Stop its local scan there so those handlers are not counted
# as GENERATE_KEY calls.
ACTIVE_CMD00_SCAN_END = 0xC7A2C

EXPECTED_TARGETS: dict[int, int] = {
    0x00: 0xC771C,
    0x04: 0xC88CC,
    0x08: 0xC9550,
    0x0C: 0xC97EC,
    0x10: 0xC9AA4,
    0x14: 0xC8B30,
    0x18: 0xC9C24,
    0x1C: 0xC9E30,
    0x20: 0xC9F24,
    0x24: 0xC8E24,
    0x28: 0xCA0D8,
    0x2C: 0xC8E74,
    0x30: 0xCA2D0,
    0x34: 0xC906C,
    0x38: 0xCA4D4,
    0x3C: 0xC7FEC,
    0x40: 0xC827C,
    0x44: 0xCA690,
    0x48: 0xCA940,
    0x4C: 0xCA89C,
    0x50: 0xCB420,
    0x54: 0xC8484,
    0x58: 0xC9218,
    0x5C: 0xCAB80,
    0x60: 0xCAC6C,
    0x64: 0xCADCC,
    0x68: 0xCB068,
    0x6C: 0xC7CC0,
    0x70: 0xC8690,
    0x74: 0xC93B0,
    0x78: 0xCB250,
    0x7C: 0xC7D68,
    0x88: 0xC8790,
    0x8C: 0xC7F44,
    0x90: 0xCB574,
}

COMMAND_NAMES = {
    0x00: "GENERATE_KEY",
    0x04: "BEGIN_OPERATION",
    0x08: "UPDATE_OPERATION",
    0x0C: "FINISH_OPERATION",
    0x10: "ABORT_OPERATION",
    0x14: "IMPORT_KEY",
    0x18: "EXPORT_KEY",
    0x1C: "GET_VERSION",
    0x20: "ADD_RNG_ENTROPY",
    0x24: "GET_SUPPORTED_ALGORITHMS",
    0x28: "GET_SUPPORTED_BLOCK_MODES",
    0x2C: "GET_SUPPORTED_PADDING_MODES",
    0x30: "GET_SUPPORTED_DIGESTS",
    0x34: "GET_SUPPORTED_IMPORT_FORMATS",
    0x38: "GET_SUPPORTED_EXPORT_FORMATS",
    0x3C: "GET_KEY_CHARACTERISTICS",
    0x40: "ATTEST_KEY",
    0x44: "UPGRADE_KEY",
    0x48: "CONFIGURE",
    0x4C: "GET_HMAC_SHARING_PARAMETERS",
    0x50: "COMPUTE_SHARED_HMAC",
    0x54: "VERIFY_AUTHORIZATION",
    0x58: "DELETE_KEY",
    0x5C: "DELETE_ALL_KEYS",
    0x60: "KM_DESTROY_ATT_IDS",
    0x64: "IMPORT_WRAPPED_KEY",
    0x68: "KM_DEVICE_LOCKED",
    0x6C: "KM_EARLY_BOOT_ENDED",
    0x70: "GET_VERSION_2",
    0x74: "KM_GENERATE_RKP_KEY",
    0x78: "KM_GENERATE_CSR",
    0x7C: "KM_GENERATE_TIMESTAMP_TOKEN",
    0x88: "KM_GET_ROOT_OF_TRUST",
    0x8C: "KM_GET_HW_INFO",
    0x90: "KM_GENERATE_CSR_V2",
}

# These are wire-level descriptions, intentionally omitting sample payloads.
# They track the archived AOSP Keymaster message definitions and are useful
# when reviewing a frame without accidentally treating a scalar as a blob.
COMMAND_SHAPES = {
    0x00: "request: AuthorizationSet + optional attestation fields; response: key blob, enforced/unenforced sets, cert chain",
    0x04: "request: purpose(u32) + key blob + AuthorizationSet; response: operation handle(u64) + output params",
    0x08: "request: operation handle(u64) + input Buffer + AuthorizationSet; response: output Buffer + consumed(u32) + params",
    0x0C: "request: operation handle(u64) + signature Buffer + AuthorizationSet + input Buffer; response: output Buffer/params",
    0x10: "request: operation handle(u64); response: empty",
    0x14: "request: AuthorizationSet + key format(u32) + key data blob (+ v4 attestation fields); response: key/certs",
    0x18: "request: key format(u32) + key blob; response: exported key data blob",
    0x1C: "request: empty; response: version bytes (major/minor/subminor)",
    0x20: "request: random-data Buffer; response: empty",
    0x24: "request: empty; response: supported-algorithm array",
    0x28: "request: algorithm(u32); response: supported-block-mode array",
    0x2C: "request: algorithm(u32); response: supported-padding-mode array",
    0x30: "request: algorithm(u32); response: supported-digest array",
    0x34: "request: empty; response: supported-import-format array",
    0x38: "request: algorithm(u32); response: supported-export-format array",
    0x3C: "request: key blob + additional AuthorizationSet; response: enforced/unenforced sets",
    0x40: "request: key blob + attestation AuthorizationSet; response: certificate chain",
    0x44: "request: key blob + upgrade parameters; response: upgraded key blob",
    0x48: "request: OS version(u32) + patchlevel(u32); response: empty",
    0x4C: "request: empty; response: seed blob + 32-byte nonce",
    0x50: "request: array of HmacSharingParameters; response: sharing-check blob",
    0x54: "request: challenge(u64) + AuthorizationSet + HardwareAuthToken; response: VerificationToken",
    0x58: "request: key blob; response: empty",
    0x5C: "request: empty; response: empty",
    0x60: "request: empty/stateful; response: empty",
    0x64: "request: wrapping-key blob + encrypted-key blob + masking-key blob + params/SIDs; response: key/certs",
    0x68: "request: password-only byte + VerificationToken; response: empty",
    0x6C: "request: empty; response: empty",
    0x70: "request: max-message-version(u32); response: three version u32 fields",
    0x74: "request: test-mode byte; response: key blob + MACed public key",
    0x78: "request: test-mode byte + key-blob array + endpoint cert chain/challenge blobs; response: 3 blobs",
    0x7C: "request: challenge(u64); response: TimestampToken (challenge/timestamp/security-level/MAC)",
    0x88: "request: root-of-trust challenge/collection; response: MACed root-of-trust blob",
    0x8C: "request: empty; response: HW info (version/author/EK curve/unique ID/CSR count)",
    0x90: "request: num_keys(u32) + length-prefixed key blobs + challenge blob; response: one CSR blob",
}

# Risk labels describe static review priorities, not a demonstrated exploit.
COMMAND_RISKS = {
    0x00: "key-generation/attestation sensitive; secure-context state",
    0x04: "operation-handle and key-blob parser",
    0x08: "variable Buffer/AuthorizationSet lengths; operation state",
    0x0C: "multiple variable blobs; operation state",
    0x10: "fixed u64 parser; operation state",
    0x14: "key import and variable blobs",
    0x18: "export-sensitive; policy-gated",
    0x1C: "small fixed response",
    0x20: "variable entropy Buffer; bounded parser expected",
    0x24: "array response; metadata",
    0x28: "u32 selector + array response",
    0x2C: "u32 selector + array response",
    0x30: "u32 selector + array response",
    0x34: "array response; metadata",
    0x38: "u32 selector + array response",
    0x3C: "key blob/AuthorizationSet parser",
    0x40: "attestation/key material policy",
    0x44: "key blob + upgrade params",
    0x48: "stateful configuration",
    0x4C: "HMAC-sharing metadata; policy-gated",
    0x50: "unbounded parameter array candidate; sensitive metadata",
    0x54: "auth token and AuthorizationSet parser",
    0x58: "key deletion; stateful",
    0x5C: "destructive stateful operation",
    0x60: "destructive attestation-ID state",
    0x64: "wrapped-key parser; sensitive blobs",
    0x68: "verification token/stateful lock transition",
    0x6C: "lifecycle transition",
    0x70: "fixed version request/response",
    0x74: "RKP key generation; secure-context/private-key boundary",
    0x78: "RKP CSR; count/blob allocation and secure-context boundary",
    0x7C: "fixed u64 + token/MAC response",
    0x88: "root-of-trust metadata; policy-gated",
    0x8C: "hardware metadata/unique-ID privacy surface",
    0x90: "CSR-v2 count/blob allocation; secure-context/private-key boundary",
}

HELPER_HINTS = {
    0x00: "0x610e8",
    0x04: "0x63db0",
    0x08: "0x640c0",
    0x0C: "0x64258",
    0x10: "0x64598",
    0x14: "0x64a18",
    0x18: "0x64610",
    0x1C: "0x604a8",
    0x20: "0x61088",
    0x24: "common writer",
    0x28: "0x606a8",
    0x2C: "0x607e8",
    0x30: "0x60928",
    0x34: "0x60a68",
    0x38: "0x60b98",
    0x3C: "0x63a80",
    0x40: "0x64750",
    0x44: "0x64908",
    0x48: "0x65108 -> 0x65238",
    0x4C: "0x60cc8",
    0x50: "0x60e08",
    0x54: "0x60ec8",
    0x58: "0x64c60",
    0x5C: "0x64d28",
    0x60: "direct/vtable (no direct BL observed)",
    0x64: "0x653d8",
    0x68: "0x65758",
    0x6C: "0x656b8",
    0x70: "0xc2100",
    0x74: "0x61960",
    0x78: "0x626c8",
    0x7C: "0x61030",
    0x88: "0x66f00 -> 0x65820",
    0x8C: "0x660d8",
    0x90: "0x636b8",
}

ALTERNATE_COMMANDS = {
    0x4000: {"name": "SET_ATTESTATION_IDS (variant A)", "target": 0xCB968},
    0x4004: {"name": "SET_ATTESTATION_IDS (variant B)", "target": 0xCB728},
    0x8000: {"name": "SET_ATTESTATION_KEY", "target": 0xC7A54, "logger_note": "stock string spells SET_ATTESTION_KEY"},
    0xC000: {"name": "SET_ATTESTATION_CERT_CHAIN", "target": 0xCBBC4},
    0x28000: {"name": "KM_CLEAR_ATTESTATION_CERT_CHAIN", "target": 0xCB794},
    0x2C000: {"name": "KM_GET_ATTESTATION_IDS", "target": 0xC7C70},
}

AOSP_HEADER_URL = (
    "https://android.googlesource.com/platform/system/keymaster/+/"
    "f0f3093bbdfe39ac3d028368b588b574d2f95570/include/keymaster/"
    "android_keymaster_messages.h"
)
AOSP_CPP_URL = (
    "https://android.googlesource.com/platform/system/keymaster/+/"
    "f0f3093bbdfe39ac3d028368b588b574d2f95570/android_keymaster.cpp"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


@dataclass(frozen=True)
class Segment:
    va: int
    file_offset: int
    file_size: int
    mem_size: int


class ElfView:
    """Small ELF64 reader sufficient for this stripped, sectionless image."""

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF":
            raise ValueError(f"not an ELF file: {path}")
        if self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("expected little-endian ELF64")
        self.entry = struct.unpack_from("<Q", self.data, 0x18)[0]
        phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        self.segments: list[Segment] = []
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + 56 > len(self.data):
                break
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", self.data, off
            )
            if p_type == 1:
                self.segments.append(Segment(p_vaddr, p_offset, p_filesz, p_memsz))

    def va_to_offset(self, va: int, allow_bss: bool = False) -> int | None:
        for seg in self.segments:
            limit = seg.mem_size if allow_bss else seg.file_size
            if seg.va <= va < seg.va + limit:
                result = seg.file_offset + (va - seg.va)
                return result if result < len(self.data) else None
        # This particular image has identity VA/file offsets for its useful
        # ranges; retain a conservative fallback for metadata addresses.
        if 0 <= va < len(self.data):
            return va
        return None

    def bytes_at(self, va: int, size: int) -> bytes:
        off = self.va_to_offset(va)
        if off is None:
            return b""
        return self.data[off : min(len(self.data), off + size)]


def parse_dispatch_table(view: ElfView) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    table_off = view.va_to_offset(TABLE_VA)
    if table_off is None or table_off + 2 * (ACTIVE_MAX_COMMAND + 1) > len(view.data):
        raise ValueError("dispatcher table is outside the archived ELF")
    for command in range(ACTIVE_MAX_COMMAND + 1):
        raw = struct.unpack_from("<H", view.data, table_off + 2 * command)[0]
        target = TABLE_BASE_VA + raw * 4
        rows[command] = {
            "command": command,
            "command_hex": f"0x{command:02x}",
            "table_raw_u16": raw,
            "target_va": target,
            "target_hex": f"0x{target:08x}",
            "is_default": target == DEFAULT_TARGET_VA,
            "expected_target": EXPECTED_TARGETS.get(command),
            "matches_expected": EXPECTED_TARGETS.get(command) == target if command in EXPECTED_TARGETS else target == DEFAULT_TARGET_VA,
        }
    active = {c: r for c, r in rows.items() if not r["is_default"]}
    summary = {
        "dispatcher_va": f"0x{DISPATCHER_VA:08x}",
        "table_va": f"0x{TABLE_VA:08x}",
        "table_base_va": f"0x{TABLE_BASE_VA:08x}",
        "default_target_va": f"0x{DEFAULT_TARGET_VA:08x}",
        "max_command_checked": ACTIVE_MAX_COMMAND,
        "active_handler_count": len(active),
        "default_count": len(rows) - len(active),
        "all_expected_targets_match": all(bool(r["matches_expected"]) for r in rows.values()),
        "indexing_note": "ldr h[w11], [table_base, command_word, lsl #1]; command is used directly (not command/4)",
    }
    return rows, summary


def printable_strings(view: ElfView) -> dict[int, str]:
    """Return NUL-delimited printable strings keyed by their ELF VA."""
    result: dict[int, str] = {}
    # Strings of interest live in file-backed ranges.  A minimum of three
    # printable bytes suppresses binary noise while retaining source labels.
    for seg in view.segments:
        start = seg.file_offset
        end = min(len(view.data), start + seg.file_size)
        pos = start
        while pos < end:
            nul = view.data.find(b"\0", pos, end)
            if nul < 0:
                break
            raw = view.data[pos:nul]
            if len(raw) >= 3 and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                # PT_LOADs in this image are identity mapped; use the segment
                # relation rather than assuming it for future inputs.
                va = seg.va + (pos - seg.file_offset)
                result[va] = raw.decode("ascii", "replace")
            pos = nul + 1
    return result


def immediate_operand(insn: Any, index: int = 1) -> int | None:
    try:
        if len(insn.operands) > index and insn.operands[index].type == CS_OP_IMM:
            return int(insn.operands[index].imm)
    except (AttributeError, IndexError, TypeError):
        return None
    return None


def register_name(md: Cs, reg_id: int) -> str:
    try:
        return md.reg_name(reg_id)
    except Exception:
        return ""


def resolve_logger_strings(insns: list[Any], strings: dict[int, str], md: Cs) -> list[dict[str, Any]]:
    """Resolve nearby ADRP+ADD pairs to source logger strings."""
    registers: dict[str, int] = {}
    found: dict[int, dict[str, Any]] = {}
    for insn in insns:
        try:
            if insn.mnemonic == "adrp" and len(insn.operands) >= 2:
                dst = register_name(md, insn.operands[0].reg)
                imm = immediate_operand(insn, 1)
                if dst and imm is not None:
                    registers[dst] = imm
            elif insn.mnemonic == "add" and len(insn.operands) >= 3:
                dst = register_name(md, insn.operands[0].reg)
                src = register_name(md, insn.operands[1].reg)
                imm = immediate_operand(insn, 2)
                if dst and src in registers and imm is not None:
                    address = registers[src] + imm
                    value = strings.get(address)
                    if value and "Dispatching " in value:
                        found[address] = {
                            "va": f"0x{address:08x}",
                            "text": value,
                            "instruction_va": f"0x{insn.address:08x}",
                        }
                    registers[dst] = address
        except Exception:
            continue
    return list(found.values())


def parse_line_from_logger(text: str) -> int | None:
    match = re.search(r"Line\s+(\d+)", text)
    return int(match.group(1)) if match else None


def parse_fixed_width(insns: list[Any], call_index: int, md: Cs) -> int | None:
    """Find a nearby ``mov w3,#N`` used by the common fixed parser."""
    for prior in reversed(insns[max(0, call_index - 12) : call_index]):
        if prior.mnemonic not in ("mov", "movz", "movk") or len(prior.operands) < 2:
            continue
        dst = register_name(md, prior.operands[0].reg)
        if dst != "w3":
            continue
        value = immediate_operand(prior, 1)
        if value is not None and 0 <= value <= 0x100000:
            return value
    return None


def parser_metadata(insns: list[Any], md: Cs) -> list[dict[str, Any]]:
    parsers = {0x910B8: "bounded_fixed_parser", 0x91118: "length_prefixed_blob_parser", 0x918B8: "vector_array_parser"}
    result: list[dict[str, Any]] = []
    for index, insn in enumerate(insns):
        if insn.mnemonic != "bl":
            continue
        target = immediate_operand(insn, 0)
        if target not in parsers:
            continue
        row: dict[str, Any] = {
            "call_va": f"0x{insn.address:08x}",
            "target_va": f"0x{target:08x}",
            "kind": parsers[target],
        }
        width = parse_fixed_width(insns, index, md) if target == 0x910B8 else None
        if width is not None:
            row["fixed_width"] = width
        result.append(row)
    return result


def virtual_call_metadata(insns: list[Any], md: Cs) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, insn in enumerate(insns):
        if insn.mnemonic != "blr":
            continue
        row: dict[str, Any] = {"call_va": f"0x{insn.address:08x}", "register": insn.op_str}
        # Capture the common ``ldr x8,[x8,#offset]; ...; blr x8`` shape.
        for prior in reversed(insns[max(0, index - 5) : index]):
            if prior.mnemonic != "ldr" or len(prior.operands) < 2:
                continue
            try:
                base = register_name(md, prior.operands[1].mem.base)
                disp = int(prior.operands[1].mem.disp)
                dst = register_name(md, prior.operands[0].reg)
            except Exception:
                continue
            if dst == "x8" and base in ("x8", "x0", "x22", "x23", "x25"):
                row["load_va"] = f"0x{prior.address:08x}"
                row["vtable_offset"] = f"0x{disp:x}"
                break
        result.append(row)
    return result


def direct_calls(insns: list[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for insn in insns:
        if insn.mnemonic != "bl":
            continue
        target = immediate_operand(insn, 0)
        if target is None:
            continue
        calls.append({"call_va": f"0x{insn.address:08x}", "target_va": f"0x{target:08x}"})
    return calls


def scan_handler(view: ElfView, start: int, end: int, strings: dict[int, str], md: Cs) -> dict[str, Any]:
    start_off = view.va_to_offset(start)
    end_off = view.va_to_offset(end)
    if start_off is None:
        return {"scan_start_va": f"0x{start:08x}", "scan_end_va": f"0x{end:08x}", "disassembly_error": "start outside file"}
    if end_off is None or end_off <= start_off:
        end_off = min(len(view.data), start_off + 0x400)
    insns = list(md.disasm(view.data[start_off:end_off], start))
    parsers = parser_metadata(insns, md)
    calls = direct_calls(insns)
    return {
        "scan_start_va": f"0x{start:08x}",
        "scan_end_va": f"0x{end:08x}",
        "instruction_count": len(insns),
        "logger_strings": resolve_logger_strings(insns, strings, md),
        "logger_source_lines": sorted({line for item in resolve_logger_strings(insns, strings, md) if (line := parse_line_from_logger(item["text"])) is not None}),
        "direct_bl_calls": calls,
        "direct_bl_targets": sorted({item["target_va"] for item in calls}),
        "parser_calls": parsers,
        "virtual_calls": virtual_call_metadata(insns, md),
        "allocator_calls": {
            "alloc_output_0x6ea98": any(item["target_va"] == "0x0006ea98" for item in calls),
            "free_output_0x6eb0c": any(item["target_va"] == "0x0006eb0c" for item in calls),
        },
    }


def build_report(view: ElfView) -> dict[str, Any]:
    table, dispatcher = parse_dispatch_table(view)
    strings = printable_strings(view)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    active_commands = sorted(EXPECTED_TARGETS)
    # Use every known handler target (including the six high-command targets)
    # to establish local ranges.  The stock binary places 0x4004 immediately
    # after the 0x90 handler and places 0x8000 inside the first handler's
    # post-dispatch area; omitting those boundaries would attribute vendor
    # instructions to GENERATE_CSR_V2/GENERATE_KEY.
    unique_targets = sorted(set(EXPECTED_TARGETS.values()) | {item["target"] for item in ALTERNATE_COMMANDS.values()})
    handlers: list[dict[str, Any]] = []
    for command in active_commands:
        start = EXPECTED_TARGETS[command]
        next_targets = [target for target in unique_targets if target > start]
        end = next_targets[0] if next_targets else min(len(view.data), start + 0x500)
        if command == 0x00:
            end = min(end, ACTIVE_CMD00_SCAN_END)
        row = dict(table[command])
        row.update(
            {
                "name": COMMAND_NAMES[command],
                "aosp_enum_value": command // 4 if command % 4 == 0 else None,
                "aosp_enum_note": "wire command equals enum*4 in this service" if command % 4 == 0 else "vendor extension/legacy command",
                "shape": COMMAND_SHAPES[command],
                "risk": COMMAND_RISKS[command],
                "helper_hint": HELPER_HINTS[command],
                "private_scalar_verdict": "No dispatcher-level raw private-scalar copy/export observed; helper/context internals require separate audit.",
            }
        )
        row["static_scan"] = scan_handler(view, start, end, strings, md)
        handlers.append(row)

    alternate = []
    for command, item in ALTERNATE_COMMANDS.items():
        row = {
            "command": command,
            "command_hex": f"0x{command:x}",
            "name": item["name"],
            "target_va": f"0x{item['target']:08x}",
            "logger_note": item.get("logger_note", ""),
            "input_output": "stateful vendor command; exact message shape is not inferred or invoked by this script",
            "safety": "do not execute on device during this host-only audit",
        }
        alternate.append(row)

    dispatcher_bytes = view.bytes_at(DISPATCHER_VA, 0xB0)
    return {
        "tool": {
            "name": SCRIPT.name,
            "mode": "host-only static analysis",
            "raw_payloads_written": False,
            "device_actions": False,
        },
        "artifact": {
            "path": str(view.path),
            "size": len(view.data),
            "sha256": sha256(view.path),
            "elf_entry": f"0x{view.entry:08x}",
            "program_load_segments": [seg.__dict__ for seg in view.segments],
        },
        "dispatcher": dispatcher
        | {
            "instruction_prefix_sha256": hashlib.sha256(dispatcher_bytes).hexdigest(),
            "instruction_prefix_length": len(dispatcher_bytes),
            "alternate_branch_start_va": f"0x{ACTIVE_CMD00_SCAN_END:08x}",
            "unknown_range_statement": "0x91..0x3fff and all high values except the six exact alternate IDs go to the default unknown-command path.",
        },
        "handlers": handlers,
        "alternate_commands": alternate,
        "focused_findings": {
            "0x7c": {
                "input_frame": "wire command 0x7c followed by one little-endian u64 challenge (8 bytes)",
                "observed_parser": "bounded fixed parser 0x910b8 called from handler near 0xc7e04 with w3=8",
                "helper": "0x61030",
                "output": "TimestampToken fields; dynamic MAC blob may be serialized, but no private scalar",
            },
            "0x8c": {
                "input_frame": "wire command 0x8c with empty request",
                "observed_parser": "no request parser; helper 0x660d8 obtains HW info",
                "output": "version/author/EK-curve/unique-ID/CSR-count metadata",
                "privacy_note": "unique ID is metadata and a privacy surface, not an EC private scalar",
            },
            "0x90": {
                "input_frame": "wire command 0x90 + u32 num_keys + num_keys length-prefixed blobs + length-prefixed challenge",
                "observed_parser": "virtual request Deserialize at handler around 0xcb62c (vtable offset 0x30)",
                "helper": "0x636b8",
                "response": "virtual response serializer around 0xcb6ec; output allocator 0x6ea98 and old-output free 0x6eb0c",
                "risk": "AOSP deserializer allocates num_keys entries before semantic validation; malformed/truncated input is checked, but a huge count/length can create allocator/DoS pressure. Challenge maximum is checked after deserialization.",
                "private_scalar_note": "dispatcher/handler has no direct raw scalar memcpy/export; CSR helper is a secure-context boundary, so this is not proof about all helper internals",
            },
        },
        "aosp_references": {"messages_header": AOSP_HEADER_URL, "android_keymaster_cpp": AOSP_CPP_URL},
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# dba51 dispatcher host-only audit (2026-09-04)",
        "",
        "This report is generated from the archived stock ELF. It contains no raw request, key, scalar, or response bytes and performs no device action.",
        "",
        f"* ELF SHA-256: `{report['artifact']['sha256']}`",
        f"* Dispatcher: `{report['dispatcher']['dispatcher_va']}`; table: `{report['dispatcher']['table_va']}`; default: `{report['dispatcher']['default_target_va']}`",
        f"* Table verification: **{'PASS' if report['dispatcher']['all_expected_targets_match'] else 'FAIL'}** ({report['dispatcher']['active_handler_count']} active rows; {report['dispatcher']['default_count']} defaults in 0x00..0x90)",
        "* Wire IDs are used directly as table indices; the standard IDs happen to be `AOSP enum * 4`.",
        "",
        "## Active handlers",
        "",
        "| wire | handler | VA | shape | helper / parser evidence | static review priority |",
        "|---:|---|---:|---|---|---|",
    ]
    for row in report["handlers"]:
        scan = row["static_scan"]
        parser = ", ".join(
            f"{p['kind']}@{p['call_va']}" + (f" width={p['fixed_width']}" if "fixed_width" in p else "")
            for p in scan["parser_calls"]
        ) or "none observed"
        evidence = f"{row['helper_hint']}; {parser}"
        lines.append(
            f"| `{row['command_hex']}` | {row['name']} | `{row['target_hex']}` | {row['shape']} | {evidence} | {row['risk']} |"
        )
    lines += [
        "",
        "## High/vendor command branches",
        "",
        "These exact IDs are checked outside the 0x00..0x90 table. Other 0x90+ values fall through to the default unknown-command path; no sequential 0x94+ vendor table was found.",
        "",
        "| wire | name | target | note |",
        "|---:|---|---:|---|",
    ]
    for row in report["alternate_commands"]:
        lines.append(f"| `0x{row['command']:x}` | {row['name']} | `{row['target_va']}` | {row['logger_note'] or 'stateful vendor path'} |")
    lines += [
        "",
        "## Focused conclusions",
        "",
        "* **0x7c / KM_GENERATE_TIMESTAMP_TOKEN:** the handler passes exactly 8 bytes to the bounded parser (`0x910b8`, `w3=8`) and calls helper `0x61030`. The returned token can contain a MAC blob; no private-key scalar path is visible at the dispatcher.",
        "* **0x8c / KM_GET_HW_INFO:** request is empty and helper `0x660d8` returns hardware/RKP metadata (including a unique ID on implementations that populate it). This is a metadata/privacy surface, not evidence of a private EC scalar leak.",
        "* **0x90 / KM_GENERATE_CSR_V2:** request deserialization is virtual (handler call near `0xcb62c`, vtable offset `0x30`), then helper `0x636b8` builds the CSR and a virtual serializer emits one blob. The credible static concern is count/length allocation pressure (`num_keys` is allocated before semantic challenge limits); no uninitialized-output or use-after-free proof was found.",
        "* No dispatcher-level direct raw private-scalar copy/export was observed. That verdict is intentionally limited to the dispatcher/handler and does not make a claim about secure helper internals.",
        "",
        "## Safe host-only frame notes (not execution commands)",
        "",
        "The following are documentation-only shapes for a future review; this script does not send them to an injector or device:",
        "",
        "* `0x7c`: command word + 8-byte little-endian challenge; output is a token object.",
        "* `0x8c`: command word + empty request; output is HW-info metadata.",
        "* `0x90`: command word + `u32 num_keys` + length-prefixed blobs + length-prefixed challenge; avoid constructing large counts or key material in a live target.",
        "",
        "AOSP message definitions: [android_keymaster_messages.h](" + AOSP_HEADER_URL + ") and [android_keymaster.cpp](" + AOSP_CPP_URL + ").",
        "",
    ]
    return "\n".join(lines)


def readme(report: dict[str, Any]) -> str:
    return f"""# K70E dba51 dispatcher audit

Generated by `{SCRIPT.name}` in host-only mode on 2026-09-04.

## Inputs and integrity

* Archived ELF: `{report['artifact']['path']}`
* Size: `{report['artifact']['size']}` bytes
* SHA-256: `{report['artifact']['sha256']}`
* Dispatcher/table: `{report['dispatcher']['dispatcher_va']}` / `{report['dispatcher']['table_va']}`
* Table check: `{'PASS' if report['dispatcher']['all_expected_targets_match'] else 'FAIL'}`

The script reads the ELF and writes only JSON/Markdown metadata. It does not
open adb or fastboot, ptrace a process, invoke a TEEC command, load a TA, or
modify a partition. The high-command rows are documented but intentionally not
given an execution recipe because they are stateful attestation operations.

## Interpretation guardrails

The `private_scalar_verdict` field means only that no direct scalar copy/export
was visible in the dispatcher/handler slices. `0x90` delegates request parsing
and CSR construction to virtual methods and `0x74` delegates RKP generation to
the remprov context; those helpers must not be conflated with a host-readable
key path. The report flags count/length allocation pressure as a static DoS
candidate, not as a demonstrated memory disclosure.

The AOSP framing references used for cross-checking are:

* {AOSP_HEADER_URL}
* {AOSP_CPP_URL}

## Re-run

```sh
python3 "{SCRIPT}"
jq '.dispatcher, .focused_findings' "{DEFAULT_OUT / 'dispatch_report.json'}"
shasum -a 256 "{DEFAULT_ELF}"
```

The commands above are host-only. Do not append an injector/device invocation
to this audit command.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    elf_path = args.elf.expanduser().resolve()
    out_dir = args.out.expanduser().resolve()
    if not elf_path.is_file():
        parser.error(f"ELF not found: {elf_path}")
    report = build_report(ElfView(elf_path))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dispatch_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "dispatch_table.md").write_text(markdown_report(report), encoding="utf-8")
    (out_dir / "README.md").write_text(readme(report), encoding="utf-8")
    print(json.dumps({
        "out": str(out_dir),
        "elf_sha256": report["artifact"]["sha256"],
        "table_check": report["dispatcher"]["all_expected_targets_match"],
        "active_handlers": report["dispatcher"]["active_handler_count"],
        "alternate_commands": len(report["alternate_commands"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
