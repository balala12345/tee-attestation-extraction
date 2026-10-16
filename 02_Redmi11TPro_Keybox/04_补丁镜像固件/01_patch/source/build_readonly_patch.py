#!/usr/bin/env python3
"""Build exact xaga Keybox caller-gate and uTsecManager verification-bypass artifacts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import struct
import sys
from pathlib import Path


HEADER_MAGIC = b"<< L4Re-bootstrap-modinfo-hdr >>"
MODULE_MAGIC = b"<< L4Re-bootstrap-modinfo-mod >>"
HEADER_SIZE = 56
MODULE_SIZE = 92

EXPECTED_TEE_SHA256 = "48edc850fcbd9f8289b813d032a0eb04ec20c049ff78f868b360b108c8295dbc"
EXPECTED_SECMANAGER_SHA256 = "d31eaa65c305201b1f920cff05770ff9a411ee1826e07c5e6db0beeeb30e9b38"
EXPECTED_KEYBOX_TA_SHA256 = "0fafcb889813891dca764f36627691a839345105d8dcbb7fbdc82d9178f0e52f"
EXPECTED_KEYBOX_ELF_SHA256 = "8488ec166e55d8c1212f5dfdacf562dd434e58e4dae0bf2fdce5fe43a6038572"

SECMANAGER_PATCH_OFFSET = 0xF218
SECMANAGER_EXPECTED = bytes.fromhex("20220035")  # cbnz w0, verification_error
KEYBOX_PATCH_OFFSET = 0x109C
KEYBOX_EXPECTED = bytes.fromhex("e008417a")  # ccmp w7, #1, #0, eq
AARCH64_NOP = bytes.fromhex("1f2003d5")


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def require_sha256(label: str, data: bytes, expected: str) -> None:
    actual = digest(data)
    if actual != expected:
        raise ValueError(f"{label} SHA256 不匹配：expected={expected}, actual={actual}")


def load_decrypt_helpers():
    helper_path = Path(__file__).resolve().parents[2] / "02_共用工程" / "02_分析脚本" / "TEE镜像分析" / "解密_精确KeyMint_TA.py"
    helper_path = helper_path.resolve()
    if not helper_path.is_file():
        raise FileNotFoundError(f"缺少同项目解密器：{helper_path}")
    spec = importlib.util.spec_from_file_location("xaga_ta_decrypt", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载解密器：{helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_module(image: bytes, wanted_name: str) -> dict[str, int | str | bytes]:
    header = image.find(HEADER_MAGIC)
    if header < 0 or image.find(HEADER_MAGIC, header + 1) >= 0:
        raise ValueError("TEE 镜像中的 L4Re 模块表不存在或不唯一")
    count = struct.unpack_from("<I", image, header + len(HEADER_MAGIC))[0]
    records: list[dict[str, int | str | bytes]] = []
    for index in range(count):
        descriptor = header + HEADER_SIZE + index * MODULE_SIZE
        if image[descriptor : descriptor + len(MODULE_MAGIC)] != MODULE_MAGIC:
            raise ValueError(f"模块 {index} 描述符 magic 错误")
        data_rel = struct.unpack_from("<Q", image, descriptor + 36)[0]
        stored_size = struct.unpack_from("<I", image, descriptor + 44)[0]
        unpacked_size = struct.unpack_from("<I", image, descriptor + 48)[0]
        name_start_rel = struct.unpack_from("<Q", image, descriptor + 52)[0]
        name_end_rel = struct.unpack_from("<Q", image, descriptor + 60)[0]
        digest_start_rel = struct.unpack_from("<Q", image, descriptor + 68)[0]
        digest_end_rel = struct.unpack_from("<Q", image, descriptor + 76)[0]
        name = image[descriptor + name_start_rel : descriptor + name_end_rel].rstrip(b"\0").decode(errors="replace")
        data_offset = descriptor + data_rel
        records.append(
            {
                "index": index,
                "descriptor": descriptor,
                "data_offset": data_offset,
                "stored_size": stored_size,
                "unpacked_size": unpacked_size,
                "digest_offset": descriptor + digest_start_rel,
                "unpacked_digest_offset": descriptor + digest_end_rel,
                "name": name,
            }
        )
    matches = [record for record in records if record["name"] == wanted_name]
    if len(matches) != 1:
        raise ValueError(f"模块 {wanted_name!r} 的数量不是 1：{len(matches)}")
    selected = matches[0]
    later_offsets = [int(record["data_offset"]) for record in records if int(record["data_offset"]) > int(selected["data_offset"])]
    selected["allocation_end"] = min(later_offsets) if later_offsets else len(image)
    selected["module_count"] = count
    return selected


def parse_gzip_identity(payload: bytes) -> tuple[str, int]:
    if payload[:3] != b"\x1f\x8b\x08":
        raise ValueError("uTsecManager 模块不是 gzip")
    flags = payload[3]
    mtime = struct.unpack_from("<I", payload, 4)[0]
    cursor = 10
    filename = ""
    if flags & 0x04:
        extra_length = struct.unpack_from("<H", payload, cursor)[0]
        cursor += 2 + extra_length
    if flags & 0x08:
        end = payload.index(b"\0", cursor)
        filename = payload[cursor:end].decode("latin-1")
    return filename, mtime


def gzip_like_original(data: bytes, original_payload: bytes) -> bytes:
    filename, mtime = parse_gzip_identity(original_payload)
    output = io.BytesIO()
    with gzip.GzipFile(filename=filename, mode="wb", compresslevel=9, fileobj=output, mtime=mtime) as stream:
        stream.write(data)
    return output.getvalue()


def patch_secmanager_and_tee(secmanager: bytes, tee: bytes) -> tuple[bytes, bytes, dict[str, object]]:
    require_sha256("uTsecManager", secmanager, EXPECTED_SECMANAGER_SHA256)
    require_sha256("tee.img", tee, EXPECTED_TEE_SHA256)
    if secmanager[SECMANAGER_PATCH_OFFSET : SECMANAGER_PATCH_OFFSET + 4] != SECMANAGER_EXPECTED:
        raise ValueError("uTsecManager 验签返回分支的原始指令不匹配")

    patched_secmanager = bytearray(secmanager)
    patched_secmanager[SECMANAGER_PATCH_OFFSET : SECMANAGER_PATCH_OFFSET + 4] = AARCH64_NOP
    patched_secmanager = bytes(patched_secmanager)

    module = find_module(tee, "uTsecManager")
    data_offset = int(module["data_offset"])
    stored_size = int(module["stored_size"])
    allocation_end = int(module["allocation_end"])
    descriptor = int(module["descriptor"])
    stored_payload = tee[data_offset : data_offset + stored_size]
    unpacked = gzip.decompress(stored_payload)
    if unpacked != secmanager:
        raise ValueError("tee.img 中的 uTsecManager 与单独输入不一致")

    recompressed = gzip_like_original(patched_secmanager, stored_payload)
    capacity = allocation_end - data_offset
    if len(recompressed) > capacity:
        raise ValueError(f"重压缩模块超过固定槽位：{len(recompressed)} > {capacity}")

    patched_tee = bytearray(tee)
    patched_tee[data_offset:allocation_end] = b"\0" * capacity
    patched_tee[data_offset : data_offset + len(recompressed)] = recompressed
    struct.pack_into("<I", patched_tee, descriptor + 44, len(recompressed))
    struct.pack_into("<I", patched_tee, descriptor + 48, len(patched_secmanager))
    stored_md5 = digest(recompressed, "md5")
    unpacked_md5 = digest(patched_secmanager, "md5")
    digest_offset = int(module["digest_offset"])
    unpacked_digest_offset = int(module["unpacked_digest_offset"])
    patched_tee[digest_offset : digest_offset + 32] = stored_md5.encode("ascii")
    patched_tee[unpacked_digest_offset : unpacked_digest_offset + 32] = unpacked_md5.encode("ascii")
    patched_tee = bytes(patched_tee)

    check_module = find_module(patched_tee, "uTsecManager")
    check_offset = int(check_module["data_offset"])
    check_size = int(check_module["stored_size"])
    check_payload = patched_tee[check_offset : check_offset + check_size]
    if gzip.decompress(check_payload) != patched_secmanager:
        raise ValueError("补丁 tee.img 回读 uTsecManager 失败")
    if digest(check_payload, "md5") != stored_md5:
        raise ValueError("补丁 tee.img stored MD5 回读失败")

    info = {
        "patch": {
            "component": "uTsecManager",
            "virtual_address": "0x0040f218",
            "file_offset": f"0x{SECMANAGER_PATCH_OFFSET:x}",
            "before_hex": SECMANAGER_EXPECTED.hex(),
            "after_hex": AARCH64_NOP.hex(),
            "meaning": "忽略 verify_ta 非零结果，之后仍执行原有 AES-CTR 解包流程",
        },
        "module": {
            "descriptor_offset": f"0x{descriptor:x}",
            "data_offset": f"0x{data_offset:x}",
            "allocation_capacity": capacity,
            "original_stored_size": stored_size,
            "patched_stored_size": len(recompressed),
            "unpacked_size": len(patched_secmanager),
            "patched_stored_md5": stored_md5,
            "patched_unpacked_md5": unpacked_md5,
        },
    }
    return patched_secmanager, patched_tee, info


def patch_keybox_ta(helper, secmanager: bytes, encrypted_ta: bytes) -> tuple[bytes, bytes, dict[str, object]]:
    require_sha256("加密 Keybox TA", encrypted_ta, EXPECTED_KEYBOX_TA_SHA256)
    rsa = helper.parse_embedded_rsa(secmanager)
    trailer_offset, trailer_size = helper.locate_trailer(encrypted_ta)
    symmetric = helper.unwrap_symmetric_material(encrypted_ta, trailer_offset, rsa)
    plaintext = helper.openssl_aes_ctr(encrypted_ta[:trailer_offset], symmetric["key"], symmetric["iv"])
    require_sha256("明文 Keybox ELF", plaintext, EXPECTED_KEYBOX_ELF_SHA256)
    if plaintext[KEYBOX_PATCH_OFFSET : KEYBOX_PATCH_OFFSET + 4] != KEYBOX_EXPECTED:
        raise ValueError("Keybox 调用者门原始指令不匹配")

    patched_plaintext = bytearray(plaintext)
    patched_plaintext[KEYBOX_PATCH_OFFSET : KEYBOX_PATCH_OFFSET + 4] = AARCH64_NOP
    patched_plaintext = bytes(patched_plaintext)
    encrypted_payload = helper.openssl_aes_ctr(patched_plaintext, symmetric["key"], symmetric["iv"])
    patched_encrypted_ta = encrypted_payload + encrypted_ta[trailer_offset:]
    if len(patched_encrypted_ta) != len(encrypted_ta):
        raise ValueError("补丁 Keybox TA 大小发生变化")

    roundtrip = helper.openssl_aes_ctr(patched_encrypted_ta[:trailer_offset], symmetric["key"], symmetric["iv"])
    if roundtrip != patched_plaintext:
        raise ValueError("补丁 Keybox TA AES-CTR 回读不一致")
    if roundtrip[KEYBOX_PATCH_OFFSET : KEYBOX_PATCH_OFFSET + 4] != AARCH64_NOP:
        raise ValueError("补丁 Keybox TA 指令回读失败")

    info = {
        "patch": {
            "component": "d91f322ad5a441d5955110eda3272fc0 Keybox TA",
            "virtual_address": "0x0040109c",
            "file_offset": f"0x{KEYBOX_PATCH_OFFSET:x}",
            "before_hex": KEYBOX_EXPECTED.hex(),
            "after_hex": AARCH64_NOP.hex(),
            "meaning": "保留 command=0x64 与 paramTypes=0x662 校验，仅取消 caller_mode==1 限制",
        },
        "enc_ta": {
            "trailer_offset": f"0x{trailer_offset:x}",
            "trailer_size": trailer_size,
            "aes_bits": len(symmetric["key"]) * 8,
            "aes_key_hex": symmetric["key"].hex(),
            "aes_iv_hex": symmetric["iv"].hex(),
        },
    }
    return patched_plaintext, patched_encrypted_ta, info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tee", required=True, type=Path, help="精确原厂 tee.img")
    parser.add_argument("--secmanager", required=True, type=Path, help="从 tee.img 解包的 070_uTsecManager")
    parser.add_argument("--keybox-ta", required=True, type=Path, help="实机 d91f...ta")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    helper = load_decrypt_helpers()
    tee = args.tee.read_bytes()
    secmanager = args.secmanager.read_bytes()
    encrypted_ta = args.keybox_ta.read_bytes()
    patched_plaintext, patched_encrypted_ta, keybox_info = patch_keybox_ta(helper, secmanager, encrypted_ta)
    patched_secmanager, patched_tee, tee_info = patch_secmanager_and_tee(secmanager, tee)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "keybox_plaintext": args.output_dir / "d91f322ad5a441d5955110eda3272fc0_caller_gate_nop_明文.elf",
        "keybox_encrypted": args.output_dir / "d91f322ad5a441d5955110eda3272fc0_caller_gate_nop.ta",
        "secmanager": args.output_dir / "uTsecManager_verify_result_nop",
        "tee": args.output_dir / "tee_xaga_V13.0.5.0_Keybox只读验证旁路.img",
    }
    outputs["keybox_plaintext"].write_bytes(patched_plaintext)
    outputs["keybox_encrypted"].write_bytes(patched_encrypted_ta)
    outputs["secmanager"].write_bytes(patched_secmanager)
    outputs["tee"].write_bytes(patched_tee)

    manifest = {
        "scope": "Redmi Note 11T Pro / xaga / V13.0.5.0.SLOMIXM exact artifacts only",
        "safety": [
            "Keybox TA 只开放原有读取命令 0x64；写入命令 0/0x65/0x66 未修改",
            "TEE 补丁只忽略第三方 TA 验签返回值；TA 解析与 AES 解包流程不变",
            "所有输入均有精确 SHA256 与原始指令双重门禁",
        ],
        "inputs": {
            "tee": {"path": str(args.tee.resolve()), "size": len(tee), "sha256": digest(tee)},
            "secmanager": {"path": str(args.secmanager.resolve()), "size": len(secmanager), "sha256": digest(secmanager)},
            "keybox_ta": {"path": str(args.keybox_ta.resolve()), "size": len(encrypted_ta), "sha256": digest(encrypted_ta)},
        },
        "keybox": keybox_info,
        "tee": tee_info,
        "outputs": {
            key: {"path": str(path.resolve()), "size": path.stat().st_size, "sha256": digest(path.read_bytes())}
            for key, path in outputs.items()
        },
    }
    manifest_path = args.output_dir / "补丁清单.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sums_path = args.output_dir / "SHA256SUMS"
    sum_lines = [f"{digest(path.read_bytes())}  {path.name}" for path in outputs.values()]
    sum_lines.append(f"{digest(manifest_path.read_bytes())}  {manifest_path.name}")
    sums_path.write_text("\n".join(sum_lines) + "\n", encoding="utf-8")

    print("[OK] Keybox 与 TEE 只读提取补丁构建完成")
    for name, path in outputs.items():
        print(f"[OK] {name}: {path.name} {path.stat().st_size} bytes SHA256={digest(path.read_bytes())}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
