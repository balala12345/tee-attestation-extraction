#!/usr/bin/env python3
"""
RKP keygen control patch.

This hooks the same success-return site as the leak experiments, but it only
re-copies the stock private blob back into the normal-world private output
buffer. The returned public/private data should be byte-for-byte compatible
with stock behavior.

Purpose:
  If system RKPD provisioning succeeds with this patch, the obj216 system
  failure is caused by changing the returned private blob content, not by the
  hook site, branch to cave, or an extra post-keygen memcpy call.
"""
from pathlib import Path
import hashlib
import struct

SRC = Path("device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin")
OUTDIR = Path("patched_ta")
TEXT_BASE = 0x1000
TEXT_OFF = 0xD0
HOOK = 0x21FE0
CAVE = 0x411EC
MEMCPY = 0x50F0
RETURN_PATH = 0x21C9C


def off(va: int) -> int:
    return TEXT_OFF + (va - TEXT_BASE)


def enc_b(src: int, dst: int, link: bool = False) -> bytes:
    if (dst - src) % 4:
        raise ValueError(f"unaligned branch {src:#x}->{dst:#x}")
    imm = (dst - src) // 4
    if not (-(1 << 25) <= imm < (1 << 25)):
        raise ValueError(f"branch out of range {src:#x}->{dst:#x}")
    return struct.pack("<I", (0x94000000 if link else 0x14000000) | (imm & 0x03FFFFFF))


def main() -> None:
    b0 = SRC.read_bytes()
    b = bytearray(b0)

    expected = {
        HOOK: bytes.fromhex("f96b45a9 751301b8"),
        CAVE: bytes(0x30),
    }
    for va, exp in expected.items():
        cur = bytes(b[off(va) : off(va) + len(exp)])
        if cur != exp:
            raise SystemExit(f"expected mismatch at {va:#x}: got {cur.hex()} expected {exp.hex()}")

    # Stub:
    #   memcpy(private_out, stock_private_blob, stock_private_len)
    #   replay original public_len write and return through stock cleanup.
    snippet = b"".join(
        [
            bytes.fromhex("e00314aa"),  # mov x0,x20
            bytes.fromhex("e16740f9"),  # ldr x1,[sp,#200]
            bytes.fromhex("e2bf40b9"),  # ldr w2,[sp,#188]
            enc_b(CAVE + 0x0C, MEMCPY, True),
            bytes.fromhex("f96b45a9"),  # ldp x25,x26,[sp,#80]
            bytes.fromhex("751301b8"),  # stur w21,[x27,#17]
            enc_b(CAVE + 0x18, RETURN_PATH, False),
        ]
    )

    if len(snippet) > 0x30:
        raise SystemExit(f"snippet too large: {len(snippet)}")

    b[off(HOOK) : off(HOOK) + 4] = enc_b(HOOK, CAVE, False)
    b[off(CAVE) : off(CAVE) + len(snippet)] = snippet

    OUTDIR.mkdir(exist_ok=True)
    system = OUTDIR / "0706000000000000000000000000004d.rkp_recopy_stock.tlbin"
    system.write_bytes(b)

    bd = bytearray(b)
    if bd[0x18:0x28] != bytes.fromhex("0706000000000000000000000000004d"):
        raise SystemExit(f"unexpected MCLF UUID: {bd[0x18:0x28].hex()}")
    bd[0x27] = 0x4E
    direct = OUTDIR / "0706000000000000000000000000004e.rkp_recopy_stock.tlbin"
    direct.write_bytes(bd)

    print("src", SRC, hashlib.sha256(b0).hexdigest())
    print("system_control", system, hashlib.sha256(b).hexdigest(), "uuid", b[0x18:0x28].hex())
    print("direct_control", direct, hashlib.sha256(bd).hexdigest(), "uuid", bd[0x18:0x28].hex())
    print("hook_branch", b[off(HOOK) : off(HOOK) + 4].hex(), "snippet_len", len(snippet))
    print("snippet", snippet.hex())


if __name__ == "__main__":
    main()
