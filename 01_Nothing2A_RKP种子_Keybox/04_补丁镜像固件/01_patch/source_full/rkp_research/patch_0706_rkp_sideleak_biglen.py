#!/usr/bin/env python3
"""
System-oriented RKP side-leak patch.

Keep the stock private blob intact at private_out[0:stock_private_len], copy the
internal 196-byte keygen object to private_out+0x400, and report private_len as
0x4c4 so the normal-world HAL/RKPD stack can persist the tail.

This must be paired with a HAL patch that allocates/passes a private buffer of
at least 0x4c4 bytes. The stock HAL only maps 228 bytes.
"""
from pathlib import Path
import hashlib
import struct

SRC = Path("device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin")
OUTDIR = Path("patched_ta")
TEXT_BASE = 0x1000
TEXT_OFF = 0xD0
HOOK = 0x21FE0
CAVE = 0x411AC
MEMCPY = 0x50F0
RETURN_PATH = 0x21C9C
LEAK_OFFSET = 0x400
LEAK_LEN = 196
RETURN_LEN = LEAK_OFFSET + LEAK_LEN


def off(va: int) -> int:
    return TEXT_OFF + (va - TEXT_BASE)


def enc_b(src: int, dst: int, link: bool = False) -> bytes:
    if (dst - src) % 4:
        raise ValueError(f"unaligned branch {src:#x}->{dst:#x}")
    imm = (dst - src) // 4
    if not (-(1 << 25) <= imm < (1 << 25)):
        raise ValueError(f"branch out of range {src:#x}->{dst:#x}")
    return struct.pack("<I", (0x94000000 if link else 0x14000000) | (imm & 0x03FFFFFF))


def mov_w(rd: int, imm16: int) -> bytes:
    if not (0 <= rd <= 31 and 0 <= imm16 <= 0xFFFF):
        raise ValueError("bad movz")
    return struct.pack("<I", 0x52800000 | (imm16 << 5) | rd)


def main() -> None:
    b0 = SRC.read_bytes()
    b = bytearray(b0)

    expected = {
        HOOK: bytes.fromhex("f96b45a9 751301b8"),
        CAVE: bytes(0x40),
    }
    for va, exp in expected.items():
        cur = bytes(b[off(va) : off(va) + len(exp)])
        if cur != exp:
            raise SystemExit(f"expected mismatch at {va:#x}: got {cur.hex()} expected {exp.hex()}")

    # Stub:
    #   memcpy(private_out + 0x400, *[sp,#216], 196)
    #   TCI.private_len = 0x4c4
    #   replay original public_len write and return through stock cleanup.
    snippet = b"".join(
        [
            bytes.fromhex("80021091"),  # add x0,x20,#0x400
            bytes.fromhex("e16f40f9"),  # ldr x1,[sp,#216]
            mov_w(2, LEAK_LEN),         # mov w2,#196
            enc_b(CAVE + 0x0C, MEMCPY, True),
            mov_w(0, RETURN_LEN),       # mov w0,#0x4c4
            bytes.fromhex("609301b8"),  # stur w0,[x27,#25]
            bytes.fromhex("f96b45a9"),  # ldp x25,x26,[sp,#80]
            bytes.fromhex("751301b8"),  # stur w21,[x27,#17]
            enc_b(CAVE + 0x20, RETURN_PATH, False),
        ]
    )

    if len(snippet) > 0x40:
        raise SystemExit(f"snippet too large: {len(snippet)}")

    b[off(HOOK) : off(HOOK) + 4] = enc_b(HOOK, CAVE, False)
    b[off(CAVE) : off(CAVE) + len(snippet)] = snippet

    OUTDIR.mkdir(exist_ok=True)
    system = OUTDIR / "0706000000000000000000000000004d.rkp_sideleak_biglen.tlbin"
    system.write_bytes(b)

    bd = bytearray(b)
    if bd[0x18:0x28] != bytes.fromhex("0706000000000000000000000000004d"):
        raise SystemExit(f"unexpected MCLF UUID: {bd[0x18:0x28].hex()}")
    bd[0x27] = 0x4E
    direct = OUTDIR / "0706000000000000000000000000004e.rkp_sideleak_biglen.tlbin"
    direct.write_bytes(bd)

    print("src", SRC, hashlib.sha256(b0).hexdigest())
    print("system_biglen", system, hashlib.sha256(b).hexdigest(), "uuid", b[0x18:0x28].hex())
    print("direct_biglen", direct, hashlib.sha256(bd).hexdigest(), "uuid", bd[0x18:0x28].hex())
    print("hook_branch", b[off(HOOK) : off(HOOK) + 4].hex(), "snippet_len", len(snippet))
    print("leak_offset", hex(LEAK_OFFSET), "leak_len", LEAK_LEN, "return_len", hex(RETURN_LEN))
    print("snippet", snippet.hex())


if __name__ == "__main__":
    main()
