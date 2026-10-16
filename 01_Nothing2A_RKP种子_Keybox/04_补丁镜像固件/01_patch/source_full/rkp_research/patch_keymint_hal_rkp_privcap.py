#!/usr/bin/env python3
"""
Patch Trustonic KeyMint HAL RKP keygen private buffer capacity.

The stock HAL allocates/maps a 228-byte private buffer for
generateEcdsaP256KeyPair. The TA sideleak_biglen experiment needs enough room
for the stock 216-byte private blob plus a leak tail at +0x400.

This patch changes only the private vector allocation/capacity immediate:
  0x1d1b0: mov w8,#228 -> mov w8,#0x600
  0x1d1b8: mov w1,#228 -> mov w1,#0x600
"""
from pathlib import Path
import hashlib
import struct

SRC = Path("device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic")
OUTDIR = Path("patched_hal")
OUT = OUTDIR / "android.hardware.security.keymint@2.0-service.trustonic.rkp_privcap_0x600"
PATCHES = {
    0x1D1B0: ("mov_w8_228", 8, 0xE4),
    0x1D1B8: ("mov_w1_228", 1, 0xE4),
}
NEW_CAP = 0x600


def mov_w(rd: int, imm16: int) -> bytes:
    if not (0 <= rd <= 31 and 0 <= imm16 <= 0xFFFF):
        raise ValueError("bad movz")
    return struct.pack("<I", 0x52800000 | (imm16 << 5) | rd)


def main() -> None:
    b0 = SRC.read_bytes()
    b = bytearray(b0)

    for off, (name, rd, old_imm) in PATCHES.items():
        expected = mov_w(rd, old_imm)
        actual = bytes(b[off : off + 4])
        if actual != expected:
            raise SystemExit(f"{name} mismatch at {off:#x}: got {actual.hex()} expected {expected.hex()}")
        b[off : off + 4] = mov_w(rd, NEW_CAP)

    OUTDIR.mkdir(exist_ok=True)
    OUT.write_bytes(b)

    print("src", SRC, hashlib.sha256(b0).hexdigest(), "size", len(b0))
    print("out", OUT, hashlib.sha256(b).hexdigest(), "size", len(b))
    for off, (name, rd, old_imm) in PATCHES.items():
        print(name, hex(off), mov_w(rd, old_imm).hex(), "->", bytes(b[off : off + 4]).hex())


if __name__ == "__main__":
    main()
