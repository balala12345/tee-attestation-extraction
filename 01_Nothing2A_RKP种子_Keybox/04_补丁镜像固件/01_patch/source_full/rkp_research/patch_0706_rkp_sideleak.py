#!/usr/bin/env python3
"""
Direct-only RKP side-channel patch for Trustonic KeyMint TA.

Purpose:
  Keep the stock RKP private handle returned by CMD 0x00050401 intact, but copy
  the internal 196-byte keygen object pointed to by [sp,#216] into a tail region
  of the direct client's large private mapped buffer at private_out + 0x400.

Do not mount this patch into the Android system HAL path: the stock HAL private
buffer is small. This patch is intended for the rkp_tee_probe direct client,
which maps an 8192-byte private buffer.
"""
from pathlib import Path
import hashlib
import struct

SRC = Path('device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin')
OUTDIR = Path('patched_ta')
TEXT_BASE = 0x1000
TEXT_OFF = 0xd0
HOOK = 0x21fe0
CAVE = 0x411ac
MEMCPY = 0x50f0
RETURN_PATH = 0x21c9c
LEAK_OFFSET = 0x400
LEAK_LEN = 196


def off(va: int) -> int:
    return TEXT_OFF + (va - TEXT_BASE)


def enc_b(src: int, dst: int, link: bool = False) -> bytes:
    if (dst - src) % 4:
        raise ValueError(f'unaligned branch {src:#x}->{dst:#x}')
    imm = (dst - src) // 4
    if not (-(1 << 25) <= imm < (1 << 25)):
        raise ValueError(f'branch out of range {src:#x}->{dst:#x}')
    return struct.pack('<I', (0x94000000 if link else 0x14000000) | (imm & 0x03ffffff))


def main() -> None:
    b0 = SRC.read_bytes()
    b = bytearray(b0)

    # Stock success-return path at 0x21fe0 starts with:
    #   ldp  x25, x26, [sp,#80]
    #   stur w21, [x27,#17]      ; TCI public_len = generated public len
    #   b    0x21c9c             ; cleanup/return
    expected = {
        HOOK: bytes.fromhex('f96b45a9 751301b8'),
        CAVE: bytes(0x40),
    }
    for va, exp in expected.items():
        cur = bytes(b[off(va):off(va) + len(exp)])
        if cur != exp:
            raise SystemExit(f'expected mismatch at {va:#x}: got {cur.hex()} expected {exp.hex()}')

    # Stub:
    #   add  x0, x20, #0x400     ; side-channel dst = private_out + 0x400
    #   ldr  x1, [sp,#216]       ; internal keygen object
    #   mov  w2, #196
    #   bl   memcpy
    #   ldp  x25, x26, [sp,#80]  ; replay original overwritten instruction
    #   stur w21, [x27,#17]      ; replay original public_len write
    #   b    0x21c9c
    # Important: no write to [x27,#25]; stock private_len/private handle stay intact.
    snippet = b''.join([
        bytes.fromhex('80021091'),                 # add x0,x20,#0x400
        bytes.fromhex('e16f40f9'),                 # ldr x1,[sp,#216]
        bytes.fromhex('82188052'),                 # mov w2,#196
        enc_b(CAVE + 0x0c, MEMCPY, True),          # bl memcpy
        bytes.fromhex('f96b45a9'),                 # ldp x25,x26,[sp,#80]
        bytes.fromhex('751301b8'),                 # stur w21,[x27,#17]
        enc_b(CAVE + 0x18, RETURN_PATH, False),    # b return path
    ])

    if len(snippet) > 0x40:
        raise SystemExit(f'snippet too large: {len(snippet)}')

    b[off(HOOK):off(HOOK) + 4] = enc_b(HOOK, CAVE, False)
    b[off(CAVE):off(CAVE) + len(snippet)] = snippet

    OUTDIR.mkdir(exist_ok=True)
    system = OUTDIR / '0706000000000000000000000000004d.rkp_sideleak.tlbin'
    system.write_bytes(b)

    bd = bytearray(b)
    if bd[0x18:0x28] != bytes.fromhex('0706000000000000000000000000004d'):
        raise SystemExit(f'unexpected MCLF UUID: {bd[0x18:0x28].hex()}')
    bd[0x27] = 0x4e
    direct = OUTDIR / '0706000000000000000000000000004e.rkp_sideleak.tlbin'
    direct.write_bytes(bd)

    print('src', SRC, hashlib.sha256(b0).hexdigest())
    print('system_direct_only_do_not_mount_to_hal', system, hashlib.sha256(b).hexdigest(), 'uuid', b[0x18:0x28].hex())
    print('direct', direct, hashlib.sha256(bd).hexdigest(), 'uuid', bd[0x18:0x28].hex())
    print('hook_branch', b[off(HOOK):off(HOOK)+4].hex(), 'snippet_len', len(snippet), 'leak_offset', hex(LEAK_OFFSET), 'leak_len', LEAK_LEN)
    print('snippet', snippet.hex())


if __name__ == '__main__':
    main()
