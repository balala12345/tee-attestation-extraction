#!/usr/bin/env python3
from pathlib import Path
import struct, hashlib
SRC=Path('device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin')
OUTDIR=Path('patched_ta')
TEXT_BASE=0x1000
TEXT_OFF=0xd0
HOOK=0x21fe0
CAVE=0x411ac

def off(va): return TEXT_OFF + (va - TEXT_BASE)

def enc_b(src,dst,link=False):
    imm=(dst-src)//4
    if (dst-src)%4:
        raise ValueError('unaligned branch')
    if not (-(1<<25) <= imm < (1<<25)):
        raise ValueError('branch out of range')
    return struct.pack('<I',(0x94000000 if link else 0x14000000)|(imm & 0x03ffffff))

# At CMD_RKP_GENERATE_ECDSA_P256_KEY success path (0x21fe0), after the stock TA
# has already produced the MacedPublicKey and before returning lengths to HAL, replace
# the private-key-handle output buffer with a bounded copy from the internal keygen
# object pointer at [sp,#216]. In previous ptr216 run the P-256 scalar is at +0x98
# inside this object; 0xc4 bytes is sufficient and also fits Android HAL's 228-byte
# mapped private-handle buffer (stock HAL maps 228 and the source alloc is cap-32=196).
#
# Logic:
#   len = min(max(w23 - 32, 0), 196)
#   memcpy(private_out=x20, src=*[sp+216], len)
#   TCI.private_len = len
#   keep original public len write and original cleanup path.
snippet=bytes.fromhex(
    'e00314aa'      # mov x0,x20
    'e16f40f9'      # ldr x1,[sp,#216]
    'ff820071'      # cmp w23,#32
    'e2820051'      # sub w2,w23,#32
    '42809f1a'      # csel w2,w2,wzr,hi
    '89188052'      # mov w9,#196
    '5f00096b'      # cmp w2,w9
    '4230891a'      # csel w2,w2,w9,lo
    'c90fff97'      # bl 0x50f0 memcpy (valid for cave 0x411ac, insn @ 0x411cc)
    'ff820071'      # cmp w23,#32
    'e0820051'      # sub w0,w23,#32
    '00809f1a'      # csel w0,w0,wzr,hi
    '89188052'      # mov w9,#196
    '1f00096b'      # cmp w0,w9
    '0030891a'      # csel w0,w0,w9,lo
    '609301b8'      # stur w0,[x27,#25]
    'f96b45a9'      # ldp x25,x26,[sp,#80] ; original overwritten instruction
    '751301b8'      # stur w21,[x27,#17]   ; original following instruction
    'aa82ff17'      # b 0x21c9c cleanup/return path (valid for insn @ 0x411f4)
)

b0=SRC.read_bytes()
b=bytearray(b0)
expected={
    HOOK: bytes.fromhex('f96b45a9'),
    CAVE: bytes(len(snippet)),
}
for va, exp in expected.items():
    cur=bytes(b[off(va):off(va)+len(exp)])
    if cur != exp:
        raise SystemExit(f'expected mismatch at {va:#x}: got {cur.hex()} expected {exp.hex()}')
# branch from hook to cave
b[off(HOOK):off(HOOK)+4]=enc_b(HOOK,CAVE,False)
b[off(CAVE):off(CAVE)+len(snippet)]=snippet
OUTDIR.mkdir(exist_ok=True)
# system replacement: original UUID 0706...4d
system=OUTDIR/'0706000000000000000000000000004d.rkp_ptr196.tlbin'
system.write_bytes(b)
# direct-test variant: change UUID last byte to 4e to avoid UUID collision with running KeyMint
bd=bytearray(b)
if bd[0x18:0x28] != bytes.fromhex('0706000000000000000000000000004d'):
    raise SystemExit('unexpected MCLF UUID')
bd[0x27]=0x4e
direct=OUTDIR/'0706000000000000000000000000004e.rkp_ptr196.tlbin'
direct.write_bytes(bd)
print('src', SRC, hashlib.sha256(b0).hexdigest())
print('system', system, hashlib.sha256(b).hexdigest(), 'uuid', b[0x18:0x28].hex())
print('direct', direct, hashlib.sha256(bd).hexdigest(), 'uuid', bd[0x18:0x28].hex())
print('hook branch', b[off(HOOK):off(HOOK)+4].hex(), 'snippet_len', len(snippet))
