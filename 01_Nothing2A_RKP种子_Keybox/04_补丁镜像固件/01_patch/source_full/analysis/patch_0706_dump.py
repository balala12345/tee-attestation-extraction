#!/usr/bin/env python3
from pathlib import Path
import struct, hashlib
SRC=Path('device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin')
DST=Path('patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin')
TEXT_BASE=0x1000
TEXT_OFF=0xd0

def off(va): return TEXT_OFF + (va - TEXT_BASE)

def enc_b(src,dst,link=False):
    imm=(dst-src)//4
    assert (dst-src)%4==0
    assert -(1<<25) <= imm < (1<<25)
    return struct.pack('<I',(0x94000000 if link else 0x14000000) | (imm & 0x03ffffff))

# cave code assembled for VA 0x411ac.  See analysis/snippet.S.
snippet=bytes.fromhex(
    'e08744a9'      # ldp x0,x1,[sp,#72]
    'e20301aa'      # mov x2,x1
    'e10300aa'      # mov x1,x0
    'e00314aa'      # mov x0,x20
    'cd0fff97'      # bl 0x50f0 memcpy
    'e08744a9'      # ldp x0,x1,[sp,#72]
    'fd71ff97'      # bl 0x1d9b8 parse
    '5f73ff17'      # b 0x1df44
    'f303002a'      # mov w19,w0
    'a0000035'      # cbnz w0, skip
    'e11b40f9'      # ldr x1,[sp,#48]
    'e00316aa'      # mov x0,x22
    'e20315aa'      # mov x2,x21
    'c40fff97'      # bl 0x50f0 memcpy
    'bd74ff17'      # b 0x1e4d8
)
# Branch patches
patches={
    0x1df3c: enc_b(0x1df3c,0x411ac,False),
    0x1e4d4: enc_b(0x1e4d4,0x411cc,False),
    0x411ac: snippet,
}
expected={
    0x1df3c: bytes.fromhex('e08744a9'),  # ldp x0,x1,[sp,#72]
    0x1e4d4: bytes.fromhex('f303002a'),  # mov w19,w0
    0x411ac: bytes(len(snippet)),
}
b=bytearray(SRC.read_bytes())
for va,exp in expected.items():
    cur=bytes(b[off(va):off(va)+len(exp)])
    if cur!=exp:
        raise SystemExit(f'expected mismatch at {va:#x}: got {cur.hex()} expected {exp.hex()}')
for va,data in patches.items():
    b[off(va):off(va)+len(data)] = data
DST.parent.mkdir(exist_ok=True)
DST.write_bytes(b)
print('wrote', DST)
print('src sha256', hashlib.sha256(SRC.read_bytes()).hexdigest())
print('dst sha256', hashlib.sha256(b).hexdigest())
for va,data in patches.items(): print(hex(va), off(va), data.hex())
