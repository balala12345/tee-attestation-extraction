#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rkp_research import build_and_send_signcerts as b

DEFAULT_FINGERPRINT = b.DEFAULT_FINGERPRINT
DEFAULT_HOST = b.DEFAULT_HOST

@dataclass
class Variant:
    name: str
    description: str
    body: bytes
    challenge_for_query: bytes


def _load_parts(raw_dir: Path, geek_dir: Path) -> dict[str, bytes]:
    raw = raw_dir / 'raw' if (raw_dir / 'raw').is_dir() else raw_dir
    cose = b.extract_cose_key_from_maced_public_key((raw / 'rkp_gen_test_pub_len.bin').read_bytes())
    mac = (raw / 'csr_maced_keys_len.bin').read_bytes()
    maced_old = b.build_maced_keys_to_sign([cose], mac)
    pub = (raw / 'rkp_gen_test_pub_len.bin').read_bytes()
    maced_raw_pub = b.build_maced_keys_to_sign([pub], mac)
    return {
        'device_info': (raw / 'csr_device_info_len.bin').read_bytes(),
        'protected_data': (raw / 'csr_protected_data_len.bin').read_bytes(),
        'challenge': (geek_dir / 'challenge.bin').read_bytes(),
        'maced_old': maced_old,
        'maced_raw_pub': maced_raw_pub,
    }


def _unverified(fingerprint: str) -> bytes:
    return b.enc_unverified_device_info(fingerprint)


def build_variants(raw_dir: Path, geek_dir: Path, fingerprint: str = DEFAULT_FINGERPRINT) -> list[Variant]:
    p = _load_parts(raw_dir, geek_dir)
    old_exact = b.build_certificate_request(
        p['device_info'], p['challenge'], p['protected_data'], p['maced_old'], fingerprint
    )
    old_empty_unverified = b.enc_array_raw([
        b.enc_array_raw([p['device_info'], b.enc_map_raw([])]),
        b.enc_bstr(p['challenge']),
        p['protected_data'],
        p['maced_old'],
    ])
    v2_append_unverified = b.enc_array_raw([
        p['device_info'],
        b.enc_bstr(p['challenge']),
        p['protected_data'],
        p['maced_old'],
        _unverified(fingerprint),
    ])
    raw_maced_public_payload = b.build_certificate_request(
        p['device_info'], p['challenge'], p['protected_data'], p['maced_raw_pub'], fingerprint
    )
    challenge_as_array_item = b.enc_array_raw([
        b.enc_array_raw([p['device_info'], _unverified(fingerprint)]),
        b.enc_array_raw([b.enc_bstr(p['challenge'])]),
        p['protected_data'],
        p['maced_old'],
    ])
    return [
        Variant('rkpd_old_exact', 'Exact old RKPD buildCertificateRequest shape.', old_exact, p['challenge']),
        Variant('rkpd_old_empty_unverified', 'Old shape but UnverifiedDeviceInfo is empty map.', old_empty_unverified, p['challenge']),
        Variant('v2_append_unverified', 'V2-like array with UnverifiedDeviceInfo appended as final item.', v2_append_unverified, p['challenge']),
        Variant('raw_maced_public_payload', 'Old shape but MacedKeysToSign payload array contains full MacedPublicKey instead of COSE_Key payload.', raw_maced_public_payload, p['challenge']),
        Variant('challenge_as_array_item', 'Malformed probe: challenge field is array containing challenge bstr.', challenge_as_array_item, p['challenge']),
    ]


def write_variants(raw_dir: Path, geek_dir: Path, outdir: Path, fingerprint: str = DEFAULT_FINGERPRINT) -> dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        'raw_dir': str(raw_dir),
        'geek_dir': str(geek_dir),
        'fingerprint': fingerprint,
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'variants': [],
    }
    for variant in build_variants(raw_dir, geek_dir, fingerprint):
        body_file = f'{variant.name}.cbor'
        (outdir / body_file).write_bytes(variant.body)
        manifest['variants'].append({
            'name': variant.name,
            'description': variant.description,
            'body_file': body_file,
            'body_len': len(variant.body),
            'body_sha256': hashlib.sha256(variant.body).hexdigest(),
            'challenge_hex': variant.challenge_for_query.hex(),
            'http_status': None,
            'http_reason': None,
            'response_file': None,
            'response_len': None,
            'response_sha256': None,
            'error_message': None,
        })
    (outdir / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    return manifest


def send_variants(outdir: Path, host: str = DEFAULT_HOST) -> dict[str, Any]:
    manifest_path = outdir / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    for item in manifest['variants']:
        body = (outdir / item['body_file']).read_bytes()
        challenge = bytes.fromhex(item['challenge_hex'])
        request_id = str(uuid.uuid4())
        info, response = b.post_sign_certificates(host, challenge, body, request_id)
        response_file = f"{item['name']}.response"
        http_file = f"{item['name']}.http.json"
        (outdir / response_file).write_bytes(response)
        (outdir / http_file).write_text(json.dumps(info, indent=2, ensure_ascii=False) + '\n')
        item['request_id'] = request_id
        item['http_status'] = info.get('status')
        item['http_reason'] = info.get('reason')
        item['http_file'] = http_file
        item['response_file'] = response_file
        item['response_len'] = len(response)
        item['response_sha256'] = hashlib.sha256(response).hexdigest()
        try:
            decoded = response.decode('utf-8')
            item['error_message'] = decoded[:1000]
        except UnicodeDecodeError:
            item['error_message'] = None
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='Build and optionally send RKPD signCertificates request variants.')
    ap.add_argument('--raw-dir', type=Path, default=b.resolve_recorded_path(Path((b.ROOT / 'rkp_research/LATEST_DIRECT_CSR_MATRIX.txt').read_text().strip())) / 'curve2_test1')
    ap.add_argument('--geek-dir', type=Path, default=b.resolve_recorded_path(Path((b.ROOT / 'rkp_research/LATEST_GEEK_FETCH.txt').read_text().strip())))
    ap.add_argument('--outdir', type=Path, default=b.ROOT / f'rkp_research/signcerts_variants_{time.strftime("%Y%m%d_%H%M%S")}')
    ap.add_argument('--fingerprint', default=DEFAULT_FINGERPRINT)
    ap.add_argument('--host', default=DEFAULT_HOST)
    ap.add_argument('--send', action='store_true')
    args = ap.parse_args(argv)
    manifest = write_variants(b.resolve_recorded_path(args.raw_dir).resolve(), b.resolve_recorded_path(args.geek_dir).resolve(), args.outdir.resolve(), args.fingerprint)
    if args.send:
        manifest = send_variants(args.outdir.resolve(), args.host)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(args.outdir.resolve())
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
