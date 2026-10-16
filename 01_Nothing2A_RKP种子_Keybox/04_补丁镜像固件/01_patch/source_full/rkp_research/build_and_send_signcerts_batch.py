#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from rkp_research import build_and_send_signcerts as b


def _raw_dir(run: Path) -> Path:
    return run / "raw" if (run / "raw").is_dir() else run


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _cert_leaf_public_xy(cert_der: bytes) -> bytes | None:
    marker = bytes.fromhex("03420004")
    pos = cert_der.find(marker)
    if pos < 0 or pos + 68 > len(cert_der):
        return None
    return cert_der[pos + 4 : pos + 68]


def _key_artifacts(key_run: Path, key_count: int, prefix: str, outdir: Path) -> list[dict[str, Any]]:
    raw = _raw_dir(key_run)
    keys: list[dict[str, Any]] = []
    for i in range(key_count):
        tag = f"{prefix}_{i:02d}"
        pub = (raw / f"{tag}_pub_len.bin").read_bytes()
        priv_full = (raw / f"{tag}_priv_full.bin").read_bytes()
        cose = b.extract_cose_key_from_maced_public_key(pub)
        x, y = b.extract_xy_from_cose(cose)
        side_obj, scalar = b.extract_sideleak_scalar(priv_full)
        if not b.verify_scalar_matches_public(scalar, x, y):
            raise ValueError(f"{tag}: sideleak scalar does not match public key")
        sec1 = b.make_sec1_der(scalar, x, y)
        pkcs8 = b.make_pkcs8_der(sec1)
        kdir = outdir / f"key_{i:02d}"
        kdir.mkdir(parents=True, exist_ok=True)
        (kdir / "maced_public_key.cbor").write_bytes(pub)
        (kdir / "cose_key.cbor").write_bytes(cose)
        (kdir / "public_xy.bin").write_bytes(x + y)
        (kdir / "private_scalar.bin").write_bytes(scalar)
        (kdir / "sideleak_object_196.bin").write_bytes(side_obj)
        (kdir / "ec_private_key_sec1.der").write_bytes(sec1)
        (kdir / "ec_private_key_sec1.pem").write_text(b.pem("EC PRIVATE KEY", sec1), encoding="ascii")
        (kdir / "ec_private_key_pkcs8.der").write_bytes(pkcs8)
        (kdir / "ec_private_key_pkcs8.pem").write_text(b.pem("PRIVATE KEY", pkcs8), encoding="ascii")
        keys.append(
            {
                "index": i,
                "tag": tag,
                "dir": str(kdir),
                "cose": cose,
                "public_xy": x + y,
                "scalar": scalar,
                "private_key_pkcs8_pem": kdir / "ec_private_key_pkcs8.pem",
                "public_xy_sha256": hashlib.sha256(x + y).hexdigest(),
                "private_scalar_sha256": hashlib.sha256(scalar).hexdigest(),
            }
        )
    return keys


def build_from_runs(
    binder_run: Path,
    key_run: Path,
    geek_dir: Path,
    outdir: Path,
    key_count: int,
    prefix: str,
    fingerprint: str,
) -> dict[str, Any]:
    binder_raw = _raw_dir(binder_run)
    challenge = (geek_dir / "challenge.bin").read_bytes()
    outdir.mkdir(parents=True, exist_ok=True)
    keys = _key_artifacts(key_run, key_count, prefix, outdir)
    maced_keys_to_sign = b.build_maced_keys_to_sign(
        [item["cose"] for item in keys],
        (binder_raw / "csr_maced_keys_len.bin").read_bytes(),
    )
    cert_req = b.build_certificate_request(
        device_info_raw=(binder_raw / "csr_device_info_len.bin").read_bytes(),
        challenge=challenge,
        protected_data_raw=(binder_raw / "csr_protected_data_len.bin").read_bytes(),
        maced_keys_to_sign_raw=maced_keys_to_sign,
        fingerprint=fingerprint,
    )
    (outdir / "maced_keys_to_sign.cbor").write_bytes(maced_keys_to_sign)
    (outdir / "certificate_request.cbor").write_bytes(cert_req)
    (outdir / "challenge.bin").write_bytes(challenge)

    protected_recipients = b.extract_protected_data_recipient_public_keys(
        (binder_raw / "csr_protected_data_len.bin").read_bytes()
    )
    google_eek_keys = b.extract_eek_public_keys_from_chain((geek_dir / "geek_curve_2.cbor").read_bytes())
    google_eek_kids = {k["kid"] for k in google_eek_keys if "kid" in k}
    summary: dict[str, Any] = {
        "binder_run": str(binder_run),
        "key_run": str(key_run),
        "binder_raw": str(binder_raw),
        "geek_dir": str(geek_dir),
        "fingerprint": fingerprint,
        "key_count": key_count,
        "key_prefix": prefix,
        "challenge_len": len(challenge),
        "maced_keys_to_sign_len": len(maced_keys_to_sign),
        "certificate_request_len": len(cert_req),
        "keys": [
            {
                "index": k["index"],
                "tag": k["tag"],
                "dir": k["dir"],
                "public_xy_sha256": k["public_xy_sha256"],
                "private_scalar_sha256": k["private_scalar_sha256"],
            }
            for k in keys
        ],
        "protected_data_recipient_kid": [r["kid"].hex() for r in protected_recipients if "kid" in r],
        "google_eek_kid": [k["kid"].hex() for k in google_eek_keys if "kid" in k],
        "protected_data_recipient_kid_matches_google_eek": [
            ("kid" in r and r["kid"] in google_eek_kids) for r in protected_recipients
        ],
        "artifacts": {
            "certificate_request": str(outdir / "certificate_request.cbor"),
            "maced_keys_to_sign": str(outdir / "maced_keys_to_sign.cbor"),
        },
        "cbor_summary": {
            "certificate_request": b.cbor_to_summary(cert_req),
            "maced_keys_to_sign": b.cbor_to_summary(maced_keys_to_sign),
        },
    }
    (outdir / "build_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    return summary


def finalize_batch_response(outdir: Path, response: bytes, key_count: int) -> dict[str, Any]:
    chains = b.parse_signed_certificates_response(response)
    result: dict[str, Any] = {"chain_count": len(chains), "chains": []}
    for i, chain in enumerate(chains):
        cdir = outdir / f"chain_{i:02d}"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "cert_chain.der").write_bytes(chain)
        cert_paths = b.write_cert_chain_artifacts(chain, cdir)
        key_dir = outdir / f"key_{i:02d}"
        pkcs8_pem_path = key_dir / "ec_private_key_pkcs8.pem"
        public_xy_path = key_dir / "public_xy.bin"
        leaf_xy = _cert_leaf_public_xy(cert_paths[0].read_bytes()) if cert_paths else None
        public_xy = public_xy_path.read_bytes() if public_xy_path.exists() else None
        if pkcs8_pem_path.exists():
            cert_pems = [(cdir / f"cert_{j:02d}.pem").read_text(encoding="ascii") for j in range(len(cert_paths))]
            (cdir / "key.xml").write_text(
                b.make_android_attestation_xml(
                    f"google_rkp_batch_{i:02d}",
                    pkcs8_pem_path.read_text(encoding="ascii"),
                    cert_pems,
                ),
                encoding="utf-8",
            )
        result["chains"].append(
            {
                "index": i,
                "chain_len": len(chain),
                "cert_count": len(cert_paths),
                "sha256": hashlib.sha256(chain).hexdigest(),
                "dir": str(cdir),
                "xml": str(cdir / "key.xml"),
                "has_private_key": pkcs8_pem_path.exists(),
                "leaf_public_matches_private_public": bool(leaf_xy and public_xy and leaf_xy == public_xy),
                "leaf_public_xy_sha256": hashlib.sha256(leaf_xy).hexdigest() if leaf_xy else None,
            }
        )
    result["expected_key_count"] = key_count
    result["chain_count_matches_key_count"] = len(chains) == key_count
    (outdir / "signed_chains_summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Build/send Google signCertificates request for a batch Binder CSR.")
    ap.add_argument("--binder-run", type=Path, default=Path((b.ROOT / "rkp_research/LATEST_BINDER_CSR_FROM_DIRECT.txt").read_text().strip()))
    ap.add_argument("--key-run", type=Path, default=None)
    ap.add_argument("--geek-dir", type=Path, default=b.resolve_recorded_path(Path((b.ROOT / "rkp_research/LATEST_GEEK_FETCH.txt").read_text().strip())))
    ap.add_argument("--outdir", type=Path, default=b.ROOT / f"rkp_research/signcerts_batch_{time.strftime('%Y%m%d_%H%M%S')}")
    ap.add_argument("--fingerprint", default=b.DEFAULT_FINGERPRINT)
    ap.add_argument("--host", default=b.DEFAULT_HOST)
    ap.add_argument("--key-count", type=int, default=12)
    ap.add_argument("--key-prefix", default="rkp_gen_prod")
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--request-id", default=None)
    args = ap.parse_args(argv)

    binder_run = b.resolve_recorded_path(args.binder_run).resolve()
    binder_summary = _load_json(binder_run / "summary.json")
    key_run = args.key_run or Path(binder_summary["key_run"])
    key_run = b.resolve_recorded_path(key_run).resolve()
    geek_dir = b.resolve_recorded_path(args.geek_dir).resolve()
    outdir = args.outdir.resolve()
    summary = build_from_runs(
        binder_run,
        key_run,
        geek_dir,
        outdir,
        args.key_count,
        args.key_prefix,
        args.fingerprint,
    )
    summary["request_id"] = args.request_id or str(uuid.uuid4())
    summary["host"] = args.host
    if args.send:
        cert_req = (outdir / "certificate_request.cbor").read_bytes()
        challenge = (outdir / "challenge.bin").read_bytes()
        info, body = b.post_sign_certificates(args.host, challenge, cert_req, summary["request_id"])
        (outdir / "response_http.json").write_text(json.dumps(info, indent=2, ensure_ascii=False) + "\n")
        (outdir / "response.cbor").write_bytes(body)
        summary["http"] = info
        if info.get("status") == 200:
            summary["signed"] = finalize_batch_response(outdir, body, args.key_count)
        else:
            try:
                summary["response_text"] = body.decode("utf-8", "replace")[:2000]
            except Exception:
                summary["response_hex_prefix"] = body[:128].hex()
        (outdir / "build_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
