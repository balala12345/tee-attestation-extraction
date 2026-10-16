#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import struct
from pathlib import Path


def der_len(blob: bytes, off: int) -> int:
    if off + 2 > len(blob) or blob[off] != 0x30:
        raise ValueError(f"not DER sequence at 0x{off:x}")
    first = blob[off + 1]
    if first < 0x80:
        return 2 + first
    count = first & 0x7f
    if count == 0 or off + 2 + count > len(blob):
        raise ValueError("invalid DER length")
    return 2 + count + int.from_bytes(blob[off + 2:off + 2 + count], "big")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("payload", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()
    blob = args.payload.read_bytes()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    off = 0
    version = struct.unpack_from("<I", blob, off)[0]
    off += 4
    entries = []
    for alg in ("ec", "rsa"):
        plen = struct.unpack_from("<I", blob, off)[0]
        off += 4
        actual = der_len(blob, off)
        if actual != plen:
            raise SystemExit(f"{alg} private length mismatch {plen}!={actual}")
        priv = blob[off:off + plen]
        (args.output / f"{alg}_private_key.der").write_bytes(priv)
        off += plen
        count = struct.unpack_from("<I", blob, off)[0]
        off += 4
        certs = []
        for index in range(count):
            clen = struct.unpack_from("<I", blob, off)[0]
            off += 4
            actual = der_len(blob, off)
            if actual != clen:
                raise SystemExit(f"{alg} cert {index} length mismatch {clen}!={actual}")
            cert = blob[off:off + clen]
            path = args.output / f"{alg}_cert_{index}.der"
            path.write_bytes(cert)
            certs.append({"path": str(path), "length": clen, "sha256": hashlib.sha256(cert).hexdigest()})
            off += clen
        entries.append({"algorithm": alg, "private_length": plen, "certificate_count": count, "certificates": certs})
    (args.output / "attestation_keybox_plain.bin").write_bytes(blob[:off])
    (args.output / "attestation_keybox_tail_unmodified.bin").write_bytes(blob[off:])
    report = {
        "status": "PASS" if version == 1 and off == 8624 else "REVIEW",
        "version_or_keybox_number": version,
        "payload_length": len(blob),
        "plaintext_length": off,
        "tail_unmodified_length": len(blob) - off,
        "payload_sha256": hashlib.sha256(blob).hexdigest(),
        "entries": entries,
        "private_values_printed": False,
    }
    report_path = args.output / "keybox_parse_report.json"
    report_path.write_text(__import__("json").dumps(report, indent=2) + "\n")
    os.chmod(report_path, 0o600)
    print(__import__("json").dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
