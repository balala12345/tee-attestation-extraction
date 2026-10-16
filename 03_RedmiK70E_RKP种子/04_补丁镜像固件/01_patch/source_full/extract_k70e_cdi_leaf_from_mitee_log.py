#!/usr/bin/env python3
"""Fail-closed, offline CDI_Leaf extraction from a K70E MiTEE log.

The stock dba51 KeyMint TA writes the P-256 CDI_Leaf scalar as exactly two
``utee:INFO/dump_to_hex/private_key`` rows.  This tool accepts either a saved
log increment or an exact before/after append pair, strictly verifies the
same-run zero-key AuthenticatedRequest, and keeps only the unique scalar whose
derived public SPKI equals that request's final DICE subject.

It never connects to a device or network and never prints private material.
The accepted raw scalar, public SPKI, and a hash-only report are committed as
one freshly-created output directory.  Private files are mode 0600.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
WORKSPACE_ROOT = HERE.parent.parent
VENV_PYTHONS = (
    WORKSPACE_ROOT / "third_party/google-rkp-sw/.venv/bin/python",
    WORKSPACE_ROOT / ".venv-rkp/bin/python",
)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ModuleNotFoundError as exc:
    if __name__ == "__main__" and os.environ.get("K70E_MITEE_LOG_VENV") != "1":
        venv_python = next((path for path in VENV_PYTHONS if path.is_file()), None)
        if venv_python is not None:
            environment = dict(os.environ)
            environment["K70E_MITEE_LOG_VENV"] = "1"
            os.execve(
                str(venv_python),
                [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
                environment,
            )
    expected = ", ".join(str(path) for path in VENV_PYTHONS)
    raise SystemExit(f"missing dependency {exc.name!r}; expected one of: {expected}") from exc

try:
    import k70e_portable_profile as profile
except (ModuleNotFoundError, SystemExit) as exc:
    if __name__ == "__main__" and os.environ.get("K70E_MITEE_LOG_VENV") != "1":
        venv_python = next((path for path in VENV_PYTHONS if path.is_file()), None)
        if venv_python is not None:
            environment = dict(os.environ)
            environment["K70E_MITEE_LOG_VENV"] = "1"
            os.execve(
                str(venv_python),
                [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
                environment,
            )
    raise SystemExit("unable to import the strict K70E AuthenticatedRequest verifier") from exc


SCHEMA = "k70e-cdi-leaf-mitee-log-extract-v1"
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_CSR_BYTES = 16 * 1024 * 1024
MAX_CHALLENGE_BYTES = 64

# The stock helper uses "%02x " sixteen times and the format
# "[%s:%s][%s:%d]%s(%4d): %s\n".  A 32-byte value therefore has exactly the
# endpoint rows 15 and 31.  Keeping this grammar exact prevents an error line,
# truncated row, interleaved dump, or hand-edited representation from being
# mistaken for a scalar.
PRIVATE_LINE = re.compile(
    rb"^(?P<prefix>[\x20-\x7e]*)"
    rb"\[utee:INFO\]\[dump_to_hex:59\]private_key"
    rb"\((?P<endpoint>  15|  31)\): "
    rb"(?P<payload>(?:[0-9a-f]{2} ){16})$"
)
ACTOR_SUFFIX = re.compile(rb"(?P<actor>[0-9]+\.[0-9]+)> $")
TARGET_HINTS = (b"dump_to_hex", b"private_key")


class ExtractionError(ValueError):
    """A public, non-secret explanation of a fail-closed rejection."""


@dataclass(frozen=True)
class Candidate:
    scalar: bytes
    public_spki: bytes
    scalar_sha256: str
    public_spki_sha256: str
    first_line: int
    second_line: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path: Path, *, limit: int, label: str) -> bytes:
    candidate = path.expanduser()
    path_metadata = candidate.lstat()
    if stat.S_ISLNK(path_metadata.st_mode):
        raise ExtractionError(f"{label} must not be a symlink")
    if not stat.S_ISREG(path_metadata.st_mode):
        raise ExtractionError(f"{label} is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ExtractionError(f"{label} is not a regular file")
        if (path_metadata.st_dev, path_metadata.st_ino) != (before.st_dev, before.st_ino):
            raise ExtractionError(f"{label} changed between path validation and open")
        if before.st_size > limit:
            raise ExtractionError(f"{label} exceeds the {limit}-byte safety limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ExtractionError(f"{label} exceeds the {limit}-byte safety limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    stable_fields_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    data = b"".join(chunks)
    if stable_fields_before != stable_fields_after or len(data) != before.st_size:
        raise ExtractionError(f"{label} changed or was short-read while it was being read")
    if len(data) > limit:
        raise ExtractionError(f"{label} exceeds the {limit}-byte safety limit")
    return data


def load_log_increment(
    *,
    increment_path: Path | None,
    before_path: Path | None,
    after_path: Path | None,
) -> tuple[bytes, dict[str, Any]]:
    """Load one unambiguous append-only increment and its public provenance."""
    if increment_path is not None:
        if before_path is not None or after_path is not None:
            raise ExtractionError("use either --log-increment or --log-before/--log-after")
        increment = read_regular_file(
            increment_path, limit=MAX_LOG_BYTES, label="log increment"
        )
        if not increment:
            raise ExtractionError("log increment is empty")
        return increment, {
            "mode": "increment",
            "increment_size": len(increment),
            "increment_sha256": sha256(increment),
        }

    if before_path is None or after_path is None:
        raise ExtractionError(
            "provide --log-increment or both --log-before and --log-after"
        )
    if before_path.expanduser().resolve() == after_path.expanduser().resolve():
        raise ExtractionError("before and after logs must be distinct saved files")
    before = read_regular_file(before_path, limit=MAX_LOG_BYTES, label="before log")
    after = read_regular_file(after_path, limit=MAX_LOG_BYTES, label="after log")
    if len(after) <= len(before):
        raise ExtractionError("after log is not a non-empty append of before log")
    if not hmac.compare_digest(after[: len(before)], before):
        raise ExtractionError(
            "after log does not have the exact before log as its prefix; rotation or rewrite is ambiguous"
        )
    increment = after[len(before) :]
    return increment, {
        "mode": "before_after_append",
        "before_size": len(before),
        "before_sha256": sha256(before),
        "after_size": len(after),
        "after_sha256": sha256(after),
        "increment_size": len(increment),
        "increment_sha256": sha256(increment),
    }


def _is_target_hint(line: bytes) -> bool:
    return all(hint in line for hint in TARGET_HINTS)


def _decode_payload(payload: bytes) -> bytes:
    # PRIVATE_LINE has already proved the exact sixteen-byte lowercase grammar.
    return bytes.fromhex(payload.decode("ascii"))


def _actor(prefix: bytes) -> bytes | None:
    match = ACTOR_SUFFIX.search(prefix)
    return match.group("actor") if match is not None else None


def parse_candidates(increment: bytes) -> list[Candidate]:
    """Parse every complete adjacent private-key pair without exposing values."""
    split = increment.split(b"\n")
    candidates: list[Candidate] = []
    seen_scalars: set[bytes] = set()
    index = 0
    while index < len(split):
        raw_line = split[index]
        terminated = index < len(split) - 1
        line = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
        if not _is_target_hint(line):
            index += 1
            continue
        if not terminated:
            raise ExtractionError("private_key row is not newline-terminated")
        first = PRIVATE_LINE.fullmatch(line)
        if first is None:
            raise ExtractionError("malformed private_key dump row")
        if first.group("endpoint") != b"  15":
            raise ExtractionError("orphan or out-of-order private_key dump row")
        if index + 1 >= len(split):
            raise ExtractionError("private_key dump is missing its second row")

        second_raw = split[index + 1]
        second_terminated = index + 1 < len(split) - 1
        second_line = second_raw[:-1] if second_raw.endswith(b"\n") else second_raw
        if not second_terminated:
            raise ExtractionError("private_key second row is not newline-terminated")
        second = PRIVATE_LINE.fullmatch(second_line)
        if second is None or second.group("endpoint") != b"  31":
            raise ExtractionError(
                "private_key rows are incomplete, interleaved, malformed, or out of order"
            )
        first_actor, second_actor = _actor(first.group("prefix")), _actor(
            second.group("prefix")
        )
        if (first_actor is None) != (second_actor is None):
            raise ExtractionError("private_key pair has inconsistent log provenance")
        if first_actor is not None and first_actor != second_actor:
            raise ExtractionError("private_key pair crosses MiTEE task/thread provenance")

        scalar = _decode_payload(first.group("payload")) + _decode_payload(
            second.group("payload")
        )
        if len(scalar) != 32:
            raise ExtractionError("private_key pair did not decode to exactly 32 bytes")
        if scalar in seen_scalars:
            raise ExtractionError("duplicate private_key candidate is ambiguous")
        seen_scalars.add(scalar)
        scalar_value = int.from_bytes(scalar, "big")
        if not 1 <= scalar_value < P256_ORDER:
            raise ExtractionError("private_key candidate is outside the P-256 scalar range")
        try:
            private = ec.derive_private_key(scalar_value, ec.SECP256R1())
            public_spki = private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError) as exc:
            raise ExtractionError("private_key candidate cannot derive a P-256 key") from exc
        candidates.append(
            Candidate(
                scalar=scalar,
                public_spki=public_spki,
                scalar_sha256=sha256(scalar),
                public_spki_sha256=sha256(public_spki),
                first_line=index + 1,
                second_line=index + 2,
            )
        )
        index += 2

    if not candidates:
        raise ExtractionError("log increment contains no complete private_key pair")
    return candidates


def select_unique_candidate(
    candidates: list[Candidate], target_spki_sha256: str
) -> Candidate:
    matches = [
        candidate
        for candidate in candidates
        if hmac.compare_digest(candidate.public_spki_sha256, target_spki_sha256)
    ]
    if not matches:
        raise ExtractionError(
            "no private_key candidate matches the same-run final DICE subject SPKI"
        )
    if len(matches) != 1:
        raise ExtractionError(
            "more than one private_key candidate matches the final DICE subject SPKI"
        )
    return matches[0]


def _write_private_file(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def commit_outputs(out_dir: Path, candidate: Candidate, report: dict[str, Any]) -> None:
    """Atomically expose one fresh mode-0700 directory with mode-0600 files."""
    target = out_dir.expanduser().absolute()
    parent = target.parent.resolve(strict=True)
    if target.exists() or target.is_symlink():
        raise ExtractionError("output directory already exists; refusing to overwrite")
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp.", dir=parent))
    os.chmod(staging, 0o700)
    try:
        scalar_path = staging / "cdi_leaf_scalar.bin"
        spki_path = staging / "cdi_leaf_public_spki.der"
        report_path = staging / "extraction_report.json"
        _write_private_file(scalar_path, candidate.scalar)
        _write_private_file(spki_path, candidate.public_spki)
        encoded_report = (
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        _write_private_file(report_path, encoded_report)
        directory_fd = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.rename(staging, target)
        parent_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log-increment", type=Path)
    source.add_argument("--log-before", type=Path)
    parser.add_argument(
        "--log-after",
        type=Path,
        help="required with --log-before; must be an exact append-only successor",
    )
    parser.add_argument("--csr", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        increment, log_provenance = load_log_increment(
            increment_path=arguments.log_increment,
            before_path=arguments.log_before,
            after_path=arguments.log_after,
        )
        csr = read_regular_file(arguments.csr, limit=MAX_CSR_BYTES, label="CSR")
        challenge = read_regular_file(
            arguments.challenge,
            limit=MAX_CHALLENGE_BYTES,
            label="challenge",
        )
        # This verifies canonical CBOR, the exact five-entry proper-DICE shape,
        # every DICE signature, the final outer signature, challenge equality,
        # DeviceInfo shape, and a zero-length KeysToSign identity request.
        csr_audit = profile.audit_authenticated_request(
            csr, challenge, expected_keys_to_sign_count=0
        )
        candidates = parse_candidates(increment)
        selected = select_unique_candidate(
            candidates, csr_audit["cdi_leaf_spki_sha256"]
        )
        candidate_summaries = [
            {
                "ordinal": ordinal,
                "line_span": [candidate.first_line, candidate.second_line],
                "scalar_sha256": candidate.scalar_sha256,
                "derived_public_spki_sha256": candidate.public_spki_sha256,
                "matches_same_run_leaf": hmac.compare_digest(
                    candidate.public_spki_sha256,
                    csr_audit["cdi_leaf_spki_sha256"],
                ),
            }
            for ordinal, candidate in enumerate(candidates, start=1)
        ]
        report = {
            "schema": SCHEMA,
            "status": "PASS",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "private_material_printed": False,
            "log": log_provenance,
            "csr": {
                "sha256": csr_audit["source_file_sha256"],
                "size": csr_audit["source_file_size"],
                "challenge_sha256": csr_audit["challenge_sha256"],
                "challenge_size": csr_audit["challenge_size"],
                "dice_signatures_verified": csr_audit["dice_signatures_verified"],
                "outer_signature_verified": csr_audit["outer_signature_verified"],
                "keys_to_sign_count": csr_audit["keys_to_sign_count"],
                "cdi_leaf_spki_sha256": csr_audit["cdi_leaf_spki_sha256"],
            },
            "candidate_count": len(candidates),
            "candidates": candidate_summaries,
            "selection": {
                "unique_same_run_leaf_match": True,
                "scalar_size": 32,
                "scalar_sha256": selected.scalar_sha256,
                "public_spki_size": len(selected.public_spki),
                "public_spki_sha256": selected.public_spki_sha256,
            },
            "outputs": {
                "cdi_leaf_scalar.bin": {
                    "mode": "0600",
                    "size": 32,
                    "sha256": selected.scalar_sha256,
                },
                "cdi_leaf_public_spki.der": {
                    "mode": "0600",
                    "size": len(selected.public_spki),
                    "sha256": selected.public_spki_sha256,
                },
                "extraction_report.json": {"mode": "0600"},
            },
        }
        commit_outputs(arguments.out_dir, selected, report)
    except (ExtractionError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Hashes are safe provenance; the private scalar itself is never rendered.
    print(
        json.dumps(
            {
                "status": "PASS",
                "output_dir": str(arguments.out_dir.expanduser().absolute()),
                "scalar_sha256": selected.scalar_sha256,
                "cdi_leaf_spki_sha256": selected.public_spki_sha256,
                "private_material_printed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
