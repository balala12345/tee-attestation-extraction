#!/usr/bin/env python3
"""One controlled upstream google-rkp-sw CDI-only/default provisioning attempt.

This runner deliberately executes the pristine upstream request constructors from
commit 8a74e55.  It supplies only the already verified K70E P-256 CDI_Leaf
scalar; no device config, native DICE chain, UdsCerts, or native DeviceInfo is
injected.  The runner adds artifact durability and strict post-response audits,
but does not alter the upstream CSR semantics.

Private CDI/key bytes are read from or written to mode-0600 files and are never
printed or placed in argv.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import types
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
ROOT = PROJECT.parent
REPO = ROOT / "third_party" / "google-rkp-sw"
CDI_FILE = (
    PROJECT
    / "03_提取结果"
    / "K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244"
    / "01_identity"
    / "google_rkp_sw_cdi_leaf_p256_scalar.bin"
)
AUDIT_MODULE_PATH = REPO / "rkp_sw.py"
GLOBAL_CLAIM_DIR = ROOT / ".k70e_google_rkp_sw_vanilla_default_ledger"
GLOBAL_CLAIM_PATH = GLOBAL_CLAIM_DIR / "TRUE_CDI_GENERIC_DEFAULT_ONCE.CLAIM.json"

UPSTREAM_COMMIT = "8a74e55e6e900c04c84e12380e467cefa1a27cc5"
UPSTREAM_SOURCE_SHA256 = (
    "e3ab9ff19cbe82cc65adec2d8b774c423baa8646dc263150d21d9aefa54f312a"
)
EXPECTED_CDI_SHA256 = (
    "ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c"
)
EXPECTED_CDI_SPKI_SHA256 = (
    "64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2"
)
EXPECTED_GOOGLE_ROOT_DER_SHA256 = (
    "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"
)
EXPECTED_GOOGLE_ROOT_SPKI_SHA256 = (
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"
)
AUDIT_MODULE_SHA256 = (
    "619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822"
)
AUDIT_MODULE_SIZE = 193_161
UPSTREAM_SERVER_URL = "https://remoteprovisioning.googleapis.com/v1"
PROVISIONING_INFO_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")


class SafeAbort(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)
    fsync_dir(path.parent)


def write_json(path: Path, value: object) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    write_exclusive(path, raw)


def create_private_dir(path: Path) -> Path:
    resolved = Path(os.path.abspath(os.fspath(path)))
    if resolved.exists():
        raise SafeAbort(f"refusing to reuse output directory: {resolved}")
    resolved.mkdir(parents=True, mode=0o700)
    os.chmod(resolved, 0o700)
    fsync_dir(resolved.parent)
    return resolved


def read_pinned_cdi() -> tuple[bytes, dict[str, object]]:
    original_meta = CDI_FILE.lstat()
    if stat.S_ISLNK(original_meta.st_mode) or not stat.S_ISREG(original_meta.st_mode):
        raise SafeAbort("pinned CDI source is not a regular non-symlink file")
    path = CDI_FILE.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if (meta.st_dev, meta.st_ino) != (original_meta.st_dev, original_meta.st_ino):
            raise SafeAbort("pinned CDI source changed during open")
        chunks = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1:
        raise SafeAbort("pinned CDI source must be mode 0600 and single-link")
    if meta.st_uid != os.getuid():
        raise SafeAbort("pinned CDI source is not owned by the current uid")
    if len(raw) != 32 or sha256(raw) != EXPECTED_CDI_SHA256:
        raise SafeAbort("pinned CDI source length/hash mismatch")
    scalar = int.from_bytes(raw, "big")
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    if not 1 <= scalar < order:
        raise SafeAbort("pinned CDI is not a valid P-256 scalar")
    pub = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
    spki = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256(spki) != EXPECTED_CDI_SPKI_SHA256:
        raise SafeAbort("pinned CDI does not reconstruct the verified K70E CDI_Leaf")
    return raw, {
        "length": len(raw),
        "sha256": EXPECTED_CDI_SHA256,
        "public_spki_sha256": EXPECTED_CDI_SPKI_SHA256,
        "source_path": str(path),
        "mode": "0600",
        "single_link": True,
        "private_bytes_printed": False,
    }


def load_pristine_upstream() -> tuple[types.ModuleType, bytes]:
    result = subprocess.run(
        ["git", "-C", str(REPO), "show", f"{UPSTREAM_COMMIT}:rkp_sw.py"],
        check=True,
        capture_output=True,
    )
    source = result.stdout
    if sha256(source) != UPSTREAM_SOURCE_SHA256:
        raise SafeAbort("pristine upstream google-rkp-sw source hash mismatch")
    module = types.ModuleType("google_rkp_sw_upstream_8a74e55")
    module.__file__ = f"git:{REPO}@{UPSTREAM_COMMIT}:rkp_sw.py"
    module.__package__ = ""
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, source


def load_strict_auditor():
    raw = AUDIT_MODULE_PATH.read_bytes()
    if len(raw) != AUDIT_MODULE_SIZE or sha256(raw) != AUDIT_MODULE_SHA256:
        raise SafeAbort("strict certificate auditor identity mismatch")
    name = "k70e_strict_pi_auditor_pinned"
    module = types.ModuleType(name)
    module.__file__ = str(AUDIT_MODULE_PATH)
    module.__package__ = ""
    sys.modules[name] = module
    exec(compile(raw, str(AUDIT_MODULE_PATH), "exec"), module.__dict__)
    return module


def path_identity(path: Path, expected_mode: int) -> dict[str, int]:
    meta = path.lstat()
    if stat.S_ISLNK(meta.st_mode):
        raise SafeAbort(f"symlink forbidden: {path}")
    expected_kind = stat.S_ISDIR if expected_mode == 0o700 else stat.S_ISREG
    if not expected_kind(meta.st_mode):
        raise SafeAbort(f"unexpected filesystem object: {path}")
    if stat.S_IMODE(meta.st_mode) != expected_mode or meta.st_uid != os.getuid():
        raise SafeAbort(f"owner/mode mismatch: {path}")
    if expected_mode == 0o600 and meta.st_nlink != 1:
        raise SafeAbort(f"private file is not single-link: {path}")
    identity = {
        "device": meta.st_dev,
        "inode": meta.st_ino,
        "mode": stat.S_IMODE(meta.st_mode),
        "uid": meta.st_uid,
    }
    if expected_mode == 0o600:
        identity["size"] = meta.st_size
    return identity


def require_same_identity(path: Path, expected: dict[str, int], expected_mode: int) -> None:
    current = path_identity(path, expected_mode)
    if current != expected:
        raise SafeAbort(f"filesystem identity drifted: {path}")


def verify_saved_private_key(
    path: Path,
    identity: dict[str, int],
    expected_sha256: str,
    expected_spki: bytes,
) -> None:
    require_same_identity(path, identity, 0o600)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if (meta.st_dev, meta.st_ino) != (identity["device"], identity["inode"]):
            raise SafeAbort("software private key changed during bound open")
        chunks = []
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if sha256(raw) != expected_sha256:
        raise SafeAbort("software private key content hash drifted")
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SafeAbort("saved software private key type drifted")
    actual_spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if actual_spki != expected_spki:
        raise SafeAbort("saved software private key public key drifted")


def create_global_claim(out: Path, out_identity: dict[str, int], script_sha256: str) -> None:
    if not GLOBAL_CLAIM_DIR.exists():
        GLOBAL_CLAIM_DIR.mkdir(mode=0o700)
        os.chmod(GLOBAL_CLAIM_DIR, 0o700)
        fsync_dir(GLOBAL_CLAIM_DIR.parent)
    path_identity(GLOBAL_CLAIM_DIR, 0o700)
    write_json(
        GLOBAL_CLAIM_PATH,
        {
            "status": "CONSUMED_NO_RETRY",
            "claimed_at": datetime.now(timezone.utc).isoformat(),
            "mode": "true_K70E_CDI_plus_pristine_upstream_generic_defaults",
            "cdi_sha256": EXPECTED_CDI_SHA256,
            "upstream_commit": UPSTREAM_COMMIT,
            "upstream_source_sha256": UPSTREAM_SOURCE_SHA256,
            "runner_sha256": script_sha256,
            "output_directory": str(out),
            "output_identity": out_identity,
            "network_budget": {"fetch_eek": 1, "sign_certificates": 1},
        },
    )


class ReplayResponse:
    def __init__(self, body: bytes, status: int, headers: Any, url: str):
        self._stream = io.BytesIO(body)
        self.status = status
        self.headers = headers
        self.url = url

    def read(self, amount: int = -1) -> bytes:
        return self._stream.read(amount)

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class CapturingUrlopen:
    """Capture exact upstream requests/responses without changing their bytes."""

    def __init__(self, out: Path, real_urlopen):
        self.out = out
        self.real_urlopen = real_urlopen
        self.seen: set[str] = set()

    @staticmethod
    def _kind(url: str) -> str:
        if url == f"{UPSTREAM_SERVER_URL}:fetchEekChain":
            return "fetch_eek"
        if url.startswith(f"{UPSTREAM_SERVER_URL}:signCertificates?challenge="):
            return "sign_certificates"
        raise SafeAbort("upstream attempted an unexpected network URL")

    def __call__(self, request, *args, **kwargs):
        if not isinstance(request, urllib.request.Request):
            raise SafeAbort("upstream urlopen argument is not Request")
        url = request.full_url
        kind = self._kind(url)
        if kind in self.seen:
            raise SafeAbort(f"duplicate {kind} network request refused")
        self.seen.add(kind)
        body = request.data
        if not isinstance(body, bytes) or not body:
            raise SafeAbort(f"{kind} request body is empty")
        write_exclusive(self.out / f"{kind}_request.cbor", body)
        write_json(
            self.out / f"{kind}_request.json",
            {
                "body_length": len(body),
                "body_sha256": sha256(body),
                "method": request.get_method(),
                "url": url,
                "saved_before_send": True,
            },
        )
        write_json(
            self.out / f"{kind}_NETWORK_STARTED.json",
            {
                "kind": kind,
                "request_sha256": sha256(body),
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        try:
            response = self.real_urlopen(request, *args, **kwargs)
            try:
                response_body = response.read()
                status_code = int(getattr(response, "status", response.getcode()))
                headers = getattr(response, "headers", {})
                header_map = {str(k): str(v) for k, v in headers.items()}
            finally:
                response.close()
        except urllib.error.HTTPError as exc:
            response_body = exc.read()
            header_map = {str(k): str(v) for k, v in (exc.headers or {}).items()}
            status_code = int(exc.code)
            write_exclusive(self.out / f"{kind}_response.raw", response_body)
            write_json(
                self.out / f"{kind}_response_http.json",
                {
                    "body_length": len(response_body),
                    "body_sha256": sha256(response_body),
                    "headers": header_map,
                    "status": status_code,
                    "url": url,
                },
            )
            raise urllib.error.HTTPError(
                exc.url, exc.code, exc.reason, exc.headers, io.BytesIO(response_body)
            ) from exc
        except Exception as exc:
            write_json(
                self.out / f"{kind}_transport_error.json",
                {"error_type": type(exc).__name__, "url": url},
            )
            raise
        write_exclusive(self.out / f"{kind}_response.cbor", response_body)
        write_json(
            self.out / f"{kind}_response_http.json",
            {
                "body_length": len(response_body),
                "body_sha256": sha256(response_body),
                "headers": header_map,
                "status": status_code,
                "url": url,
            },
        )
        return ReplayResponse(response_body, status_code, headers, url)


def cose_public_spki(cose_key: dict) -> bytes:
    if (
        set(cose_key) != {1, 3, -1, -2, -3}
        or cose_key.get(1) != 2
        or cose_key.get(3) != -7
        or cose_key.get(-1) != 1
        or not isinstance(cose_key.get(-2), bytes)
        or not isinstance(cose_key.get(-3), bytes)
        or len(cose_key[-2]) != 32
        or len(cose_key[-3]) != 32
    ):
        raise SafeAbort("software COSE key is not exact P-256/ES256")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose_key[-2], "big"),
        int.from_bytes(cose_key[-3], "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def decode_one_cbor(raw: bytes, label: str):
    stream = io.BytesIO(raw)
    value = cbor2.CBORDecoder(stream).decode()
    if stream.read(1):
        raise SafeAbort(f"{label} contains trailing CBOR bytes")
    return value


def verify_vanilla_request(upstream, csr: bytes, identity_keys, device_info: dict, cose_pub: dict) -> dict:
    value = decode_one_cbor(csr, "certificate request")
    if not isinstance(value, list) or len(value) != 4:
        raise SafeAbort("upstream request top-level shape mismatch")
    if value[0] != 1 or value[1] != {}:
        raise SafeAbort("upstream request version/empty map mismatch")
    dice = value[2]
    if not isinstance(dice, list) or len(dice) != 2:
        raise SafeAbort("request is not vanilla two-item degenerate DICE")
    if dice[0] != identity_keys.cose_key():
        raise SafeAbort("degenerate DICE UDS is not the supplied CDI key")
    entry = dice[1]
    if not isinstance(entry, list) or len(entry) != 4 or entry[1] != {}:
        raise SafeAbort("degenerate DICE entry shape mismatch")
    identity_keys.verify(
        entry[3], cbor2.dumps(["Signature1", entry[0], b"", entry[2]])
    )
    entry_payload = cbor2.loads(entry[2])
    if entry_payload.get(upstream.DICE_SUBJECT_PUB_KEY) != cbor2.dumps(identity_keys.cose_key()):
        raise SafeAbort("degenerate DICE subject is not the supplied CDI key")
    signed_data = value[3]
    identity_keys.verify(
        signed_data[3],
        cbor2.dumps(["Signature1", signed_data[0], b"", signed_data[2]]),
    )
    signed_payload = cbor2.loads(signed_data[2])
    csr_payload = cbor2.loads(signed_payload[1])
    if csr_payload != [3, "keymint", device_info, [cose_pub]]:
        raise SafeAbort("CSR payload differs from upstream default DeviceInfo/one-key contract")
    if device_info != upstream.load_device_config(None):
        raise SafeAbort("DeviceInfo is not the pristine upstream default")
    return {
        "request_length": len(csr),
        "request_sha256": sha256(csr),
        "curve": "P-256",
        "config_argument": None,
        "device_info_source": "pristine_upstream_generic_default",
        "device_info": device_info,
        "dice_mode": "upstream_degenerate_UDS_equals_CDI_Leaf",
        "dice_item_count": 2,
        "native_dice_injected": False,
        "native_device_info_injected": False,
        "uds_equals_cdi_leaf": True,
        "identity_and_outer_signatures_verified": True,
        "keys_to_sign_count": 1,
    }


def provisioning_count(leaf: x509.Certificate) -> int | None:
    try:
        extension = leaf.extensions.get_extension_for_oid(PROVISIONING_INFO_OID)
    except x509.ExtensionNotFound:
        return None
    raw = getattr(extension.value, "value", None)
    if not isinstance(raw, bytes):
        return None
    value = decode_one_cbor(raw, "Provisioning Info")
    if not isinstance(value, dict) or type(value.get(1)) is not int:
        return None
    return value[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--attended", action="store_true", required=True)
    parser.add_argument("--execute-google-once", action="store_true", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    out = create_private_dir(args.output_dir)
    out_identity = path_identity(out, 0o700)
    write_json(
        out / "RUN_STARTED.json",
        {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": "pristine_upstream_CDI_only_default_DeviceInfo",
            "network_request_budget": {"fetch_eek": 1, "sign_certificates": 1},
            "phone_or_adb_used": False,
            "flash_or_reboot_performed": False,
        },
    )
    try:
        seed, identity_summary = read_pinned_cdi()
        upstream, upstream_source = load_pristine_upstream()
        auditor = load_strict_auditor()
        identity_keys = upstream.DeviceKeys(seed, curve="p256")
        if sha256(cose_public_spki(identity_keys.cose_key())) != EXPECTED_CDI_SPKI_SHA256:
            raise SafeAbort("upstream P-256 identity does not match pinned CDI")
        device_info = upstream.load_device_config(None)
        fingerprint = upstream.get_fingerprint(None)
        if device_info != upstream._DEFAULT_DEVICE_INFO:
            raise SafeAbort("upstream default DeviceInfo resolution drifted")
        if fingerprint != "generic/default/default:13/TP1A.220624.014/0:user/release-keys":
            raise SafeAbort("upstream generic fingerprint resolution drifted")
        write_json(
            out / "INPUT_AUDIT.json",
            {
                "cdi": identity_summary,
                "curve_override_required_by_extracted_identity": "p256",
                "device_config_supplied": False,
                "device_info": device_info,
                "fingerprint": fingerprint,
                "native_dice_supplied": False,
                "native_device_info_supplied": False,
                "upstream_commit": UPSTREAM_COMMIT,
                "upstream_source_length": len(upstream_source),
                "upstream_source_sha256": UPSTREAM_SOURCE_SHA256,
            },
        )

        key_dir = out / "key_00"
        key_dir.mkdir(mode=0o700)
        key_dir_identity = path_identity(key_dir, 0o700)
        software_private, cose_pub = upstream.generate_ec_keypair()
        private_pem = software_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        software_spki = software_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if software_spki != cose_public_spki(cose_pub):
            raise SafeAbort("new software private key does not match its COSE public key")
        if sha256(software_spki) == EXPECTED_CDI_SPKI_SHA256:
            raise SafeAbort("software key unexpectedly equals the CDI identity key")
        write_exclusive(key_dir / "private_key_pkcs8.pem", private_pem)
        write_exclusive(key_dir / "public_key_spki.der", software_spki)
        private_identity = path_identity(key_dir / "private_key_pkcs8.pem", 0o600)
        private_sha256 = sha256(private_pem)
        saved_private = (key_dir / "private_key_pkcs8.pem").read_bytes()
        reopened = serialization.load_pem_private_key(saved_private, password=None)
        if not isinstance(reopened, ec.EllipticCurvePrivateKey) or not isinstance(
            reopened.curve, ec.SECP256R1
        ):
            raise SafeAbort("saved software private key is not unencrypted P-256 PKCS#8")
        if reopened.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ) != saved_private:
            raise SafeAbort("saved software private key is not canonical PKCS#8 PEM")
        private_meta = (key_dir / "private_key_pkcs8.pem").lstat()
        if stat.S_IMODE(private_meta.st_mode) != 0o600 or private_meta.st_nlink != 1:
            raise SafeAbort("saved software private key permissions/link count changed")
        write_json(
            key_dir / "key_summary.json",
            {
                "curve": "P-256",
                "generated_by": "pristine upstream google-rkp-sw generate_ec_keypair",
                "private_key_pkcs8_sha256": sha256(private_pem),
                "private_material_printed": False,
                "public_key_spki_sha256": sha256(software_spki),
                "saved_before_network": True,
            },
        )

        runner_sha256 = sha256(Path(__file__).resolve(strict=True).read_bytes())
        require_same_identity(out, out_identity, 0o700)
        require_same_identity(key_dir, key_dir_identity, 0o700)
        verify_saved_private_key(
            key_dir / "private_key_pkcs8.pem",
            private_identity,
            private_sha256,
            software_spki,
        )
        create_global_claim(out, out_identity, runner_sha256)

        capture = CapturingUrlopen(out, upstream.urllib.request.urlopen)
        upstream.urllib.request.urlopen = capture
        upstream_log = io.StringIO()
        try:
            require_same_identity(out, out_identity, 0o700)
            require_same_identity(key_dir, key_dir_identity, 0o700)
            verify_saved_private_key(
                key_dir / "private_key_pkcs8.pem",
                private_identity,
                private_sha256,
                software_spki,
            )
            with contextlib.redirect_stdout(upstream_log):
                challenge, eek_pub, eek_curve, eek_chains = upstream.fetch_eek(
                    fingerprint, UPSTREAM_SERVER_URL
                )
            if not isinstance(challenge, bytes) or not challenge:
                raise SafeAbort("upstream fetch returned no challenge")
            if not isinstance(eek_pub, bytes) or eek_curve is None:
                raise SafeAbort("upstream fetch returned no supported EEK")
            write_exclusive(out / "challenge.bin", challenge)
            csr = upstream.build_csr(
                identity_keys,
                challenge,
                [cose_pub],
                eek_pub,
                device_info,
                eek_curve,
            )
            request_audit = verify_vanilla_request(
                upstream, csr, identity_keys, device_info, cose_pub
            )
            write_exclusive(out / "certificate_request.cbor", csr)
            write_json(out / "REQUEST_AUDIT.json", request_audit)
            require_same_identity(out, out_identity, 0o700)
            require_same_identity(key_dir, key_dir_identity, 0o700)
            verify_saved_private_key(
                key_dir / "private_key_pkcs8.pem",
                private_identity,
                private_sha256,
                software_spki,
            )
            with contextlib.redirect_stdout(upstream_log):
                chains = upstream.submit_csr(csr, challenge, UPSTREAM_SERVER_URL)
        finally:
            upstream.urllib.request.urlopen = capture.real_urlopen
            write_exclusive(out / "upstream_console.txt", upstream_log.getvalue().encode())

        if capture.seen != {"fetch_eek", "sign_certificates"}:
            raise SafeAbort("exactly one fetch and one sign request were not observed")
        if len(chains) != 1:
            raise SafeAbort(f"Google returned {len(chains)} certificate chains, expected one")

        require_same_identity(out, out_identity, 0o700)
        require_same_identity(key_dir, key_dir_identity, 0o700)
        verify_saved_private_key(
            key_dir / "private_key_pkcs8.pem",
            private_identity,
            private_sha256,
            software_spki,
        )
        summaries = auditor._save_certificate_chains(out, chains, (software_spki,))
        if len(summaries) != 1:
            raise SafeAbort("strict auditor did not save exactly one chain")
        summary = summaries[0]
        certs = auditor._sort_cert_chain(auditor.parse_der_cert_chain(chains[0]))
        if len(certs) != 4:
            raise SafeAbort(f"Google chain has {len(certs)} certificates, expected four")
        leaf = certs[0]
        root = certs[-1]
        now = datetime.now(timezone.utc)
        validity_all = all(
            cert.not_valid_before_utc < cert.not_valid_after_utc
            and cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
            for cert in certs
        )
        root_der_sha256 = sha256(root.public_bytes(serialization.Encoding.DER))
        root_spki_sha256 = sha256(
            root.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        if root_der_sha256 != EXPECTED_GOOGLE_ROOT_DER_SHA256:
            raise SafeAbort("returned root certificate does not match the pinned Google root")
        if root_spki_sha256 != EXPECTED_GOOGLE_ROOT_SPKI_SHA256:
            raise SafeAbort("returned root SPKI does not match the pinned Google root")
        count = provisioning_count(leaf)
        pi = summary["provisioning_info_audit"]
        if summary["leaf_public_matches_private_public"] is not True:
            raise SafeAbort("leaf certificate public key does not match the new software private key")
        if summary["signature_links_valid"] is not True:
            raise SafeAbort("certificate issuer signature links are invalid")
        if summary["root_self_signature_valid"] is not True:
            raise SafeAbort("certificate root self-signature is invalid")
        if not validity_all:
            raise SafeAbort("one or more returned certificates are not currently valid")
        if type(count) is not int or count < 0:
            raise SafeAbort("leaf Provisioning Info has no valid non-negative issuance count")
        result = {
            "status": (
                "PASS_CLEAN"
                if pi["ctf_no_not_approved"] is True
                else "REJECTED_PROVISIONING_INFO"
            ),
            "completed_at": now.isoformat(),
            "certificate_chain_count": 1,
            "certificate_count": len(certs),
            "leaf_not_before": leaf.not_valid_before_utc.isoformat(),
            "leaf_not_after": leaf.not_valid_after_utc.isoformat(),
            "leaf_valid_now": leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc,
            "all_certificates_valid_now": validity_all,
            "leaf_validity_seconds": int(
                (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds()
            ),
            "provisioning_count_key_1": count,
            "provisioning_count_semantics": "Google approximate rolling last 30 days",
            "not_approved_hit_count": pi["not_approved_hit_count"],
            "ctf_no_not_approved": pi["ctf_no_not_approved"],
            "provisioning_info_parse_error_count": pi["parse_error_count"],
            "software_private_spki_equals_request_cose": True,
            "software_private_spki_differs_from_identity_spki": True,
            "software_private_spki_equals_leaf_spki": summary[
                "leaf_public_matches_private_public"
            ],
            "signature_links_valid": summary["signature_links_valid"],
            "root_self_signature_valid": summary["root_self_signature_valid"],
            "root_der_sha256": root_der_sha256,
            "root_spki_sha256": root_spki_sha256,
            "root_matches_pinned_google_root": True,
            "request_sha256": sha256(csr),
            "leaf_sha256": sha256(leaf.public_bytes(serialization.Encoding.DER)),
            "private_material_printed": False,
        }
        write_json(out / "FINAL_RESULT.json", result)
        print(json.dumps({"output_dir": str(out), **result}, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "PASS_CLEAN" else 3
    except KeyboardInterrupt:
        interrupted = {
            "status": "INTERRUPTED_NO_RETRY",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "private_material_printed": False,
        }
        try:
            write_json(out / "INTERRUPTED.json", interrupted)
        except FileExistsError:
            pass
        print(json.dumps({"output_dir": str(out), **interrupted}, ensure_ascii=False), file=sys.stderr)
        return 130
    except Exception as exc:
        error = {
            "status": "FAILED_OR_REJECTED",
            "error_type": type(exc).__name__,
            "message": str(exc)[:500],
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "private_material_printed": False,
        }
        try:
            write_json(out / "FAILED.json", error)
        except FileExistsError:
            pass
        print(json.dumps({"output_dir": str(out), **error}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
