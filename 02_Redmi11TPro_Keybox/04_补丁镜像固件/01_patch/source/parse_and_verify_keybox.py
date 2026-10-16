#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path


ENTRY_WORDS = 15
ENTRY_SIZE = ENTRY_WORDS * 4
HEADER_SIZE = 32
MAX_CERTIFICATES = 4
DESCRIPTOR_SIZE = 168


def run(command, *, input_data=None, check=True):
    result = subprocess.run(
        command,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stderr.decode(errors='replace')}"
        )
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data, mode=0o644):
    path.write_bytes(data)
    os.chmod(path, mode)


def openssl_key_algorithm(key_path):
    result = run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(key_path),
         "-text", "-noout"]
    )
    text = result.stdout.decode(errors="replace")
    if "ASN1 OID:" in text or "EC Private-Key:" in text:
        return "EC", text
    if "Private-Key:" in text and "modulus:" in text:
        return "RSA", text
    return "未知算法", text


def certificate_metadata(cert_path):
    result = run(
        [
            "openssl", "x509", "-inform", "DER", "-in", str(cert_path),
            "-noout", "-subject", "-issuer", "-serial", "-startdate",
            "-enddate", "-fingerprint", "-sha256",
        ]
    )
    values = {}
    for line in result.stdout.decode(errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def extract_entry(payload, descriptor_words, entry_index, output_root):
    base = 8 + entry_index * ENTRY_WORDS
    key_size = descriptor_words[base]
    key_offset = descriptor_words[base + 1]
    certificate_count = descriptor_words[base + 2]
    certificate_sizes = descriptor_words[base + 3:base + 7]
    certificate_offsets = descriptor_words[base + 7:base + 11]
    reserved = descriptor_words[base + 11:base + 15]

    if not 0 < key_size <= len(payload):
        raise ValueError(f"entry {entry_index + 1}: invalid key size")
    if key_offset < 4 or key_offset + key_size > len(payload):
        raise ValueError(f"entry {entry_index + 1}: invalid key offset")
    if struct.unpack_from("<I", payload, key_offset - 4)[0] != key_size:
        raise ValueError(f"entry {entry_index + 1}: key length prefix mismatch")
    if not 0 < certificate_count <= MAX_CERTIFICATES:
        raise ValueError(f"entry {entry_index + 1}: invalid certificate count")
    if any(reserved):
        raise ValueError(f"entry {entry_index + 1}: reserved words are not zero")

    key_data = payload[key_offset:key_offset + key_size]
    temporary_directory = output_root / f"条目{entry_index + 1}_待识别"
    temporary_directory.mkdir(parents=True, exist_ok=False)
    key_der = temporary_directory / "私钥_原始DER.bin"
    write_bytes(key_der, key_data, 0o600)

    algorithm, key_text = openssl_key_algorithm(key_der)
    output_directory = output_root / f"条目{entry_index + 1}_{algorithm}"
    temporary_directory.rename(output_directory)
    key_der = output_directory / key_der.name
    write_bytes(output_directory / "私钥_OpenSSL文本.txt", key_text.encode(), 0o600)

    private_pem = run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(key_der)]
    ).stdout
    write_bytes(output_directory / "私钥_PKCS8.pem", private_pem, 0o600)
    private_public_der = run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(key_der),
         "-pubout", "-outform", "DER"]
    ).stdout
    write_bytes(output_directory / "私钥对应公钥_SPKI.der", private_public_der)

    chain_count_offset = key_offset + key_size
    if chain_count_offset + 4 > len(payload):
        raise ValueError(f"entry {entry_index + 1}: missing chain count")
    payload_chain_count = struct.unpack_from("<I", payload, chain_count_offset)[0]
    if payload_chain_count != certificate_count:
        raise ValueError(f"entry {entry_index + 1}: chain count mismatch")

    certificates = []
    certificate_metadata_list = []
    for cert_index in range(certificate_count):
        cert_size = certificate_sizes[cert_index]
        cert_offset = certificate_offsets[cert_index]
        if cert_offset < 4 or cert_offset + cert_size > len(payload):
            raise ValueError(
                f"entry {entry_index + 1} certificate {cert_index + 1}: "
                "invalid bounds"
            )
        if struct.unpack_from("<I", payload, cert_offset - 4)[0] != cert_size:
            raise ValueError(
                f"entry {entry_index + 1} certificate {cert_index + 1}: "
                "length prefix mismatch"
            )
        cert_data = payload[cert_offset:cert_offset + cert_size]
        certificates.append(cert_data)
        label = "叶证书" if cert_index == 0 else (
            "根证书" if cert_index == certificate_count - 1 else "中间证书"
        )
        stem = f"证书_{cert_index + 1:02d}_{label}"
        cert_der = output_directory / f"{stem}.der"
        cert_pem = output_directory / f"{stem}.pem"
        cert_text = output_directory / f"{stem}_详细信息.txt"
        write_bytes(cert_der, cert_data)
        pem_data = run(
            ["openssl", "x509", "-inform", "DER", "-in", str(cert_der),
             "-outform", "PEM"]
        ).stdout
        write_bytes(cert_pem, pem_data)
        text_data = run(
            ["openssl", "x509", "-inform", "DER", "-in", str(cert_der),
             "-text", "-noout"]
        ).stdout
        write_bytes(cert_text, text_data)
        metadata = certificate_metadata(cert_der)
        metadata.update(
            {
                "index": cert_index + 1,
                "role": label,
                "offset": cert_offset,
                "size": cert_size,
                "sha256": sha256(cert_data),
            }
        )
        certificate_metadata_list.append(metadata)

    if any(certificate_sizes[certificate_count:]):
        raise ValueError(f"entry {entry_index + 1}: unused cert sizes are nonzero")
    if any(certificate_offsets[certificate_count:]):
        raise ValueError(f"entry {entry_index + 1}: unused cert offsets are nonzero")

    leaf_public_pem = run(
        ["openssl", "x509", "-inform", "DER", "-in",
         str(output_directory / "证书_01_叶证书.der"), "-pubkey", "-noout"]
    ).stdout
    leaf_public_der = run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input_data=leaf_public_pem,
    ).stdout
    public_key_matches = private_public_der == leaf_public_der
    if not public_key_matches:
        raise ValueError(f"entry {entry_index + 1}: private key does not match leaf cert")

    chain_pem = b"".join(
        run(
            ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
            input_data=cert_data,
        ).stdout
        for cert_data in certificates
    )
    write_bytes(output_directory / "完整证书链_叶到根.pem", chain_pem)

    root_pem = output_directory / f"证书_{certificate_count:02d}_根证书.pem"
    leaf_pem = output_directory / "证书_01_叶证书.pem"
    verify_command = ["openssl", "verify", "-CAfile", str(root_pem)]
    if certificate_count > 2:
        untrusted_path = output_directory / "中间证书集合.pem"
        untrusted_data = b"".join(
            run(
                ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                input_data=certificates[index],
            ).stdout
            for index in range(1, certificate_count - 1)
        )
        write_bytes(untrusted_path, untrusted_data)
        verify_command.extend(["-untrusted", str(untrusted_path)])
    verify_command.append(str(leaf_pem))
    verify_result = run(verify_command, check=False)
    chain_verified = verify_result.returncode == 0
    write_bytes(
        output_directory / "证书链验证结果.txt",
        verify_result.stdout + verify_result.stderr,
    )
    if not chain_verified:
        raise ValueError(f"entry {entry_index + 1}: certificate chain verification failed")

    return {
        "entry": entry_index + 1,
        "algorithm": algorithm,
        "key_offset": key_offset,
        "key_size": key_size,
        "key_sha256": sha256(key_data),
        "private_public_spki_sha256": sha256(private_public_der),
        "leaf_public_spki_sha256": sha256(leaf_public_der),
        "private_key_matches_leaf_certificate": public_key_matches,
        "certificate_count": certificate_count,
        "certificate_chain_verified": chain_verified,
        "certificates": certificate_metadata_list,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Parse and verify the xaga Keybox payload returned by TA command 0x64"
    )
    parser.add_argument("payload", type=Path)
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    payload = args.payload.read_bytes()
    descriptor = args.descriptor.read_bytes()
    if len(descriptor) != DESCRIPTOR_SIZE:
        raise ValueError(f"descriptor must be {DESCRIPTOR_SIZE} bytes")
    if args.output.exists():
        raise FileExistsError(f"refusing existing output directory: {args.output}")
    args.output.mkdir(parents=True)

    words = list(struct.unpack_from("<38I", descriptor, 0))
    descriptor_md5 = descriptor[-16:]
    payload_md5 = hashlib.md5(payload).digest()
    if words[0] != 0x12345678:
        raise ValueError("descriptor magic mismatch")
    if words[2] != len(payload):
        raise ValueError("descriptor payload length mismatch")
    if any(words[3:8]):
        raise ValueError("descriptor header reserved words are not zero")
    if descriptor_md5 != payload_md5:
        raise ValueError("descriptor MD5 does not match payload")

    entries = [extract_entry(payload, words, index, args.output) for index in range(2)]
    metadata = {
        "descriptor_magic": f"0x{words[0]:08x}",
        "descriptor_word_1_unknown": f"0x{words[1]:08x}",
        "payload_size": len(payload),
        "payload_sha256": sha256(payload),
        "payload_md5": payload_md5.hex(),
        "descriptor_md5": descriptor_md5.hex(),
        "descriptor_md5_matches": True,
        "entries": entries,
    }
    metadata_path = args.output / "解析与验证总清单.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
