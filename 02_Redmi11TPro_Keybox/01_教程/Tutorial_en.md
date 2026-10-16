# Redmi 11T Pro: Detailed read-only Keybox tutorial (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


## Variables and hard gates

```sh
set -euo pipefail
WORK="$PWD"
SERIAL="$TARGET_SERIAL"
```

The route is version-locked. Before any write, compare the target product, active slot, kernel, TA, TEE client library, `lk`/`tee` inputs, and every patch/image SHA-256 with the manifest in `04_补丁镜像固件/01_patch`. Keep the untouched slot and a full pre-write backup.

## 1. Baseline and negative control

Collect properties, kernel/permissions, slot, TEE devices, KeyMint services, partition links, mounts, and recent logs. Save both boot slots, both TEE slots, the TA set, and the exact TEE client library. Run the same Keybox client against the stock chain and save the failure baseline. This establishes that the client does not already read the Keybox.

## 2. Temporary privilege route

The recorded route used a temporary authorized root session. UID 0 alone is insufficient: the session also needs the capabilities required for `mount`, `dd`, and service control, plus a compatible SELinux state. The ledger keeps failed calibrator, task-list, capability, SELinux, and kernel-domain samples; do not substitute one of those samples for the verified binary.

## 3. Build and verify the read-only patch

The builder decrypts and re-encrypts the TA container using the exact matching manager material, changes only the caller-mode check at the recorded offset, and re-packs the L4Re module table. The secure manager patch ignores the TA signature error but still performs container parsing, AES-CTR unwrap, and decompression. The builder must verify original bytes, patched bytes, sizes, stored/unpacked MD5 values, and module-slot capacity.

## 4. Deploy only to the test slot

Push the complete patched boot-chain images and deployment script. The script must check serial, product, kernel, slot, partition sizes, pre-write hashes, and backup paths before writing. Write only the test slot, read the entire partition back, compare the post-write hash, and verify that the untouched slot is unchanged. A failed deployment restores its backup.

## 5. Invoke the existing read command

After reboot, re-check the slot and SELinux state. Push the patched TA, the read-only client, the exact client library, and the temporary override script. Stop the KeyMint service, bind-mount the patched TA over the temporary runtime path, and call only the existing read command. The expected evidence contains a zero TEE return code, a successful origin, a payload length, and a descriptor length. Commands that write or replace Keybox objects are outside this route.

## 6. Parse and verify

The parser checks descriptor magic, declared length, payload MD5, length prefixes, EC/RSA key encodings, three certificate chains, private-to-leaf SPKI equality, and OpenSSL verification for both chains. Save stdout, stderr, the parser report, and the hash manifest.

## 7. Rollback

Use the saved pre-write images and rollback script. Read both written partitions back after rollback; a successful `dd` return code is not sufficient. Reboot and re-run the baseline property/service checks.
