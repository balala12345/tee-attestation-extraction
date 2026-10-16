# Redmi K70E: Detailed RKP/CDI seed and identity tutorial (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


## Route selection

There are three separate activities in the record: historical patched-Tee exploration, stock-MiTEE log capture, and a host-only clean-DeviceInfo issuance test. The old patched route produced a `NOT_APPROVED` result and is retained for analysis only. A fresh run must start with a new profile, new one-shot values, new hashes, and all preflight gates passing.

## 1. Zero-risk offline audit

Set `WORK`, `SERIAL`, `SUBMISSION`, and the verifier path. Run the frozen offline verifier without touching the device or the network. Check file count, permissions, symlink rejection, scalar/SPKI equality, DICE signatures, raw CBOR canonicality, certificate-chain signatures, and Provisioning Info. Stop on any failure; do not rebuild a manifest just to hide a mismatch.

## 2. Host-only inputs

Keep the identity scalar, native zero-key CSR, proper five-entry DICE chain, UDS material, DeviceInfo, generated software private key, request bytes, HTTP metadata, raw response, ordered chain, provenance, and verification JSON as separate artifacts. The raw scalar/private key and raw identity CBOR are excluded from this delivered copy, but their sizes, hashes, and equality relationships remain in the evidence files.

## 3. Dynamic capture route (only with a fresh authorized batch)

1. Run host-only builders and verify the exact TA, TEE, init_boot, and stock recovery hashes.
2. Pre-stage the stock TEE recovery image and use the target gate for serial, product, and current slot.
3. Boot the early-bind/init_boot candidate in a fail-closed mode. Verify that it refuses to arm when any hash/token/latch is wrong.
4. On the single armed boot, capture a native zero-key CSR, validate the UDS and five DICE signatures, then parse the secure-world log for exactly two private-key lines that form one legal P-256 scalar.
5. Derive the scalar's SPKI and accept it only if it equals the final DICE leaf SPKI from the same CSR. Zero matches or multiple matches are failures.
6. If a BCC/CDI KDF output is being tested, record its label, status, exact length, and hash, but do not call it an identity seed until the downstream SPKI relationship proves it.

## 4. `google-rkp-sw` construction

Use a seed file with mode `0600`; never pass the scalar on the command line. Reuse the same-run DICE/UDS source only after verifying its raw hashes. Build the AuthenticatedRequest, sign it with the matched identity scalar, generate exactly one fresh P-256 software key, fetch a fresh Google EEK/challenge, and submit once. Save request bytes and raw HTTP response before parsing.

## 5. Approval and offline acceptance

A passing cryptographic chain is not sufficient. Parse every Provisioning Info map, preserve unknown keys and types, reject duplicate CBOR keys and trailing items, and fail closed on `NOT_APPROVED` or parse errors. The accepted clean run recorded `fetchEekChain=200`, `signCertificates=200`, one four-certificate chain, matching software private/leaf public keys, valid chain signatures, and `NOT_APPROVED=0`. The result classification was `PASS_CLEAN_HYBRID`; it was not a fully-stock same-run claim.

## 6. Recovery and archival

Restore stock `tee` and known-good `init_boot`, verify size and SHA-256 on device, reboot, confirm `boot_completed`, root, slot, and service health, and then freeze the submission directory and manifests. Do not reuse the original serial, UDS, token, latch, or private key on another device.
