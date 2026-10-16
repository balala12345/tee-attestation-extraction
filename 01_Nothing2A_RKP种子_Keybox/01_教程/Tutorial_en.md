# Nothing 2a: Detailed reproduction tutorial (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


## Scope and inputs

This procedure covers two separate result chains: (1) read-only KeyMint factory Keybox collection and cryptographic validation, and (2) extraction and offline use of the 32-byte RKP/CDI-derived material. Use only the matching stock firmware, TA/HAL build, slot, and patch set. Do not mix a Keybox artifact with an RKP seed artifact.

Use these variables in every shell:

```sh
set -euo pipefail
WORK="$PWD"
SERIAL="$TARGET_SERIAL"
OUT="$WORK/result"
```

Do not put a secret in a command-line argument. The delivered copy keeps fingerprints and lengths, but omits Keybox plaintext, private keys, and the 32-byte material itself.

## Part A — Keybox chain

1. **Baseline.** Capture `getprop`, slot, boot state, KeyMint/RKPD services, TEE client library, TA input, and the current boot images. Compute SHA-256 before changing anything. Preserve the original boot material as the rollback set.
2. **Trigger the local fallback.** Generate an Android Keystore attestation key with a fresh challenge and save the returned chain and logs. A transient RKP/network error followed by a local TEE attestation chain is the evidence that the local factory Keybox path is active.
3. **Confirm the call path.** Use the direct Trustonic client with the stock TA and the two Keybox input objects. The command path must return success while the mapped normal-world buffer remains unchanged. This is the control run: it proves that the client and TCI layout are correct and that the stock TA decrypts inside secure world.
4. **Build the read-only patch.** Rebuild the TA and direct client from the source scripts in `04_补丁镜像固件/01_patch/source_full`. Keep the original command ID and parameter type. The patch changes only the data-return path; it must not add Keybox write commands.
5. **Deploy in the authorized test slot.** Upload the exact matching patched TA and client, stop the KeyMint service only for the duration of the direct call, and load the patched TA from a temporary path. Record the TA return code, TCI origin, payload length, descriptor length, and stderr. Do not overwrite the vendor partition.
6. **Parse the descriptor.** Check the magic, declared payload length, reserved words, per-entry length prefixes, and payload digest. Extract the EC and RSA entries only after all bounds checks pass.
7. **Verify the cryptographic closure.** For each entry, parse the private-key DER and three-certificate chain, derive the public key from the private key, compare it byte-for-byte with the leaf SPKI, and run a leaf-to-root OpenSSL verification plus a private-key signature test.
8. **Rollback.** Remove temporary mounts, restart the service, restore the saved boot images if they were changed, and recompute the full partition hashes.

Keybox acceptance is `PASS` only when all structure, digest, SPKI, chain, and signature checks pass together.

## Part B — RKP/CDI 32-byte material

1. Start with the stock RKP provisioning baseline and the already verified production keygen path. Do not treat an arbitrary 32-byte memory window or an opaque 216-byte key handle as a seed.
2. Use the documented KDF hook with label `rkp_bcc_km`, output length 32, and an explicit status/marker written beside the output buffer. Restore the keygen cleanup path and do not change the externally reported private length.
3. Run the direct client and record only status, output length, SHA-256, and the session identifier. The raw 32-byte value stays out of the delivered copy.
4. Build the offline CSR with the fixed `google-rkp-sw` revision. Use a seed file instead of a command-line literal, hide the seed from `info`, set secret-file permissions to `0600`, and verify the signed CSR locally before any network call.
5. For a controlled online run, save the request bytes, HTTP metadata, raw response, generated private key, and ordered certificate chain before parsing. A successful run must report the HTTP status, chain count, per-chain certificate count, leaf/SPKI match, and OpenSSL chain result.
6. Distinguish the certificate extension's approximate historical count from the number of certificates returned by the current request. Do not call a local test CA certificate a Google RKP result.

## Failure branches retained in the record

- Widevine/DRM Keybox evidence is a different object and was discarded as the target.
- Direct scalar side-leak can succeed while direct CSR still fails; the working route used the leaked key material with a stock Binder CSR path.
- Modified production TA in the system CSR path consistently returned `-100005`; this is a negative control, not a missing final step.
- A 32-byte value is accepted only when provenance, length, independent hash, and the offline derivation/verification chain agree.
