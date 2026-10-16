# Nothing 2a: Principles and evidence boundaries (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


## Keybox path

The Keybox is not a normal filesystem XML. The effective path crosses the normal-world client, the Trustonic client library, the TEE transport, the secure manager, the KeyMint TA, and an existing read command. The TCI contains a command, return code, and a mapped bulk buffer. The stock control run proves that the command is valid and that plaintext is produced inside secure world.

The read-only patch preserves command ID and parameter-type gates. Its purpose is to copy the already decrypted/parsed structure into a mapped buffer. The descriptor contains a magic, declared payload length, reserved fields, per-entry offsets and sizes, certificate counts, and a payload digest. The payload carries length-prefixed EC/RSA private-key DER and certificate DER objects. A result is real only when structural checks, digest checks, private-to-leaf SPKI equality, certificate-chain validation, and a private-key signature check all pass.

## RKP/CDI path

RKP has multiple kinds of 32-byte-looking values: an opaque key handle, a P-256 private scalar, a DICE/CDI-derived seed, a BCC/KDF output, and arbitrary memory windows. They are not interchangeable. The project records provenance, label, output length, status, hash, and the consumer protocol for every candidate.

The `rkp_bcc_km` hook is accepted only when KDF status is successful, exactly 32 bytes are produced, the output hash matches an independent session, and offline derivation/CSR verification succeeds. A direct scalar side-leak can be useful for a direct client while still being unusable as a system CSR input. The working evidence therefore separates direct keygen, stock Binder CSR, KDF-derived material, and Google certificate issuance.

## Evidence boundary

The public delivery retains patch sources and binaries, boot/TEE/firmware images, logs, parser output, and SHA-256 manifests. It omits raw Keybox XML, private keys, raw CDI/seed bytes, host identity paths, and device serials.
