# Redmi K70E: Principles and evidence boundaries (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


## Identity hierarchy

The RKP stack exposes several related but distinct values. UDS is a device-root input; DICE derives a certificate chain and a CDI leaf; a CDI leaf scalar is a P-256 signing key for that leaf; BCC/KDF outputs and active RKP key scalars serve different consumers. A value is not promoted to “seed” by length alone.

## Same-run identity proof

The strongest identity check is relational: parse the final DICE leaf SPKI from the same native zero-key CSR, derive a SPKI from each captured 32-byte candidate, and accept exactly one equality. The secure-world log is only a candidate source; it is not sufficient by itself.

## Google approval gate

Certificate-chain signatures, private-to-leaf SPKI equality, and HTTP 200 form the cryptographic gate. Provisioning Info is a separate policy gate. The verifier preserves all CBOR keys and types, rejects duplicate-key collisions and trailing items, and fails closed for `NOT_APPROVED` or parse errors. HLOS `green/locked` properties cannot substitute for the signed DeviceInfo carried in the request.

## Evidence classes

The delivery distinguishes stock baseline, patched historical runs, clean hybrid issuance, offline audit, and recovery evidence. It does not claim that the hybrid run was a fully-stock same-run extraction. The patch/image/firmware folders retain build inputs and binary hashes; the evidence folder retains only sanitized summaries and fingerprints.
