# Redmi 11T Pro: Principles and patch boundaries (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


The read path spans a normal-world client, the TEE client library, the MediaTek secure transport, the secure manager, and a Keybox TA. The TA already contains a read command; the problem is the combination of caller-mode and container-signature gates.

The LK/Fenrir layer only permits the patched TEE to boot. It does not return the Keybox. The TA container has an encrypted ELF and a trailer protected by the secure manager. Repacking a modified ELF necessarily invalidates the original TA signature, so the manager patch must ignore the verification result while keeping the container format checks and AES-CTR unwrap intact.

The TA patch removes only the caller-mode rejection for the existing read command. It does not modify the command ID, parameter types, or write commands. Runtime deployment uses a temporary bind mount, so the vendor filesystem is not permanently changed.

The payload descriptor is a fixed header with magic, declared length, reserved fields, per-entry offsets/sizes, certificate counts, and an MD5 of the payload. The payload contains length-prefixed DER objects. The result is accepted only when descriptor and payload bounds agree, the digest matches, the EC/RSA private keys derive the respective leaf SPKIs, and both certificate chains verify.
