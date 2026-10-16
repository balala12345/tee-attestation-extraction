# Nothing 2a: Full practice ledger (sanitized)

> **Documentation provenance and reproduction note:** The organization, splitting, translation, sanitization, and chapter arrangement of this directory were produced by an AI reading the existing project tree, source documents, practice ledgers, and artifact manifests. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result. “Tutorial,” “result,” and “acceptance” refer to source records, evidence models, or AI-organized conclusions; they do not mean that the public copy has been independently validated, and they are not guaranteed to work outside the complete project context. The intended workflow is to have an AI read the complete target-device directory and produce prerequisites, version/hash gates, invalid routes, missing evidence, and steps requiring validation, then have an authorized human review each item in an isolated environment. Never execute an AI-generated command without human review.


The Chinese master ledger and split source records contain the original operation text. This English ledger preserves the same decisions and checkpoints in execution order.

## Keybox investigation

1. The first route followed DRM/Widevine strings containing “keybox”. The dump and logs proved that route was a DRM trustlet and not the Android KeyMint attestation Keybox.
2. The target path was narrowed to Android Keystore → keystore2 → KeyMint HAL → Trustonic KeyMint TA → persistent attestation objects. A local attestation request was used to prove the fallback path even though RKP services were present.
3. Static analysis identified the dispatcher, the Keybox command handlers, the secure-object decrypt/parse functions, and the mapped TCI buffer. The unpatched direct client returned success but did not copy plaintext to normal world, establishing the control result.
4. Several TA candidates were rejected because they were the wrong trustlet or because an input buffer was unchanged. The successful read-only patch kept the command and parameter gates and altered only the return/copy path.
5. The patched TA was loaded temporarily, the direct read-only command completed, and the returned descriptor/payload lengths were recorded. The parser then validated magic, lengths, MD5, EC/RSA DER, three certificates per chain, SPKI equality, OpenSSL chain verification, and private-key signing.
6. The final Keybox result was archived with the patch sources, patched TA, boot/TEE images, parser output, and hash evidence. Plaintext Keybox and private keys were deliberately excluded from this copy.

## RKP/CDI investigation

1. The existing RKP pool proved that the device could obtain certificate chains, but the database blobs were opaque handles and contained no usable private scalar.
2. A direct TA side-leak exposed the internal P-256 scalar for a batch of keys. Twelve keygens and scalar-to-public-key checks passed, but the direct CSR still returned `-100005`.
3. Outer `signCertificates` encodings and several system-path TA patches were tested and preserved as negative controls. The failures showed that the production CSR path is sensitive to the loaded TA state and that changing the outer CBOR alone cannot repair an invalid protected-data relationship.
4. Restoring stock TA/HAL and running provisioning produced the expected stock baseline. A stock HAL memory capture revealed the real 12-key CSR shape, which ruled out the one-key hypothesis.
5. The working route combined direct scalar capture with the stock Binder CSR path. The KDF hook for `rkp_bcc_km` then produced a separately audited 32-byte material value with success status and stable hash.
6. Offline CSR construction, signature checks, DICE/CSR parsing, and certificate-chain verification were completed before the controlled network request. The final records separate local-format tests, historical 12-chain results, and the single controlled run.

## Final acceptance and de-identification

The delivered copy keeps operation order, return codes, offsets, hashes, failure evidence, scripts, patches, images, and firmware. It removes absolute host paths, user names, device serials, raw Keybox/private-key material, and the raw 32-byte material. Source files were copied; they were not moved or deleted.
