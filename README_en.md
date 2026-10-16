# Android TEE Keybox and RKP Seed Extraction Research Archive

> ⚠️ **MIRROR NOTICE**
>
> This repository is a **mirror copy**, not the original project. All credit belongs to the upstream author.
>
> | | |
> |---|---|
> | **Upstream** | <https://github.com/gungnir-sanye/tee-attestation-extraction> |
> | **Author** | [@gungnir-sanye](https://github.com/gungnir-sanye) |
> | **Snapshot commit** | `2fc26d8cc983798a86fdce5f54be5c448c7cc019` |
> | **Mirrored at** | 2026-10-16 |
>
> This mirror only byte-copied the file contents (651 files, identical to upstream). **No technical
> content was modified, removed, or added.** Original commit history is not preserved.
> **Upstream prevails.** Licensing follows upstream's layered non-commercial terms — see
> [MIRROR_NOTICE.md](MIRROR_NOTICE.md) and [LICENSE](LICENSE).
>
> If the upstream author objects, please open an issue and it will be removed immediately.

> 🔧 **Added by this mirror**: `tools/tee_extract.py` — a host-side gate-enforcing pipeline that
> chains the archive's scattered precheck / capture / parse / verify scripts (read-only, no flashing).
> See [tools/README.md](tools/README.md). This is the **only addition**; the original 651 files are untouched.

中文 | [English](README_en.md)

[中文](README.md) | English

This is a technical documentation archive for authorized CTF work, Android TEE security research, and defensive review. The project is organized into three independent device tracks and records research targets, extraction objects, validation status, technical principles, actual operation ledgers, failed branches, rollback requirements, and publication boundaries.

The public copy keeps the reviewable documentation structure, result models, version gates, audit rules, patch/image/firmware registers, and sanitized evidence. Real secrets, unique device identity material, and unauthorized device-operation material are outside the public scope.

## Documentation provenance, AI organization, and reproduction method

This delivery directory is not a certification report produced after manually reproducing every experiment. The collection was made by an AI reading the existing project tree, source documents, actual ledgers, scripts, patch/image registers, and file manifests, then performing structural splitting, sanitization, bilingual arrangement, and cross-document organization. The public copy does not represent manual execution, independent reproduction, or sign-off for every command, patch, image, or result.

Accordingly, “tutorial,” “result,” “acceptance,” “success,” “failure,” and “current route” must be read together with the source record and its time context. They may be historical records, AI-organized judgments, incomplete states, or conclusions that require revalidation. They do not mean that a human has validated them, and they are not guaranteed to be directly executable outside the complete project tree.

The recommended reproduction method is **AI-assisted reading plus human authorization and review**:

1. Give the AI the complete target-device directory rather than a single README or command block;
2. Have the AI extract prerequisites, version/slot/hash gates, inputs, failed routes, rollback conditions, missing evidence, and contradictions requiring confirmation;
3. Have the AI produce a read-only review plan and a human confirmation checklist;
4. Have an authorized person with the required device-operation capability check each item in an isolated, reversible environment;
5. Decide whether to perform any operation only after the human confirms the inputs, environment, and risks;
6. Write actual execution results, deviations, and unverified items back into the practice ledger.

AI-generated commands, patch explanations, path inferences, and result conclusions are not executable instructions or human certification. Reading only the README, copying commands, or seeing one successful boot is not sufficient to establish reproduction success.

## Device result overview

| Project directory | Practical result recorded in source material | Organized material | Main entry |
|---|---|---|---|
| [`01_Nothing2A_RKP种子_Keybox/`](01_Nothing2A_RKP种子_Keybox/) | RKP seed extraction and Keybox extraction | Tutorial, complete practice ledger, principles, patch/image/firmware material, bilingual indexes | [中文教程](01_Nothing2A_RKP种子_Keybox/01_教程/教程_zh-CN.md) · [English tutorial](01_Nothing2A_RKP种子_Keybox/01_教程/Tutorial_en.md) |
| [`02_Redmi11TPro_Keybox/`](02_Redmi11TPro_Keybox/) | Keybox extraction | Tutorial, complete practice ledger, principles, patch/image/firmware material, bilingual indexes | [中文教程](02_Redmi11TPro_Keybox/01_教程/教程_zh-CN.md) · [English tutorial](02_Redmi11TPro_Keybox/01_教程/Tutorial_en.md) |
| [`03_RedmiK70E_RKP种子/`](03_RedmiK70E_RKP种子/) | RKP seed extraction | Tutorial, complete practice ledger, principles, patch/image/firmware material, bilingual indexes | [中文教程](03_RedmiK70E_RKP种子/01_教程/教程_zh-CN.md) · [English tutorial](03_RedmiK70E_RKP种子/01_教程/Tutorial_en.md) |

Every device directory retains four result classes: an implementation tutorial, a full research-operation ledger, a principles document, and related patches/images/firmware packages with evidence. Chinese and English documents follow the same directory structure; the manifests under `99_索引/` identify the current public copy.

## Directory layout

```text
README.md                         Chinese project entry
README_en.md                      English project entry
LICENSE                           Split licensing policy
01_Nothing2A_RKP种子_Keybox/      Nothing 2a research results
02_Redmi11TPro_Keybox/            Redmi 11T Pro research results
03_RedmiK70E_RKP种子/             Redmi K70E research results
```

Each device directory uses the same layers:

```text
01_教程/                           Step-by-step tutorial, prerequisites, order, and acceptance
02_流水记录/                       Full research operation ledger, output, failures, and fixes
03_原理/                           Call paths, data structures, trust boundaries, and interpretation
04_补丁镜像固件/                   Copied patch sources, images, firmware packages, inputs, and sanitized evidence
99_索引/                           Bilingual directory notes, file lists, and SHA-256 manifests
```

`02_流水记录/` is not a tutorial summary. It is the historical ledger of each research round. It preserves the execution order, inputs, commands or operations, actual output, decisions, failure causes, corrective actions, rollback actions, and final evidence. Historical failed routes remain part of the record and must not be overwritten by the final conclusion.

## Recommended reading order

1. Read `目录说明_zh-CN.md` or `Directory_Note_en.md` in the target device directory to confirm the layers and publication boundary.
2. Read `01_教程/` for the target, prerequisites, inputs, version gates, operation steps, and acceptance conditions.
3. Read `03_原理/` to understand the relationship between the boot chain, TEE/KeyMint, Keybox, RKP/CDI, certificates, and result validation.
4. Read `02_流水记录/` in chronological order and review the original record sections; pay attention to historical failures and deprecated-route markers.
5. Inspect `04_补丁镜像固件/` for artifact purpose, provenance, version, hash, supported scope, and rollback requirements.
6. Check `99_索引/` last to confirm that files belong to the current public copy and verify their SHA-256 values.

## Fenrir's research role

Fenrir is used in this project only as a boot-chain research foundation inside an authorized laboratory. At the public documentation level, its role is limited to the following boundary: it addresses a verification-boundary issue in the MediaTek boot chain so that researchers can observe later boot-stage behavior on controlled devices. Device-specific patch builds, flashing commands, TEE/KeyMint bypass details, and real key material are not part of the public project.

This project does not treat “the research environment boots” as equivalent to “the extraction succeeded.” Every device must pass gates for the version, model, slot, image hash, runtime capability, and result public-key match.

## Principle overview

The core chain can be summarized as: **Fenrir boot-chain research foundation → controlled loading of research components → version-matched TEE diagnostic patch → host-side result parsing and acceptance**.

Fenrir relies on a verification-boundary weakness in the boot chain. When the authorized experimental prerequisites are satisfied, it allows researchers to bypass the integrity-verification constraint applied to later boot components and enter a controlled research environment. This bypass concerns boot-chain loading and verification boundaries; it is not an ordinary application privilege and does not mean that installing an APK or obtaining ADB/root directly provides TEE access.

Once inside the research environment, a diagnostic patch matched to the device model, system build, slot, and TA/TEE version is used to observe the TEE call chain and extract results under control. Keybox, RKP CDI/seed, and certificate materials follow independent result-validation paths. They must pass length, structure, hash, public-key matching, and evidence-traceability checks; logs, certificates, or simulated data must not be treated as real extraction results.

Fenrir does not create vendor signatures, forge Google certificates, or turn ordinary system privileges into permanent TEE privileges. A TEE patch is not universal firmware and must match the target build and input hashes exactly. The public project keeps only principles, interfaces, synthetic fixtures, and audit rules; device-specific patches, flashing materials, and real secrets remain authorized internal materials.

If this technical archive is useful to your research, donations through an appropriate channel are welcome to support future maintenance and research.

## Donations and support

If this technical archive is useful to your research, you are welcome to use the public channels below to support future maintenance and research. Donations do not provide restricted vulnerability material, real keys, or device-extraction services. Confirm the network and asset type before sending; blockchain transfers are usually irreversible, so a small test transfer is recommended.

### Platform donation

- [Ko-fi donation page](https://ko-fi.com/sanyegungnir)

### Telegram technical discussion

- [Join the Telegram channel](https://t.me/keybox_playintegrityfix) (channel: @keybox_playintegrityfix)
- The channel is for related technical discussion and experience sharing. It does not promise restricted vulnerability material, real keys, or device-extraction services.

### WeChat support

![WeChat support QR](assets/donations/wechat.jpg)

The maximum single appreciation is 200 CNY, subject to the rules shown by WeChat at the time of payment.

### Cryptocurrency donations

| Network | Address | Asset note |
|---|---|---|
| Ethereum Mainnet | `0x04989a778AC28A60Cc5eF68DCaea379633E0189e` | ETH / ERC-20; confirm the receiving asset |
| Arbitrum | `0x04989a778AC28A60Cc5eF68DCaea379633E0189e` | ETH / ERC-20 on Arbitrum One; select the correct network |
| TRON Mainnet | `TScTH4VifRKja3NSvaWcPXmb99y3JjgYQ3` | TRX / TRC-20; confirm the receiving asset |
| Bitcoin Mainnet | `bc1q886gc0mt0w9rre3zjct7vvvyrryerm7p2k9nfc` | BTC, native SegWit `bc1q` address |

| Network | QR code |
|---|---|
| Ethereum Mainnet | ![Ethereum donation QR](assets/donations/ethereum.png) |
| Arbitrum | ![Arbitrum donation QR](assets/donations/arbitrum.png) |
| TRON Mainnet | ![TRON donation QR](assets/donations/tron.png) |
| Bitcoin Mainnet | ![Bitcoin donation QR](assets/donations/bitcoin.png) |

Important notes:

- Ethereum and Arbitrum use the same address string but are different networks; select the correct network when sending.
- Use the TRON address only on the TRON network; do not send ERC-20, BEP-20, or other network assets to it.
- The Bitcoin address accepts BTC only; do not send tokens from another chain.
- Cryptocurrency addresses are public and on-chain transfers are generally traceable, so this is not fully anonymous.
- The project will never ask for a seed phrase, private key, verification code, or extra fee by private message.

## Result acceptance gates

The following are acceptance conditions and public-review gates that the source records say should be checked; they do not mean that the public copy has been independently verified. Each extraction result should be checked as an independent result class. A log, certificate, simulated value, or one successful boot is not treated as the final result. At minimum, check:

- **Target identity**: device model, build, system version, slot, and runtime components match the record;
- **Input identity**: original inputs, patched inputs, images, and firmware packages pass the SHA-256 values in the manifest;
- **Environment**: boot state, research components, TEE/KeyMint services, permissions, and runtime capabilities satisfy the tutorial gates;
- **Result structure**: length, encoding, fields, container format, and parsed result satisfy the relevant result-class constraints;
- **Key and certificate relations**: public keys, certificate chains, issuance relations, RKP/CDI relations, and same-run evidence validate each other;
- **Provenance**: the result maps back to the relevant ledger, inputs, version, slot, and original evidence;
- **Public safety**: the public copy contains no real Keybox, seed, private key, unique device identity fields, tokens, or raw identity responses.

When any gate does not match, stop the route and record the reason in the ledger. Do not create a passing result by editing a manifest or deleting failed evidence.

## Artifacts, patches, and manifests

`04_补丁镜像固件/` is the artifact register organized by device and version. It may contain patch sources, diagnostic inputs, build outputs, images, firmware packages, parsing tools, and sanitized evidence. Files are retained by copying so their research provenance remains connected; they are not rewritten into unrelated snippets.

These materials are bound to the recorded model, build, slot, and input hashes. They are not universal firmware and do not authorize use on devices without permission. Visible paths in the public image and archive artifacts were checked; real secrets and device-specific internal materials remain represented only by hashes in the authorized workspace.

The SHA-256 manifests under `99_索引/` describe the current public copy. Historical hashes in the ledgers preserve provenance and do not replace the current manifest. After adding, deleting, or replacing any published file, regenerate the device manifest and record the change in the ledger.

## Failure and rollback rules

- Tutorial labels such as “stop,” “invalid,” “review only,” and “do not rerun” take precedence over old command examples;
- Failed historical routes are evidence, not recommended procedures;
- Before flashing, switching slots, stopping services, or changing persistent state, confirm the recovery conditions and retain the original inputs and rollback materials;
- Perform dynamic operations only on authorized, isolated, reversible test devices;
- If the version, hash, slot, identity, or result relations do not match, stop and record the mismatch instead of bypassing the gate through privilege expansion or repetition;
- After recovery, run the device health checks again and write the recovery result into the ledger.

## Publication boundary and sanitization rules

This project publishes the documentation structure, principle explanations, result models, synthetic fixtures, audit templates, and generic tool interfaces without real secrets. Real Keybox, CDI, EEK, RKP seed, private keys, raw device dumps, device identity data, private firmware, and directly executable device-extraction chains are restricted materials. Only their hashes may be registered in an authorized internal workspace; they are not copied into this directory.

Host paths, user names, serials, tokens, personal identifiers, and raw identity responses were removed from the public copy. Visible build paths inside text, scripts, JSON, logs, binary files, and compressed archives were also checked and processed. New material must be sanitized before it is placed into any project directory.

## Licensing, noncommercial restriction, and liability boundary

This repository does not use AGPL as one license for every file. Because it contains documentation, scripts, patches, images, firmware packages, and third-party materials, licensing is separated by content type:

- **Original scripts, parsers, and tools**: [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0), allowing noncommercial research, experiments, testing, modification, and redistribution, but not commercial purposes;
- **Original documentation, tutorials, principles, practice ledgers, and diagrams**: [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/), allowing attributed noncommercial copying, modification, and republication;
- **Third-party patches, images, firmware, tools, code, and components**: retain their original licenses, copyrights, and NOTICE files; this repository does not relicense them;
- **Materials with unclear ownership**: no additional permission is granted beyond applicable law until provenance and authorization are confirmed.

The noncommercial restriction means that the material may not be used primarily for commercial advantage or monetary compensation, sold, provided as a commercial service, integrated into a commercial product, or included as part of a commercial deliverable. The formal text of the applicable license controls the final interpretation.

This repository is not Open Source under the OSI definition because a noncommercial restriction does not satisfy the requirement that a license permit use in every field of endeavor. “Public release” here means public inspection and permitted noncommercial research; it does not mean commercial use is allowed.

Because this repository uses a split noncommercial policy, GitHub’s standard license picker or automatic detection may show `Other`, an unknown license, or no standard license label. This is an expected consequence of the noncommercial restriction. The project will not remove the commercial-use restriction just to obtain an AGPL, GPL, or MIT label, and it will not misrepresent this repository as using one of those licenses.

To the maximum extent permitted by applicable law, this repository and its materials are provided “as is” and “as available,” without warranties of accuracy, completeness, fitness, security, or continued availability. The releasing party and contributors are not liable for direct, indirect, incidental, special, punitive, consequential, or other losses arising from downloading, copying, modifying, running, flashing, testing, redistributing, or relying on these materials, except where mandatory law does not allow that exclusion or limitation.

See [`LICENSE`](LICENSE) for the complete licensing policy. Third-party materials must also comply with their own licenses and NOTICE files.

## Reproduction order

1. Read this README to confirm the research scope, publication boundary, and result classes.
2. Enter the target device directory and read its directory note, tutorial, and principles document.
3. Confirm the model, build, slot, inputs, and SHA-256 gates; stop if any item does not match.
4. Review the complete ledger, including failed routes, deprecated routes, and rollback steps.
5. Use internal materials only in an authorized, isolated, reversible test environment; use the public project for static research and synthetic-data testing.
6. Record new observations without overwriting historical ledgers; update the bilingual indexes and SHA-256 manifest for every new public artifact.
7. Re-run device acceptance and confirm the evidence and publication boundary before release.

## Public-release review checklist

Before submitting or republishing, check each item:

- The default entry is the Chinese `README.md`, with the language bar `中文 | English`;
- `README_en.md` has corresponding sections, links, and publication boundaries;
- All three device directories contain tutorials, ledgers, principles, patch/image/firmware material, and indexes;
- Chinese and English primary documents can be reached from the project entry or device directory;
- Each device SHA-256 manifest matches the current public copy;
- No personal path, user name, serial, token, or real secret appears in documents, scripts, logs, JSON, binaries, or archives;
- Historical failures remain, and deprecated routes are clearly marked;
- Third-party licenses, copyright notices, and NOTICE files remain intact;
- Original scripts, original documentation, and third-party materials are not incorrectly declared under one license;
