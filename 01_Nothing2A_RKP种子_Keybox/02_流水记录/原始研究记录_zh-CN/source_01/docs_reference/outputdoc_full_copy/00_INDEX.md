# outputdoc 文档索引

项目根目录：`<PROJECT_ROOT>`

本目录汇总本次 CTF 课题的可交付文档。文档已经结合以下现有记录整理：

- `<PROJECT_ROOT>/ACTIONS.md`
- `<PROJECT_ROOT>/PROGRESS.md`
- `<PROJECT_ROOT>/gptdoc/QUICK_REPRO.md`
- `<PROJECT_ROOT>/gptdoc/WORKLOG.md`

## 文档列表

1. `<PROJECT_ROOT>/outputdoc/01_NECESSARY_IMPLEMENTATION_FLOW.md`  
   整个实现的必要步骤，按执行流程抽象，只保留关键节点和必要动作。

2. `<PROJECT_ROOT>/outputdoc/02_FULL_REPLAY_REPRODUCTION.md`  
   全流程重放复现文档，包含清晰路径、命令、成功判据，末尾有避坑/问题/踩坑与解决办法。

3. `<PROJECT_ROOT>/outputdoc/03_FULL_ANALYSIS_PROCESS_RECORD.md`  
   全流程分析过程记录，按分析链路解释为什么从 Widevine 纠偏到 KeyMint、如何定位 TA、handler、patch 点。

4. `<PROJECT_ROOT>/outputdoc/04_CTF_VULNERABILITY_REPORT.md`  
   CTF 漏洞报告，说明漏洞链、影响、利用条件、复现结果、证据与修复建议。

5. `<PROJECT_ROOT>/outputdoc/05_KEYBOX_LEAK_VALUE_ASSESSMENT.md`  
   keybox 是否疑似已公开泄漏、公开指纹检查、价值评估。

6. `<PROJECT_ROOT>/outputdoc/keybox_public_fingerprints.txt`  
   可公开对照的证书指纹、序列号、公钥哈希。未包含私钥内容。

7. `<PROJECT_ROOT>/outputdoc/06_FROM_REPO_TO_TEE_KEYBOX_EXTRACTION_GUIDE.md`  
   从当前仓库出发，按目录资产、patch 原因、命令和成功判据，详细说明如何一步步实现 TEE / KeyMint attestation keybox 提取。

8. `<PROJECT_ROOT>/outputdoc/07_RKP_POOL_DUMP_20260815.md`  
   2026-08-15 当前设备 RKPD/RKP 池 dump：12 条 provisioned key 的 key_blob/public_key/cert_chain 拆分、证书链验证与下一轮 RKP key 攻击结论。

9. `<PROJECT_ROOT>/outputdoc/08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md`  
   Google RKP attestation private key capture 尝试记录：patched TA 已验证，系统级挂载与 RKPD job 已触发；当前被设备网络阻塞并已恢复。

10. `<PROJECT_ROOT>/outputdoc/09_CURRENT_CTF_RKP_PROGRESS_20260815.md`  
    当前 CTF/RKP 目标总进展：已做事项、当前阻塞点、目录地图、继续执行计划和成果状态。

11. `<PROJECT_ROOT>/outputdoc/12_NO_AI_KEYBOX_EXTENSION_REIMPLEMENTATION_GUIDE.md`  
    脱离 AI 重做 KeyMint keybox 提取扩展的多设备复现与迁移指南：按 fenrir 支持设备建立兼容性矩阵、离线 triage、KeyMint TA profile、proof-only 验证和受控完整提取流程。

## 最终产物位置

### Factory KeyMint keybox

- 明文 keybox：`<PROJECT_ROOT>/extracted_keybox/attestation_keybox_plain.bin`
- EC 私钥：`<PROJECT_ROOT>/extracted_keybox/ec_private_key.der` / `.pem`
- RSA 私钥：`<PROJECT_ROOT>/extracted_keybox/rsa_private_key.der` / `.pem`
- 证书链：`<PROJECT_ROOT>/extracted_keybox/ec_cert_*.der`、`rsa_cert_*.der`
- XML：`<PROJECT_ROOT>/extracted_keybox/keybox.xml`

### RKP pool dump

- RKP 总入口：`<PROJECT_ROOT>/rkp_dumps/`
- RKP 总索引：`<PROJECT_ROOT>/rkp_dumps/manifest.json`
- RKP 聚合 XML：`<PROJECT_ROOT>/rkp_dumps/all_rkp_keys.xml`
- 每条 RKP XML：`<PROJECT_ROOT>/rkp_dumps/rkp_*/key.xml`

### Google RKP private key capture 工作区

- Runbook：`<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/RECOVERY_AND_RUNBOOK.md`
- Patched TA / helper：`<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/tools/`
- 日志：`<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/`
- 成功续跑后的目标目录：`<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/google_rkp_dumps/`
- `10_RKP_CURRENT_PROGRESS_SNAPSHOT_20260815_164139.md`：2026-08-15 16:41 RKP CTF 当前进展快照；记录已完成动作、system RKPD 最新失败点、root cause 与 direct-only side-channel 下一步。
- `rkp_research/patch_0706_rkp_sideleak.py` / `verify_rkp_sideleak.py`：direct-only RKP side-channel 补丁与验证脚本；保持 216B private handle，额外泄漏 196B keygen object。
- `11_RKP_PROGRESS_SNAPSHOT_20260815_170519.md`：2026-08-15 17:05:19 CST RKP direct CSR/signCertificates 当前进展快照（Google 返回 400，production CSR 仍需排障）。
- 进展更正：`11_RKP_PROGRESS_SNAPSHOT_20260815_170519.md` 已补充 `ProtectedData` recipient 与 Google curve2 EEK 公钥不匹配的逐字节证据；当前重点是 TA 的 test/VTS EEK-root 分流，而不是重新修改外层 CBOR。
