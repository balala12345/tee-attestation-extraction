# RKP CTF 当前进展快照（2026-08-15 16:41）

项目根目录：`<PROJECT_ROOT>`  
记录时间：`2026-08-15 16:41 CST +0800`  
当前目标：拿到 **Google RKP provisioning 后生成证书链所对应的 attestation certificate chain + 同一 keypair 的 P-256 attestation private key**，并按“一条 RKP 一个目录”的结构整理为可恢复、可提交的 XML/PEM/DER 产物。

## 1. 当前总状态

| 项目 | 状态 |
|---|---|
| 旧 factory keybox EC/RSA 提取 | 已完成，产物有效 |
| 当前设备 RKPD/RKP pool dump | 已完成，12 条 Google provisioned key，证书链有效 |
| 已有 RKP pool 的明文私钥 | 未获得；DB `key_blob` 是 216B Trustonic opaque wrapped blob |
| direct RKP keygen 私钥泄漏点 | 已验证，`rkp_ptr196` 可泄出 196B keygen object，scalar 在 `0x98` |
| system RKPD 重新联网 provisioning | 已触发到 CSR 阶段，但当前补丁破坏 CSR 所需 private handle，`generateCertificateRequest` 返回 code 5 |
| 当前推荐路线 | 复用上一轮 keybox 的 direct-client 思路，改为 direct-only side-channel 泄漏：保持 TA 返回的原始 private handle 不变，同时把 196B 明文对象写到 direct client 的大缓冲尾部 |

## 2. 已做过什么

### 2.1 阅读并复用上一轮 keybox 文档

重点复核了：

```text
<PROJECT_ROOT>/outputdoc/01_NECESSARY_IMPLEMENTATION_FLOW.md
<PROJECT_ROOT>/outputdoc/02_FULL_REPLAY_REPRODUCTION.md
<PROJECT_ROOT>/outputdoc/03_FULL_ANALYSIS_PROCESS_RECORD.md
<PROJECT_ROOT>/outputdoc/06_FROM_REPO_TO_TEE_KEYBOX_EXTRACTION_GUIDE.md
<PROJECT_ROOT>/gptdoc/QUICK_REPRO.md
<PROJECT_ROOT>/gptdoc/WORKLOG.md
<PROJECT_ROOT>/ACTIONS.md
<PROJECT_ROOT>/PROGRESS.md
```

结论：上一轮可直接参考的不是“把系统 `/vendor` 长期替换”，而是 **Trustonic direct client 通过 `mcOpenTrustlet()` 直接加载 patched TA bytes** 的方法。这个方法对 RKP 同样有价值，因为它避免系统 HAL/session/RKPD 状态干扰，并允许我们把 mapped buffer 做得更大，用作 side-channel 输出区。

### 2.2 已整理旧 RKP pool

产物入口：

```text
<PROJECT_ROOT>/rkp_dumps
<PROJECT_ROOT>/outputdoc/07_RKP_POOL_DUMP_20260815.md
```

结果：

- `provisioned_keys` 共 12 条。
- 每条有 216B `key_blob`、64B P-256 raw `public_key`、4 张 DER X.509 certificate chain。
- 12/12 leaf certificate public key 与 DB `public_key` 匹配。
- 12/12 openssl chain verify OK。
- 每条已整理为单独目录并生成 `key.xml` / `metadata.json` / cert chain / verify 输出。

限制：这批 DB 内 `key_blob` 不是明文私钥，不能直接生成可签名 XML key；需要在新 provisioning key 生成时同步泄漏 private scalar。

### 2.3 已验证 RKP keygen object 泄漏

补丁与客户端：

```text
<PROJECT_ROOT>/rkp_research/patch_0706_rkp_ptr196.py
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004e.rkp_ptr196.tlbin
<PROJECT_ROOT>/rkp_research/rkp_tee_probe
<PROJECT_ROOT>/rkp_research/rkp_tee_probe.c
```

direct 验证目录：

```text
<PROJECT_ROOT>/rkp_research/direct_after_invalid_session_20260815_162942
```

关键结果：

```text
mcOpenTrustlet ret=0x0 sessionId=0x501
[rkp_gen_prod] tci_ret=0x0 pub_len=119 priv_len=196
[rkp_gen_test] tci_ret=0x0 pub_len=125 priv_len=196
DONE rc0=0 rc1=0
```

技术结论：

- 命令：`0x00050401` / `GenerateEcdsaP256KeyPair`。
- hook：TA 成功返回路径附近 `0x21fe0`。
- keygen object 指针：`[sp,#216]`。
- 泄漏长度：196B。
- private scalar：对象偏移 `0x98..0xb7`。
- 已用 P-256 scalar multiplication 验证：泄漏 scalar 对应当次 direct-generated public key。

### 2.4 已尝试 system RKPD + Google provisioning

主要 run：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_20260815_161025
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655
<PROJECT_ROOT>/rkp_research/reboot_clear_bfm_20260815_163048
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_after_reboot_20260815_163210
```

已完成动作：

1. 备份 RKPD app data。
2. 临时 bind mount patched system UUID TA 到：

   ```text
   /vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
   ```

3. 重启 `vendor.keymint-trustonic` / `keystore2` / 必要服务链。
4. 清空/重建 RKPD app data，触发 BootReceiver 与 WorkManager jobs。
5. 网络恢复后，设备能解析并 ping `remoteprovisioning.googleapis.com`。
6. RKPD 已进入 provisioning flow，并请求生成 12 条 key。
7. 失败后已解除 bind mount 并恢复原始 TA hash。

### 2.5 system 路线最新失败点

最新 capture run：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_after_reboot_20260815_163210
```

关键日志：

```text
Active default network: 100
PING remoteprovisioning.googleapis.com ... OK
RkpdKeyPoolStats: PoolStats{keysInUse=0, idealTotalSignedKeys=12, keysToGenerate=12, keysUnassigned=0}
RkpdProvisioner: Requested number of keys for provisioning: 12
RkpdSystemInterface: HAL returned a batch size that's too small (4), defaulting to 20
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
android.os.ServiceSpecificException: (code 5)
IRemotelyProvisionedComponent.generateCertificateRequest
```

对应 DB 结果：

```text
provisioned_keys row count = 0
```

根因判断：

- `rkp_ptr196` 当前补丁把 TA 返回给 HAL/RKPD 的 private output 从原始 opaque private handle 替换成了 196B 明文 keygen object。
- RKPD 下一步 `GenerateCertificateRequest` 需要的是原始 private handle，用它生成 CSR。
- handle 被替换后，CSR 生成失败，Google server 还没收到可用 CSR，所以没有证书链下发。

这说明：`rkp_ptr196` 对 direct proof-of-leak 有效，但不适合直接跑完整 system RKPD flow。

## 3. 当前设备恢复状态

最近一次 capture 后做了 minimal cleanup：

```text
原始 TA SHA256:
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2

无 070600 bind mount
tee-1-1 / vendor.keymint-trustonic / keystore2 服务运行中
```

恢复记录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_after_reboot_20260815_163210/device_logs/minimal_cleanup_after_capture.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_after_reboot_20260815_163210/device_logs/status_after_capture_before_cleanup.txt
```

## 4. 下一步执行路线

### 4.1 立即改补丁：direct-only side-channel leak

目标：

- 保持 `0x50401` 原始返回的 private handle 和 `private_len` 不变。
- 额外把 `[sp,#216]` 指向的 196B keygen object 拷贝到 direct client private mapped buffer 的尾部，例如 `private_out + 0x400`。
- direct client 的 private buffer 当前是 8192B，足够容纳 side-channel。
- 不把这个补丁挂给 system HAL 使用，因为 system HAL 的 private buffer cap 很小，尾部写入可能越界；该补丁仅用于 `mcOpenTrustlet()` direct client。

预期验证标准：

```text
0x50401 返回 success
public output 正常
private_len 恢复为 stock opaque handle 长度（预期 216B，而不是 196B）
private buffer[0x400:0x400+196] 出现 keygen object
side-channel object[0x98:0xb8] scalar 推导出的公钥 == public output
```

### 4.2 后续 CSR 生成

如果 side-channel 补丁验证成功，继续扩展 direct client：

1. 使用同一个 direct TA session 调用 `0x00050402` / `GenerateCertificateRequest`。
2. 输入有效原始 private handle + public MacedPublicKey。
3. 输出 CSR blob。
4. 再研究 RKPD app/server protocol，把 CSR 发给 Google RKP endpoint，获取 certificate chains。
5. 将 certificate chain 与 side-channel scalar 合并，生成最终 RKP XML/PEM/DER 目录。

## 5. 本快照对应文档更新

本文件：

```text
<PROJECT_ROOT>/outputdoc/10_RKP_CURRENT_PROGRESS_SNAPSHOT_20260815_164139.md
```

同步更新：

```text
<PROJECT_ROOT>/outputdoc/00_INDEX.md
<PROJECT_ROOT>/outputdoc/08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md
<PROJECT_ROOT>/outputdoc/09_CURRENT_CTF_RKP_PROGRESS_20260815.md
<PROJECT_ROOT>/gptdoc/WORKLOG.md
```

## 2026-08-15 16:47 direct-only side-channel 补丁验证成功

新增脚本/测试：

```text
<PROJECT_ROOT>/rkp_research/test_rkp_sideleak_patch.py
<PROJECT_ROOT>/rkp_research/patch_0706_rkp_sideleak.py
<PROJECT_ROOT>/rkp_research/verify_rkp_sideleak.py
```

新增 patched TA：

```text
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004d.rkp_sideleak.tlbin
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004e.rkp_sideleak.tlbin
```

注意：`rkp_sideleak` 是 **direct-only** 补丁。它会写 `private_out + 0x400`，不能挂给 system HAL 小 buffer 使用。

验证 run：

```text
<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431
```

设备 direct client 输出：

```text
mcOpenTrustlet ret=0x0
[rkp_gen_prod] tci_ret=0x0 pub_len=119 priv_len=216
[rkp_gen_test] tci_ret=0x0 pub_len=125 priv_len=216
DONE rc0=0 rc1=0
```

关键结论：

- `priv_len` 已恢复为 216B，说明 stock Trustonic opaque private handle 保留，不再被 196B 明文对象替换。
- side-channel 区域 `private_full[0x400:0x400+196]` 成功输出 keygen object。
- object 起始 magic：`3c000000070000000a00001001000000`。
- `object[0x98:0xb8]` scalar 推导出的 P-256 public key 与 TA 返回的 MacedPublicKey 匹配。
- 由 scalar 生成的调试 EC private key PEM 可完成 openssl sign/verify。

摘要：

```json
[
  {
    "mode": "prod",
    "public_len": 119,
    "private_handle_len": 216,
    "private_handle_first16": "01020000ec3da19b884057babbd6db7d",
    "sideleak_object_len": 196,
    "sideleak_object_first16": "3c000000070000000a00001001000000",
    "scalar_offset": "0x98",
    "scalar_sha256": "2134d29244b3f167b4e018e721275caf92738e63e6178bbcbff10bd115099810",
    "public_xy_sha256": "f92e93f003a4ecdb683898c396547ae6c20a4eda3c80f7a2278aceb6ef82a885",
    "sideleak_object_sha256": "7262a5cd495678765abc258c7b27d7b4091c7b85cc1fbf103a7a1475637839e6",
    "private_handle_sha256": "45122fc95378548e0a7095413ad2799739b4f021f201cb6aa711d969fcc8f4b2",
    "derived_public_matches": true,
    "tci_ret": 0,
    "tci_pub_len": 119,
    "tci_priv_len": 216,
    "artifacts": {
      "object": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/rkp_sideleak_object_196.bin",
      "scalar": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/private_scalar.bin",
      "debug_xml": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_key.xml",
      "debug_pem": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_ec_private_key.pem",
      "stock_private_handle": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/stock_private_handle_216.bin"
    }
  },
  {
    "mode": "test",
    "public_len": 125,
    "private_handle_len": 216,
    "private_handle_first16": "01020000b317cbb89a19bfdfa7041ba5",
    "sideleak_object_len": 196,
    "sideleak_object_first16": "3c000000070000000a00001001000000",
    "scalar_offset": "0x98",
    "scalar_sha256": "3d8f1de849679a2d8efce2b9bb85a070dd232663983bb81679af519cfc52e175",
    "public_xy_sha256": "4b2fae0cb4e64b1448689ff6b518dac9d9ee509c294b896f66a36c151d5423a5",
    "sideleak_object_sha256": "5aeb14e69c6c862ee8e365b3f00bd57a866967169934fff63066ac0c473726d4",
    "private_handle_sha256": "ea48bf9ec241b38843af06aa8cad3dd2c988e7826a34847866a0fba7bc81c807",
    "derived_public_matches": true,
    "tci_ret": 0,
    "tci_pub_len": 125,
    "tci_priv_len": 216,
    "artifacts": {
      "object": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/rkp_sideleak_object_196.bin",
      "scalar": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/private_scalar.bin",
      "debug_xml": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_key.xml",
      "debug_pem": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_ec_private_key.pem",
      "stock_private_handle": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/stock_private_handle_216.bin"
    }
  }
]
```

下一步：逆向并实现 direct `0x00050402` / `GenerateCertificateRequest` 调用，用刚刚保留下来的 216B private handle 生成 CSR blob，再继续研究 Google RKP endpoint 请求/响应。

