# Google RKP Attestation Key Capture Attempt 2026-08-15

Run 目录：`<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635`

## 结果摘要

- 已完成并验证 `rkp_ptr196` patched KeyMint TA：direct probe 可泄出 RKP keygen object，私钥 scalar 在偏移 `0x98`，并已验证 scalar 推导公钥与当次 RKP public key 匹配。
- 已成功临时 bind mount system UUID patched TA 到 `/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin`，并重启 `vendor.keymint-trustonic`。
- 已备份 RKPD app 数据、清空 DB、通过 BootReceiver 重新调度 RKPD provisioning job，并强制运行 jobId `26/27`。
- Google provisioning 未完成，失败原因是设备没有 Android 默认网络：`Active default network: none`，RKPD 无法解析 `remoteprovisioning.googleapis.com`。
- 已完整恢复原始 KeyMint TA 挂载与 RKPD DB；恢复后 DB 为原 12 条 216B opaque key_blob，KeyMint/RKP binder 正常。

## 恢复确认

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin SHA256:
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2

RKPD DB restored:
count=12, min_key_blob_len=216, max_key_blob_len=216
```

## 详细恢复/续跑文档

详见：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/RECOVERY_AND_RUNBOOK.md
```

后续只需先让设备连上可信网络/热点，再按 runbook 第 6 节续跑即可。

## 2026-08-15 16:10 后续续跑补充

网络已恢复，设备连接 `xnhzplus`，`Active default network: 101`，`remoteprovisioning.googleapis.com` ping OK。

续跑结果：

1. `google_rkp_keydump_retry_20260815_161025`：原 helper 路线失败，原因是 tar 恢复后的 RKPD `no_backup/`、`databases/`、`shared_prefs/` 子路径为 `system_data_file`，RKPD app 被 SELinux 拒绝访问 WorkManager DB。
2. `google_rkp_keydump_retry_pmclear_20260815_161655`：改用 `pm clear com.android.rkpdapp` 后，RKPD app data context 正常，WorkManager 可启动；但 KeyMint HAL 在 RKP keygen 处返回 `TrustonicKeymintDeviceImpl: generate_ecdsa_p256_key: Invalid session handle`，DB schema 创建但 `provisioned_keys=0`。
3. 清理后 patched TA 已解除，原 TA hash 恢复为 `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`，RKPD app data context 正常。

当前新阻塞点：Trustonic/KeyMint/RPC session handle 失效。下一步需要人工明确授权后重启 `tee-1-1`、`vendor.keymint-trustonic`、`keystore2` 服务链，或重启设备，然后再运行 pmclear helper。

最终只读核验：原 TA hash 为 `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`，无 `070600` bind mount，RKPD app data context 为 `u:object_r:privapp_data_file:s0:c512,c768`。`cmd remote_provisioning dump` 正常，但 `cmd remote_provisioning csr default` 仍返回 code 1，logcat 为 `TrustonicKeymintDeviceImpl: generate_certificate_request: Invalid session handle`。

## 2026-08-15 16:41 最新结论：system patch 破坏 CSR handle

网络和 BFM/session 问题排除后，最新运行目录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_after_reboot_20260815_163210
```

证据：

```text
Active default network: 100
remoteprovisioning.googleapis.com ping OK
PoolStats{keysInUse=0, idealTotalSignedKeys=12, keysToGenerate=12, keysUnassigned=0}
Requested number of keys for provisioning: 12
Failed to generate CSR blob. Failed with 5
android.os.ServiceSpecificException: (code 5)
```

当前判断：`rkp_ptr196` 适合证明 196B RKP keygen object 可泄漏，但它把返回给 RKPD 的 opaque private handle 改成了明文对象，导致后续 `GenerateCertificateRequest` 无法消费 handle 生成 CSR。因此 system RKPD 尚未走到 Google cert 下发阶段。

下一步路线：改成 direct-only side-channel leak 补丁，保留原始 handle，并额外在 direct mapped buffer 尾部输出 196B 明文对象；验证后再扩展 direct client 调 `0x50402` 生成 CSR。

进展快照：

```text
<PROJECT_ROOT>/outputdoc/10_RKP_CURRENT_PROGRESS_SNAPSHOT_20260815_164139.md
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



---

## 2026-08-15 17:05:19 CST 更新：direct CSR/signCertificates 当前状态

详见快照：`<PROJECT_ROOT>/outputdoc/11_RKP_PROGRESS_SNAPSHOT_20260815_170519.md`

- 新增 `rkp_research/build_and_send_signcerts.py` 与 `rkp_research/test_build_signcerts.py`，按 RKPD 旧流程构造 `MacedKeysToSign` 与最终 `CertificateRequest`。
- `curve=2 + testMode=1` direct CSR 已确认成功：`dev_len=198`、`protected_len=433`、`maced_keys_len=32`。
- 用该 CSR 构造出的 `certificate_request.cbor` 长度为 `877`，sideleak scalar 与 public key 验证为 `true`。
- 已向 Google `v1:signCertificates` 提交，请求目录：`<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send`。
- Google 返回 `HTTP 400 Bad Request`，错误：`Invalid request payload: Failed to verify certificate chain`。
- 额外复测 `4d` production key + Google curve2：TA CSR 返回 `0xfffe795b` / signed `-100005`，未得到 production CSR。
- 后续逐字节解析确认：`ProtectedData` recipient 公钥 X 为 `567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d`，而 Google curve2 EEK 公钥 X 为 `be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260`，两者不匹配。
- 当前应记录为：EEK 存在，但 test-mode TA 生成的 ProtectedData 使用了另一把 EEK；这与设备日志中的 `USING EEK ROOT KEY FROM VTS` 相符，并解释 Google 侧 `Failed to verify certificate chain`。
- 更正旧判断：不能再写成“ProtectedData 已使用 Google curve2 EEK”；URL-safe Base64 保留 padding 的原实现与 RKPD flags=10 一致。
- 下一步重点：确认 TA 的 test/VTS EEK-root 选择逻辑，并单独解决 production CSR 的 `-100005`。
