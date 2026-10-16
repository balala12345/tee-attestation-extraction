# RKP 当前进展快照（2026-08-15 17:05:19 CST）

## 1. 当前结论

- 已经从直连 Trustonic RKP TA 路径确认并提取到 **RKP 临时 attestation key 的私钥侧信道对象**，并验证 scalar 可还原对应 P-256 public key。
- 已经复刻 RKPD 的旧版 `generateCertificateRequest()` CBOR 构造流程，能在 **curve=2 + testMode=1** 条件下让 TA 生成完整 CSR 三段输出：`DeviceInfo`、`ProtectedData`、`MacedKeysToSign MAC`。
- 已经成功向 Google `fetchEekChain` 获取 GEEK/EEK 与 challenge；并已经把本地构造的 signCertificates 请求实际发到 `remoteprovisioning.googleapis.com`。
- 当前还没有拿到 Google 返回的最终 cert chain：`signCertificates` 返回 HTTP 400，错误为 `Invalid request payload: Failed to verify certificate chain`。这说明请求已到 Google 服务端，但当前 CSR 内 `ProtectedData` 中的链/根不被 Google 接受。
- 额外复测了 `4d` TA + production key + Google curve2 EEK，TA 本地 CSR 阶段仍返回 `0xfffe795b`（signed `-100005`），没有生成可提交的 production CSR。

### 2026-08-15 后续核对：实际 EEK recipient 不匹配

此前曾根据结构摘要误判 `ProtectedData` 使用了 Google curve2 EEK。对 `ProtectedData` recipient 内部 COSE_Key 与 `geek_curve_2.cbor` 中第二个 EEK COSE_Key 做逐字节解析后，结论已更正：两者不是同一把公钥。

```text
Google curve2 EEK public X:
be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260

ProtectedData recipient public X:
567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d

match = false
```

这直接解释了 Google 的错误：请求中虽然存在 EEK，且 endpoint 也传入了 Google curve2 EEK，但 TA 生成的 `ProtectedData` 实际没有使用该 Google EEK，Google 无法按对应 EEK 解密/验证其中的证书链，最终返回 `Failed to verify certificate chain`。

当前最可能的模式分流是：`testMode=1` 走 Trustonic 的 VTS/test EEK-root 路径。设备侧已有字符串/日志 `USING EEK ROOT KEY FROM VTS`，因此测试模式可能从 TA 内置测试配置选择了另一把 EEK，而不是 TCI 输入的 Google EEK。该判断需要以更多 TA 输入输出实验确认，但 recipient 公钥不匹配本身已经是确定事实。

同时更正：之前关于 URL Base64 padding 的临时判断不成立，Android Base64 flags=10 为 URL-safe、no-wrap 且保留 padding，现有 `urlsafe_b64encode` 行为与设备侧一致，不是本次失败原因。

## 2. 本轮做了什么

### 2.1 新增/验证签发请求构造脚本

新增文件：

- `<PROJECT_ROOT>/rkp_research/test_build_signcerts.py`
- `<PROJECT_ROOT>/rkp_research/build_and_send_signcerts.py`

功能：

1. 从 TA 返回的 `MacedPublicKey` 里提取 COSE_Key payload。
2. 按 RKPD 旧流程构造 `MacedKeysToSign`：
   - protected headers bstr = `a10105`
   - empty unprotected map = `a0`
   - payload bstr = CBOR array of COSE_Key
   - tag bstr = TA 输出的 32B MAC
3. 构造最终 `CertificateRequest`：
   - `[ [DeviceInfo, UnverifiedDeviceInfo], challenge, ProtectedData, MacedKeysToSign ]`
4. 从 sideleak buffer 提取 scalar，并验证 scalar 对应 public key。
5. 可选 `--send` 向 Google `v1:signCertificates` 提交请求。
6. 如果 Google 返回成功，脚本已预留解析 signed cert response 并生成 `key.xml`/PEM/DER 的逻辑。

单元测试覆盖：

```bash
python3 -m unittest rkp_research.test_build_signcerts -v
```

### 2.2 使用成功的 direct CSR 产物构造 signCertificates 请求

输入路径：

- CSR 成功样本：`<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw`
- GEEK/challenge：`<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246`
- sideleak key 来源：`<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/rkp_gen_test_priv_full.bin`

成功 direct CSR 的设备侧证据：

```text
=== curve=2 testMode=1 ===
tl_path=/data/local/tmp/0706000000000000000000000000004e.rkp_sideleak.tlbin testMode=1
tl=281651 endpoint_len=269 challenge_len=29
mcOpenDevice ret=0x0
mcOpenTrustlet ret=0x0 sessionId=0x1101 deviceId=0x0
[rkp_gen_test] pub mcMap ret=0x0 sVA=0x300e30 sLen=0x1000
[rkp_gen_test] priv mcMap ret=0x0 sVA=0x400e34 sLen=0x2000
[rkp_gen_test] wait ret=0x0 tci_ret=0x0 pub_len=125 priv_len=216
[csr] in mcMap ret=0x0 sVA=0x3005d0 sLen=0x1af keys_len=133 endpoint_len=269 challenge_len=29
[csr] devinfo mcMap ret=0x0 sVA=0x400290 sLen=0x400
[csr] protected mcMap ret=0x0 sVA=0x500010 sLen=0x1000
[csr] maced_keys mcMap ret=0x0 sVA=0x6008e0 sLen=0x20
[csr] wait ret=0x0 tci_ret=0x0 dev_len=198 protected_len=433 maced_keys_len=32
close ret=0x0 tci_ret=0x0
DONE rc_gen=0 rc_csr=0
```

构造出的 signCertificates 请求目录：

- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170029`

关键结果：

- `certificate_request_len`: `877`
- `maced_keys_to_sign_len`: `126`
- `cose_key_len`: `83`
- `challenge_len`: `29`
- `scalar_matches_public`: `true`
- `private_scalar_sha256`: `7768175dfb6af937c841413fdf526610a2821eccf75cb4c71a33d1ab149c28fa`
- `public_xy_sha256`: `206050ad33d74793f09572b491945b47f893d1d2db149b89e103aa0a196585e3`

### 2.3 已实际提交 Google signCertificates

提交目录：

- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send`

请求信息：

- Host: `remoteprovisioning.googleapis.com`
- RequestId: `3e3e9f87-52a2-4ba5-8260-2f78287d0b8f`
- URL: `https://remoteprovisioning.googleapis.com/v1:signCertificates?challenge=AAABoASgDxEBILStYzZuEwWkYugNEFE6csrWiHE=&request_id=3e3e9f87-52a2-4ba5-8260-2f78287d0b8f`
- HTTP status: `400 Bad Request`
- Response length: `198`

Google 返回体：

```json
{
  "error": {
    "code": 400,
    "message": "Invalid request payload: Failed to verify certificate chain\nRequestId: 3e3e9f87-52a2-4ba5-8260-2f78287d0b8f",
    "status": "INVALID_ARGUMENT"
  }
}
```

当前判断：Google 已解析到请求，并在服务端验证 CSR 中的 certificate chain 时失败；这不是网络问题，也不是 CBOR 顶层格式完全错误导致的无响应。

### 2.4 额外复测 production 路径

复测目录：

- `<PROJECT_ROOT>/rkp_research/direct_csr_4d_curve2_prod_20260815_170255`

命令路径：

- TA：`/data/local/tmp/0706000000000000000000000000004d.rkp_sideleak.tlbin`
- EEK：Google curve2 (`geek_curve_2.cbor`)
- mode：`testMode=0` / production key

设备侧结果：

```text
tl_path=/data/local/tmp/0706000000000000000000000000004d.rkp_sideleak.tlbin testMode=0
tl=281651 endpoint_len=269 challenge_len=29
mcOpenDevice ret=0x0
mcOpenTrustlet ret=0x0 sessionId=0x1101 deviceId=0x0
[rkp_gen_prod] pub mcMap ret=0x0 sVA=0x300860 sLen=0x1000
[rkp_gen_prod] priv mcMap ret=0x0 sVA=0x400864 sLen=0x2000
[rkp_gen_prod] wait ret=0x0 tci_ret=0x0 pub_len=119 priv_len=216
[csr] in mcMap ret=0x0 sVA=0x300550 sLen=0x1a9 keys_len=127 endpoint_len=269 challenge_len=29
[csr] devinfo mcMap ret=0x0 sVA=0x400d00 sLen=0x400
[csr] protected mcMap ret=0x0 sVA=0x500020 sLen=0x1000
[csr] maced_keys mcMap ret=0x0 sVA=0x600460 sLen=0x20
[csr] wait ret=0x0 tci_ret=0xfffe795b dev_len=1024 protected_len=4096 maced_keys_len=32
close ret=0x0 tci_ret=0x0
DONE rc_gen=0 rc_csr=-20
shell_status=10
```

结论：production key generation 正常（`pub_len=119`, `priv_len=216`），但 CSR 命令 `0x00050402` 返回 `0xfffe795b`，无法得到有效 `DeviceInfo/ProtectedData` 长度，因此当前还不能提交 production CSR。

## 3. 当前重要产物清单

### 3.1 Google fetchEekChain 产物

- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/request.cbor`
- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/response.cbor`
- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/challenge.bin`
- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/geek_curve_1.cbor`
- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/geek_curve_2.cbor`
- `<PROJECT_ROOT>/rkp_research/geek_fetch_20260815_165246/geek_summary.json`

摘要：

- HTTP status: `200`
- challenge: `000001a004a00f110120b4ad63366e1305a462e80d10513a72cad68871`
- curve2 EEK length: `269`

### 3.2 direct sideleak / key dump 产物

- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_key.xml`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/private_scalar.bin`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_ec_private_key.pem`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_key.xml`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/private_scalar.bin`
- `<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_ec_private_key.pem`

### 3.3 direct CSR 成功样本

- `<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/csr_device_info_len.bin`
- `<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/csr_protected_data_len.bin`
- `<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/csr_maced_keys_len.bin`
- `<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/rkp_gen_test_pub_len.bin`
- `<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw/rkp_gen_test_priv_full.bin`

### 3.4 signCertificates 提交产物

- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/certificate_request.cbor`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/maced_keys_to_sign.cbor`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/cose_key_0.cbor`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/private_scalar.bin`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/ec_private_key_pkcs8.pem`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/ec_private_key_sec1.pem`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/response_http.json`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/response.cbor`
- `<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/build_summary.json`

## 4. 和“之前 keybox 提取方式”的关系

之前 keybox 提取方式的核心价值仍然有参考意义：

- 能证明 Trustonic TA 可以通过 `mcOpenTrustlet()` 直连加载并被 patch。
- patch/code cave/TCI 逆向方法可以复用。
- 侧信道拷贝私钥对象的方式已经在 RKP TA 上复用成功。

但不能直接照搬到系统 RKPD 池里：

- RKPD DB 中已有的 Google provisioned keys 只保存 opaque `key_blob`，不是 raw private scalar。
- 系统 HAL route 使用 production 验证链，不能用 direct-only sideleak patch 简单 bind mount；之前 `ptr196` patch 会破坏 HAL CSR 流程。
- 当前 direct testMode CSR 能成功，但 Google sign 阶段验证链失败，说明还需要解决 BCC/EEK root/production chain 兼容问题。

## 5. 当前阻塞点与下一步

### 阻塞点

1. `testMode=1 + curve2` 可以得到 CSR，但 `ProtectedData` recipient 公钥与 Google curve2 EEK 不一致，Google 返回：`Failed to verify certificate chain`。
2. `testMode=0 + curve2` 在 TA CSR 阶段返回 `-100005`，无法生成 production CSR。
3. 需要确认 TA 在 `testMode=1` 下为何忽略/替换传入 EEK，以及 `USING EEK ROOT KEY FROM VTS` 对 EEK root 和 BCC 链的具体影响。

### 下一步计划

1. ~~将 `csr_protected_data_len.bin` recipient 公钥与每个候选 EEK COSE_Key 自动比对，确认 TA 实际选用的 EEK 来源。~~ 已完成离线自动化；见下方 7.1。
2. 对比 `testMode=1` 成功 CSR 与 `testMode=0` 失败路径在 TA 中的分支差异。
3. 尝试恢复 production CSR 需要的 endpoint/EEK root 条件，优先从 TA 里 `0xfffe795b` 返回路径向上追踪。
4. 若能让 production CSR 成功，再用同一 `build_and_send_signcerts.py --send` 路径提交并解析返回证书链，最后整理成 `rkp_dumps/<rkp-id>/key.xml`、PEM、DER。

## 7. 2026-08-15 后续进展：recipient/Eek 自动比对工具

### 7.1 已完成

对 `rkp_research/build_and_send_signcerts.py` 做了两项增强：

1. 新增 `extract_eek_public_keys_from_chain()`：从 Google `geek_curve_2.cbor` 的 COSE_Mac0 EEK chain 中抽取每个 COSE_Key 的 public X。
2. 新增 `extract_protected_data_recipient_public_keys()`：从 TA 返回的 `ProtectedData` / COSE_Encrypt tag(96) recipients 中抽取 recipient COSE_Key public X。

同时 `build_summary.json` 现在会自动记录：

```json
{
  "protected_data_recipient_public_x": [
    "567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d"
  ],
  "google_eek_public_x": [
    "99b9eedd5ee452f685c64c62dc3e61ab57487d753729ad768032d2b3cb6358d9",
    "be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260"
  ],
  "protected_data_recipient_matches_google_eek": [
    false
  ]
}
```

新增离线诊断目录：

```text
<PROJECT_ROOT>/rkp_research/signcerts_request_diag_20260815_recipient_match
```

测试：

```text
python3 -m unittest rkp_research.test_build_signcerts -v
Ran 8 tests ... OK
```

### 7.2 当前根因判断

自动化比对确认：`testMode=1 + curve2` 的成功 CSR 中，`ProtectedData` recipient public X 仍不属于 Google curve2 EEK chain。也就是说，外层 `signCertificates` 请求格式、challenge 编码和 `MacedKeysToSign` 构造不是当前第一根因；CSR 内部的 `ProtectedData` 已经在 TA 阶段绑定到了另一条 EEK/test root 路径。

因此下一步应继续走两条线：

1. **逆向线**：从 `0x50402` wrapper 调用的 `0x21190` 核心路径继续追踪 `0xfffe795b`，重点关注 `0x1f650` / `0x1f840` 附近 COSE/recipient/ECDH 相关分支。
2. **实验线**：构造 direct CSR matrix 时同时记录 `testMode`、curve、prod/test key COSE map 差异、recipient X、Google EEK X，并确认是否存在任何输入组合能让 `recipient_matches_google_eek=true`。

## 6. 恢复/复现命令

```bash
# 验证签发请求构造逻辑
python3 -m unittest rkp_research.test_build_signcerts -v

# 仅构造 signCertificates 请求，不发送
python3 rkp_research/build_and_send_signcerts.py   --outdir rkp_research/signcerts_request_REPRO

# 构造并发送到 Google（需要主机网络）
python3 rkp_research/build_and_send_signcerts.py   --send   --outdir rkp_research/signcerts_request_REPRO_send

# 查看最近一次 Google 返回
cat <PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/response_http.json
cat <PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send/response.cbor
```
