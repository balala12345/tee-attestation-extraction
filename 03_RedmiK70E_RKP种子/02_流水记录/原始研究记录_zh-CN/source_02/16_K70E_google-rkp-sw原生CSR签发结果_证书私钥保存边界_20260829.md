# K70E `google-rkp-sw` 原生 CSR 签发结果与证书/私钥保存边界

日期：2026-08-29（UTC）  
设备：Redmi K70E / `duchamp`
工作目录：`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/`

## 结论先行

- **证书已保存**：Google `signCertificates` 返回 HTTP 200，返回 1 条完整四级证书链。原始 CBOR、HTTP 元数据、链的 DER/PEM、独立验证和审计文件均已落盘。
- **可导出的主机私钥没有保存**：本次使用 K70E 原厂 TEE 的 `generateCertificateRequestV2`。匹配的 P-256 私钥仍由设备 TEE/KeyMint 持有，CSR 签名过程没有把私钥明文或 PKCS#8 文件返回到主机。
- 目录中的 `private_key_blob_opaque.bin` 只是 **275 字节 KeyMint 不透明密钥句柄/密钥 blob 的备份**，不是 32 字节 raw scalar，也不是可用 `openssl`/`google-rkp-sw` 脱机签名的私钥。不要把它改名或宣称为 `private_key.pem`。

## 证书位置

证书链目录：

`<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/`

- 完整有序 PEM 链：[`ordered_certificate_chain.pem`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/ordered_certificate_chain.pem)  
  SHA-256：`a852a6cbd517a62dd83601994d666b97163b7fe61cad4844286597623ea1663b`
- 叶证书 PEM：[`ordered_cert_00.pem`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/ordered_cert_00.pem)  
  SHA-256：`ba669d8fc83a816f20ffc1ee7fe242efae619a1d1fcf4b8fc80fec3c1dd2fb98`
- 完整有序 DER 链：[`ordered_certificate_chain.der`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/ordered_certificate_chain.der)
- 各张证书的独立 PEM/DER 文件：同一 `chain_00` 目录下的 `ordered_cert_00..03.*` 与 `cert_00..03.*`。

原始 Google 响应：

- [`response.cbor`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/response.cbor)，2415 字节，SHA-256：`fa5efe34fd4e2012fa5f3250ac60fe70381811ad86ba15c0c45a2d0394d483c0`
- [`response_http.json`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/response_http.json)，记录 HTTP 200 与 `request_id=45a42fb5-70ad-49a7-869e-65e203bb2686`。

## “私钥”相关文件位置与含义

- [`private_key_blob_opaque.bin`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/private_key_blob_opaque.bin)：275 字节，SHA-256 `ac9ea690b6383af4717fcce3a9f2eb7c0b00f8683c89c696263646aa54d2560e`。这是设备 KeyMint 的不透明句柄/blob 备份，**不能作为主机私钥使用**。
- [`maced_public_key.bin`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/maced_public_key.bin)：119 字节，SHA-256 `cc5025fffaa8696e6dbe085988e851f31591629c78b86c4b7407ff8fd95db45d`。这是请求中的公钥材料，**不是私钥**。

本次目录中不存在 `private_key.pem`、`private_key.pk8`、PKCS#8 DER 或可直接导入软件的 32 字节 P-256 私钥文件。证书叶公钥与 `MacedPublicKey` 的 SPKI SHA-256 都是 `a7a7555e392b7cd416c89dcaf9b1710fe6cb04e7bd153e0437ed3cb18c0c6cd1`，证明证书对应的是该 TEE 内密钥；这不等于私钥已被导出。

## CSR 与签发验收

- fresh challenge：29 字节，SHA-256 `c9a65c315d7ef2ca4bdfb0b06336210bc4ff5f5908c7cc8f49ecb0ae960edabd`。
- [`certificate_request.cbor`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/certificate_request.cbor)：2611 字节，SHA-256 `f03011311dca791fccca64f1f78323ba113197f56ac368fbdeeb97162c3ccf56`。
- [`independent_verification.json`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/independent_verification.json)：`PASS`；5/5 DICE 签名、外层签名、challenge 绑定和 `MacedPublicKey` 绑定通过。
- [`certificate_audit.json`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/certificate_audit.json)：链签名、根自签、叶公钥匹配和 OpenSSL 验证均通过；SHA-256 `774a1741c34a1562a98e56ed9bd8f765c784e99275bde8aac5dcc36eb8dda5d9`。
- 复核说明：首次提交因缺少 `request_id` 得到 HTTP 403 `Challenge validation failed`；随后按请求协议补充 UUID `request_id` 重试，最终 HTTP 200。首次 403 响应不应当作为签发证书。

## 叶证书有效期

- Subject：`CN=e539a35f3c7c69b9a5d70400fbe0541c,O=TEE`
- Issuer：`CN=Droid CA3,O=Google LLC`
- `notBefore`：`2026-08-27 08:40:55 UTC`
- `notAfter`：`2026-09-09 04:41:24 UTC`
- 有效时长：`12 天 20:00:29`（约 12.83 天）。
- 根：Google `Key Attestation CA1`，SHA-256 `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`。

## 本月/近期颁发次数口径

叶证书 provisioning-information 扩展 `1.3.6.1.4.1.11129.2.1.30` 明确写入：

```text
certificates_issued_last_30_days_approx = 8
manufacturer = Xiaomi
```

因此本次证书能直接证明的是 **最近 30 天约 8 张**（滚动窗口近似值），不是自然月 2026-08-01 至 2026-08-31 的精确后端总数。设备本地当前只读统计为 `last_stats_day=20260829`、`google_count=18`、`proxy_count=0`；`google_count` 是客户端请求计数，不能当作 Google 后端签发数，也不能当作本次返回链数量。

## 完整工作记录

本目录已有过程报告：[`REPORT.md`](../03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/REPORT.md)。其中还列出 EEK 请求/响应、CSR、HTTP 元数据、审计和 OpenSSL 验证文件。  

本次结论仅适用于这次 K70E 原生 TEE 生成的这把 per-key 密钥。仓库内 Nothing 的本地测试 seed/私钥材料属于另一设备案例，不能与 K70E 的 `private_key_blob_opaque.bin` 或本证书混用，也不能据此宣称获得通用、长期 IDC。
