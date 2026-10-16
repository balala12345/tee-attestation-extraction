# K70E CTF：RKP 证书离线验收与 Pixel 部署记录

日期：2026-09-06  
项目：Redmi K70E / duchamp CTF 靶机研究

## 1. 本次输入材料

本次检查针对以下一次性签发产物：

- PKCS#8 DER 私钥：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/key_00/private_key_pkcs8.der`
- 四证书链 DER：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.der`
- 四证书链 PEM：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.pem`
- 叶证书 DER：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_cert_00.der`

私钥文件权限为 `0600`。文档不记录私钥内容、标量、PEM 私钥文本或任何可恢复私钥的材料。

## 2. 文件摘要

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `private_key_pkcs8.der` | 138 B | `58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8` |
| `ordered_certificate_chain.der` | 2486 B | `423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20` |
| `ordered_certificate_chain.pem` | 3593 B | `c63a4e76d3af5cc6f857ca6bbf102f5a63d2755aab3a088ba39a5e7045defc34` |
| `ordered_cert_00.der` | 565 B | `b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180` |

## 3. 离线验收结果

### 私钥与叶证书关系

- 私钥派生公钥 SPKI SHA-256：
  `1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67`
- 叶证书公钥 SPKI SHA-256：
  `1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67`
- 结论：匹配。

### 证书链

- 证书数量：4
- 叶证书：`CN=df5d0b538f137beaf18aa9ab7252043a, O=TEE`
- 叶证书签发者：`CN=Droid CA3, O=Google LLC`
- 链路顺序：叶证书 -> Droid CA3 -> Droid CA2 -> Key Attestation CA1
- 所有证书字节均被严格消费，无尾部数据
- 子证书签名链验证：通过
- 根证书自签名验证：通过
- 根证书 SHA-256：
  `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`
- 结论：四证书链结构和签名关系正常，根与项目固定的 Google Key Attestation CA1 锚点一致。

### 叶证书有效期

- 生效：2026-09-04 12:00:30 UTC
- 到期：2026-09-16 14:47:51 UTC

## 4. Provisioning Info 扩展解析

目标 OID：`1.3.6.1.4.1.11129.2.1.30`

叶证书 CBOR 解码结果为：

```text
{
  1: 32,
  3: "Xiaomi",
  5: {
    1: "APPROVED",
    2: "acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"
  }
}
```

检查结果：

- 叶证书扩展存在
- CBOR 单项解析成功
- 无尾随字节
- 原始 CBOR 长度：91 B
- 原始 CBOR SHA-256：
  `8a28b6caee0213767426c60bacb6e9fae9ad064fbe24d18449583fea2041dab7`
- 链中 `NOT_APPROVED` 命中数：0
- 解析错误数：0
- 非叶证书未携带该扩展，符合本次链审计结果

## 5. 结论

这组产物通过了离线材料验收：

1. 私钥与叶证书公钥匹配。
2. 四证书链完整，签名和根锚点验证通过。
3. Provisioning Info 可解析，叶状态为 `APPROVED`，没有 `NOT_APPROVED`。
4. 因此，当前证书文件、私钥编码、证书链顺序和 CBOR 扩展不是明显的格式错误来源。

该结果对应原始流水线的 `FINAL_RESULT.status=PASS_CLEAN`，但语义标签仍为 `PASS_CLEAN_HYBRID` / `research_only_semantically_hybrid`：它是研究用的混合来源候选，不能等同于赛事方已接受，也不能等同于全量 stock 同次运行证明。

## 6. Pixel 部署状态

本次没有连接、刷写、重启或修改 Pixel，也没有将私钥和证书写入或替换真实设备的 Trickystore。原因是这会改变真实设备对外呈现的硬件认证状态，超出本记录的离线 CTF 材料验收范围。

后续安全测试应使用 Android Emulator、本地模拟 verifier 或专用隔离靶机，并保留原始证书、哈希和验收日志作为只读 fixture。

## 7. 证据来源

- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/FINAL_RESULT.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/REQUEST_AUDIT.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/chain_summary.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.der`

