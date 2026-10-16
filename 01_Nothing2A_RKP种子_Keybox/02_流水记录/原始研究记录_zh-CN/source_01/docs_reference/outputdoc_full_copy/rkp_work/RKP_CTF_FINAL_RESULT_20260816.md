# RKP CTF Final Result - 2026-08-16

目标完成：已取得 12 组 Google RKP attestation private key + 对应短期 attestation certificate chain。

核心成功路线：

1. 用 direct sideleak TA 生成 12 个 production `MacedPublicKey`，并从 `private_out+0x400` 取出对应 P-256 private scalar。
2. 不再让 direct TA 生成 CSR；改用 stock KeyMint HAL Binder 调用 `generateCertificateRequest(false, MacedPublicKey[12], fresh GEEK, fresh challenge, out DeviceInfo, out ProtectedData)`。
3. 用 stock HAL 返回的 `DeviceInfo`、`ProtectedData`、`MacedKeysToSign MAC` 组装 RKPD old-flow `CertificateRequest`。
4. 发送 Google `signCertificates`，返回 12 条 4-cert chain。
5. 每条 leaf public key 均验证匹配对应 private scalar 推导出的 public key。

关键产物目录：

```text
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send
```

可直接使用的 XML：

```text
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_00/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_01/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_02/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_03/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_04/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_05/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_06/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_07/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_08/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_09/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_10/key.xml
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_11/key.xml
```

验证摘要：

```text
Google signCertificates HTTP = 200
chain_count = 12
cert_count per chain = 4
leaf_public_matches_private_public = 12/12
openssl verify = OK for 12/12
```

辅助产物：

```text
rkp_research/direct_csr_batch_sideleak4d_20260816_1916
rkp_research/binder_csr_from_direct4d_freshgeek_20260816_1943
rkp_research/geek_fetch_20260816_1942
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/signed_chains_summary.json
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/openssl_verify_all.json
```

设备收尾状态：

```text
stock HAL sha256 = bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a
stock TA  sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
vendor.keymint-trustonic = running
```
