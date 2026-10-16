# K70E 赛事“私钥 + 证书”交付审计与 `google-rkp-sw` 核心参数边界

日期：2026-08-29（UTC）  
设备目标：Redmi K70E / `duchamp`  
目的：纠正“原生 CSR 已签发”与“赛事要求的可交付私钥 + 证书”之间的差异。

## 结论

当前没有证据证明工作区已经拥有一组 **K70E 原生 RKP 公钥对应的可导出私钥 + Google 证书**。已经完成的原生 TEE 签发只保存了证书链，叶证书对应的私钥仍在设备 TEE/KeyMint 内。

赛事要求的交付物若严格定义为：

1. 可在主机上读取的 P-256 私钥（raw scalar、PKCS#8 或 `keybox.xml` 中的 PEM）；
2. 与该私钥公钥逐把匹配的 Google RKP 证书链；

则此前的 `K70E_google_rkp_raw_native_submit_20260829_081925` 只能算 **原生 TEE 签发证据**，不能算赛事交付完成。

## `google-rkp-sw` 真正需要的核心参数

仓库 [`rkp_sw.py`](../../third_party/google-rkp-sw/rkp_sw.py) 的 `resolve_seed()` 明确只接受：

- 恰好 32 字节 raw `CDI_Leaf` seed；或
- 64 个十六进制字符表示的同一 seed。

`DeviceKeys` 用该 seed 派生 DICE/CSR 身份；`provision`/`keybox` 再生成 P-256 attestation key，并把私钥保存为 `key_00/private_key_pkcs8.pem`，随后提交 CSR，只有叶证书公钥与该主机私钥公钥匹配时才形成完整交付物。

因此，`google-rkp-sw` 需要的是 **可脱机重建 DICE 身份的 32 字节 `CDI_Leaf` seed**，不是：

- 275 字节 KeyMint `privateKeyHandle`/opaque blob；
- 119 字节 `MacedPublicKey`；
- CSR 中任意 32 字节窗口；
- MAC、签名、EEK 或 `ProtectedData`。

## 工作区内所有“看起来像私钥”的材料分类

### 1. K70E 原生新签发目录：没有主机私钥

目录：

`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/`

- `response.cbor` 与 `chain_00/ordered_certificate_chain.pem` 是 Google HTTP 200 的证书产物；
- `private_key_blob_opaque.bin` 为 275 字节 KeyMint opaque blob，SHA-256：`ac9ea690b6383af4717fcce3a9f2eb7c0b00f8683c89c696263646aa54d2560e`；
- 目录中没有 `private_key.pem`、`private_key.pk8`、PKCS#8 DER 或 32 字节 P-256 scalar；
- 叶证书公钥与 `MacedPublicKey` 匹配，但这只能证明 TEE 内私钥对应关系，不能证明私钥已导出。

### 2. 设备 `keybox.xml`：有 PEM 私钥，但不是 K70E 原生 RKP 身份

文件：

`03_提取结果/K70E_当前开机RKP日志只读_20260829/keybox.xml`  
SHA-256：`e14aa5f6fce07048d5d38ddc186c5ad53af54e4ad64698b098e78d190ffb8789`

只读解析结果：

- XML 自报 `DeviceID=Samsung_1fd03bc9-be0d-4b6b-ac2c-6124b38a331e`；
- 含 1 把 ECDSA 和 1 把 RSA PEM 私钥；两把私钥均与各自 XML 首张叶证书公钥匹配；
- 叶证书 `notBefore` 均为 2018-11-28，`notAfter` 为 2028-11-25；
- 项目既有状态审计将其记录为 `REVOKED / KEY_COMPROMISE`，并判定为外来 keybox 注入痕迹。

所以它不能作为 K70E/duchamp 的 Google RKP 交付物，也不能拿来冒充本次原生 CSR 生成的密钥。

### 3. 仓库 `ctf_artifacts`：有私钥和证书，但明确是本地测试

目录：`third_party/google-rkp-sw/ctf_artifacts/`

- `ctf_seed.bin` SHA-256：`e0e2617b3156d12a0b7108b71340484c3e4ae965ae686d7360c8032f2d82a7c3`；
- `ctf_attestation_ec_private.pem` SHA-256：`9e73c9e9c3247b46b45bd33735bf6cb18b3c41a46ae1cacd7b3557262ad111c2`；
- `ctf_local_keybox.xml` SHA-256：`fa0e36916d0391445f6a4308a435c652217f72e8853fe11e015923e9da6e9853`；
- `ctf_local_keybox_summary.json` 明确写有 `scope=LOCAL_CTF_ONLY`、`google_signed=false`，配置身份是 `Nothing/A142/Pacman`，不是 K70E。

这组材料可以用于验证仓库的“私钥落盘格式”和离线 keybox 结构，但不能当作 Google 生产签发，也不能当作 K70E 身份。

## 已完成的 K70E seed 证据门控

此前发现的两份 K70E 32 字节候选均已用独立 Open-DICE P-256 派生与原生 UDS SPKI 基线复核，结果都是 `FAIL`。它们不能作为 `--seed-file` 输入。对已闭合的 `generateCertificateRequestV2` 调用链，主机可见边界仍只有 challenge、MacedPublicKey、签名/MAC、opaque handle 和 CSR 字节，没有发现可重建原生 UDS SPKI 的私密 32 字节出口。

## 当前阻塞与可接受的下一步

要生成赛事要求的 **同一组“私钥 + Google 证书”**，必须有以下任一项由赛事方/设备方明确提供并授权使用：

1. K70E 专用、可导出的 32 字节 `CDI_Leaf` seed，以及允许该软件身份向 Google 或赛事沙箱申请证书的配置；或
2. 赛事方提供的 RKP 测试端点/签发沙箱和其规定的可导出测试 seed；或
3. 赛事方明确接受 `LOCAL_CTF_ONLY` 根签发的离线测试 keybox，而不要求 Google 生产链。

在没有上述授权材料的情况下，继续从 K70E TEE、诊断 TA、KeyMint opaque blob 或任意内存窗口“拿出”受保护私钥，会变成绕过硬件密钥保护，而不是对 `google-rkp-sw` 的正常参数补全；现有证据不足以声称已经拿到该核心参数。

## 相关证据

- 原生签发报告：`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/REPORT.md`
- 原生证书/私钥保存边界：`00_文档/16_K70E_google-rkp-sw原生CSR签发结果_证书私钥保存边界_20260829.md`
- K70E 原生 CSRv3 与调用链结论：`00_文档/11_K70E_P256KeypairFromCDI_32字节路径提取计划_20260829.md`
- 外来 keybox 来源与状态：`00_文档/15_K70E_CTF赛事项目资料汇总_20260829.md`
