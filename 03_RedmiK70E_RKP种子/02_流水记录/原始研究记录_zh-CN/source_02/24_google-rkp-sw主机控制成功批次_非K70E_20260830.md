# `google-rkp-sw` 主机控制成功批次（非 K70E）

日期：2026-08-30（Asia/Taipei）  
用途：在设备失联期间验证 `google-rkp-sw` 的完整“私钥 + Google 证书”保存链路。  
身份边界：本批次使用工作区既有 Nothing A142/Pacman 配置，**不是 Redmi K70E 身份，也不能作为 K70E 赛事最终提交物**。

## 运行目录

```text
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01
```

输入材料（只记录路径，不复制秘密内容）：

```text
seed：<PROJECT_ROOT>/third_party/google-rkp-sw/ctf_artifacts/ctf_seed.bin
config：<PROJECT_ROOT>/third_party/google-rkp-sw/device_prop.conf
```

该配置的设备字段是 `Nothing / A142 / Pacman`，因此本批次只证明主机软件流程和服务器签发链路可用。

## 成功结果

`google-rkp-sw keybox` 返回 Google `signCertificates` **HTTP 200**，并在网络前保存待签 EC 私钥，在响应解析后保存完整四层证书链、公私钥校验、原始请求和响应。

```text
run_summary.status             complete
requested_key_count            1
received_chain_count           1
http_status                    200
request_len                    672
response_len                   2415
request_sha256                 d8a700865d695f912f5314d6e305424c5db03815f150f050561eb86777538577
response_sha256                c7516a868458cacf7983b64e04e956263023e5cf6b6f7e6aeb52fba9fac9e1fa
keybox_sha256                  0cd55cdf539a14d4688fdff66c7274e7e6c41744d27f08224eb3ad9d8144faa3
```

核心交付文件已经保存：

```text
私钥（PKCS#8 PEM）：
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01/key_00/private_key_pkcs8.pem

证书链（叶到根 PEM）：
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01/chain_00/ordered_certificate_chain.pem

Keybox 容器：
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01/keybox.xml
```

文件 SHA-256：

```text
private_key_pkcs8.pem          d93f70bfb57e02fddf39370061fae95d14bb8aed4a1e2554a88dd94471262067
ordered_certificate_chain.pem  91daf4475bd927785da476bd7a488d0949f97ef5afdfc8b0677cb7005bcd5c77
keybox.xml                     0cd55cdf539a14d4688fdff66c7274e7e6c41744d27f08224eb3ad9d8144faa3
```

## 证书审计

完整审计文件：

```text
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01/verification_report.json
<PROJECT_ROOT>/正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/google_rkp_sw_host_control_nothing_20260830_01/REPORT.md
```

审计结论：

* 四层链逐层签名通过，根自签通过；
* 叶证书公钥与保存私钥匹配；
* 叶证书 SHA-256：`ee36a1977d281c821042909b60d0a2d2111c307e001dd5579c100f11514eafa6`；
* 叶证书有效期：`2026-08-28T14:56:55Z` 至 `2026-09-11T09:22:35Z`；
* 证书总有效期：`13.767824` 天；
* provisioning-information OID `1.3.6.1.4.1.11129.2.1.30` 的 key `1`：`128`。

`128` 是 Google 写入证书的滚动近 30 天近似签发量，不是本次返回数量，也不是自然月精确值；本次实际返回链数为 `1`。

## 与 K70E 最终目标的关系

本批次证明“主机可以生成私钥、保存私钥、提交 CSR、保存 Google 证书，并完成公私钥匹配”。它没有证明 Nothing 的 seed 是 K70E 的 seed，也没有改变 K70E 当前缺少与其 `MacedPublicKey` 匹配私钥的事实。K70E 最终产物仍需使用 K70E 对应的私钥材料重新生成 CSR 并取得对应证书。
