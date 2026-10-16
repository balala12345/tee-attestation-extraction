# K70E CTF clean DeviceInfo `APPROVED` 傻瓜式验收与交付教程

> 用途：让下一位 AI 或人工操作者在不重放 Google 请求、不碰手机、不泄露私钥的前提下，找到、验证并交付本次三件套。  
> 结果：本地 Google/密码学/Provisioning Info 验收已通过；赛事方对本新包的最终回执尚未记录。
> 2026-09-07 更新：三件套已冻结成正式提交候选，直接使用文档 71 的目录和专用校验器，不再手工散拷文件。

---

## 0. 只记住四句话

1. 不要再运行联网脚本；这次 one-shot 已经成功且已消耗。
2. 题目要的软件私钥是 `key_00/private_key_pkcs8.der`，不是 K70E identity scalar。
3. 完整证书链优先交付 `ordered_certificate_chain.der`，同时可附 PEM 版方便查看。
4. 任何交付前必须再看 `chain_summary.json` 中 `ctf_no_not_approved=true`。

## 1. 成功目录

```text
RUN=<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot
```

不要对该目录里的证据文件做任何写入。目前它包含 45 个 0600 普通文件，所有目录为 0700。

## 2. 私钥在哪里

### 2.1 题目要的新软件私钥

```text
$RUN/key_00/private_key_pkcs8.der
```

完整绝对路径：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/key_00/private_key_pkcs8.der
```

属性：

```text
format  canonical unencrypted PKCS#8 DER
curve   P-256 / secp256r1
mode    0600
size    138 bytes
sha256  58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
```

对应公钥：

```text
$RUN/key_00/public_key_spki.der
sha256 1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

### 2.2 K70E identity scalar（另一份秘密）

它用来签 outer request，不是本次新生成的软件 key：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
mode    0600
size    32 bytes
sha256  ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c
```

对应 identity SPKI：

```text
.../identity/cdi_leaf_public_spki.der
sha256 64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

不要混淆：

```text
K70E identity SPKI  64c672...ba4ad2
software key SPKI   1e5ec6...84bc67
Google leaf SPKI    1e5ec6...84bc67
```

## 3. 证书在哪里

### 3.1 完整四证书链

DER：

```text
$RUN/chain_00/ordered_certificate_chain.der
size    2486 bytes
sha256  423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
```

PEM：

```text
$RUN/chain_00/ordered_certificate_chain.pem
size    3593 bytes
sha256  c63a4e76d3af5cc6f857ca6bbf102f5a63d2755aab3a088ba39a5e7045defc34
```

### 3.2 只要单张 leaf 时

DER：

```text
$RUN/chain_00/ordered_cert_00.der
size    565 bytes
sha256  b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180
```

PEM：

```text
$RUN/chain_00/ordered_cert_00.pem
```

不建议只交 leaf；赛事验收应同时保留四张完整 Google 链。

## 4. 身份数据在哪里

本次用的 modified K70E 身份源请求：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/native_trigger_csr.cbor
size    2534 bytes
sha256  c8f7eb8d20474a549aa73a301a8ca1780586853c057e9b5421307057f8566b47
```

本次实际送给 Google 的新请求：

```text
$RUN/certificate_request.cbor
size    2611 bytes
sha256  f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303
```

本 run 中拆出的可复核身份组件：

```text
$RUN/verified_modified_dice.cbor  # [registered UDS, five DICE entries]
$RUN/verified_uds_certs.cbor      # 1-byte empty top-level UdsCerts map
$RUN/clean_device_info.json
$RUN/challenge.bin
```

`verified_uds_certs.cbor` 不是 registered UDS；它只是请求顶层空
`UdsCerts={}` 的持久证据。registered UDS 位于
`verified_modified_dice.cbor[0]`，其后才是五个 DICE entry。

只交一个 32-byte scalar 无法让审计者验证它与 DICE leaf 的关系。完整身份交付应包含源 CSR、实际请求、registered UDS + DICE、空顶层 UdsCerts、DeviceInfo 和关系审计，scalar 只通过私密渠道提供。

## 5. 最快只读验收

在终端中：

```bash
RUN='<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot'
jq . "$RUN/FINAL_RESULT.json"
jq . "$RUN/REQUEST_AUDIT.json"
jq . "$RUN/key_00/key_summary.json"
jq . "$RUN/chain_00/chain_summary.json"
```

应看到：

```text
FINAL_RESULT.status                         PASS_CLEAN
ctf_no_not_approved                        true
not_approved_hit_count                     0
provisioning_info_parse_error_count        0
certificate_chain_count                    1
certificate_count                          4
software_private_spki_equals_leaf_spki     true
root_matches_pinned_google_root            true
REQUEST_AUDIT.keys_to_sign_count           1
REQUEST_AUDIT.all_five_dice_signatures...  true
REQUEST_AUDIT.outer_leaf_signature...      true
```

## 6. 不读私钥内容的文件验收

```bash
stat -f '%Sp %Su:%Sg %z %N' "$RUN/key_00/private_key_pkcs8.der"
shasum -a 256 "$RUN/key_00/private_key_pkcs8.der"
shasum -a 256 "$RUN/chain_00/ordered_certificate_chain.der"
shasum -a 256 "$RUN/certificate_request.cbor"
```

不要执行：

```text
cat/xxd/hexdump/base64 private_key_pkcs8.der
cat/xxd/hexdump/base64 google_rkp_sw_cdi_leaf_p256_scalar.bin
set -x
```

对私钥的正确验收是派生公钥哈希和证明持有性，而不是把私钥打印出来。`key_summary.json` 明确记录 PoP；独立审计 JSON 记录 private-derived SPKI、请求 sole key 与 Google leaf SPKI 的三方关系。

## 7. 独立 Provisioning Info 验收

```bash
PY='<PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python'
AUDIT='<CODEX_HOME>/skills/k70e-rkp-ctf/scripts/audit_provisioning_info.py'
"$PY" "$AUDIT" "$RUN/chain_00/ordered_certificate_chain.der"
```

预期结果：

```text
PASS
certificates=4
ctf_no_not_approved=true
not_approved_hit_count=0
parse_error_count=0
```

解码必须包含：

```text
5/1 = "APPROVED"
5/2 = "acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"
```

## 8. 交付清单

最小私密交付：

```text
[identity]
google_rkp_sw_cdi_leaf_p256_scalar.bin
native_trigger_csr.cbor

[software key]
key_00/private_key_pkcs8.der
key_00/public_key_spki.der

[request]
certificate_request.cbor

[certificate]
chain_00/ordered_certificate_chain.der
chain_00/ordered_certificate_chain.pem

[proof]
FINAL_RESULT.json
REQUEST_AUDIT.json
key_00/key_summary.json
chain_00/chain_summary.json
K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_INDEPENDENT_AUDIT.json
```

如果赛事系统只允许三个上传项，可对应为：

1. 身份数据压缩包：scalar + source/request + verified registered UDS/DICE + empty top-level UdsCerts evidence + DeviceInfo + audit；
2. 私钥：`private_key_pkcs8.der`；
3. 证书：`ordered_certificate_chain.der`。

上传前根据赛事具体格式要求决定是否转 PEM，但不应重新生成私钥或重新向 Google 签发。

## 9. 绝对不要做

- 不要重跑 `run_k70e_modified_dice_clean_deviceinfo_once.py --execute-google-once`。
- 不要删除 `.k70e_google_rkp_hybrid_clean_di_ledger` 中的 claim。
- 不要为了确定三个 DeviceInfo 中的单一字段而继续消耗 Google 签发。
- 不要用旧 `K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244` 冒充本次成功包。
- 不要把手机已经修好写进报告；本次没有修手机。
- 不要宣称赛事方已接收；目前有的是 Google/密码学/PI 成功证据。

## 10. 另一台 K70E 怎么复现

另一台 K70E 不能复制这台机的 UDS、identity scalar、软件私钥或证书。它需要：

1. 自己的 native zero-key CSR，其中有该机注册 UDS 和完整 DICE。
2. 该机最终 DICE leaf 对应的 P-256 scalar，必须用公钥 SPKI 精确匹配证明。
3. 该型号/固件已知 Google-approved 的完整 DeviceInfo，保留类型；相同固件的 `vbmeta_digest` 可作为候选基线，但要在离线比对后才使用。
4. 一把在该次授权边界内新生成的软件 P-256 私钥。
5. 联网前先证明 DICE 5/5 签名、outer 签名、UDS exact match、scalar-to-leaf 和 software-key 关系。
6. 仅一次 fetch + sign，保存 raw evidence，签发后扫描全链 PI。

本次最重要的可移植知识是：不需要先拿到更底层 UDS/root seed 才能使用 proper-DICE；只要拿到与当前完整 DICE leaf 匹配的最终 scalar，就能给 outer request 签名。服务端是否批准则取决于它看到的整体 profile 和一致性，不是“字段看上去越安全越好”。

## 11. 阅读顺序

1. 文档 65：完整流水线和原始证据。
2. 本文档 66：路径、验收和交付。
3. 文档 67：坑和故障树。
4. 文档 68：正式根因报告。
5. 文档 69：Skill v3 和下一位 AI 的接手规则。
6. 文档 70：证据 SHA-256 清单。
