# K70E CTF clean DeviceInfo `APPROVED` 完整流水线记录

> 日期：2026-09-06（Asia/Taipei）  
> 成功时间：2026-09-06 19:59:57–20:00:00（Asia/Taipei）  
> 对象：Redmi K70E / `duchamp` / 参考机身份  
> 结果：证据分类 `PASS_CLEAN_HYBRID`（程序原始状态 `PASS_CLEAN`）/ Google 四证书链 / Provisioning Info `APPROVED` / `NOT_APPROVED=0`  
> 2026-09-07 更新：正式冻结提交候选和专用离线校验器已完成，见文档 71；赛事方接收仍待回执。  
> 实验性质：主机端一次性、语义上 hybrid 的根因实验；未操作手机，未调 Binder，未刷机，未重启。  
> 秘密边界：本文只记录秘密文件路径、大小、哈希和公钥关系，不记录 CDI Leaf scalar 或软件私钥字节。

---

## 0. 一页结论

本轮已经实际向 Google RKP 生产端点提交了一个精确受控请求：

```text
2026-09-05 modified 请求的注册 UDS
  + 同一 modified 请求的完整五层 DICE（原样）
  + 当前 modified DICE Leaf 对应的 P-256 私钥 scalar（只用于 outer 签名）
  + 2026-08-29 历史 Google-approved K70E 请求的完整 DeviceInfo
  + google-rkp-sw 新生成并先于联网保存的一把 P-256 软件私钥
  + 本次 fetchEekChain 返回的 challenge/EEK
```

Google 结果：

```text
fetchEekChain       HTTP 200
signCertificates   HTTP 200
certificate chains 1
certificates       4
leaf PI             {1:32, 3:"Xiaomi", 5:{1:"APPROVED", 2:"acaa9258...b6e9"}}
NOT_APPROVED hits   0
PI parse errors     0
ctf gate            true
```

因果结论：

- 这套 exact modified 五层 DICE 不是触发 `NOT_APPROVED` 的充分条件。
- 旧失败与本次成功之间的设备审批输入差异已收窄到 DeviceInfo 的三项：`vb_state`、`bootloader_state`、`vbmeta_digest`，或 Google 对它们的一致性规则。
- 三项是同时替换的，因此不能把本次写成“严格证明只有 `vbmeta_digest` 单字段负责”。
- 但 Google 返回的 `APPROVED` 块在字段 `5/2` 精确回显了 clean `vbmeta_digest=acaa9258...b6e9`，所以 digest/身份一致性是最强线索。
- 本次同一 modified DICE 能够获批，也排除了“这个身份当前因尝试次数过多而被统一风控”的解释。

## 1. 实验要回答的问题

旧包的 Provisioning Info 为：

```text
{1:32, 3:"Xiaomi", 5:{1:"NOT_APPROVED"}}
```

当时同时存在两类差异：

1. DICE 第 1、2、4 层的 measurement/security claim 与历史 approved 请求不同，并导致后续公钥、issuer/subject 级联变化。
2. signed DeviceInfo 有三个字段不同。

所以原有样本只能说“环境差异相关”，无法回答下列问题：

- Google 是否因为 modified DICE 的 hash 直接拒绝？
- 是否只要使用 clean DeviceInfo，保留 modified DICE 也能获批？
- 当前 `0xdd934:x26` 提取值是否已经足够供 `google-rkp-sw` 签 outer request，还是必须再提取更底层 seed？
- `count=32` 是否就是次数风控？

本次用最少一次 Google 提交同时回答了前三个问题，并再次用干净 `count=32` 反例排除了第四个假设。

## 2. 作业范围和安全边界

本次执行范围：

| 动作 | 是否发生 |
|---|---:|
| 读取已保存的 K70E 请求/身份文件 | 是 |
| 主机生成一把新 P-256 软件私钥 | 是 |
| Google `fetchEekChain` | 1 次 |
| Google `signCertificates` | 1 次 |
| 自动重试 | 否 |
| HTTP 重定向 | 否 |
| 连接手机/ADB/Fastboot | 否 |
| 调用真机 Binder | 否 |
| 刷写分区 | 否 |
| 重启手机 | 否 |

手机当时的恢复/AVB 问题并未被本次修复。这不影响已完成的 host-only Google 发行证据，但若以后要求 fresh fully-stock same-run provenance，仍须单独处理手机恢复。

## 3. 执行程序和冻结身份

执行程序：

```text
02_脚本与补丁/run_k70e_modified_dice_clean_deviceinfo_once.py
size    39963
sha256  116a47dd00421896e9526c1816a441fc30c521335436678707e613b2fdc89767
```

主要依赖的本地 `google-rkp-sw` 核心：

```text
third_party/google-rkp-sw/rkp_sw.py
size    193161
sha256  619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822
repo HEAD 8a74e55...
```

实际执行权威是文件哈希，不是仅依赖 Git commit，因为工作树的 `rkp_sw.py` 包含本项目严格门禁修改。

## 4. 两个源请求

### 4.1 modified 身份/DICE 源

```text
03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/native_trigger_csr.cbor
size    2534
sha256  c8f7eb8d20474a549aa73a301a8ca1780586853c057e9b5421307057f8566b47
```

从该请求使用：

- 注册 UDS；
- 完整五层 proper-DICE；
- 与本请求 leaf 匹配的当前 P-256 identity scalar；
- 作为旧 modified DeviceInfo 对照。

当前 identity leaf SPKI SHA-256：

```text
64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

scalar 派生公钥与 modified DICE 最终 leaf 精确匹配。这证明它是最终 leaf 的签名私钥 scalar，不是通用的最底层 UDS/raw CDI seed。

### 4.2 clean DeviceInfo 源

```text
03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/certificate_request.cbor
size    2611
sha256  f03011311dca791fccca64f1f78323ba113197f56ac368fbdeeb97162c3ccf56
```

该历史请求有 Google-approved 对照证书。本次只使用它的完整 signed DeviceInfo 值和类型，没有使用它的 clean leaf 私钥，也没有用它的 clean leaf 签名 outer request。

clean leaf SPKI SHA-256：

```text
0684d469c8afecf9d1a7a86cfc67e4996f2712d5edfcfed80745eeb105b1130b
```

它与本次 outer identity leaf `64c672...` 不同。

## 5. DeviceInfo 精确差分

clean/hybrid DeviceInfo 共14个字段：

| 字段 | 值 |
|---|---|
| `brand` | `Redmi` |
| `manufacturer` | `Xiaomi` |
| `product` | `duchamp` |
| `device` | `duchamp` |
| `model` | `<DEVICE_SERIAL>` |
| `fused` | `1` |
| `security_level` | `tee` |
| `os_version` | `160000` |
| `system_patch_level` | `202606` |
| `boot_patch_level` | `20260201` |
| `vendor_patch_level` | `20260201` |
| `vb_state` | `orange` |
| `bootloader_state` | `unlocked` |
| `vbmeta_digest` | 32-byte `acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9` |

与 modified DeviceInfo 相比，仅三项变化：

| 字段 | modified/NOT | clean/hybrid/APPROVED |
|---|---|---|
| `vb_state` | `green` | `orange` |
| `bootloader_state` | `locked` | `unlocked` |
| `vbmeta_digest` | `b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744` | `acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9` |

CBOR 规范化哈希：

```text
modified DeviceInfo canonical CBOR
82e42dd801204a814823be7f14a5912501dc5ffee4c0323c748e5618eaecd1ad

clean DeviceInfo canonical CBOR
19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921
```

注意：`clean_device_info.json` 是 JSON 表示，文件自身 SHA-256 为 `843cddbba747228feb1f3ccaf319f6cf1d660d5824380f7413815e9270994336`，不应与上述 canonical CBOR 哈希混用。

## 6. DICE 精确保留和对照

本次保存的 DICE：

```text
verified_modified_dice.cbor
size    2125
sha256  842b5124721d07b84291c8e95406801f0bf88bb7ba0066ee740a42ceaa1d21ea
```

严格检查：

- proper-DICE entry count = 5；
- 5/5 DICE 签名逐级验证通过；
- 完整 DICE 与 modified 源请求逐字节一致；
- 注册 UDS 与 modified 及 clean 源请求一致；
- 本次 outer 签名由当前 modified leaf scalar 完成并验证通过；
- 没有修改、伪造或重签任何 DICE hash。

与历史 clean DICE 相比：

- 完整 payload 5/5 不同，因为前级身份公钥变化会级联改变 issuer/subject/subject key；
- measurement/security 真正不同的是第 1、2、4 层；
- 第 3、5 层的 measurement/security/code claim 相同，但完整 payload 仍因身份链不同而不同。

### 6.1 五层哈希附表

| 层 | modified/hybrid payload SHA-256 | measurement SHA-256 | security SHA-256 | code-hash claim SHA-256 |
|---:|---|---|---|---|
| 1 | `ff2572c3f3f1aec6a0495f555c100784cdf7ce5bf87457b359a7b81fc468607c` | `7735927281593d3c05d2cf49285549d2b92b61263792b5e02285a1938d8bd5a9` | `d57ac0c4e30fb7989c83b1a4cd8822e086f09ee6217aaa4272a4007d4fca43c1` | `332111300009a42d3acad550d52d7fc991631bc55c009fde0f2a50d80d73da3f` |
| 2 | `8c16ea83be8fe7e89cef273b82dff14730655c38d67d7c91eb32a653f79d602b` | `4a1c1a41effb9f2196d5c8e78be0477582d8e43af6da46bf67a8c0e96699a214` | `2f7c288ba2a5113e86bd7fcf2057f83fc33491f0736a1f64a0faadb0d80f7e9f` | `95b9b181e6e6188aa6a9f4d41132736d51f95cc84721a5a6881869ca81b1a596` |
| 3 | `e4a61de8ee2140aafe17d4773d52bdf5ec6faae93971d21667cf6f20b4d0eec7` | `e4871ba986a51e9c12231a02808b5b0f12ee57d66172a3ef0d6e0d772eb1b1c7` | `79c2db5f14814cee50916fe5091fa39609f3672c51856a5b8c3d84771149f43c` | `1fc37a350b57c482b74a108af609bb42964fba907a2816bcde9412adc4c5729b` |
| 4 | `0966b679d13f64dbb2b4b4084fb60fd52316812523f78d6be072cf79bc33a708` | `c480c701a0697c71daf3499d8cc99bd3d0f29ba10cab10e3cfa171adf5468145` | `29fb04515c75e0c8e90bee323310c196c655bd2b8e0a34c620ef07c9f3013b96` | `25a897343462a1f482f0c076c635c7b6ac8e51f745df0394dd220cd55223af66` |
| 5 | `850b48eb3502ad2bcc938b8c1da364dda857d80d7931b45f498aed3c83cf569e` | `8a31a5f1414333bab96cafc460c4e2bd96dc4c2e9c09214500d3582e08af6bba` | `7ccb65d24fdd02146cec2e2e952fad5a53e818833d108a4c9308c522e53e7f77` | `f3e70c4c0514a7f5da48942e69318e90b8be3a1bb551654f16890f48e9ae7405` |

该表用于证明本次送出的就是旧失败环境的 exact DICE，不能被解读为“所有可能的 DICE 差异都不影响 Google 政策”。

## 7. 新软件私钥

本次 `google-rkp-sw` 新生成一把 secp256r1/P-256 私钥：

```text
key_00/private_key_pkcs8.der
format  canonical unencrypted PKCS#8 DER
mode    0600
size    138
sha256  58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
```

公钥：

```text
key_00/public_key_spki.der
mode    0600
size    91
sha256  1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

关系门：

```text
私钥派生 SPKI == 保存的软件 SPKI         true
软件 SPKI == 请求中唯一 KeysToSign 公钥      true
软件 SPKI == Google 返回的 leaf SPKI               true
软件 SPKI != K70E DICE identity leaf SPKI              true
新 nonce 私钥持有性签名验证                         true
私钥在联网前写盘并 fsync                         true
私钥字节打印到终端/报告                           false
```

这把软件私钥才是题目要求的“本次 `google-rkp-sw` 生成的私钥”。它与用于签 outer request 的 K70E identity scalar 是两把不同的钥匙。

## 8. 请求结构和离线门

请求文件：

```text
certificate_request.cbor
size    2611
sha256  f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303
```

语义展开如下。真实 outer `COSE_Sign1` 的 payload 是 canonical CBOR
`[challenge bstr, CSRPayload canonical-CBOR bstr]`，不是直接嵌套的对象：

```text
AuthenticatedRequest v1
  [ version=1,
    UdsCerts={},
    DiceCertChain=[registered UDS, five ES256 DICE entries],
    outer COSE_Sign1(
      payload=CBOR([Google challenge bstr,
                    canonical-CBOR(CSRPayload=[3, "keymint",
                      clean DeviceInfo,
                      [one new software P-256 COSE key]]) bstr])) ]
```

离线预检：

| 项目 | 结果 |
|---|---:|
| modified DICE exact match | PASS |
| registered UDS exact match | PASS |
| proper-DICE entries | 5 |
| DICE signatures | 5/5 PASS |
| current scalar -> modified leaf SPKI | PASS |
| outer leaf signature | PASS |
| clean DeviceInfo exact value/type match | PASS |
| KeysToSign count | 1 |
| software key differs from identity leaf | PASS |
| challenge SHA-256 | `70451453a549999e66ec652d77c770e7f8edeab15dd53cd78a543c7d25e39219` |

## 9. 一次性账本和网络时间线

全局独占 claim：

```text
<PROJECT_ROOT>/.k70e_google_rkp_hybrid_clean_di_ledger/
  MODIFIED_DICE_CLEAN_DEVICEINFO_ONCE.CLAIM.json
mode    0600
sha256  e9c7cf433d4d313779ff4b8b8291845a9c3c2d7f29cad00d88fc63a5c76a1149
status  CONSUMED_NO_RETRY
```

时间线（UTC / 台北 +08:00）：

| 事件 | UTC | Asia/Taipei |
|---|---|---|
| run created | 11:59:57.115 | 19:59:57.115 |
| global claim | 11:59:57.117 | 19:59:57.117 |
| fetch marker | 11:59:57.118 | 19:59:57.118 |
| fetch HTTP 200 Date | 11:59:59 | 19:59:59 |
| sign marker | 11:59:59.759 | 19:59:59.759 |
| sign HTTP 200 Date | 12:00:00 | 20:00:00 |
| SUCCESS | 12:00:00.686 | 20:00:00.686 |

网络证据：

| 调用 | 请求大小 / SHA-256 | HTTP | 返回大小 / SHA-256 |
|---|---|---:|---|
| fetchEekChain | 101 B / `fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2` | 200 | 699 B / `b4eb4e924d406be2355e5ba14c3ab5b47c8a85473b21c6dc1e63cce3fd44d250` |
| signCertificates | 2611 B / `f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303` | 200 | 2494 B / `9cc11011bb67258487a7a3cc3b23bcb36f996839c6770e169c6adec2891cb939` |

两个 POST 各一次，无自动重试，无重定向，单次 timeout 20s；请求和 NETWORK_STARTED marker 在 POST 前持久化。没有 429、`Retry-After`、quota 或 abuse 信号。

## 10. Google 证书链

共返回 1 条链、4 张证书，有序 DER 链：

```text
chain_00/ordered_certificate_chain.der
size    2486
sha256  423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
```

| 序号 | 角色 | DER size | DER SHA-256 | 有效期 UTC |
|---:|---|---:|---|---|
| 0 | leaf / `O=TEE` | 565 | `b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180` | 2026-09-04 12:00:30 → 2026-09-16 14:47:51 |
| 1 | Droid CA3 | 755 | `12642d51c5a0f2900625517363d78758bbf905a4609bc1463cf8589bcedb97fd` | 2026-09-05 15:50:55 → 2026-11-14 15:50:54 |
| 2 | Droid CA2 | 616 | `187521be8eec99791aa793ab339172a67f05b1ec1d1259adbe6d5fe7d7f5d43b` | 2026-02-09 20:01:11 → 2029-02-08 20:01:11 |
| 3 | Key Attestation CA1 root | 550 | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` | 2025-07-17 22:32:18 → 2035-07-15 22:32:18 |

链验证：

```text
strict DER fully consumed                  true
unique connected leaf-to-root path         true
all child signature links                  true
root self-issued and self-signature valid  true
pinned Google root DER                     true
pinned Google root SPKI                    true
all certificates valid at audit time       true
```

根公钥 SPKI SHA-256：

```text
3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec
```

leaf 有效期长度：`1046841` 秒，约 `12.116` 天。

## 11. Provisioning Info 精确结果

OID：

```text
1.3.6.1.4.1.11129.2.1.30
```

仅 leaf 存在该扩展；非 critical；原始 CBOR 91 B，SHA-256：

```text
8a28b6caee0213767426c60bacb6e9fae9ad064fbe24d18449583fea2041dab7
```

精确类型解码：

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

审计结果：

```text
parsed_extension_count      1
parse_error_count           0
not_approved_hit_count      0
ctf_no_not_approved         true
```

`android_schema_current_strict=false` 仅表示真实 Xiaomi 扩展不符合一个窄化公开 schema 诊断；它不是本 CTF 的拒绝门。真正的硬门是全链无 `NOT_APPROVED`，该门已通过。

## 12. 三路独立复核

完成了三路只读复核：

1. 请求组成、DICE/outer 签名、DeviceInfo/UDS exact match、软件公钥关系。
2. 全局 one-shot claim、两次 NETWORK_STARTED、原始请求/返回/marker 哈希一致性，无未知传输状态。
3. 不依赖运行器结论的私钥派生公钥、CSR key、Google leaf、四证书链、根 pin 和 Provisioning Info 重验。

独立审计产物：

```text
03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_INDEPENDENT_AUDIT.json
mode    0600
size    6198
sha256  473cac82fa8282bbc9f755aba53d7d1d132f9160273fbaefd8a16a7a3e1e4b0c
```

源 run 在独立审计前后保持：45 个普通文件，总大小 48916 B，路径/大小/哈希规范 manifest SHA-256 `ac7a5c696d6861bbce79cd7c8aefd82137ff0f97d3d5a75ac8c07bf2cc29109d`。所有目录 0700，所有文件 0600，无 symlink、special file 或多硬链。

## 13. 证明了什么，没证明什么

### 13.1 已证明

- 当前 K70E final DICE leaf scalar 可以直接作为 `google-rkp-sw` P-256 outer signing identity；无需为本目标再去提取更早 UDS/root seed。
- exact modified five-layer DICE + clean historical same-K70E DeviceInfo 能获得 Google `APPROVED`。
- DICE 第 1/2/4 层的这组已知差异不会单独必然导致 `NOT_APPROVED`。
- 新软件私钥、请求公钥、Google leaf 是同一把钥匙，且与 identity leaf 不同。
- `count=32` 可以出现在干净 APPROVED 证书中，不能把它等同于风控拒绝。
- 本次 Google 返回了完整有效四证书链，全链无 `NOT_APPROVED`。

### 13.2 尚未单独证明

- 三个 DeviceInfo 字段中究竟是一个、两个还是组合规则决定。
- 不能从一次成功泛化为“Google 完全不看任何 DICE”。
- 本地 one-shot marker 不是 Google 签名的防重放回执。
- 该 run 自标 `research_only_semantically_hybrid=true`；它已通过 Google/密码学/Provisioning Info 门，但截至本文没有赛事方对这一新包的最终回执。
- 它不是 fresh stock same-run DeviceInfo+DICE 包，也没有 `POSTBOOT_VERIFIED.json`。如果赛事额外要求 fully-stock provenance，仍须走 stock-log 支线。

## 14. 成功运行目录和三件套

成功 run：

```text
<PROJECT_ROOT>/
  <DEVICE_WORKSPACE>/03_提取结果/
  K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot
```

题目三件关系对应：

1. K70E 身份：modified source CSR + exact registered UDS/five-layer DICE + 与 leaf SPKI 匹配的 identity scalar。identity scalar 仍保存在原身份目录，不复制到本 run。
2. `google-rkp-sw` 新软件私钥：`key_00/private_key_pkcs8.der`。
3. 该私钥对应 Google 证书链：`chain_00/ordered_certificate_chain.der` 或 PEM 版。

关键审计：

- `FINAL_RESULT.json`
- `REQUEST_AUDIT.json`
- `key_00/key_summary.json`
- `chain_00/chain_summary.json`
- run 外独立审计 JSON。

## 15. 不可重跑和后续决策

这个 one-shot 已消耗。不得：

- 删除或改写 global claim；
- 换新目录重放相同实验；
- 为了逐字段好奇再浪费 Google 签发次数；
- 把本次生成的私钥字节贴入文档、聊天、Git 或公开网盘；
- 把旧 `NOT_APPROVED` 包重命名为 PASS；
- 把赛事方尚未给出的最终接收回执伪写为已有。

当前有价值的后续工作是离线整理和赛事提交，不是继续试探 Google。

## 16. 权威结果文件

```text
FINAL_RESULT.json
  sha256 8135d8674e20f5c3ebb0b265f2a31e46af2b4c70c3a8833e7b0d83e0cbaff36f

REQUEST_AUDIT.json
  sha256 9e92b7c7e9a5a4b1f41b3ebfde144e8f50fbc089494861b6f854dc2a17970b9f

chain_00/chain_summary.json
  sha256 358b5269c517a29fc2cc0731375a14deadd038336fc029b96ff3c9be9928a9e6

SUCCESS.json
  sha256 54d69f9ea17cb1020ad889bdd44e7a378b5f749946406f4ebfc36165d2b27839
```

完整文件级 SHA-256 见文档 70。
