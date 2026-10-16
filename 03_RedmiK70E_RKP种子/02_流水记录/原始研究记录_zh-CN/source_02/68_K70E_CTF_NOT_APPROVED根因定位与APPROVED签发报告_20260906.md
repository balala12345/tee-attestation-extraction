# K70E CTF `NOT_APPROVED` 根因定位与 `APPROVED` 签发报告

> 报告日期：2026-09-06  
> 报告结论：问题已从泛化的“启动环境/DICE 污染”收窄到 signed DeviceInfo 的三个字段或它们的服务端一致性规则。  
> 处理结果：原样 modified five-layer DICE + clean historical K70E DeviceInfo 获得 Google `APPROVED` 四证书链，并保存了 `google-rkp-sw` 新生成的对应软件私钥。  
> 报告边界：这是 `research_only_semantically_hybrid` 的 Google/密码学/PI `PASS_CLEAN_HYBRID` 候选（程序原始状态 `PASS_CLEAN`）；没有伪造赛事方尚未给出的最终接收回执。

---

## 1. 执行摘要

旧提交包的密码学链、私钥和 leaf 公钥关系均正常，但 Google-signed leaf 的 Provisioning Info 明确包含：

```text
{1:32, 3:"Xiaomi", 5:{1:"NOT_APPROVED"}}
```

赛事方因此不接受。

项目前期把原因归结为 patched preloader/LK/TEE 对 DICE measurement 的影响，并转向 fully-stock 恢复。该恢复又因 OrangeFox `vendor_boot_a` 和 Magisk `init_boot_a` 与 stock `vbmeta_a` 的双重 AVB mismatch 导致 `the system has been destroyed`，stock Fastboot 写入被 lock control 拒绝，BROM 授权也未进入 DA。

然而，“DICE 变了”与 `NOT_APPROVED` 只是在同一失败环境中同时发生，并没有被单独隔离。新实验保留 exact modified DICE，只把 DeviceInfo 整体换成历史 approved 值，结果 Google 明确返回：

```text
{1:32, 3:"Xiaomi", 5:{1:"APPROVED", 2:"acaa9258...b6e9"}}
```

这一结果改写了本项目的核心判断：

- modified DICE 不是本次 `NOT_APPROVED` 的充分原因；
- 当前 final DICE leaf scalar 已足够供 `google-rkp-sw` 完成 outer 签名；
- 不需要为完成当前 CTF 再提取更底层 UDS/root seed；
- 修正重点是 signed DeviceInfo 与已注册 K70E profile 的一致性。

## 2. 事件时间线

| 时间 | 事件 | 结论 |
|---|---|---|
| 2026-08-29 | K70E native request 获得历史 clean Google 证书 | 保留了 approved DeviceInfo/UDS/DICE 对照 |
| 2026-09-05 | patched route 提取 final leaf scalar，完成 host `google-rkp-sw` 签发 | 密码学关系通过，但 PI=`NOT_APPROVED` |
| 2026-09-06 | 独立 PI 审计确认旧包不可提交 | 旧 PASS 结论作废 |
| 2026-09-06 | 对比 native modified 和 host modified | 两者均 NOT，排除单纯 host framing |
| 2026-09-06 | 排查 count=32/HTTP 200 | 无 429/quota/abuse，干净 count-32 对照存在 |
| 2026-09-06 | 尝试 stock/CN304 恢复 | 恢复合同有误，双 AVB mismatch；设备恢复与 CTF 根因实验分离 |
| 2026-09-06 19:59:57 | 启动 one-shot hybrid 实验 | 无手机/ADB/Binder/刷写/重启 |
| 2026-09-06 19:59:59 | fetchEekChain HTTP 200 | challenge/EEK 保存 |
| 2026-09-06 20:00:00 | signCertificates HTTP 200 | 唯一 4-cert chain |
| 2026-09-06 20:00:00 | 审计完成 | `PASS_CLEAN_HYBRID`（raw `PASS_CLEAN`）, PI `APPROVED`, NOT=0 |
| 2026-09-06 20:04:49 | 独立复核 | 请求、私钥关系、链和 PI 全部重验通过 |

## 3. 事故症状

旧包：

```text
03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244
leaf SHA-256  8d1eeefd7ad252ec78c53859be595b935faa2cdb5f1bff597f6a817351d22553
PI raw SHA    be1579a137030a4b5ac21f7538a43f6d64c317a3c03ec8f390cbb0f3241de393
PI hit path   $/5/1
verdict       REJECTED_NOT_APPROVED
```

这个包仍必须保留为 negative fixture，不得修改证书扩展、不得删字段、不得用新报告将它重命名为 PASS。

## 4. 假设和排除过程

### 4.1 假设 A：签发尝试过多/风控

排除证据：

- 多张历史 clean 证书同样 `count=32`；
- 旧失败请求 HTTP 200，无 429/quota/abuse；
- 本次使用同一 modified UDS/DICE/final-leaf identity 获得 APPROVED，且仍 `count=32`。

结论：`count=32` / 当前 identity 被统一封锁这一简单解释，在本次运行中被排除；这不泛化为 Google 不存在其他 rate/risk 策略。

### 4.2 假设 B：host `google-rkp-sw` 模拟请求不被认可

排除证据：

- 旧 native Binder 和 host software 请求在同一 modified profile 下都返回 NOT；
- 本次 host `google-rkp-sw` 组包获得 APPROVED。

结论：host 组包本身不是拒绝原因。

### 4.3 假设 C：当前 final leaf scalar 层级太晚，Google 必须要更底层 seed

排除证据：

- scalar 派生 SPKI 精确等于 modified DICE 最终 leaf；
- 该 scalar 成功签署 outer request；
- Google 验证并返回 APPROVED 链。

结论：它不是最底层 seed，但是当前 proper-DICE request 所需的 final leaf signing scalar，对本 CTF 已足够。

### 4.4 假设 D：modified DICE hash 本身必然导致 NOT

排除证据：

- 本次 DICE 与 modified 源逐字节一致；
- 五层签名全部有效；
- 同一 DICE + clean DeviceInfo 获 APPROVED。

结论：这套 modified DICE 不是充分拒绝条件。

### 4.5 假设 E：DeviceInfo 无关，用默认值就行

排除证据：

- generic/default degenerate 试验返回 HTTP 444 `DeviceNotRegisteredError`；
- modified DeviceInfo 与 NOT 对应；
- clean DeviceInfo 与 APPROVED 对应；
- APPROVED PI 回显 clean vbmeta digest。

结论：DeviceInfo 是服务端 profile 评估的关键组成，不能当作可任意默认的装饰数据。

## 5. 差分实验设计

为了不继续刷机或修复手机，也为了不浪费多次 Google 签发，选择了一个直接的输入交叉：

| 部分 | 来源 | 目的 |
|---|---|---|
| registered UDS | modified 与 clean 共同的 K70E 注册根 | 保持设备根身份 |
| five-layer DICE | 2026-09-05 modified request | 直接测试 modified DICE 是否必然 NOT |
| outer identity key | 当前 modified leaf scalar | 保证与 modified DICE leaf 匹配 |
| DeviceInfo | 2026-08-29 historical clean-chain request | 检验 clean tuple 能否改变结果 |
| key to certify | 本次新生成 P-256 key | 满足题目私钥/证书关系 |
| challenge/EEK | 本次 fetchEekChain | 保持官方新鲜请求 |

这不是严格的“只改一个原子字段”实验：DeviceInfo 中三个字段同时恢复，新 challenge、software key、request_id、时间和不透明的服务端状态也会变化。它直接证明 exact modified DICE 不是拒绝的充分原因，并证明 clean DeviceInfo tuple 对该次请求足以获批；它只能把设备控制的 signed approval profile 首要嫌疑收窄到 DeviceInfo 子集，不能排除所有非设备变量。

## 6. 执行与证据保全

运行器使用全局 O_EXCL claim，在第一个 POST 前固化：

- 脚本 SHA-256；
- modified/clean 源请求 SHA-256；
- current identity leaf SPKI；
- 新 software key SPKI；
- 输出目录 device/inode/mode/UID；
- fetch/sign 各 1 次且无重试的网络预算。

每次 POST 之前先保存请求和 NETWORK_STARTED marker，每个 raw response 先保存再解析。完成后全局 claim 为 `CONSUMED_NO_RETRY`，目录有 `SUCCESS.json`，无 `BURNED.json`、`SAFE_ABORT.json` 或未知传输 marker。

## 7. 结果

### 7.1 请求

```text
request SHA-256       f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303
request size          2611
proper DICE entries   5
DICE signatures       5/5 valid
outer signature       valid
KeysToSign            1
```

### 7.2 私钥和 leaf

```text
software private PKCS8 SHA  58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
software SPKI SHA            1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
Google leaf DER SHA          b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180
identity leaf SPKI SHA       64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
private=request=Google leaf  true
software != identity         true
```

### 7.3 证书链

```text
chain count                    1
cert count                     4
ordered chain SHA              423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
all DER bytes consumed         true
signature links                true
root self signature            true
pinned Google root             true
all valid at audit time        true
```

### 7.4 Provisioning Info

```text
{1:32, 3:"Xiaomi", 5:{1:"APPROVED", 2:"acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"}}

NOT_APPROVED hits  0
parse errors       0
CTF gate           true
```

## 8. 根因定级

### 8.1 直接证据支持的设备 profile 首要嫌疑范围

在设备控制的 signed approval profile 内，旧 `NOT_APPROVED` 的首要嫌疑落在下列集合中：

```text
DeviceInfo.vb_state
DeviceInfo.bootloader_state
DeviceInfo.vbmeta_digest
以及/或服务端对三者与已注册 profile 的一致性检查
```

这是强证据范围，不是服务器策略的单变量数学证明。新 challenge、software key、request_id、EEK/时间及服务端状态并未固定；因此只能说 clean tuple 在这一次 observed run 中足够，不能说三字段是全局唯一可能原因。

### 8.2 最强嫌疑项

`vbmeta_digest`，或它与已注册固件 profile 的一致性。理由：Google 在 APPROVED PI 的 `5/2` 中直接回显 clean digest。

### 8.3 不再成立的主根因说法

- “modified DICE hash 必然被服务端拒绝”；
- “final leaf scalar 层级太晚，必须提取 UDS/root seed”；
- “host `google-rkp-sw` 生成的请求不会被认可”；
- “`count=32` 表示已被次数风控”；
- “必须先修好手机/恢复 fully stock 才能获得任何 clean 证书”。

## 9. 核心影响

### 9.1 对 CTF 解题路线

已经有一份同时满足下列关系的候选：

1. K70E identity scalar 可验证匹配 exact DICE leaf；
2. `google-rkp-sw` 新生成且保存的 P-256 软件私钥；
3. Google 为该新私钥公钥签发的四证书链；
4. Provisioning Info `APPROVED`，全链 NOT=0。

主线由“继续修复手机后再碰运气”变为“离线整理已有成功证据并按赛事格式提交”。

### 9.2 对 stock-log 路线

stock-log 不再是得到 Google clean chain 的唯一必要路线，但它仍是下列需求的有价值严格支线：

- fresh fully-stock same-run DeviceInfo+DICE provenance；
- 赛事方若额外拒绝 semantic hybrid；
- 在另一台 K70E 上从头生成自己的身份/私钥/证书。

### 9.3 对手机恢复

手机的双 AVB mismatch、Fastboot lock control 和 BROM 授权问题仍然存在。它们不再是这份已有 hybrid clean chain 的前置，但仍是修好设备或完成 fresh stock recapture 的前置。

### 9.4 对文档和 Skill

文档/Skill 不得再将下列表述当作当前真相：

- 项目没有新软件私钥和 Google chain；
- modified DICE 必然 NOT；
- 唯一解法是恢复 stock；
- 还必须得到更底层 seed；
- Google 请求 one-shot 尚未消耗。

## 10. 交付物

### 成功 run

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot
```

### 软件私钥

```text
.../key_00/private_key_pkcs8.der
```

### 完整证书链

```text
.../chain_00/ordered_certificate_chain.der
.../chain_00/ordered_certificate_chain.pem
```

### 实际 Google 请求

```text
.../certificate_request.cbor
```

### 独立审计

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_INDEPENDENT_AUDIT.json
```

## 11. 限制和保留项

1. DeviceInfo 三个字段同时替换，没有用三次额外签发做单字段 A/B。
2. 本次新生成 software key 和新 challenge 是每次合法请求必然变化的项；它们不是设备审批 profile 字段，但严格实验描述不应隐藏。
3. run 是 semantic hybrid：DICE 和 DeviceInfo 来自同一 K70E 的不同历史环境，不是 fresh same-run stock capture。
4. Google 及本地审计已通过，但赛事方对新包的正式回执尚未记录。
5. 证书有有效期，leaf 截止 2026-09-16 14:47:51 UTC。过期不授权自动重跑签发。
6. 手机未在本次修复，不得将证书成功扩展为设备恢复成功。

## 12. 最终判定

```text
old 20260905 package                    REJECTED_NOT_APPROVED
count=32 / blanket identity block       EXCLUDED IN THIS RUN
host google-rkp-sw incompatibility      EXCLUDED
need for deeper UDS/root seed            EXCLUDED FOR THIS CTF PATH
exact modified five-layer DICE           ACCEPTED IN THIS RUN
clean DeviceInfo tuple                   SUFFICIENT IN THIS RUN
device-profile primary suspect          THREE DEVICEINFO FIELDS / CONSISTENCY
strongest single clue                    VBMETA DIGEST / PROFILE CONSISTENCY
new software private key                 SAVED
Google chain                             1 x 4 CERTIFICATES
Provisioning Info                        APPROVED / NOT=0
crypto and independent audit             PASS
organizer acceptance                     PENDING / NOT RECORDED
phone recovery                           SEPARATE UNRESOLVED TASK
```

本项目的技术核心问题“如何产生无 `NOT_APPROVED` 的 `google-rkp-sw` 私钥+证书链”已实际解决。2026-09-07 已完成正式冻结包和专用离线校验器（见文档 71）；后续主任务是按赛事格式提交并保存回执，不是继续向 Google 试探。
