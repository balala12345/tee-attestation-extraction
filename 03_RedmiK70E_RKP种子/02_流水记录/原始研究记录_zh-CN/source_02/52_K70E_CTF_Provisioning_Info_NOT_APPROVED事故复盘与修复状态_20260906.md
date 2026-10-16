# K70E CTF `Provisioning Info / NOT_APPROVED` 事故复盘与修复状态

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 终态覆盖：**本文的事故样本仍有效，但“modified DICE/measurement 是主拒绝原因、必须 stock recapture 才能得 clean chain”已被新实验推翻。exact modified DICE + clean DeviceInfo 已获 Google `APPROVED`；根因收窄到 DeviceInfo 三项/一致性。见文档 65–70。

> **2026-09-06 18:05 状态覆盖：** 本文保留根因证据，但现场状态与恢复指令已由文档 59–63 覆盖。旧八步恢复已执行后造成 OrangeFox vendor_boot + Magisk init_boot 双重 AVB mismatch；用户已要求暂停，本文不得作为手机操作手册。

> 日期：2026-09-06（Asia/Taipei）  
> 状态：旧提交已判定 **不合格**；stock MiTEE 路线现有 8 组 178/178 离线回归通过；简单次数风控已排除；尚未生成新的无 `NOT_APPROVED` 合格三件套  
> 历史快照（已失效）：下述“ADB 稳定、尚未刷写/重启、按文档 58 执行”只描述恢复前现场，严禁按它操作。当前以文档 59–63 为准；approved-stock 专用 one-shot 未开始，但 generic/default 负实验已有 fetch/sign `NETWORK_STARTED`。  
> 秘密处理：仅记录路径、长度、哈希和公钥关系，不记录任何私钥原文

---

## 0. 必须先纠正的结论

此前冻结包：

```text
03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/
```

虽然满足身份、软件私钥、请求公钥、叶证书公钥和四级链的密码学闭环，但其叶证书的 Google Provisioning Information 扩展中包含：

```text
OID = 1.3.6.1.4.1.11129.2.1.30
CBOR = {1: 32, 3: "Xiaomi", 5: {1: "NOT_APPROVED"}}
命中路径 = $/5/1
```

赛事方不接受该字段，因此这个包不得再标为 CTF PASS，也不得提交。它被保留为失败证据，不能修改证书或重新生成 manifest 来“洗白”。文档 45–51 中原有的 PASS/结题结论只代表旧验证器当时检查过的密码学关系，不代表赛事验收通过。

旧验证器的直接缺陷是：`rkp_sw.py::_provisioning_info()` 只投影已知键 1、3、4，完全丢弃未知键 5；最终验证器又没有独立扫描原始扩展，导致 `NOT_APPROVED` 被静默忽略。

## 1. 当前结论

### 1.1 简单次数/计数风控已被现有样本排除

对 `03_提取结果` 中所有可找到的 DER 证书做去重后的 Provisioning Info 离线普查，结果为：

| 不同 DER 证书数 | 无 `NOT_APPROVED` | 含 `NOT_APPROVED` | 解析失败 |
|---:|---:|---:|---:|
| 27 | 25 | 2 | 0 |

干净样本中有 13 张为 `{1:8,3:"Xiaomi"}`，另有 **12 张为 `{1:32,3:"Xiaomi"}`**。因此 count=32 与认可结果可以同时出现；它不是这两张失败证书的充分解释，也不能当作公开的拒绝码。例证干净 count-32 叶证书 SHA-256 为 `8acd8ff7cebbccbcdfb8e91276a7b1af60a46f6c0e8664613666e165030ae36e`。

两张失败证书对应的 native Binder 请求和 host `google-rkp-sw` 请求都得到 HTTP 200；现有 HTTP 元数据中没有 429、`quota` 或 `abuse`。Android 公共文档把键 1 解释为最近约 30 天内该设备获发证书的近似数量，而不是公开拒绝状态。

结论：**在当前证据集合内，简单尝试次数/键 1 计数风控已经排除；环境/请求语义差异是必须继续追查和修复的主因。** 只有将来出现明确 HTTP 429、`quota` 或 `abuse` 信号时，才暂停新的外部请求。单次返回 `NOT_APPROVED` 只烧毁该 ATTEMPT、禁止盲目重放；它不授权停止离线差分、恢复和修复工作。

### 1.2 不是“host 模拟可以造请求，但真机才会被认可”这么简单

两个相互独立的失败结果含有完全相同的 Provisioning Info 原始 CBOR：

| 路径 | 请求来源 | 请求 SHA-256 | 叶证书 SHA-256 | HTTP | Provisioning Info |
|---|---|---|---|---:|---|
| `K70E_scalar_final_google_provision_20260905_2206` | 真机 `IRemotelyProvisionedComponent/default` Binder `generateCertificateRequestV2` | `139aaad1c4ab10901c6d25114c990f06e7e74c0b537ada399ea4d6b699bcd458` | `bfd4d433a7679db684caecdc5ced1b766a338205abaf75964aa68424378c3b29` | 200 | `{1:32,3:"Xiaomi",5:{1:"NOT_APPROVED"}}` |
| `K70E_google_rkp_sw_provision_20260905_2244` | host `google-rkp-sw`，使用同一套真机 UDS/DICE/DeviceInfo | `029c2bae4fdf94b461ff343d8a67e5106a76d9a3a515dae38e5d5b4953c5f4c4` | `8d1eeefd7ad252ec78c53859be595b935faa2cdb5f1bff597f6a817351d22553` | 200 | 同上 |

原始 CBOR 十六进制和哈希：

```text
a301182003665869616f6d6905a1016c4e4f545f415050524f564544
SHA-256 be1579a137030a4b5ac21f7538a43f6d64c317a3c03ec8f390cbb0f3241de393
```

第一条是真机 TEE/Binder 生成的请求，不是 host 自己拼的模拟请求；其 proper-DICE 五段签名、outer 签名、challenge、MacedPublicKey 都已独立验证。因此，单纯把 host 请求改得“更像真机”不能解决当前问题。

协议侧的共同控制量也一致：三次已保存运行都使用官方 `https://remoteprovisioning.googleapis.com/v1:fetchEekChain`；fetch body 均为 101 字节且 SHA-256 均为 `fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2`；从三份 fetch response 中抽出的 canonical EEK chains 都是 613 字节且 SHA-256 均为 `11dc72f46af10129d6a2584ebbd1c6e44ca2d26322f534606435808da42e9305`。三次 sign 都使用同一官方 `v1:signCertificates` endpoint；完整查询串里的 fresh challenge 和 request_id 按设计不同。由此没有证据把 URL、fetch body、EEK chain 或 host HTTP framing 列为主因。

modified native 与 modified host 请求中的五段 COSE_Sign1 原始 payload 逐字节相同，SHA-256 依次为：

```text
ff2572c3f3f1aec6a0495f555c100784cdf7ce5bf87457b359a7b81fc468607c
8c16ea83be8fe7e89cef273b82dff14730655c38d67d7c91eb32a653f79d602b
e4a61de8ee2140aafe17d4773d52bdf5ec6faae93971d21667cf6f20b4d0eec7
0966b679d13f64dbb2b4b4084fb60fd52316812523f78d6be072cf79bc33a708
850b48eb3502ad2bcc938b8c1da364dda857d80d7931b45f498aed3c83cf569e
```

这意味着 host 路径保留了真机 modified source chain；两者不同的 fresh challenge、outer signature 和待签 key 不改变服务器看到同一套 modified 五层 DICE 的事实。

### 1.3 最强证据指向启动环境/测量态，而非请求编码

已获认可的 2026-08-29 真机 stock 请求与失败请求使用同一台设备的 UDS，但服务器可见的安全测量明显不同：

| 比较项 | 已认可 stock 请求 | 失败的改造环境请求 |
|---|---|---|
| signed DeviceInfo canonical SHA-256 | `19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921` | `82e42dd801204a814823be7f14a5912501dc5ffee4c0323c748e5618eaecd1ad` |
| `vb_state / bootloader_state` | `orange / unlocked` | `green / locked` |
| `vbmeta_digest` | `acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9` | `b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744` |
| 三项 boot-security canonical SHA-256 | `a52531f754137d88cee853bd59804e867560e70bb0d856957e1c5894715cb5e6` | `cf6f1419e802c56bcec2fa1b8bf9ad1c08140540dc7a2c4a3918e4ad677a9efc` |
| CDI leaf SPKI SHA-256 | `0684d469c8afecf9d1a7a86cfc67e4996f2712d5edfcfed80745eeb105b1130b` | `64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2` |
| DICE 第 1 层 CodeHash | stock | 改变 |
| DICE 第 2 层 CodeHash | stock LK/BL2_EXT | Fenrir BL2_EXT，改变 |
| DICE 第 3 层 CodeHash | 相同 | 相同 |
| DICE 第 4 层 CodeHash | stock TEE | patched TEE，改变 |
| DICE 第 5 层 CodeHash/ConfigHash | 相同 | 相同 |
| Google Provisioning Info | `{1:8,3:"Xiaomi"}` | `{1:32,3:"Xiaomi",5:{1:"NOT_APPROVED"}}` |

五层 measurement claims 和 security claims 的逐层相等结果都是：

```text
[false, false, true, false, true]
```

但比较每层完整 COSE_Sign1 payload 原始字节时，五层全部不同：

```text
approved stock
  6d662c12275ea9a0adf35e94e8ba339c0e0a4cc4247cee30289dfc84360dc6ec
  229219105fcb22e2dce684fd424a1d379069e146ef2c75b777d8a08ad4c1de34
  08606b4a703df5252c5d0dc9d57294c0e7722a027b49bf930d303da587c1ff8b
  6b8586445c3c891a8be4026a8384e2a81fd897ac3b217ea9b3c7145ee138f90d
  e4f17a71c000068f62b506d16c0322967b9dd4e58b6cdda9e9e2831fbba72792

modified native = modified host
  ff2572c3f3f1aec6a0495f555c100784cdf7ce5bf87457b359a7b81fc468607c
  8c16ea83be8fe7e89cef273b82dff14730655c38d67d7c91eb32a653f79d602b
  e4a61de8ee2140aafe17d4773d52bdf5ec6faae93971d21667cf6f20b4d0eec7
  0966b679d13f64dbb2b4b4084fb60fd52316812523f78d6be072cf79bc33a708
  850b48eb3502ad2bcc938b8c1da364dda857d80d7931b45f498aed3c83cf569e
```

这里并不矛盾：第 3、5 层的 measurement/security 子集可以相同，但前层改变会使派生 subject key、issuer/subject 等身份字段级联变化，所以完整 signed payload 仍不同。联网门必须同时检查完整五层 payload 与安全 claim，不能只看 `[F,F,T,F,T]` 中的两个 `T`。

进一步的镜像解析已把这些差异对应到实际被测 payload：

- 第 2 层认可值对应 stock `lk_a` 中的 `bl2_ext.bin`，失败值对应 Fenrir `bl2_ext.bin`；
- 第 3 层等于 TEE 镜像顶层 `atf` payload，双方相同；
- 第 4 层认可值等于 stock `tee` payload，失败值等于 patched `tee` payload；
- 第 1 层与 stock/engineering preloader 差异一致。

所以当前最佳解释是：Google 根据 UDS、DICE CodeHash/ConfigHash、完整 signed payload 和 signed DeviceInfo 看到了 engineering preloader/Fenrir/patched TEE 测量态，并给证书加上未公开的拒绝状态。服务端策略仍不可从公开材料完全推导，但现有样本已经排除简单计数/尝试次数解释；在取得新 clean chain 之前，结论只能写“环境/请求差异已定位到具体字段和层，待 approved-baseline fresh-boot 新运行验证”，不能写成赛事修复完成。

### 1.4 “恢复磁盘 stock”不等于“本次 boot 已恢复 stock”

失败运行的证据树说明了一个关键时序坑：启动与捕获早期曾使用 patched TEE、candidate init_boot 和 namespace patched TA。`device_preflight.json` 虽已看到 `tee_a` 磁盘恢复为 stock `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d`，但同一文件仍记录 init_boot 磁盘为 candidate `4d83cd26f02c585dce733f81d05faf38ec5c8f247f89fbaa9fcf46b70d2b4d85`、当前 tee-supplicant mount namespace 中 TA 为 patched `6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0`。后来 `04_postrestore_stock_preflight.json` 再看到 TEE/TA 磁盘回到 stock、init_boot 回到固定的 known-good Magisk 锚，也不能倒转本次开机早期已经完成的 DICE 派生，不能卸载已经进入当前 namespace 的 TA，更不能改变已经签进 AuthenticatedRequest 的 DeviceInfo/DICE。

正确恢复合同是：先让原厂 preloader/LK/TEE/TA 与明确固定的 known-good Magisk `init_boot_a=9d5d12…` 全部回到参考机的 approved-baseline 组合；确认不会在 early boot 再 bind/替换；然后执行一次 **fresh boot**；在这个新 boot 中重新采集 zero-key AuthenticatedRequest，并要求五层完整 payload、measurement/security claims 和 signed DeviceInfo 全部通过 approved baseline 门。这里的 `init_boot` 不是工厂原版；不得把路线名“stock”误读为每个分区都是工厂字节。仅在捕获后把磁盘文件恢复到这组锚，或在同一 boot 中解除 bind，不能使已生成请求获得认可。

注意：键 5 和 `NOT_APPROVED` 的精确定义目前没有在 Android/AOSP 的公开 schema 中找到，不能伪装成已知官方枚举。本文只陈述可复现的相关性和赛事方的明确拒绝，不把推断写成 Google 官方定义。

## 2. 为什么不能直接删字段或改证书

Provisioning Info 位于 Google 签名覆盖的 `TBSCertificate` 内。删掉、重编码或覆盖 `NOT_APPROVED` 会破坏叶证书签名；重新本地签名又不再是 Google 链。RFC 5280 的证书结构决定这不是一个可后处理修复的问题。

唯一合格结果是：使用赛事认可的设备身份/测量态生成新的软件私钥和请求，并由 Google 返回一张原始 Provisioning Info 中没有 `NOT_APPROVED` 的叶证书。

## 3. 已完成的代码修复

### 3.1 `google-rkp-sw` 全量、无损审计

`third_party/google-rkp-sw/rkp_sw.py` 已加入：

- 对每张证书扫描 OID `1.3.6.1.4.1.11129.2.1.30`；
- 保存原始 CBOR 长度和 SHA-256；
- 严格只解一个 CBOR item，拒绝尾随字节；
- 要求原始 CBOR 与确定性 canonical 重编码逐字节相等，拒绝重复 map key、`true`/整数 `1` 等解码后键碰撞及非规范编码，防止 `NOT_APPROVED` 在构造 Python dict 时被后值覆盖；
- 以保留键和值类型的 JSON-safe tree 记录全部字段，不再只挑已知键；
- 递归扫描允许的 map key、map value 和 array 中的精确文本 `NOT_APPROVED`，包括 tuple、FrozenDict 等复合 map key 内部，输出证书索引和路径；
- 对任意显式 `CBORTag` 统一 fail-closed，包括 tag 24 封装的 encoded-CBOR；对 `cbor2` 已自动解码的 tag 258 `set`/`frozenset`、tag 35 `re.Pattern` 及任何其他未列入的 semantic object 同样 fail-closed，不做有损字符串投影；
- 叶证书缺扩展、任一出现的扩展畸形或全链任意位置命中 `NOT_APPROVED` 均令 CTF 门失败；
- 网络返回后先耐久保存原始响应，再解析和判定；失败状态写为 `rejected_provisioning_info`，绝不生成 SUCCESS；
- 软件 P-256 私钥、SPKI、CSR、原始响应、逐张证书和有序链仍按同轮保存，私钥不打印。

两个结论被明确分开：

1. `ctf_no_not_approved`：赛事当前要求的硬门；全链没有 `NOT_APPROVED`，并且 leaf 扩展可解析。
2. `android_schema_current_strict`：按当前公开 Android CDDL 检查键 1 和键 4=`TEE`。历史 Google 真机证书可能没有键 4，所以这个值单独报告，不拿它替代赛事规则。

### 3.2 portable 遗留边界和最终打包门

以下遗留入口仍保留 fail-closed 离线解析/验包能力：

```text
02_脚本与补丁/rkp_sw_portable.py
02_脚本与补丁/package_verify_k70e_portable.py
```

- `rkp_sw_portable.py` 的 direct-online 分支已永久 `SAFE_ABORT`；它只能作为预检、离线 `--resume-finalize` 和被固定核心加载的历史库层，不再是在线发行入口；
- `package_verify_k70e_portable.py` 独立重算，不信任 summary 中已有的 PASS；
- SUCCESS、final report、package verifier 必须就 `ctf_no_not_approved=true` 达成一致；
- 缺失扩展、畸形 CBOR、命中 `NOT_APPROVED` 的旧包均返回非零失败。

当前唯一受支持的在线入口是 `rkp_sw_stock_log_once.py --attended --execute-google-once`；旧 probe、OEMCrypto CSR probe 和 in-process injector 的可执行体已从活动树移除，源文件改为固定 `SAFE_ABORT` tombstone，原始能力只在 `06_历史危险能力隔离/` 中作受控历史证据保留。

### 3.3 环境认可门

旧 `k70e_portable_profile.py` 把 `vb_state`、`bootloader_state`、`vbmeta_digest` 当作可变字段，并且没有比较五层 DICE CodeHash/ConfigHash；这会错误允许已知失败的 patched 测量态进入网络阶段。

profile schema v4 现将三个概念分开，并新增五层完整 same-handset DICE payload 门；当前 runtime profile 使用 `k70e-portable-macos-host-20260906-v5` stock-log-only toolchain，不再继承 V4 中的 patched/candidate/restore 在线能力：

```text
structural_and_portability = PASS/FAIL
approval_environment      = ELIGIBLE/INELIGIBLE
network_issuance          = ALLOWED/BLOCKED
```

`network_issuance_allowed=true` 必须同时满足：

- profile 的 stock baseline 与 2026-08-29 已获 Google 正常证书的公开安全测量锚一致；
- stock TA/TEE 是 exact-reference；
- 当前 CSR 与该手机 baseline 的 UDS、stock CDI leaf 完全相同；
- signed DeviceInfo 所有字段，包括三个 boot security 字段，类型和值完全相同；
- 五层 DICE 测量 claim 全部完全相同；
- 五层完整 verified DICE payload raw hash 全部与同机 approved baseline 相同，包含 issuer、subject 和中间公钥；
- 现场 scalar 合法，派生 SPKI 等于当前 CSR 的 CDI leaf；
- 工具链使用新的版本化 allowlist，不能拿旧 `rkp_sw.py` 哈希冒充新解析器。

`structural_and_portability=PASS` 只表示 CBOR/DICE 结构可用，永远不再被解释为允许联网。

### 3.4 软件私钥持久化与授权边界

在任何网络副作用前，core 必须完成以下全部条件：

- 在已通过 same-handset approved-baseline 授权的 one-shot capability 内生成恰好一把 P-256 软件私钥，以 canonical unencrypted PKCS#8 PEM 写入 `key_00/private_key_pkcs8.pem`；
- 目录必须由当前 UID 所有且精确为 0700，文件必须 0600、regular、single-link、no-symlink；写入后对文件和目录层级 `fsync`；
- 绑定 capture 目录及其 parent 的解析路径、device/inode、UID 和 mode；在 fetch/sign 关键阶段重开并再次校验，拒绝路径、权限或存储对象替换；
- 从落盘 PKCS#8 重开、重新解析和派生 SPKI/COSE key，对 fresh nonce 执行 proof-of-possession；fetch 前和 submit 前都重复完成绑定读取/PoP；
- 软件待签私钥 SPKI **必须不等于** CDI_Leaf identity SPKI，且必须同时等于请求唯一 KeysToSign 和 Google leaf SPKI；
- dispatch ticket、authorization constructor 和后续每个状态转移绑定 creator PID，拒绝在构造前、构造中或构造后通过 fork 继承授权。

Python 进程内的恶意 same-UID 代码不是密码学隔离边界；这些门禁的作用是缩小并关闭已测试的实用绕过和存储竞态，不把 Python 反射写成强隔离保证。

### 3.5 当前冻结工具链身份

```text
gate                       gate-v7
toolchain                  k70e-portable-macos-host-20260906-v5 (stock-log-only)
core rkp_sw.py             619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  193161
profile helper             724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  134026
portable library           0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c  76113  direct-online disabled
stock log collector        732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c  75305
stock one-shot wrapper     99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3  121031
stock offline verifier     f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357  120223
profile internal SHA-256   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
profile file SHA-256       5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81  17803
```

### 3.6 新增 live transport 门与 ATTEMPT v1 边界

- collector 的初始检查和 point-of-no-return 检查各自都把 strict `adb devices -l` inventory 放在该阶段任何设备 shell 之前；只接受精确表头加一条 pinned serial、状态为 `device` 的规范记录。额外或重复设备、`offline`、`unauthorized`、非目标 serial、非 ASCII/控制字符、坏换行、畸形 detail token 或重复 detail key 全部 `SAFE_ABORT`；第二次 inventory 一旦失败，不再发送 cleanup shell、Binder 或一次性 marker，已 staged 的远端临时目录改为安全延期清理并写入 `remote_cleanup.json`；手工清理也只能在重新确认 strict inventory 中唯一目标后进行；
- wrapper 在 `ATTEMPT` 保留之前的 live preflight，以及 device-latch 单 root shell 之前，也各先执行同一 strict 唯一 ADB inventory；第二次 inventory 失败时已保留的 attempt 会被烧毁，但不会进入该 root shell；
- collector 与 wrapper 都要求 `tee-supplicant` 恰好返回一个 ASCII 十进制 PID，空值、多 PID、空格分隔值或其他字符均拒绝，禁止把不明确 PID 交给 `nsenter`；
- 真实发行必须显式传 `--attended --execute-google-once`。缺 `--attended` 在 `build_preflight()` 之前即失败，不读取设备、不构建/比较 preflight，也不保留 `ATTEMPT`；`--preflight-only` 反而禁止携带 `--attended`。

当前 `k70e-rkp-ctf-stock-log-issuance-attempt-v1` 还有一个必须如实解释的预承诺：`ATTEMPT.json` 在真实 `DEVICE_LATCH.json` 创建前，已经写入 `device_latch_consumed=true` 以及未来成功 latch 的确定性路径/哈希合同。这里的 `true` 不是对当时现场的既成事实陈述，而是“本 attempt 只允许继续到这一个成功 DEVICE_LATCH”的承诺。若两者之间手机掉线或第二门失败，wrapper 会写 `BURNED.json`，且不会写 `NETWORK_STARTED.json` 或 `SUCCESS.json`，所以不会联系 Google；但失败现场单看 ATTEMPT 字段，语义确实不直观。若要把“已消费”改成只记录实际发生，必须把 writer、verifier、marker 哈希链和 schema 一起迁移为 **gate-v8/新 attempt schema**；禁止只把 ATTEMPT 与 DEVICE_LATCH 的顺序简单倒置，或在 v1 内偷偷改字段含义。

## 4. 离线回归结果

当前最终冻结回归为 **8 组 / 178 项，178/178 PASS**，分组映射为 **Provisioning Info/core 23 + profile 13 + device evidence 12 + capture 31 + extractor 10 + legacy quarantine 10 + wrapper 42 + verifier 37 = 178**。覆盖范围包括 Provisioning Info、profile/approval、device evidence、stock log extractor/capture、core authorization/durability、stock one-shot wrapper、stock offline verifier 和 legacy capability quarantine。关键用例如下：

| 用例 | 预期和实际 |
|---|---|
| 旧最终叶证书 | `ctf_no_not_approved=false`；命中 cert 0、路径 `5/1` |
| 2026-08-29 正常真机叶证书 | `ctf_no_not_approved=true` |
| 叶证书缺 Provisioning Info | fail-closed |
| Provisioning Info 是畸形/尾随 CBOR | fail-closed |
| 重复键先放 `NOT_APPROVED`、后用同键覆盖 | 非 canonical，parse_error，fail-closed |
| CBOR `true` 与整数 `1` 键碰撞后覆盖 | 非 canonical，parse_error，fail-closed |
| 任意显式 `CBORTag`，包括 tag 24 encoded-CBOR | fail-closed |
| tag 258 自动解码的 `set`/`frozenset`、tag 35 的 `re.Pattern` 及其他 semantic object | fail-closed |
| 同时有公开 strict 字段和 `NOT_APPROVED` | CTF=false、Android schema=true，证明两个 verdict 不混淆 |
| stock approved CSR | approval environment ELIGIBLE；未给 scalar 时 network 仍 BLOCKED |
| final patched `64c...` CSR | approval environment INELIGIBLE；五层匹配 `[F,F,T,F,T]`；network BLOCKED |
| 软件待签 key 与 CDI identity 同 SPKI | 授权内拒绝，不可 fetch/sign |
| PKCS#8 非 canonical、文件/目录 mode 改变、路径或 inode 交换 | 重开/绑定验证失败，不可 POST |
| authorization 构造前后 fork/PID 变化 | 授权失效，不可 POST |
| collector 两阶段的 ADB inventory 出现额外/重复设备、offline/unauthorized 或畸形记录 | 在该阶段任何设备 shell 前 fail-closed |
| wrapper 的 ATTEMPT 前 inventory 或 device-latch shell 前 inventory 不唯一/不规范 | fail-closed；后者烧毁已保留 attempt，但不写 NETWORK_STARTED/SUCCESS |
| execute 缺 `--attended`，或 preflight 错带 `--attended` | 在 `build_preflight()` 前拒绝 |
| `tee-supplicant` PID 为空、多值或不是唯一 ASCII 十进制 | collector/wrapper 均拒绝，不调用 `nsenter` |
| `rkp_sw_portable.py` direct-online、旧 probes/injector | 固定 `SAFE_ABORT`，不具备活动在线/动态能力 |

相关测试：

```text
02_脚本与补丁/test_provisioning_info_gate_offline.py
02_脚本与补丁/test_k70e_portable_approval_gate.py
```

表中的 178/178 是离线代码与证据门禁结果，不是新 Google 证书的真机验收结果。

## 5. 已闭合的 stock CDI_Leaf 提取路线

### 5.1 关键更正

先前“stock MiTEE 日志没有 CDI_Leaf scalar”的结论是调用图覆盖不完整造成的，现已被原厂 TA 的静态证据推翻。原厂签名 KeyMint TA 在活动 `generateCertificateRequestV2` 设备签名路径中会调用已有的 `dump_to_hex("private_key", ...)`，不需要修改 TA、TEE、SProvider、LK 或 preloader。

活动调用链为：

```text
Binder generateCertificateRequestV2(keysToSign=[])
  -> MiteeRemoteProvisioningContext::SignWithDeviceKey        0x0be710
  -> hwbcc wrapper                                             0x0c2e18
  -> tee_sign_key                                              0x0dd9b0
  -> hwbcc_sign_key                                            0x0dd438
  -> get_attest_cdi                                            0x0dcd10
  -> P256KeypairFromCDI                                        0x0db330
  -> success                                                   0x0dd934: x26
  -> mov x5, x26                                               0x0dd94c
  -> bl dump_to_hex                                            0x0dd954 -> 0x0d87f0
```

`0xdd934:x26` 是派生完成后的 32-byte big-endian P-256 `CDI_Leaf` 私钥标量，不是 raw CDI、KeyBlob、KAK 或每次 `GenerateRkpKey` 的软件/硬件待签私钥。`dump_to_hex` 固定输出两条相邻、每条 16 字节的 INFO 行：

```text
[utee:INFO][dump_to_hex:59]private_key(  15): <16 个小写十六进制字节>
[utee:INFO][dump_to_hex:59]private_key(  31): <16 个小写十六进制字节>
```

normal-world 路径是 `TA printf -> MiTEE memlog -> /proc/mitee_log -> vendor miteelog -> /data/vendor/mitee/mitee.log`，轮转文件为 `last_mitee.log`。现有日志中的 `MIKEYMINT` KAK 行属于另一个调用者，不能替换上述精确语法。

### 5.2 已实现的离线捕获器

新增以下入口：

```text
02_脚本与补丁/rkp_binder_csr_v2_zero_key_client.cpp
02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload
02_脚本与补丁/extract_k70e_cdi_leaf_from_mitee_log.py
02_脚本与补丁/capture_k70e_stock_cdi_log_once.py
```

受控 zero-key 载荷的完整绝对路径为：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload
```

捕获器只做一次 `keysToSign_count=0` 的本机 Binder CSRv2 调用；它不生成待签软件 key、不请求 EEK、不调用 Google、不刷写、不重启。调用前和 point-of-no-return 前各做一次门禁：每阶段先在任何设备 shell 前完成 strict 唯一 ADB inventory，再固定 USB serial、`duchamp`、slot `_a`、fingerprint、root、boot ID、服务、stock TEE、stock TA、唯一 ASCII 十进制 `tee-supplicant` PID、已知 init_boot，以及已保存的原版 `lk_a`/`preloader_raw_a` 整体哈希。HLOS 的 `ro.boot.*` 只记录、不作为认可证据；本机历史已经证明 HLOS 可显示 `green/locked`，而同轮原厂 TA 签名 DeviceInfo 为 `orange/unlocked`。

飞行模式下 AOSP `netd` 会给 dummy 网络安装丢包用 default；`dummy0` 的 ifindex 加 1000 即可表现为 table 1002。它不是可转发外网路由。捕获器仍然 fail-closed：IPv4/IPv6 路由查询任一返回码非 0 即 `SAFE_ABORT`；除下面两种已知精确形态外，任何以 `default` 开头的路由都会拒绝：

```text
default dev dummy0 table 1002 proto static scope link
default dev dummy0 table 1002 proto static metric <十进制整数> pref medium
```

证据必须分开记录 `forwarding_default_route_count=0` 与 `ignored_dummy_sink_default_route_count`/对应 inventory hash，并保留兼容字段 `default_route_count=0`；黑洞 default 不可被当成外网路由，也不可泛化成忽略任意 dummy/default 的例外。

上述“只有两种”是 **collector** 的语法。在线 wrapper 是 family-aware：IPv4 只接受无 gateway 的裸形态 `default dev dummy0 table 1002` 或其 `proto static scope link` 形态；IPv6 只接受同一裸形态或 `proto static metric <十进制整数> pref medium` 形态。两路实现对 `via`/`nexthop`/`nhid`/`encap`、错表、重复字段和未知尾缀都拒绝。这项门严格证明的是飞行模式、Wi-Fi 关闭、双栈查询成功和零可转发 `/0` default；不能单凭该报告扩大声称已排除所有 host-specific、VPN 或 fwmark 路径。

捕获器先保存 `mitee.log`/`last_mitee.log` 基线，耐久写 `DISPATCHING_NO_RETRY`，再执行唯一 zero-key Binder 调用，随后保存完整 post 日志。只接受单一 append-only 增量；若发生轮转，仅在 `post last_mitee.log` 逐字节以前一份 current log 为前缀时重建增量。任何不明确轮转都保留原始日志并返回 `PARSER_REQUIRED`，绝不重跑同一输出目录。

解析器只接受精确的两行语法，允许同一 CSR 产生其他 `private_key` 候选，但只选择派生 P-256 SPKI 与同轮 AuthenticatedRequest 最终 DICE subject 完全相同的唯一候选。它同时验证 canonical CBOR、UDS、五段 DICE 签名、outer 签名、challenge、zero KeysToSign 和完整 DeviceInfo；输出目录为 0700，scalar/SPKI/report 为 0600，不打印秘密原文。

### 5.3 当前状态与边界

- 已认可历史 stock leaf SPKI 仍为 `0684d469...b1130b`；新的现场 scalar 只能由本次同轮 CSR 公钥关系确认，不能靠硬编码哈希直接接受。
- Pixel 已不在场，唯一 K70E native ADB 已通过稳定性观察；尚未产生新 stock scalar 的原因已变为 live 门确认当前 HLOS/AVB 仍是 `b9b1d867…` 拒绝环境。必须先按文档 58 恢复 CN304 并 fresh boot/post-boot 验收。
- 现场未消耗 Binder zero-key one-shot 或 Google one-shot。Pixel 已移除，native platform-tools ADB 的单 K70E 稳定性也已通过；当前真正前置是按文档 58 完成受控恢复并由独立验证器写出 `POSTBOOT_VERIFIED.json`。之后仍要在 Binder 紧前重做物理 USB 与严格 ADB inventory。
- 捕获前若 `lk_a`、preloader、TEE、TA 或 init_boot 任一 live hash 不符，必须停在 Binder 之前。先恢复目标自己的已知原版，再重新启动；不得用 patched `64c...` 身份联网。
- zero-key 是离线身份 CSR，不是 Google 签发，也不消耗一把待签软件 key；同一输出目录在 `DISPATCHING` 后禁止重跑。新的输出目录只可在确认未调用 Google且已修复环境后创建。
- 若原厂日志未出现、语法畸形或轮转来源不明确，保留日志供离线解析，不回到补丁 TEE 路线。

### 5.4 已排除的旧优先路线

- stock `mitee_shell` 目标 UUID TA 不在 vendor TA 集，`ta-mgr` 只是转发 socket；stock `kernel.console=false` 且 BootFS 无 `/boot/bin/sh`，现有 `zx mwd/hwd/asd` 是 watchdog/映射元数据，不是任意 `readmem`。它不再是主路线。
- 原样旧签名 TA handler、SProvider/ta-mgr TOCTOU、normal-world ptrace/HBP/shared memory、nonce reuse 和离线文件扫描均未给出 stock scalar。
- patched TA/TEE/Fenrir 捕获只保留为历史研究；它改变服务器可见测量并已实证得到 `NOT_APPROVED`，不再执行。
- 原先可选 TA/TEE/OEMCrypto probes 和 in-process injector 已退役；活动源只是必然返回 78 的 tombstone，原 ELF/源只作隔离归档，不得从归档解包恢复到执行路径。

## 6. 下一次唯一允许的在线流程

只有 stock approval gate 和现场 scalar gate 全部通过后，才允许一次新的 Google 运行：

1. 用 `capture_k70e_stock_cdi_log_once.py` 保存同轮 stock zero-key AuthenticatedRequest、challenge、UDS、五段 DICE、signed DeviceInfo 和密码学匹配的 CDI_Leaf scalar；
2. 用专用 `rkp_sw_stock_log_once.py --preflight-only` 完整重验捕获合同、profile、core gate-v7、toolchain V5、scalar/SPKI/CSR 和 approved-baseline 认可环境；此阶段零网络；
3. 保持同一设备、同一 boot ID 和同一 approved-baseline 哈希组合；只用显式 `--attended --execute-google-once`。wrapper 先在 `build_preflight()` 前检查 attended，再在任何 `ATTEMPT` marker 之前以 strict 唯一 ADB inventory 开门，完整重验 live boot/hash/service、唯一 ASCII 十进制 `tee-supplicant` PID、飞行模式、Wi-Fi 和零可转发 default；准备 device-state 目录后保留/消费 host `ATTEMPT`，随后再次 strict inventory，才进入 device latch 前的单个 root shell，原子重验 boot/分区/TA namespace/service 和同一手机离线政策；全部通过才实际消费 device latch，再写 `NETWORK_STARTED`。第二门失败时 host attempt 已被烧毁，不得重试，也不会联网；ATTEMPT v1 中提前出现的 `device_latch_consumed=true` 只是对未来成功 latch 的预承诺，不是失败现场的既成事实；
4. `google-rkp-sw` 在授权内新生成恰好一把 P-256 软件私钥，要求其 SPKI 不同于 CDI identity SPKI，并以 canonical PKCS#8 先耐久保存、`fsync`、重开、重解析和完成 PoP；
5. 构造 fresh challenge 的 one-key proper-DICE 请求，并在发送前验证 source UDS/DICE/DeviceInfo 与捕获逐字节/逐类型一致；
6. 只运行一次官方 Google RKP 流程；fetch/sign 原始响应都先落盘再解析；
7. 要求 HTTP 200、恰好一条四证书链、软件私钥公钥=请求唯一 key=leaf SPKI、链签名与固定 Google 根全部通过；
8. 对完整链执行 Provisioning Info 硬门；任何 `NOT_APPROVED`、缺 leaf 扩展或畸形扩展都拒绝本次结果并烧毁同一 ATTEMPT；公开 Android key-4 schema 只单独报告，不能拒绝已满足赛事规则的历史型 `{1,3}` 扩展；verifier 对第一次 `LIVE_STOCK_PREFLIGHT.phone_offline_gate` 强制 exact typed fields、两个 route query success、`forwarding_default_route_count=0`、dummy sink count 和 inventory hash，并绑定 `ATTEMPT`/`DEVICE_STATE_DIR_PREPARED`/`DEVICE_LATCH`/`NETWORK_STARTED`/`SUCCESS` 链；第二次原子手机门只由成功 device-latch 合同间接证明，它没有第二份 raw route inventory，也不是 Google freshness receipt；
9. 只有 `ctf_no_not_approved=true` 后才写 SUCCESS，并把身份 scalar/SPKI/zero-key CSR/challenge、软件私钥和同轮 Google 链收进一个私有交付目录。

若新请求仍含 `NOT_APPROVED`，不得重放同一 ATTEMPT，也不得在没有新假设和新门证据时盲开下一次；应保留完整证据，继续离线比较 clean native control 与失败请求，找出并修正具体 DeviceInfo/DICE/启动链差异。只有差异已经被修复、fresh boot 的新捕获通过全部新门后，才允许新的 controlled attempt。只有出现明确 429、`quota` 或 `abuse` 时才暂停外部请求；暂停外部请求不等于停止离线调查。

## 7. 公开资料边界

- Android Provisioning Information：<https://source.android.com/docs/security/features/keystore/attestation#provisioning-information-extension>
- Android RKP `IRemotelyProvisionedComponent`：<https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl>
- Android RKP `DeviceInfo`：<https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/DeviceInfo.aidl>
- AOSP `DummyNetwork` 丢包 default 语义：<https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/DummyNetwork.cpp#30>
- AOSP `RouteController` 的 dummy default 安装：<https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp#788>
- AOSP 接口路由表 ID 映射（ifindex + 1000）：<https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp#149>
- RFC 5280 证书签名结构：<https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.3>

公开 Android verifier 只读取已知字段、忽略未知字段的行为可以解释旧通用验证为什么没有报错，但赛事规则更严格：任何 verifier 的“链有效”都不能替代对原始 Provisioning Info 的全量审计。

## 8. 给下一位 AI 的终态

```text
旧 frozen bundle：REJECTED_NOT_APPROVED，保留证据，不可提交
样本普查：27 unique ProvisioningInfo certs = 25 clean / 2 NOT_APPROVED；12 张 clean 同为 count=32
简单次数/计数风控：已由现有样本和 HTTP 证据排除；两坏请求均 200，无 429/quota/abuse
host framing 主因：已由真机 Binder 同样失败、相同 modified 五层 payload、相同 fetch/EEK 控制量排除
主因：modified boot/DICE/signed DeviceInfo environment；磁盘 post-restore 不能倒转当前 boot 测量
实现/离线门禁：gate-v7 + V5 stock-log-only + 8 组 178/178 PASS（PI/core23 + profile13 + device12 + capture31 + extractor10 + legacy10 + wrapper42 + verifier37）
PI 解析：显式 CBORTag、tag24、tag258/tag35 semantic object 全部 fail-closed
软件私钥：PKCS#8 耐久化/重开/PoP/fsync；capture UID/0700/path/dev/inode/PID 绑定；SPKI != CDI identity SPKI
在线入口：只允许 stock one-shot wrapper；portable direct-online/probes/injector 已禁用隔离
手机/网络：Pixel 已不在场，唯一 K70E native ADB 已稳定；手机保持飞行模式/无可转发 default，但当前仍是 `b9b1d867…` 拒绝环境
一次性副作用：Binder zero-key 和 Google one-shot 均未消耗
新的合格三件套：尚未产生
下一技术阻塞：收到当前交互的新鲜在场确认后，按固定八步恢复 CN304 批准环境并独立 reboot；再由 post-boot 验证器完整读取 raw/9 个逻辑分区、确认 HLOS/TA/boot_id/离线门并写 `POSTBOOT_VERIFIED.json`
```

任何后续 AI 如果没有先证明 `network_issuance_allowed=true`，不得联系 Google；如果没有看到最终链 `ctf_no_not_approved=true`，不得写 PASS。失败 ATTEMPT 必须保留且不可重放，但在没有明确 429/`quota`/`abuse` 时，必须继续离线差分和环境修复，不能把 `NOT_APPROVED` 误写成整个调查的停止条件。
