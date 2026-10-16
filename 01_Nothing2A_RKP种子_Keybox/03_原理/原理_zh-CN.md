# Nothing 2a：原理与证据链（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里保留 KeyMint/Trustonic/Keybox 载荷格式、RKP KDF、直接客户端与 Binder 路径、补丁点和验收不变式的完整原始分析。

---

## 原始记录段 1 / Source section 1: 03_漏洞原理详解.md

# Keybox 提取漏洞原理详解

题目目录：`<PROJECT_ROOT>/最终结果/keybox提取`

## 1. 漏洞不是单点，而是一条链

本题能成功不是因为 `attest_keybox.so` 本身可直接解密，也不是因为 Android Framework 暴露了私钥，而是组合链：

```text
Bootloader unlock
  -> fenrir / preloader 对 bl2_ext/LK 校验策略缺陷
  -> patched LK 启动
  -> patched TEE 启动
  -> Trustonic t-base MCLF 签名校验绕过
  -> modified KeyMint TA 可加载
  -> KeyMint TA 正常解密 persist secure object
  -> patch TA 把 secure world 明文 copy-out 到 normal world mapped buffer
  -> normal world direct client 拉回明文
  -> DER parser 拆出 EC/RSA 私钥和证书链
```

因此漏洞本质是：

```text
一旦攻击者能在同一 TEE 环境中加载 modified KeyMint trustlet，
原本只应在 secure world 短暂存在的 factory attestation keybox plaintext
可以被 patch 后复制回 normal world。
```

## 2. KeyMint factory keybox 的位置

Android Keystore/KeyMint attestation 的长期 factory material 存在 persist secure object 中：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
```

它们不是普通明文结构。正常系统路径是：

```text
KeyMint HAL 读取 secure object
  -> 通过 Trustonic TCI 传入 KeyMint TA
  -> TA 在 secure world 中解密和校验
  -> TA 保存或解析 attestation key material
  -> normal world 不得到私钥明文
```

本题导出的 `keybox.xml` 来自 `attest_keybox.so` 解密后的明文，不是从 Java Keystore API 导出，也不是从 RKPD DB opaque blob 直接解密。

## 3. HAL 到 TA 的协议

Trustonic client/HAL 与 TA 通过 TCI 通信。对本题最重要的两个命令：

```text
0x00050202: 处理 attest_keybox.so
0x00050204: 处理 attestation_ids.so
```

TCI 中携带 normal world mapped buffer 的地址和长度：

```text
offset 0x00: command
offset 0x04: return code
offset 0x0c: mcBulkMap_t.sVirtualAddr
offset 0x10: mcBulkMap_t.sVirtualLen
```

`kmtee_probe.c` 复刻 HAL 的最小行为：

```text
mcOpenDevice()
mcOpenTrustlet(patched TA)
mcMap(attest_keybox.so buffer)
TCI cmd = 0x00050202
mcNotify()
mcWaitNotification()
读取 mapped buffer after
```

这就是为什么不需要替换系统 HAL 或系统 TA：direct client 只要能加载 trustlet，就能直接喂同样的 secure object。

## 4. TA 内部处理路径

`0x00050202` handler 大致逻辑：

```text
0x1e430 handler:
  读取 TCI+0x0c 的 mapped buffer 信息
  校验 normal world buffer
  分配 heap buffer
  memcpy(mapped encrypted attest_keybox.so -> heap)
  调用 0x1de70(heap, len)
  释放 heap
  返回
```

`0x1de70` 大致逻辑：

```text
分配 plaintext buffer
调用 0x22738 解密 secure object
调用 0x1d9b8 parse plaintext keybox
释放 plaintext buffer
返回 ret
```

关键点：

- plaintext 确实出现过。
- plaintext 的生命周期很短。
- stock TA 不会把 plaintext 写回 mapped input。
- 所以 unpatched direct client 的 before/after 完全一致。

## 5. Patch 为什么选这两个点

已知条件：

```text
plaintext pointer 和 plaintext length 在 0x1de70 parse 前仍在栈上
handler 的 heap input buffer 和 mapped input pointer 在返回前仍可访问
TA text 区有 code cave 0x411ac
TA 内已有 memcpy 0x50f0
```

目标是不改变成功路径的语义：

```text
原逻辑仍然 decrypt
原逻辑仍然 parse
原逻辑仍然返回成功
只是在中途把 plaintext 复制出来
```

Patch 1：

```text
地址 0x1df3c
原位置：准备调用 parse plaintext
新行为：branch 到 code cave
code cave:
  memcpy(input_heap, plaintext, plaintext_len)
  call original parse 0x1d9b8
  branch 回 0x1df44
```

Patch 2：

```text
地址 0x1e4d4
原位置：handler 保存返回值后准备收尾
新行为：branch 到 code cave
code cave:
  mov w19, w0
  if ret == 0:
      memcpy(mapped_input, input_heap, original_len)
  branch 回 0x1e4d8
```

结果：

```text
normal world mapped buffer after = plaintext keybox prefix + 未覆盖尾部
```

其中尾部 `tail_unmodified_len=92` 是原始 mapped buffer 中没有被 plaintext 覆盖的残留，不属于解析出的 keybox 主体。

## 6. 为什么能拆出 EC 和 RSA 两套 key

解密出的 plaintext keybox 是长度前缀结构。解析结果：

```text
u32 version_or_keybox_number = 1
u32 EC private DER length = 138
DER EC private key
u32 EC cert count = 3
DER EC leaf/intermediate/root
u32 RSA private DER length = 1794
DER RSA private key
u32 RSA cert count = 3
DER RSA leaf/intermediate/root
```

DER 的首字节是 `0x30` SEQUENCE，因此 `extract_keybox_plain.py` 用 DER length 反查每段长度是否与前缀一致。这比按固定偏移切更稳，因为证书长度可能随设备或版本变化。

## 7. 为什么证明它是真正的 attestation keybox

仅仅导出私钥还不够，必须证明它和 AndroidKeyStore 实际 attestation chain 对得上。

验证分三层：

第一层，私钥和 leaf cert 公钥匹配：

```text
openssl pkey -pubout(private) == openssl x509 -pubkey(cert0)
```

第二层，证书链可验证：

```text
cert0 signed by cert1
cert1 signed by cert2/root
```

第三层，AndroidKeyStore 实际触发链对照：

```text
AndroidKeyStore generated key leaf
  -> extracted attestation leaf
  -> extracted intermediate
  -> extracted root
```

这说明提取物不是随机私钥，也不是 DRM keybox，而是 KeyMint factory attestation keybox。

## 8. RKP 与本地 keybox 的关系

设备支持 RKP，但本题仍成立，原因是：

```text
RKP 支持存在 != 本地 factory keybox 不存在
RKP 可用 != 永远不 fallback
```

本机实测有 RKP transient failure / network failure 后，本地 TEE chain 仍可生成。这个现象让本地 `attest_keybox.so` 仍有可验证价值。

RKP 题目后来进一步证明，Google RKP 短期链可以另走一套 route；但这不否定 factory keybox 提取。两题共享底层 KeyMint TA 和启动链能力，但目标不同：

```text
keybox 题目：导出本地长期 factory attestation keybox
RKP 题目：拿到 Google RKP 短期 attestation private key + cert chain
```

## 9. 安全影响

如果该漏洞链出现在真实攻击条件中，影响包括：

- 本地 factory attestation private key 保密性破坏。
- 可在设备外部用提取私钥执行与该 factory chain 对应的签名。
- 依赖该 chain 做硬件认证判断的服务端，如果不检查 boot state、patch level、risk list，可能被误导。
- RKP 覆盖不完整或 fallback 策略宽松时，长期本地 factory keybox 仍是风险点。

## 10. 修复方向

防护应覆盖整条链：

```text
preloader/LK 验签策略：unlock 状态也不能允许未授权 EL3/TEE 代码路径
TEE/t-base：modified MCLF 不能被加载
KeyMint TA：明文 buffer 生命周期最小化并及时清零
HAL/TEE 接口：避免可被 direct client 复刻敏感初始化命令
RKP/fallback 策略：RKP 设备应谨慎 fallback 到长期 factory key
服务端：对可疑 chain、orange state、旧补丁级别做严格策略判断
```

本 CTF 中真正的可利用点是“能加载 modified TA”之后的明文 copy-out；`attest_keybox.so` 自身并没有在 normal world 被直接破解。



---

## 原始记录段 2 / Source section 2: 原理与边界.md

# Nothing 2a 原理与边界

## 1. Keybox 路线

传统 factory Keybox 不是普通文件系统上的 XML，而是由 KeyMint/TEE 侧使用的二进制密封对象。正常流程中，普通世界只能通过受限命令让 KeyMint 使用它；私钥和证书链不会作为普通世界返回值出现。

本题的关键点有两个：

1. Trustonic TA 的加载信任链可以在授权 CTF 设备上被修改，使研究版 TA 被加载。
2. 研究版 TA 在原本用于初始化 `attest_keybox.so` 和 `attestation_ids.so` 的映射缓冲区上增加只读旁路，把 TA 已经解封的明文复制回普通世界。

客户端仍按原始 MC/TCI 协议打开 TA、映射缓冲区、发送命令、等待通知和关闭会话。它没有伪造证书，也没有从 XML 猜私钥；真正的秘密来源是 TA 处理过的 mapped buffer。

返回的 Keybox 明文布局是长度前缀序列：版本/编号、EC 私钥 DER、EC 证书链、RSA 私钥 DER、RSA 证书链，后面可能保留未解密尾部。解析器先按 DER 长度检查，再按头部长度切分；因此长度、DER、私钥/叶证书 SPKI 和整链签名要分层验证。

## 2. RKP `rkp_bcc_km` 路线

RKP 生成流程通常由 RKPD/HAL 调用 KeyMint TA。TA 内部用设备绑定的秘密材料和标签 `rkp_bcc_km` 调用 KDF，得到后续设备身份或认证流程使用的 32 字节材料。正常调用不会把它返回给 host。

本包的授权诊断 TA 只挂到 direct native probe：

```text
keygen -> internal KDF(label=rkp_bcc_km, len=10, out=32, mode=1)
      -> copy 32 bytes to private_out+0x400
      -> copy KDF status to private_out+0x420
      -> write marker 0x1234 at private_out+0x424
      -> replay stock cleanup
```

这样既能保留原始 keygen 返回路径，也能把材料和原始 `priv_full` 一起归档。`status=0` 和 32 字节长度是必要条件；seed SHA-256 只用于确认传输和版本，没有把哈希当作秘密替代物。

## 3. CDI 命名边界

在本设备和当前 `google-rkp-sw` 实验中，这 32 字节材料可以作为软件身份 seed，派生签名身份并参与 CSR 构造，所以历史文档会称其为 CDI 相关材料。严格写法应是：

> Nothing 2a KeyMint TA 内部 `rkp_bcc_km` KDF 导出的 32-byte 派生材料，实测可作为当前软件 RKP 身份的 seed。

不能只凭标签名称断言它就是所有平台都采用相同格式的原始 UDS、DICE `CDI_Leaf_Priv` 或任意手机可通用的根种子。不同厂商可能把它用于不同层级的派生。

## 4. 固件门禁原因

TA 内部地址、代码洞、MCF/MCLF 布局、KeyMint 服务、TEE client 和 boot chain 都属于版本相关输入。补丁 TA 在另一个构建上可能：

- 直接无法加载；
- 通过加载但命令偏移改变；
- 写入错误 buffer，导致结果看似成功但内容无效；
- 破坏 KeyMint 初始化或启动链。

因此本包提供 U2.5 成功基线、原厂回滚输入和 hash 索引，而不是所谓“所有 Nothing 2a 通用固件”。

## 5. 证据链

一份合格结果的逻辑顺序是：设备基线 -> 输入哈希 -> TA 加载 -> TCI 返回 -> 原始 buffer -> 解析长度 -> 私钥公钥/叶证书匹配 -> 链签名验证。缺少任一环节，只能叫“观察到字节”或“生成了 CSR”，不能叫已提取可用凭据。


---

## 原始记录段 3 / Source section 3: 04_CTF_RKP_经验总结_20260826.md

# CTF RKP 安全测试报告、经验总结与证书审计

文档类型：报告（只针对 RKP，不作为传统 Keybox 报告）

审计更新时间：2026-08-26 09:00:13 UTC（2026-08-26 17:00:13 UTC+8）

## 0. 目标完成状态（重要）

用户的实际目标是：从当前 CTF 设备提取身份材料，交给 `google-rkp-sw`构造请求，
再由 Google 生产 RKP 服务验证并签发证书，最后保存私钥、原始请求/响应和完整证书链。

**该目标已完成。**

在用户确认的授权 CTF 范围内，`google-rkp-sw` 使用从 Nothing A142
导出的 32 字节 `rkp_bcc_km` 材料，完成了一次单密钥签发：

- `fetchEekChain` 成功；
- `signCertificates` 返回 HTTP 200；
- 实际返回 1 条四层 Google RKP 证书链；
- 待签 P-256 私钥与 RKP 叶证书公钥匹配；
- 链上三段签名和根自签全部验证成功；
- 叶证书包含 RKP provisioning information OID，近 30 天近似签发数为 128；
- 私钥、CSR、原始 HTTP 响应、拆分证书、重排链、`keybox.xml`、验证
  报告和 SHA-256 清单均已保存。

成功运行目录：
`04_结果/outputs/google_rkp_sw_live_1key_20260826_03`。

本地 CTF CA 的两张测试证书仍然只是离线格式自测，不是这次的 RKP
签发产物。历史 12 条链则是 stock Binder / 旧协议路径；它们和本次
`google-rkp-sw` 单密钥成功运行已分别记录。

## 1. 当前阶段结论

1. 在授权 CTF 设备 Nothing A142 / Pacman 上，已通过 KeyMint TA 内部
   `rkp_bcc_km` KDF 取得一份稳定的 32 字节派生材料。KDF 返回 `0`，不同
   KeyMint 会话中结果一致。
2. 这 32 字节被 `google-rkp-sw` 作为 Ed25519 seed 派生身份密钥，对新
   challenge 签名，并构造 CSR v3。在复制已知的公开 DeviceInfo 后，授权
   CTF 签发端已接受该请求。
3. 本次成功响应新增 **1 张 RKP attestation signing certificate**，对应
   1 条四层链，不是 4 张 RKP；其余 3 张是链上 CA。
4. 新证书的 RKP 扩展 key `1` 为 **128**；这是滚动近 30 天近似签发量，
   不是本次返回数。
5. 新 RKP 证书有效期为 2026-08-24 09:09:08 至 2026-09-06 19:44:56 UTC，
   总窗口约 13.44 天；2026-08-26 09:00:13 UTC 复核时有效。
6. 项目历史 stock Binder 成功批次另有 12 张 RKP 证书。就能从明确
   HTTP 200 记录核实的两次成功而言，已保存的签发数是 **12 + 1 = 13**。

## 2. 数量口径

### 2.1 证书内的“过去 30 天证书颁发数量”

该数字不需要根据当地文件计算，而是 Google provisioning server 写入 RKP 证书
OID `1.3.6.1.4.1.11129.2.1.30` 的 provisioning information 扩展。扩展内层是
CBOR map，其中 key `1` 是服务端所知的该设备过去 30 天获得证书的近似数量。

实际解析项目中四批 RKP 证书：

| 批次 | 该批实际保存的 RKP 证书 | 扩展原始 CBOR | key `1` 颁发数量 | key `3` |
|---|---:|---|---:|---|
| `rkp_pool_dump_reference` | 12 | `a2 01 08 03 67 4e6f7468696e67` | 8 | `Nothing` |
| `stock_rkpd_provision_baseline` | 12 | `a2 01 10 03 67 4e6f7468696e67` | 16 | `Nothing` |
| `final_google_signcerts_12chains` | **12** | `a2 01 18 80 03 67 4e6f7468696e67` | **128** | `Nothing` |
| `google_rkp_sw_live_1key_20260826_03` | **1** | `a2 01 18 80 03 67 4e6f7468696e67` | **128** | `Nothing` |

因此用户所指的那个证书字段，在历史 12 张批次和本次 `google-rkp-sw`
新证书中均为 **128**。

AOSP 对该字段的定义是“过去 30 天签发给设备的证书近似数量”，用作潜在滥用的
风险信号。因此：

- **128 不是这次 HTTP 响应返回的证书数量**；
- 历史批量 HTTP 200 实际返回 12 张 RKP 证书 / 12 条链；
- 本次 `google-rkp-sw` HTTP 200 实际返回 1 张 RKP 证书 / 1 条链；
- 128 是服务端为该设备写入的近似滚动统计，不应当作精确的本地可见证书数；
- 本地四批观察到的值为 8、16、128、128，数值形态很像服务端做了分桶或近似化，但具体算法是
  服务端实现细节，仅凭证书无法反推精确张数。

规范参考：[AOSP Provisioning information extension](https://source.android.com/docs/security/features/keystore/attestation#provisioninginfo_extension)。

### 2.2 实际生成了多少张

项目历史最终成功的 Google 批量请求中：

- `chain_count = 12`；
- 每条链有 4 个 X.509 证书对象；
- 每条链只有第 0 张是本次待签 P-256 密钥对应的 RKP attestation signing
  certificate；
- 所以本次实际生成的 RKP 证书是 **12 张**，不是 48，也不是 128。

48 只是 12 条链中的 X.509 对象数简单相加，其中 Droid CA3、Droid CA2 和 Key
Attestation CA1 在多条链中重复。128 是证书内的近 30 天近似颁发统计。

本次 `google-rkp-sw` 成功请求只包含 1 个 KeysToSign 公钥，所以实际新签发是
**1 张 RKP 证书 / 1 条链 / 4 个链内 X.509 对象**。

### 2.3 附加的当地文件清点

另外，对工作区的 DER 证书按指纹去重，原有三批各 12 张，本次又新增
1 张，现共有 37 张不同的 Google RKP 证书。这只是本地已保存证书的文件清点，
**不是**证书扩展中的
“过去 30 天颁发数量”，两者不能混用。

### 2.4 签发产物是否真的丢失

对工作区内所有明确的 `signCertificates` HTTP 记录去重，现共有 5 次：

| 时间（UTC） | HTTP | 实际签发 | 请求/响应是否保存 | 结果 |
|---|---:|---:|---|---|
| 2026-08-15 09:00:43 | 400 | 0 | 是 | 失败，无证书 |
| 2026-08-16 11:04:49 | 403 | 0 | 是 | 失败，无证书 |
| 2026-08-16 11:05:27 | 200 | 12 | 是 | 12 私钥、12 链、原始响应和 key.xml 均保存 |
| 2026-08-26 08:57:26 | 400 | 0 | 是 | CSRv3 误含 DeviceInfo.version，无签发 |
| 2026-08-26 08:58:17 | 200 | **1** | **是** | 私钥、CSR、响应、四层链和 keybox 均保存 |

所以，在能从 HTTP 证据直接确认的两次成功中，没有出现“已签发但什么都
没保存”：历史 12 张在 `final_google_signcerts_12chains`，本次 1 张在
`google_rkp_sw_live_1key_20260826_03`。

两批系统 RKPD 签发产物也保存了 12 + 12 条链、KeyMint opaque key blob、公钥和数据库
备份；但它们没有单独截留 Google 原始 HTTP 响应，这是历史留档缺口。

这也不能证明更早的所有签发都已完整保存。最新证书中的服务端近似值是 128，而工作区
现能找到 37 张不同的 RKP 证书。差值可能同时包含未归档的其他历史签发和服务端近似
分桶，不能由 `128 - 37` 得出精确的“丢失 91 张”。能确定的是：历史记录不足以当作
服务器端全量台账，所以后续必须强制逐次落盘。

2026-08-26 的第一次网络提交因 CSRv3 字段错误返回 400，签发 0；修正后的第二次
提交返回 200，签发 1。两次的请求和响应都已保存。

完整机器可读台账：
`04_结果/outputs/rkp_issuance_ledger_20260826.json`。

## 3. 证书是不是 RKP

### 3.1 项目中的 37 张 Google RKP 证书

37/37 都同时满足以下特征：

- Subject 为 `O=TEE, CN=<随机 128-bit 标识>`；
- Issuer 为 `O=Google LLC, CN=Droid CA3`；
- 包含 Google Remote Key Provisioning 扩展 OID
  `1.3.6.1.4.1.11129.2.1.30`；
- 公钥为 P-256（`secp256r1`）；
- 证书签名算法为 ECDSA with SHA-256；
- `BasicConstraints CA=TRUE`。

另外，37/37 都能在各自的归档目录中组成完整的 4 证书链，逐层 issuer/subject
关系正确，逐层 ECDSA 签名及根自签全部验证成功。

`CA=TRUE` 不代表分类错了。RKP 下发的这张证书用于让该 attestation key
后续签发 Android key attestation certificate，因此本身是一张受限的签发证书，
不是普通 TLS 终端叶证书。

对历史最终批次 12 条链还额外复核了私钥对应关系：12/12 的第 0 张证书
公钥与对应私钥的公开部分一致。
本次 `google-rkp-sw` 返回链也已验证 1/1 叶证书与保存私钥匹配。

### 3.2 历史成功批次的四层结构

| 位置 | Subject | Issuer | 公钥 / 签名 | 有效期示例 |
|---|---|---|---|---|
| `cert_00` | `O=TEE, CN=<id>` | Droid CA3 | P-256 / ECDSA-SHA256 | 2026-08-14 至 2026-08-27，约 13.4 天 |
| `cert_01` | Droid CA3 | Droid CA2 | P-256 / ECDSA-SHA384 | 2026-08-15 至 2026-10-24 |
| `cert_02` | Droid CA2 | Key Attestation CA1 | P-384 / ECDSA-SHA384 | 2026-02-09 至 2029-02-08 |
| `cert_03` | Key Attestation CA1 | 自签 | P-384 / ECDSA-SHA384 | 2025-07-17 至 2035-07-15 |

历史成功批次还有直接的服务端证据：Google
`remoteprovisioning.googleapis.com/v1:signCertificates` 返回 HTTP 200，响应时间为
2026-08-16 11:05:27 UTC，响应长度 16108 字节，解析得到 12 条链。

### 3.3 本次 `google-rkp-sw` 成功证书链

| 顺序 | Subject | Issuer | 有效期（UTC） |
|---:|---|---|---|
| 0 | `O=TEE,CN=8082805171e0537a51311a9292ab6716` | Droid CA3 | 2026-08-24 09:09:08 至 2026-09-06 19:44:56 |
| 1 | Droid CA3 | Droid CA2 | 2026-08-25 17:02:12 至 2026-11-03 17:02:11 |
| 2 | Droid CA2 | Key Attestation CA1 | 2026-02-09 19:59:18 至 2029-02-08 19:59:18 |
| 3 | Key Attestation CA1 | 自签 | 2025-07-17 22:32:18 至 2035-07-15 22:32:18 |

原始服务器拼接顺序是 `Droid CA2 -> root -> leaf -> Droid CA3`，不是信任链顺序。
留档后处理已按 issuer/subject 重排为表中的“叶到根”，但原始 `response.cbor` 和
`certificate_chain.der` 保持不变。`keybox.xml` 内部证书顺序也已验证与重排链一致。

### 3.4 本次本地 CTF 自签测试证书

| 证书 | Subject / Issuer | 有效期（UTC） | 结构 |
|---|---|---|---|
| 本地叶证书 | Nothing A142 Local CTF RKP Leaf / Local CTF RKP Root | 2026-08-26 07:51:51 至 2026-09-25 07:56:51 | P-256，CA=FALSE |
| 本地根证书 | Local CTF RKP Root / 自签 | 2026-08-25 07:56:51 至 2027-08-26 07:56:51 | P-256，CA=TRUE |

本地叶证书有效期约 30 天，私钥与证书公钥匹配，叶签名可验证。但它没有
Google issuer，也没有 RKP OID `1.3.6.1.4.1.11129.2.1.30`，所以只是本地测试链，
不能当作 Google keybox 或 Google RKP 证书使用。

## 4. 32 字节是不是全部身份

32 字节是 256 bit 高熵私密根材料，不是可猜的序列号。它短，但并不容易伪造；
安全问题是一旦被完整提取，就可以无损复制，并用于签名新 challenge。

完整 RKP 身份还包括：

- 种子派生的公钥与签名；
- UDS certificates（如果平台提供）；
- DICE/BCC 链及上游签名；
- DeviceInfo、固件和启动状态测量；
- 服务端实时 challenge；
- 每次待签的 P-256 公钥。

本次实测已把“可能”提升为当前授权 CTF 身份的实证：该 32 字节秘密加上可复制的
DeviceInfo/DICE 公开结构，足以对新 challenge 签名并获得一条新 RKP 证书链。
所以从防守角度看，这 32 字节是可克隆的核心秘密。

但“完整身份只有 32 字节”仍不准确：请求还携带 DeviceInfo、DICE 封装和待签公钥。
区别在于后者可以从固件、历史 CSR 或配置中复制，而 32 字节种子提供了不可替代的
签名能力。这一结果不证明在未授权零售机上可以无 root 提取该秘密。

### 4.1 本次成功方案实际采集了什么

必须把四类输入分开：

| 类别 | 本次输入 | 来源 | 是否秘密 | 作用 |
|---|---|---|---|---|
| 从设备安全侧提取 | `rkp_bcc_km` KDF 的 32 字节输出 | 修改的 KeyMint TA 内部 KDF | **是，核心秘密** | 作为 Ed25519/CDI_Leaf seed，派生设备身份公钥并签新 challenge/CSR |
| 从设备/历史资料复制 | fingerprint、14 项 DeviceInfoV3、DICE issuer/subject 文本 | `getprop`、历史成功请求和配置 | 否 | 描述机型/build/启动状态并构造 DICE/CSR 外形 |
| 每次本地新生成 | P-256 attestation 私钥和公钥、临时 ECDH key、nonce | `google-rkp-sw` CSPRNG | P-256 私钥是本次证书对应秘密 | P-256 公钥进入 `KeysToSign`，Google 为它签发叶证书 |
| Google 实时下发 | fresh challenge、EEK chain、刷新配置 | `fetchEekChain` | 否，但有时效 | challenge 防重放；本次 CSRv3 对 fresh challenge 做身份签名 |

本次成功请求中实际发送的 DeviceInfoV3 为：

```text
brand/manufacturer     Nothing / Nothing
product/device/model   PacmanEEA / Pacman / A142
vb_state               orange
bootloader_state       unlocked
vbmeta_digest          32-byte digest
os_version             13
system_patch_level     202607
boot_patch_level       20190606
vendor_patch_level     20260705
security_level         tee
fused                  1
```

`fetchEekChain` 另发送 build fingerprint：
`Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`。

需要注意：这些 DeviceInfo 值是 CTF/历史配置值，不等于签发瞬间由 Google 远程读取
手机当前运行状态。本次请求的 DICE 链也是脚本用 32 字节 seed 构造的退化 DICE
`[身份公钥, 自签 entry]`，UDS certificates 位置为空；成功说明 Google 对当前登记身份
接受这种结构，不能外推到其他设备。

本方案没有采集或提交 IMEI、MEID、序列号、Android ID、Google 账号凭据、传统
factory keybox 私钥或完整 RPMB/TEE 镜像。root/修改 TA 用于把 32 字节材料从本机安全
侧导出；一旦已有该材料，`google-rkp-sw` 构造 CSR 和请求证书的阶段本身不再实时依赖
这台手机。

### 4.2 术语纠偏：32 字节、RKP 私钥和 ECC 不是同一层

“`google-rkp-sw` 使用 32 字节材料成功签发”不能缩写成“完整 RKP 只有 32 字节”。
本次实际存在两种不同私钥：

| 私钥 | 来源 | 算法/大小 | 用途 | 是否被 Google 叶证书认证 |
|---|---|---|---|---|
| 设备 provisioning 身份秘密 | 从 `rkp_bcc_km` KDF 导出 | 32-byte seed，脚本按 Ed25519 使用 | 派生 DICE/CDI 身份并签 fresh challenge + CSR | 否；它认证的是请求资格 |
| attestation signing 私钥 | 脚本每次新生成 | P-256 EC private key | 后续实际执行 Android key attestation | **是**；其公钥在 `KeysToSign` 中并成为叶证书公钥 |

因此完整路径是：

```text
提取的 32-byte 身份 seed
  -> 派生 Ed25519 身份私钥/公钥和退化 DICE 链
  -> 签名 [Google fresh challenge, DeviceInfo, 新 P-256 公钥]
  -> Google 验证设备身份
  -> Google 给该 P-256 公钥签 RKP 叶证书
  -> 最终可用材料 = 新 P-256 私钥 + Google 四层证书链
```

EC/ECC 是算法家族，不是必须另行提取的一份独立秘密。P-256 私钥本质上也是一个
256-bit 标量，公钥可从私钥确定性计算；Ed25519 的 32-byte private seed 同样可以
确定性派生 32-byte 公钥。本次 seed 派生出的 Ed25519 公钥已离线复核稳定，原文仍不
写入文档。

旧 sideleak/Binder 路线与当前路线的层级不同：

| 路线 | 得到/控制的东西 | 设备身份 CSR 由谁完成 | 能力边界 |
|---|---|---|---|
| 旧 direct sideleak + stock Binder | 每把 P-256 attestation key 的私有 scalar、对应 `MacedPublicKey` | stock KeyMint/TA | 主要恢复那一批已生成 key 的私钥 |
| 当前 32-byte + CSRv3 软件路线 | provisioning/DICE 身份签名 seed；P-256 key 由脚本新建 | `google-rkp-sw` | 可为新生成的 P-256 公钥构造新 CSR，但仍受服务端登记、配额和吊销策略约束 |

AOSP CSRv3 对这一分层写得很直接：`SignedData` 的签名使用
`CDI_Leaf_Priv`，而 CSR payload 中的 `KeysToSign` 是另一组待签的公钥。AOSP 还说明
Phase 1 Degenerate DICE 可以由 TEE root keypair 签请求并用一个自签 entry 表示。
本项目捕获物严格应称为 **`rkp_bcc_km` 32-byte 派生秘密，实测可作为当前身份的
Ed25519/CDI signing seed**；仅凭名称和单设备实验，不应无条件断言它是所有平台上都以
同样格式存放的原始 UDS 或 CDI_Leaf。

若口语里的“ECC”实际是指 **EEK**（Endpoint Encryption Key），则 EEK 是 Google
`fetchEekChain` 下发的服务端加密公钥，不是设备长期私钥。旧 CSRv2/ProtectedData
路线强依赖它；当前 CSRv3 的身份核心是 DICE/CDI 签名和 fresh challenge。

协议依据：

- [AOSP CSRv3 CDDL：CDI_Leaf_Priv 签 SignedData，KeysToSign 为另一组公钥](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
- [AOSP RKP：UDS/DICE 身份、Degenerate DICE 和 P-256 attestation key 分层](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/README.md)

## 5. 核心经验

- 要把“私密根材料可导出”、“CSR 可离线构造”和“Google 生产签发成功”分成
  三个完全不同的验收层级。
- CSR 上的签名 `VALID` 只能证明数学关系正确，不代表 Google 信任这条 DICE 链。
- CSRv3 的 DeviceInfo 不能混入 CSRv2 的 `version` 字段，也不能把
  `dice_issuer` / `dice_subject` 这类脚本内部参数放进 DeviceInfo。
- 证书数量必须按 RKP attestation certificate 指纹去重，不能把每条链的共享
  CA 重复计数。
- 判断 RKP 不应只看文件名或 keybox XML，应同时检查 issuer、RKP OID、公钥、
  链签名和生产 HTTP 响应证据。
- 本机 direct TA 试验依赖 ADB、`su`/Magisk 和允许加载修改 trustlet 的 CTF 环境。
  它不能证明市场上“无需 root”或“不解锁 BL”的说法。
- 生产请求绝对不能走“先发送，成功后再看要不要保存”的路径。必须先创建新的
  run 目录并保存私钥和 CSR，读回校验后才能调用签发端；收到响应后先原样落盘，
  再做 CBOR 解析。
- 任何成功批次的完整性条件是：原始请求、原始响应、HTTP metadata、每把私钥、
  每条完整证书链、拆分 DER/PEM、私钥—证书公钥匹配、证书有效期和 provisioning
  information 扩展全部有记录。
- 服务器回传的 DER 拼接顺序不能当作信任链顺序；应根据 issuer/subject 重排，
  同时保留原始 bytes 供取证。

## 6. “默认 14 天，再往后延两周”说法的判断

### 6.1 最可能的实现：14 天后重新 provision 一张

这不是把第一张证书的到期日改长，而是用仍然有效的设备级 RKP 身份能力再走一次
provisioning：

```text
设备级身份材料（本项目中是 32 字节核心秘密 + 可复制的公开结构）
  -> 获取新的服务端 challenge / EEK
  -> 新生成一把 P-256 attestation key
  -> 构造包含新公钥的 CSR
  -> Google 再签一张新的约 14 天 RKP 证书
  -> 用新私钥和新证书链替换上一份 keybox
```

本地 `google-rkp-sw` 的代码路径正是这样：每次运行先调用
`generate_ec_keypair()` 生成新的 P-256 私钥，再把新公钥放入 `KeysToSign`；32 字节
材料派生的是签署新 challenge/CSR 所需的设备身份能力，不是那张短期 P-256
attestation key 本身。

因此，商家只要保留了可被签发端接受的设备身份材料，或者一直能访问作为身份源的
设备，就可能在第一张快到期时再申请一张新证书。两段约 14 天窗口接起来，商业上会
被称为“延长两周”或“30 天服务”，但密码学上应称为 **换证/轮换**。

能否再次成功仍由服务端决定，可能受设备状态、固件信息、风险策略、颁发统计和限额
影响，不应把一次成功推导为可以无限续签。

### 6.2 同一张证书本身仍然不能延期

X.509 的 `notBefore`、`notAfter` 位于受 Google CA 签名保护的
`tbsCertificate` 中。修改第一张证书的 `notAfter` 会立刻破坏签名。因此：

- 第一张证书到期后仍然是过期状态；
- 第二个两周窗口必须由另一张 Google 签名证书提供；
- 如果第二张仍使用同一个 P-256 公钥，也必须有新的 DER、序列号、有效期和 Google
  签名；本项目脚本当前没有走这种同公钥重签路线，而是每次生成新 P-256 key；
- 只修改 XML、回拨客户端时间或签一个更长有效期的下级证书，都不是严格验证意义下
  的 RKP 延期。

Android 当前验证文档明确要求 RKP 证书持续检查有效期；AOSP RKPD 也以链中 RKP
证书的 `notAfter` 记录 key 的过期时间，并避免分配过旧 key。

### 6.3 为什么不能一次提前申请两张再分开发

证书有效期由服务端签发时写入，不从商家开始销售或用户第一次使用时起算。如果同一天
申请两张，两张通常处在相同或高度重叠的有效期窗口；把第二张文件藏 14 天再交付，并
不会让它的 `notAfter` 自动向后移动。

要真正增加第二个窗口，合理做法是在更晚的时间重新取得 challenge 并重新签发，或者
由商家的模块/API 在后台按时下载替换后的新 keybox。若用户拿到的只是一个永不更新的
静态 XML，它不能在第 14 天凭空多出另一个有效窗口。

### 6.4 本项目现有链的只读控制验证

本次 RKP 证书于 2026-09-06 19:44:56 UTC 到期，中间 CA3 到 2026-11-03 才到期。
将 OpenSSL 验证时间设为 2026-09-10 后，现有完整链仍在 depth 0 返回：

```text
error 10 at 0 depth lookup: certificate has expired
verification failed: 10 (certificate has expired)
```

这证明任何所谓“再延两周”都不能由现有链的 CA3 剩余寿命提供；必须出现新 RKP
证书，或者依赖不严格检查有效期的特定验证端。

官方实现参考：

- [AOSP RemoteProvisioner：约每 24 小时检查，并支持按需 provisioning](https://android.googlesource.com/platform/packages/apps/RemoteProvisioner/+/HEAD/README.md)
- [AOSP Provisioner：以链中 RKP 证书 notAfter 记录过期时间](https://android.googlesource.com/platform/packages/modules/RemoteKeyProvisioning/+/582e0fe0e93093a499adb9286ea9f4733b0d3a28/app/src/com/android/rkpdapp/provisioner/Provisioner.java)
- [AOSP ProvisionedKeyDao：过滤、删除即将过期或已过期的 key](https://android.googlesource.com/platform/packages/modules/RemoteKeyProvisioning/+/4892b71dfe6dca1772f2a701cbec0b58611ef56f/app/src/com/android/rkpdapp/database/ProvisionedKeyDao.java)
- [Android Developers：RKP 证书必须检查有效期](https://developer.android.com/privacy-and-security/security-key-attestation#expired-factory-keys)

### 6.5 如何向商家验证

索取第一次和“延期后”的两份完整 keybox/证书链，对两张 RKP 证书比较：

- DER SHA-256；
- serial number；
- SubjectPublicKeyInfo SHA-256；
- `notBefore` / `notAfter`；
- RKP OID `1.3.6.1.4.1.11129.2.1.30` 及其中的近 30 天近似颁发量；
- 第二张交付时间和完整路径验证结果。

| 第二份证据 | 实际机制 |
|---|---|
| 新 DER、新序列号、新公钥、晚约两周的 `notAfter` | 新 key + 新证书，标准 RKP 轮换 |
| 新 DER、新序列号、同公钥、晚约两周的 `notAfter` | 同一 attestation key 被重新签证；仍是新证书，需要 Google 新签名 |
| 文件始终不变，但商家/API 在第 14 天下发新 XML | 商家代管身份并提供续签/替换服务 |
| 同一 DER 声称 `notAfter` 已改变 | 不成立；同一签名证书不能这样延期 |
| 同一旧链只在某个工具中继续通过 | 该验证器可能忽略过期，不是标准续签 |

当前证据下，**“再延两周”最符合一次初始签发加一次延后重新签发**。商家真正有价值的
资产很可能不是现成的 14 天 keybox，而是能在以后继续签 CSR 的设备级身份材料或设备
访问能力。

### 6.6 公开网络资料检索结论

2026-08-26 按商家原话检索后，公开资料的证据强度如下：

1. Google/Android 当前公开文档确认 RKP 使用短期证书，而且必须持续检查 RKP
   有效期，但没有找到一条把所有生产 RKP 证书固定写死为精确 14 天的公开规范；
2. AOSP 明确记录周期和按需 provisioning，并允许后端按设备型号下发过期预警等
   配置，说明补充/轮换是设计内行为；
3. `google-rkp-sw` 的公开仓库说明每次 `provision` 都为 P-256 key 构造新 CSR，
   再调用 Google `signCertificates`，与“以后再签一张”的模型一致；
4. 公开社区中已有提取者明确声称其 RKP 证书有效 14 天，可作为当前市场观察，但不是
   Google 规范；
5. 没有找到权威资料支持“同一张 RKP 证书到期后自动宽限 14 天”或客户端能修改
   Google 已签 `notAfter` 的说法。

本次实签证书自身是最强的当前样本：完整 X.509 窗口约 13.44 天，但它的
`notBefore` 比实际 HTTP 200 响应早约两天。因此从本次收到响应到 `notAfter`，实际只剩
**11 天 10 小时 46 分 39 秒**。商家口中的“14 天 + 14 天”更可能是按证书名义窗口
计价，不应直接理解为从交付时刻起保证完整 28 天。

公开参考：

- [Google/Android：RKP 有效期必须检查](https://developer.android.com/privacy-and-security/security-key-attestation#expired-factory-keys)
- [AOSP RemoteProvisioner：周期、按需及服务端配置](https://android.googlesource.com/platform/packages/apps/RemoteProvisioner/+/HEAD/README.md)
- [google-rkp-sw：以设备 seed 构造 CSR 并请求 Google 证书](https://github.com/MhmRdd/google-rkp-sw)
- [公开社区样本：提取者称 RKP 证书有效 14 天](https://www.reddit.com/r/Magisk/comments/1vqnf2v/keyboxi_have_extracted_the_keybox_and_rkp_from/)

### 6.7 能否请求 28 天，或把 14 天延期为 28 天

#### 本次证书从收到时算确实只剩约 11.45 天

三个可信时间点为：

```text
RKP leaf notBefore       2026-08-24 09:09:08 UTC
Google HTTP Date         2026-08-26 08:58:17 UTC
RKP leaf notAfter        2026-09-06 19:44:56 UTC
```

因此：

- 证书字段内总窗口：13 天 10 小时 35 分 48 秒，约 13.44 天；
- 从 Google HTTP 200 返回到过期：11 天 10 小时 46 分 39 秒，约 11.45 天；
- `response_http.json` 的本地捕获时间与 Google `Date` 响应头相同，排除本机时钟错误
  或保存晚了两天；
- 新 P-256 key 是请求前几秒才在本地生成的，所以证书不可能真的在 8 月 24 日已存在；
  这是签发端主动设置了早于签发时刻的 `notBefore`。公开资料未说明 RKP 后端的具体
  回溯/时间分桶算法，不能进一步断言内部原因。

#### 标准 CSR 没有“申请 28 天”字段

AOSP CSR v3 的固定结构只有：

```text
[version, CertificateType, DeviceInfo, KeysToSign]
```

`KeysToSign` 只包含待签公钥。公开 CDDL 中没有 `duration`、`validity`、`notBefore`
或 `notAfter`。AOSP 客户端调用的签发 URL 也只有：

```text
:signCertificates?challenge=<server challenge>
```

POST body 是 CSR，没有续期或天数参数。本次 `fetchEekChain` 返回的配置只有：

```text
time_to_refresh_hours        72
num_extra_attestation_keys   12
```

前者是设备多早检查/补充即将过期 key 的刷新策略，后者是希望保留的额外 key 数量；
二者都不是请求证书寿命。

#### 结论

- 没有发现公开、标准的“请求 28 天 RKP”参数；
- 没有发现把现有 14 天证书原地延期的接口；
- Google 后端在技术上可以按自己的策略签出更长证书，早期官方资料也曾描述“最长
  两个月”，但客户端不能通过当前公开 CSR 选择 28 天；
- 对本次 Nothing 身份，当前生产端实际选择的是约 13.44 天总窗口；
- 公开可见的正常延续方式是以后重新获取 challenge、提交新 key/CSR，并获得另一张
  短期证书。它可以形成两个连续窗口，但不是一张 28 天证书。

协议证据：

- [AOSP CSR v3 CDDL：只有证书类型、DeviceInfo 和 KeysToSign](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl)
- [AOSP ServerInterface：公开客户端只有 fetchEekChain 与 signCertificates](https://android.googlesource.com/platform/packages/apps/RemoteProvisioner/+/refs/tags/android-13.0.0_r15/src/com/android/remoteprovisioner/ServerInterface.java)
- [AOSP RKP 流程：服务端验证 CSR 后自行生成证书](https://android.googlesource.com/platform/hardware/interfaces/+/main/security/rkp/README.md#design)

### 6.8 Google 会不会按当前设备可信度决定有效期

**技术上可以，但公开证据只证明“可信度会影响签不签”，尚不能证明 Google 会把单台
设备的可信度分数直接映射为不同的证书天数。**

可以确认的部分：

1. Google 官方介绍明确说，RKP 后端可以停止向运行已知被攻破软件的设备 provision
   新证书。也就是说，设备身份、软件版本和可信状态至少会影响接受或拒绝；
2. AOSP RemoteProvisioner 会向后端提供设备 ID 和 build fingerprint，后端可以按
   设备型号/软件批次下发不同配置，配置中包括 key 的过期预警阈值和备用 key 数量；
3. CSR 的 `DeviceInfo` 还暴露 verified-boot 状态、bootloader 状态、补丁级别、
   security level 等信息，Google 在签发时有足够信息实行型号、版本或风险策略；
4. 证书的 `notBefore`/`notAfter` 完全由服务端写入，客户端 CSR 没有寿命参数。因此
   Google 若要按策略区分寿命，在协议上做得到。

但上述资料没有写明存在如下规则：

```text
单台设备可信分数较高 -> 签 14/28 天
单台设备可信分数较低 -> 签 7/11 天
```

本项目还对目标二目录中带 provisioning-information OID 的 DER 叶证书做了只读去重
统计，共得到 **37 张唯一 RKP 叶证书**。四批样本如下：

| 批次 | 证书内近 30 天近似颁发量 | 唯一叶证书数 | 叶证书总有效窗口 |
|---|---:|---:|---|
| pool 参考批次 | 8 | 12 | 13 天 7:52:09 ～ 13 天 8:25:39 |
| stock rkpd 基线批次 | 16 | 12 | 13 天 0:28:25 ～ 13 天 1:04:58 |
| Google 12-chain 批次 | 128 | 12 | 13 天 9:08:25 ～ 13 天 9:44:09 |
| 本次单 key 批次 | 128 | 1 | 13 天 10:35:48 |

尽管证书内的近 30 天近似颁发量从 8、16 上升到 128，37 张证书的总窗口仍全部紧密
聚集在约 13 天。至少在这台 Nothing 身份的现有样本里，没有观察到“颁发次数越高/
越可疑，证书寿命越短”的简单关系。几个批次相差数小时，更像服务端批次、时间分桶或
统一签发策略造成的差异；这是基于样本的推断，不是 Google 已公开的内部算法。

因此当前最稳妥的判断是：

- **可信度很可能首先决定能否签发**，例如拒绝已知受攻破的软件或异常身份；
- **后端也可以按型号、build、灰度批次选择策略**；
- **不能排除** Google 内部还会按风险调整有效期，但目前没有官方说明或本项目证据；
- 本次“收到后只剩 11.45 天”主要由服务端把 `notBefore` 回溯近两天造成，不能据此
  单独推断设备被降信任或处罚；
- 要验证按可信度动态定时，需在授权条件下比较多个设备型号、build/boot 状态和多个
  时间批次；继续向同一身份重复申请只会增加颁发量，不能形成有效对照，本次没有这样做。

公开依据：

- [Google Android Developers Blog：后端可停止向已知受攻破软件的设备 provision](https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html)
- [AOSP RemoteProvisioner：设备 ID/build fingerprint 与服务端分型号配置](https://android.googlesource.com/platform/packages/apps/RemoteProvisioner/+/HEAD/README.md)
- [Android Key Attestation：RKP 有效期与 provisioning information](https://developer.android.com/privacy-and-security/security-key-attestation)

### 6.9 公开论坛和社区样本检索

2026-08-26 继续检索 Reddit、4PDA、Telegram 公开频道、XDA 和 GitHub issue。社区资料
只能作为观察样本，不能替代证书 DER 或 Google 规范。

#### 找到的直接有效期口径

- Reddit `r/Magisk` 一位声称能提取 keybox/RKP 的发布者明确写道，其可供测试的 RKP
  证书“valid for 14 days”。帖子没有附 DER、`notBefore`/`notAfter` 或不同可信状态的
  对照，所以只能证明当前市场有人使用 14 天口径；
- 没有找到有人公开展示同一设备在 locked/unlocked、stock/custom build 或不同风险
  状态下，分别获得 7、14、28 天生产 RKP 叶证书的可验证样本；
- 也没有找到商家展示一张原 14 天证书被原地改为 28 天的前后 DER。

#### 社区更常见的是“成功/失败”，不是缩短寿命

- Magisk Alpha 公开频道记录：部分 Oplus 设备解锁 bootloader 后密钥认证直接失败，
  回锁恢复。该观察可能同时涉及 OEM KeyMint/TEE 策略，不能单独归因于 Google 后端，
  但表现是拒绝/失败，不是发一张更短的证书；
- 4PDA 的 Redmi Note 12 讨论称设备会周期性获得/更新由 Google 签发的 ECDSA RKP
  证书，但帖子没有给出周期长度；
- 另有 Reddit 评论声称“server side memory is 14 days”，上下文讨论的是服务端设备
  状态/完整性记忆，没有提供 RKP 证书字段。它不能用来证明证书寿命是 14 天，更不能
  证明可以续期 14 天；
- 公共 keybox 被吊销后“一周都用不到”的社区抱怨讨论的是共享泄露证书被 Google
  封禁，不是 Google 在签发时把 X.509 `notAfter` 缩短到一周。

#### 与 AOSP 权威条件交叉核对

AOSP RKP/DICE 设计给出了更明确的生产资格门槛：DICE 链中的每张证书都必须处于
`normal` mode 才能获得 production RKP 证书；`normal` 要求 verified boot 与
anti-rollback 开启、只允许生产启动授权、关闭 debug 能力并从正常主存储启动。

这进一步支持：**启动链可信状态会决定是否获得生产证书**。但同一文档没有规定
`normal` 内部再按可信度分数分配不同有效期。

论坛检索后的结论没有改变：当前公开证据支持“可信状态决定签/不签、可撤销/不撤销”，
不支持“可信度越低就签得越短”。Google 后端有实现后者的技术能力，但若商家声称某个
身份能拿 28 天，应要求其提供完整 DER，以 `notBefore`/`notAfter` 验证，而不能只听
“高可信设备”或“服务端记忆”话术。

社区与协议链接：

- [Reddit：提取者声称 RKP 证书有效 14 天](https://www.reddit.com/r/Magisk/comments/1vqnf2v/keyboxi_have_extracted_the_keybox_and_rkp_from/)
- [Magisk Alpha：RKP 测试和 Oplus 解锁 BL 后认证失败观察](https://t.me/s/MagiskAlpha?before=672)
- [4PDA：Redmi Note 12 的周期性 Google RKP 证书观察](https://4pda.to/forum/index.php?showtopic=826244&st=64540)
- [AOSP RKP/DICE：production provisioning 要求整条链为 normal mode](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/README.md#mode)

## 7. 产物和证据

- 本次成功运行目录：
  `04_结果/outputs/google_rkp_sw_live_1key_20260826_03`
- 可直接使用的完整 keybox：同目录 `keybox.xml`
- 私钥：同目录 `key_00/private_key_pkcs8.pem`
- 原始 CSR / 响应：同目录 `certificate_request.cbor` / `response.cbor`
- 证书链结果：同目录 `chain_00/`
- 独立验证摘要：同目录 `verification_report.json`
- 全文件哈希清单：同目录 `SHA256SUMS.txt`
- 离线 CSR：`third_party/google-rkp-sw/ctf_artifacts/ctf_csr_v3.cbor`
- CSR 摘要：`third_party/google-rkp-sw/ctf_artifacts/ctf_offline_csr_summary.json`
- 本地 keybox：`third_party/google-rkp-sw/ctf_artifacts/ctf_local_keybox.xml`
- 本地证书摘要：`third_party/google-rkp-sw/ctf_artifacts/ctf_local_keybox_summary.json`
- 历史 12 链摘要：
  `正规目录_按目标分类/目标三_PI3层绕过/04_RKP输入与转换/final_google_signcerts_12chains副本/signed_chains_summary.json`
- 历史 12 链 OpenSSL 验证：同目录 `openssl_verify_all.json`
- 历史 Google 响应摘要：同目录 `response_http.json`
- 签发台账：`04_结果/outputs/rkp_issuance_ledger_20260826.json`

含种子、私钥或 keybox XML 的文件均应按敏感材料管理，不应提交到公开仓库。


---

## 原始记录段 4 / Source section 4: 04_CTF_Keybox_安全测试报告_20260826.md

# CTF Keybox 安全测试报告

文档类型：报告（只针对传统 KeyMint factory Keybox，不包含 RKP 签发结果）

报告日期：2026-08-26

## 1. 范围和目标

本报告记录授权 CTF 环境内 Nothing A142 / Pacman / MT6886 的传统
Android KeyMint factory attestation Keybox 提取结果。目标是验证：

1. `/mnt/vendor/persist/attest_keybox.so` 的明文是否会在 KeyMint TA 中出现；
2. 在允许加载修改 trustlet 的 CTF 条件下，是否可将明文复制到 normal world；
3. 解析出的 EC/RSA 私钥、证书链和 `keybox.xml` 是否完整可验证。

本报告不评估 RKP CDI/DICE 材料、RKP CSR 或短期 RKP 证书。这些内容单独放在
`目标二_提取RKP`。

## 2. 测试结论

结论：**Keybox 提取目标已完成。**

已从 KeyMint TA 解密路径中导出明文 keybox，并保存：

- 1 把 EC attestation 私钥及 3 张 EC 证书；
- 1 把 RSA attestation 私钥及 3 张 RSA 证书；
- 1 份 AndroidAttestation `keybox.xml`；
- 私钥—叶证书公钥匹配记录；
- EC/RSA 链验证和独立签名验证记录。

关键数量：

```text
plaintext keybox length  8624
EC private key DER       138 bytes
EC certificate count     3
RSA private key DER      1794 bytes
RSA certificate count    3
unmodified mapped tail   92 bytes
```

## 3. 技术根因

问题不是 `attest_keybox.so` 在 normal world 可被直接解密，而是一条组合链：

```text
启动链/TEE 测试能力
  -> 允许加载修改的 KeyMint trustlet
  -> stock 安全对象进入 KeyMint TA
  -> TA 内部正常解密和解析
  -> patch 将短暂存在的 plaintext 复制回 mapped buffer
  -> direct client 保存明文并拆分 DER
```

主要安全边界破坏是：原本只应在 secure world 中存在的 factory attestation
私钥明文，被复制到 normal world 可读缓冲区。

## 4. 证据和验证

### 4.1 输入指纹

```text
stock KeyMint TA
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2

attest_keybox.so
64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69

attestation_ids.so
5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74
```

### 4.2 Patch 和对照

- 未 patch TA：命令成功，mapped buffer before/after 相同；
- patch TA：命令成功，mapped buffer 前 8624 字节变为 keybox 明文；
- patch 后 TA SHA-256：
  `92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016`。

### 4.3 密钥和证书

- EC 私钥公开部分与 EC `cert_0` 公钥相同；
- RSA 私钥公开部分与 RSA `cert_0` 公钥相同；
- EC/RSA 证书链 OpenSSL verify 都为 `OK`；
- EC/RSA 私钥独立签名后，对应公钥验签通过。

EC 和 RSA factory attestation 叶证书的有效期均约为 10 年：

```text
EC  2023-10-16 23:37:51Z -> 2033-10-13 23:37:51Z
RSA 2023-10-16 23:37:50Z -> 2033-10-13 23:37:50Z
```

这与 RKP 约 14 天的短期 attestation signing certificate 不是同一种产物。

## 5. 安全影响

- factory attestation 私钥失去不可导出性；
- 提取后的私钥和链可在设备外部复制；
- 多台实例复用同一 keybox 时，都共享同一 attestation 身份，不会产生多个独立
  factory 身份；
- 只依赖证书链、不检查 boot state、patch level、撤销和风险信号的验证端可能
  被误导。

## 6. 边界和限制

- 实验依赖授权 CTF 环境、ADB/root、启动链修改和加载修改 TA 的能力；
- 结果不证明锁定零售机可以无 root 完成同样提取；
- 报告不把 RKP 短期证书或 32 字节 CDI/DICE 种子计入 Keybox 产物；
- 私钥和 `keybox.xml` 是高敏感资产，不应提交到公开仓库。

## 7. 修复建议

1. 启动链和 TEE loader 在 unlock 状态下仍必须拒绝未授权 secure-world 代码。
2. Trustonic loader 应完整校验 trustlet 签名、UUID 和 rollback 状态。
3. KeyMint TA 应缩短明文生命周期，使用后及时清零，并限制敏感初始化命令的可调用上下文。
4. 服务端应将证书撤销、启动状态、补丁级别和异常复用信号结合，不只信任链签名。

## 8. 产物入口

- 教程：`01_文档/02_二次复现文档.md`
- 流水账：`01_文档/01_全流程流水账.md`
- 原理：`01_文档/03_漏洞原理详解.md`
- 最终产物：`04_结果/outputs/extracted_keybox/`
- 最终 XML：`04_结果/outputs/extracted_keybox/keybox.xml`
