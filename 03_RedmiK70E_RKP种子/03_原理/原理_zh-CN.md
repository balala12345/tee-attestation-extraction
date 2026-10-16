# Redmi K70E：RKP/CDI 原理与证据边界（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里保留 CDI leaf、UDS、DICE、DeviceInfo、RKP CSR、Google 审批门和 stock/modified 路线差异的完整分析。

---

## 原始记录段 1 / Source section 1: 64_K70E_CTF_Nothing_seed层级与UDS根提取可行性_20260906.md

# K70E CTF Nothing seed 层级与 UDS 根提取可行性

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 结论修正：**本文对 final leaf scalar 不是最底层 seed、Nothing/K70E DICE 形态不同的术语分析仍有效。但“modified DICE 不能最终签发、必须先提更早 root 或恢复 stock”已被实测推翻：当前 final leaf scalar + exact modified DICE + clean DeviceInfo 已获 Google `APPROVED`。对当前 CTF 不需要再挖更底层 seed。见文档 65–70。

> 日期：2026-09-06（Asia/Taipei）  
> 目标设备：Redmi K70E / `duchamp` / `<DEVICE_SERIAL>` / A 槽  
> 审计性质：纯离线；没有连接手机、没有调用 Binder、没有联网、没有写分区  
> 权威顺序：原始状态文件 > 文档 59 > 文档 60 > 文档 61 > 文档 62 > 文档 63。文档 59–63 是暂停/交接主线；本文仅保留为可选离线研究支线，本文件不覆盖它们。文档 58 仅作历史记录，旧八步表已经撤销。  
> 秘密边界：本文不记录 CDI/UDS 私密字节、软件私钥、完整 MiTEE 日志或 BROM challenge。

---

## 0. 一页结论

用户关于“Nothing 的值能单独用，而 K70E 的值已经太晚、受启动环境影响”的核心观察是对的；但准确术语不是简单的“Nothing 更早”。

- 两者使用同一个 Android RKP CSRv3/Google 签发协议。
- Nothing 成功样本使用的是 **degenerate DICE（退化 DICE）**：`UDS_Pub == CDI_Leaf_Pub`，同一把硬件绑定身份键既当根又当 leaf，只带一个自签条目；因此一个可直接重建该键的 32-byte 值就足够构造请求。
- K70E 原生使用 **proper DICE（完整测量 DICE）**：独立 UDS 根加五个逐级签名的测量条目。现有 `0xdd934:x26` 是最后 KeyMint 层已经派生完成的 P-256 `CDI_Leaf` 私钥标量，它继承所有上游测量，修改 preloader/LK/TEE 等会改变它。
- “早/晚”不是唯一维度。一个运行得很晚的 TA 也可能从独立的硬件根 KDF 分支取到稳定身份；一个运行得很早的阶段也可能已经拿到 measurement-bound CDI。真正目标必须定义成：**能够重建本机原生 UDS 公钥的根私钥材料**，而不是“任意更早的 32 字节”。
- 当前官方 CN304 的 stock 接口没有导出 UDS/root/private。最早可见的软件消费点在 preloader 第一次 DICE 派生前，但其输入来自更早的 ROM/硬件 handoff；修改 preloader 抓取会污染后续测量，而且不能保证拿到的是 raw UDS。
- CVE-2026-20435 是相关研究线索，但当前只在 engineering preloader 证明了无认证 `GET_SOC_ID/GET_ME_ID`。精确 CN304 production preloader 没有该 USB dispatcher；也没有证据证明这些 ID 等于或足以重建 MiTEE HWBCC/DICE UDS。
- 因此，**“提取更早 root/seed”现在不能升为实机完成主线**。它是有价值的离线研究支线。当前完成主线仍是：先成对修复官方 CN304 `vendor_boot_a + init_boot_a`、重新建立可启动且服务器认可的 stock/approved 测量环境，再从 stock MiTEE 日志取得同轮最终 leaf，最后只执行一次受控 `google-rkp-sw` 签发。

这不是说理论上永远做不到；而是当前没有同时满足“值语义正确、能重建 UDS、不会变砖、不会自污染”四个条件的入口。

## 1. 协议相同，身份证明形态不同

Android RKP 的 `generateCertificateRequestV2` wire protocol 同时允许 proper DICE 和 degenerate DICE。AOSP 明确定义：

- proper DICE 从 UDS 根开始，每个启动阶段用前级秘密和下级代码/配置测量产生新的 CDI；服务器可验证设备身份和具体启动软件；
- degenerate DICE 只有一个自签硬件绑定键，`UDS_Pub` 与 `CDI_Leaf_Pub` 相同，适用于没有实现完整 DICE 的设备。

官方规范：

- https://android.googlesource.com/platform/hardware/interfaces/+/5f3589afed165a8a5fc8b14bf33a7e49cf382d13/security/rkp/aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.aidl

因此，“协议一样”完全正确；不同的是服务器收到的 DICE 身份结构和注册 profile。

### 1.1 Nothing 有两条成功路线，本文讨论的是哪一条

工作区至少保存了两条不同的 Nothing 成功路线：

1. 2026-08-16 的 12-chain 旧路线：从具体 RKP keygen 路径导出每把待签 P-256 key 的 private scalar，再配合 stock Binder/公开请求材料提交。它不是一个长期设备 seed。
2. 2026-08-26 的单密钥 `google-rkp-sw` 路线：修改 Nothing KeyMint TA，在内部调用 KDF `0x22770`，标签为 `rkp_bcc_km`、输出 32B、status=0；该输出与另一独立 KeyMint 会话结果一致。脚本把它按 Ed25519 identity seed 使用，Google `signCertificates` 返回 HTTP 200。

用户所说“Nothing 提取的 seed 可以直接用”，指第 2 条，这个事实成立。后面的 K70E 比较只针对这条 32B `rkp_bcc_km` 路线，不能拿第 1 条 per-key scalar 当作佐证。

更重要的是，`rkp_bcc_km` KDF 是在已经运行到 KeyMint TA 后才被调用和导出的；它在时间线上并不比 K70E 的 KeyMint leaf 抓点更早。它之所以能直接用，是因为输出的**密码学语义**是 Nothing 退化 RKP profile 的稳定 provisioning 身份 seed，而不是因为 dump 指令发生得更早。

### 1.2 Nothing 单密钥请求的结构

现有成功请求离线解码为：

```text
DiceCertChain = [root COSE_Key, one self-signed DiceChainEntry]
root key == entry subject key == outer signing key
curve = Ed25519
```

`google-rkp-sw` 不识别输入来自 UDS、CDI、HUK、TA KDF 还是文件。它只按曲线把 32 字节变成一把软件私钥，然后固定构造上述退化链。Nothing 的值能用，只能证明该 32-byte 值能重建服务器认可的那把退化身份键；不能仅凭文件名 `seed` 证明它是在更早启动阶段抓到的 raw UDS。

更准确的描述是：**Nothing 的 RKP 身份 profile 把根与 leaf 折叠了，而且 `rkp_bcc_km` 是一个稳定 provisioning 身份分支的输出，不是 K70E 这种完整启动测量链的最终 descendant。**

因此 K70E 的类比目标不是“把 dump 点机械地提前一层”，而是“找到能重建 K70E 已登记 UDS 的稳定根分支或根签名能力”。

### 1.3 K70E 原生样本

现有 K70E native zero-key 请求离线验证为：

```text
DiceCertChain = [independent P-256 UDS root, five ES256 DiceChainEntry]
outer request signed by final CDI_Leaf private key
UDS SPKI SHA-256 = d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9
```

历史 approved 与 modified rejected 的 UDS 公钥保持相同，但 final leaf 公钥、DICE 测量和完整 payload 变化。这个对照直接证明：K70E 的 UDS 是稳定身份根，当前提取的 final leaf 是测量相关后代。

## 2. `google-rkp-sw` 的“seed”不是通用 DICE 根派生器

当前仓库 commit 基线为 `8a74e55`。代码的真实行为：

```text
Ed25519: Ed25519PrivateKey.from_private_bytes(seed)
P-256:   d = int.from_bytes(seed, "big")，要求 1 <= d < n
default chain: [same key, self-signed entry]
```

工作区证据：

- `third_party/google-rkp-sw/rkp_sw.py` 的 `DeviceKeys`；
- `build_dice_chain()` 固定返回同一键的 root 加一张自签条目；
- 本地 modified 主线虽然增加 proper-DICE 导入和严格门禁，但默认 seed 的密码学含义没有自动变成 Open-DICE raw CDI。

所以必须区分两种“拿到 root seed”：

1. **拿到最终 UDS P-256 私钥标量**：可以直接作为当前 P-256 `google-rkp-sw` 的 32-byte 输入，并先离线重建 UDS SPKI。
2. **拿到 raw UDS、initial CDI、HUK/HBK 输出或某个 KDF 输入**：不能直接喂给当前脚本。必须先复现 K70E 的 exact `DiceKeypairFromSeed`/KDF，把它转换成 UDS 私钥标量。

任何候选的第一道门都不是“长度等于 32”，而是：

```text
candidate
  -> 按候选语义执行 exact derivation
  -> derive P-256 public key / SPKI
  -> SHA-256 必须精确等于 d1a3f13b...a3c9
```

不匹配时只能叫“32-byte 候选”，不能叫 K70E UDS identity seed。

## 3. K70E 已确认的层级

### 3.1 简化链

```text
ROM / hardware initial secret or handoff
  -> official preloader first visible DICE consumption
  -> BL2_EXT: pvmfw / ATF / TEE DICE updates
  -> ATF copies current CDI_Attest + CDI_Seal
  -> /dev/misc/hwinfo exposes current CDI pair + public BCC
  -> KeyMint TA gets current parent CDI_Attest
  -> KeyMint "CDI_Attest" KDF / P256KeypairFromCDI
  -> 0xdd934:x26 final P-256 CDI_Leaf scalar
  -> outer CSRv3 signature
```

### 3.2 `/dev/misc/hwinfo` 不是 root 出口

official CN304 `hwinfo`/ATF 的离线逆向已经确认：

- SMC `0x82000021`, x2=0：current CDI_Attest；
- x2=1：current CDI_Seal；
- x2=2：public BCC；
- 其他 x2：立即拒绝。

没有 x2=3，也没有 UDS、HUK/HBK、root private、私钥导出或根签名 oracle。AOSP Trusty 的 HWBCC handover 设计同样只交付当前 CDI pair 和 BCC，不把前级 UDS 私钥交给后级：

- https://android.googlesource.com/trusty/external/trusty/+/master/ql-tipc/include/trusty/hwbcc.h

### 3.3 `get_attest_cdi` 仍不是 final leaf

BL2_EXT 会从 PA `0x1040d640/+0x20` 读取两组 CDI，并对 pvmfw、ATF、TEE 三个 flow 逐级更新；ATF 只把更新后的 2×32B 搬给 hwinfo。KeyMint 再以其中的 current CDI_Attest 做一次 `CDI_Attest` KDF，成功点 `0xdd934:x26` 才是 final P-256 leaf scalar。

因此：

- 抓 hwinfo CDI 比 x26 早一层，但已经继承 preloader/BL2_EXT 测量；
- 抓 BL2_EXT 输入更早，但已经过 preloader；
- “更早一层”不等于“回到 UDS”。

### 3.4 preloader 最早可见消费点

exact CN304 preloader 中，`0x1040d640` 只在 DICE driver 内出现。成功路径在第一次 DICE main wrapper 前从该 PA 读取两组 32B：

```text
read incoming pair   file 0x74adc..0x74afc
DiceMain calls       file 0x74b2c / 0x74b5c
write updated pair   file 0x74fc4..0x7503c
```

preloader 内没有已证明的普通 setter。严格结论是：这里是 **最早可见的软件消费点**；初始值可能由 BROM/硬件 handoff 提供，也可能在更低层硬件回调中生成。不能把它直接命名为 raw UDS。

修改 preloader 在该点 dump：

- 可能得到 incoming initial/current CDI；
- 不保证得到 UDS 私钥标量；
- 会改变 preloader 测量，使同次启动后续 DICE/BCC 自污染；
- 在当前设备恢复状态下还会引入最高级别变砖风险。

## 4. CVE-2026-20435 能证明什么，不能证明什么

MediaTek 官方公告确认 MT6897 preloader 存在 CVE-2026-20435，可在物理接触下无额外权限读取 device-unique identifiers：

- https://www.mediatek.com/product-security-bulletin/March-2026

RECON 2026 的 Ledger Donjon 摘要称其 PoC 可向 preloader 请求推导 TEE cryptographic root 所需的输入，并仍需一次 initial encrypted-flash read：

- https://cfp.recon.cx/recon-2026/talk/KZCARU/

本地 engineering preloader 逆向已确认：

```text
handshake A0 0A 50 05
E1 GET_ME_ID  -> 16 bytes
E7 GET_SOC_ID -> 32 bytes
handlers have no SLA branch
```

但是 exact CN304 official production preloader：

- 没有该 handshake/table；
- 没有 engineering download command loop；
- 没有 `GET_SOC_ID` / `GET_ME_ID`、`usbdl_send_da`、`usbdl_verify_da` 或 `download.c` 标记。

因此不能把 engineering dispatcher 的调用方法直接用在当前 CN304。

而且“TEE cryptographic/storage root”不能自动等同于 “MiTEE HWBCC/DICE UDS”：

- storage root 与 DICE UDS 可能只是同一硬件根通过 domain separation 派生的兄弟分支；
- 已知 SOC_ID/ME_ID 可能是标识/盐/公开上下文，不一定包含不可替代秘密；
- 当前没有找到 CN304 中 `SOC_ID/ME_ID -> initial DICE CDI/UDS` 的 exact 调用链或 KDF；
- 不能把 Kinibi/其他 TEE 的结论直接套到 MiTEE。

所以 CVE 是“寻找无污染 preloader/BROM 只读窗口”的候选研究线，不是已完成的 K70E UDS 提取方案。

## 5. 候选路线可行性矩阵

| 路线 | 能到哪一层 | 无污染 | 当前可用 | 结论 |
|---|---|---:|---:|---|
| stock `/dev/misc/hwinfo` | current CDI_Attest/Seal + public BCC | 是 | 是 | 太晚；无 UDS/root/private |
| stock KeyMint 日志 | final CDI_Leaf scalar | 是（需 approved 启动） | 恢复后才可 | 当前完成主线 |
| patched KeyMint/TEE | final leaf 或内部中间值 | 否 | 历史可用 | 已实际产生 modified DICE/`NOT_APPROVED`，禁止最终签发 |
| patched BL2_EXT | preloader 后的 CDI | 否 | 理论可做 | 仍太晚且自污染 |
| patched preloader | first visible incoming CDI | 否 | 当前不安全 | 不保证是 raw UDS；最高风险 |
| engineering preloader E1/E7 | SOC_ID/ME_ID | 对工程镜像只读 | CN304 不可用 | 不是已证 DICE UDS |
| CVE-2026-20435 exact CN304 | 未知 | 若存在则可能 | 未证实 | 继续离线研究，不实机调用 |
| BROM/硬件调试直接读 first secret | 理论 root/initial CDI | 可能 | 未证实 | 唯一符合目标的理论方向之一 |
| 从 UDS 公钥反推私钥 | UDS private | 不适用 | 不可能 | P-256 离散对数不可行 |

## 6. 即使拿到真 UDS，也有两个后续方案

### 6.1 退化链方案

将真 UDS 私钥标量作为 `UDS == CDI_Leaf`，由 pristine `google-rkp-sw` 构造一个自签退化链。协议结构合法，Nothing 成功样本证明 Google 后端支持这种 profile。

但 K70E 后端是否允许一台原本登记为 proper-DICE/P-256/五层 profile 的设备突然改成 degenerate profile，当前是 UNKNOWN。此前 `true K70E final leaf + generic/default degenerate DeviceInfo` 的 HTTP 444 同时改变了 root、链形、DeviceInfo 等多个变量，不能用来单独裁决“真 UDS + degenerate”一定成功或一定失败。

### 6.2 重建 proper-DICE 方案

若得到真 UDS 私钥能力，更稳妥的研究方向是扩展 `google-rkp-sw`，按 K70E 已知 approved measurement/config profile 生成一条新的、逐级签名的五层 proper DICE，再由新 final leaf 签 CSR。

该方案仍需：

- 精确 K70E claim/schema/config descriptor；
- 逐层签名、outer、canonical DeviceInfo 全部离线验证；
- 明确区分“复现 exact Open-DICE 派生”与“只构造密码学有效链”；
- 在联网前由独立 verifier 证明 root SPKI、五层签名和 approved profile；
- 只做一个隔离的一次性服务器实验。

在 root 私钥尚未取得前，不写实现、不制造伪成功包。

## 7. 当前刷机指南：哪些可以刷，哪些不能刷

### 7.1 文档 58 的旧八步表全部失效

旧八步已经实际执行并重启。它错误地把 OrangeFox `vendor_boot_a=501ec32c...d9c9` 当 stock，并保留 Magisk `init_boot_a=9d5d12a7...2fab4`；两者均不满足 stock `vbmeta_a`，设备随后显示 `the system has been destroyed`。

因此旧表中的 `super`、`vbmeta_system_a`、`vbmeta_vendor_a`、旧 `vendor_boot_a`、`dtbo_a`、`gz_a`、`lk_a`、`preloader_a` **都不得重跑**。旧 whole-super 跨槽例外已经消费，不是持续授权。

### 7.2 目前没有立即可执行的写操作

最后已固化的 stock Fastboot 视图是 `unlocked=no / secure=yes`，官方 `init_boot_a` 下载成功但写阶段明确失败：`No support by lock control`。BROM 虽取得 fresh challenge，但 Auth 卡密耗尽，没有 response、没有 DA、没有分区 IO。当前物理模式仍按 UNKNOWN 处理。

只有重新证明真实写通道、重建 paired-restorer 并完成独立审计后，未来才允许在同一会话中成对恢复：

| 顺序 | 唯一候选目标 | 官方 CN304 SHA-256 |
|---:|---|---|
| 1 | `vendor_boot_a` | `63531c1f25db3b5676c0fcb3fb241f8795e24846841d7f065462019ef77517ef` |
| 2 | `init_boot_a` | `8367dddeb8629def57d702eb26d92219654cca4d952e1d5ad0557cae47583c93` |

两项必须逐项写后 readback，全部匹配后才可重启。现有单 `init_boot` 脚本不是执行授权。

### 7.3 当前恢复分支永久禁止

- 所有 B 槽、`_b`、`*_ab`、`set_active`；
- `tee*`、`boot*`、顶层 `vbmeta*`、`lk*`、`preloader*`、`super`、`gz*`、`dtbo*`；
- `seccfg`、`expdb`、RPMB、efuse、proinfo、persist、nvram、nvdata、nvcfg、metadata、userdata；
- erase/format/wipe/flash_all、fastbootd、lock/unlock/oem cdms；
- Fenrir、patched TA/TEE、SProvider、OrangeFox/Magisk 测量态作为最终签发环境；
- 在 replacement `POSTBOOT_VERIFIED.json` 之前运行 Binder、zero-key、software keygen 或 Google 请求。

`preloader_a` 曾在旧恢复表中出现，不表示现在可拿来做 root dump 实验。当前它既是已测量阶段，又是高砖风险分区，且文档 60 已明确禁止再写。

## 8. 主线决策

### 8.1 完成主线

```text
只读确认当前屏幕/USB模式
  -> 建立可审计写通道
  -> 成对恢复 official CN304 vendor_boot_a + init_boot_a
  -> 写后 readback + boot-chain/postboot verifier
  -> 重新证明 approved DeviceInfo + 五层 DICE profile
  -> stock MiTEE log 同轮提取 final CDI_Leaf scalar
  -> scalar SPKI == same-run DICE leaf SPKI
  -> google-rkp-sw 新生成一把软件 P-256 私钥
  -> 一次 Google issuance
  -> 全证书链 NOT_APPROVED=0 + key/SPKI/签名/根链全验
```

### 8.2 UDS/root 研究支线

```text
继续逆向 exact CN304 preloader 首次 DICE input 来源
  -> 定位 ROM/hardware handoff 或硬件回调
  -> 寻找不改 flash/不改 measured code 的只读 primitive
  -> 复现 exact UDS key derivation
  -> UDS SPKI gate == d1a3...a3c9
  -> 离线比较 degenerate 与 proper-DICE 两种构造
  -> 独立审计后才考虑一次服务器实验
```

root 支线只有同时通过以下四门，才可升级为实机主线：

1. 候选值的确切语义和 KDF 已证明；
2. 派生公钥精确匹配本机 UDS SPKI；
3. 抓取过程不写早期分区、不会变砖、不会依赖同次 polluted measurement；
4. 离线请求结构和服务器 profile 假设有独立 verifier 支撑。

当前通过数：0/4。故不刷 preloader、不刷 TEE、不发送试探请求。

## 9. 下一位 AI 不得重犯的推理错误

1. 不要把“32 字节”当成同一种秘密。
2. 不要把 `get_attest_cdi` 叫 UDS；它是进入 KeyMint 的当前父级 CDI。
3. 不要把 preloader 输入 CDI 自动叫 raw UDS；它可能已是硬件/ROM 派生输出。
4. 不要把 SOC_ID/ME_ID 叫秘密根，更不能直接喂 `google-rkp-sw`。
5. 不要把 TEE storage root 与 DICE/HWBCC UDS 合并。
6. 不要认为补丁刷得更早就不会污染；preloader 本身就是测量链的一部分。
7. 不要认为 pristine 的 seed 参数会自动执行 K70E Open-DICE KDF。
8. 不要从协议允许 degenerate 推导 K70E 后端一定接受 profile 迁移。
9. 不要重跑文档 58 的八步表；它已经执行且被撤销。
10. 不要只补 `init_boot_a`；当前是 `vendor_boot_a + init_boot_a` 双 mismatch。
11. 不要再刷 TEE。历史 modified TEE 已改变 DICE 并实际得到 `NOT_APPROVED`。
12. 不要删除 `PARTIAL_OR_UNKNOWN` 或任何 one-shot/network marker。

## 10. 关键本地证据入口

- 文档 59：CN304 八步实际执行、双 AVB mismatch、Fastboot/BROM 现场流水线。
- 文档 60：当前唯一恢复入口、成对官方镜像和永久禁止项。
- 文档 61：恢复/BROM 故障树。
- 文档 62：`NOT_APPROVED` 阶段总结；与 59 的现场时序冲突处以原始状态文件和 59 为准。
- `04_第三方源码/mt6897-unlock-attempt/35-20-26-07-2026-mt6897-exploit-disclosures-and-preloader-dispatcher.md`：engineering preloader E1/E7 与 production 差异。
- `third_party/google-rkp-sw/rkp_sw.py`：seed 映射、degenerate chain、proper-DICE 导入和严格门禁。
- `03_提取结果/K70E_CN304_APPROVED_RESUME_20260906_live5_step2/REBOOTED.json`：`postboot_verified=false`, `rkp_authorized=false`。
- `03_提取结果/K70E_CN304_INIT_BOOT_RECOVERY_20260906_live1/PARTIAL_OR_UNKNOWN.json`：官方 init_boot 写入未获成功证据。

## 11. 最终状态

```text
CTF                              UNSOLVED
NOT_APPROVED simple count risk   EXCLUDED BY EXISTING CONTROLS
environment/measurement cause    PROVEN PRIMARY FAMILY
Nothing direct seed semantics    DEGENERATE IDENTITY KEY, NOT PROVEN RAW EARLY UDS
K70E x26 semantics               FINAL MEASUREMENT-BOUND P-256 CDI_LEAF SCALAR
K70E stock root export           NOT FOUND
exact CN304 CVE dispatcher       NOT FOUND
SOC_ID/ME_ID -> DICE UDS KDF     NOT PROVEN
safe early-root capture          NOT AVAILABLE
live flashing authorization      NONE
future minimal recovery write    OFFICIAL VENDOR_BOOT_A + INIT_BOOT_A AS AN ATOMIC PAIR
completion mainline              RECOVER -> APPROVED STOCK LOG LEAF -> ONE-SHOT ISSUANCE
UDS/root route                   OFFLINE RESEARCH SIDE TRACK
```


---

## 原始记录段 2 / Source section 2: 67_K70E_CTF_DeviceInfo_NOT_APPROVED最终踩坑与故障树_20260906.md

# K70E CTF DeviceInfo / `NOT_APPROVED` 最终踩坑与故障树

> 本文是文档 47、55、61的最新增量。旧文档仍保留历史事实，但凡是与本文“modified DICE + clean DeviceInfo 已获 `APPROVED`”冲突的因果或完成状态，以本文和文档 65、68 为准。

---

## 1. 把“DICE 变了”直接写成 `NOT_APPROVED` 原因

### 旧推理

modified 环境的 DICE 第 1、2、4 层 claim 不同，Google 返回 `NOT_APPROVED`，因此 DICE hash 就是拒绝原因。

### 错在哪里

旧请求同时改变了 DICE 和 DeviceInfo，只有相关性，没有单独因果。

### 新证据

同一 exact modified 五层 DICE，仅换入历史 clean DeviceInfo 后，Google 返回 `APPROVED`。DICE 5/5 签名和 outer 签名全部通过。

### 正确结论

这套 modified DICE 不是触发 `NOT_APPROVED` 的充分条件。不能泛化为“Google 从不看 DICE”。

## 2. 认为 `green + locked` 一定比 `orange + unlocked` 更容易获批

这是本次最重要的坑。

实际对照：

```text
NOT_APPROVED  green / locked   / b9b1d867...9744
APPROVED      orange / unlocked / acaa9258...b6e9
```

Google 不是对三个字符串做“看上去安全”排序。更合理的解释是：服务端需要 DeviceInfo 与已注册设备/固件 profile 相符。伪装成更安全反而会造成不一致。

## 3. 宣称已精确证明单一字段

本次一次替换了：

- `vb_state`；
- `bootloader_state`；
- `vbmeta_digest`。

所以安全结论是：clean DeviceInfo tuple 对该次 exact modified DICE 请求足以获批；在设备控制的 signed approval profile 内，这三项或它们的一致性组合是首要嫌疑。新 challenge、software key、request_id、时间与不透明的服务端状态也随请求变化，不能宣称完成了严格因果隔离。

Google leaf 的 PI `5/2` 精确回显 clean `vbmeta_digest`，使 digest/一致性成为最强线索，但这仍不等于严格 A/B 单字段证明。

现在已有干净证书，为满足好奇而继续烧 Google 请求没有必要。

## 4. 把 `count=32` 写成尝试次数风控

新 APPROVED leaf 同样包含：

```text
Provisioning Info key 1 = 32
```

而 `NOT_APPROVED` 命中为 0。这与历史 12 张 clean count-32 证书一致。

所以：

- `count=32` 不是本项目中“风控已触发”的证据；
- 没有 429、quota、abuse、`Retry-After` 时，不应以这个数字停止离线根因调查；
- 现在同一 modified UDS/DICE/final-leaf identity 已获批，“当前 identity 被统一封锁”的说法不成立；这不等于否认 Google 可能存在其他 rate/risk 策略。

## 5. 把 HTTP 200 当成赛事 PASS

旧失败和新成功都是 HTTP 200。真正分界在 Google-signed leaf Provisioning Info：

```text
old  5/1 = NOT_APPROVED
new  5/1 = APPROVED, 5/2 = acaa9258...b6e9
```

每次必须扫描全部四张证书的 OID `1.3.6.1.4.1.11129.2.1.30`，不只是看 HTTP、不只是看证书能解析。

## 6. 只检查 leaf 或只扫描 JSON 里已知字段

正确的 PI 验证必须：

- 枚举全链每一张证书；
- 每个扩展精确解码一个 CBOR item；
- 无 trailing bytes；
- 检查重复/等价 key collision；
- 递归扫描未知键、值、数组和 tag；
- 任何 `NOT_APPROVED` 精确命中或解析错误都拒绝。

本次为 1 个已解析扩展、0 解析错误、0 命中。

## 7. 混淆四把钥匙/秘密

本项目至少要分清：

| 名称 | 作用 | 本次是否秘密 |
|---|---|---:|
| K70E UDS public root | DICE 注册根公钥 | 否（公钥） |
| final DICE leaf scalar | 签 outer AuthenticatedRequest | 是 |
| final DICE leaf public key | 身份链最后一层 | 否（公钥） |
| 新 software P-256 private key | 本次请 Google 签发的 key | 是 |

两个关键公钥：

```text
identity leaf SPKI  64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
software/Google leaf 1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

二者必须不同。

## 8. 把 final leaf scalar 当成最底层 CDI/UDS seed

当前 32-byte 值派生公钥精确等于 modified DICE 最终 leaf，因此它的实证语义是：

```text
final measurement-bound P-256 DICE leaf private scalar
```

不要因变量名叫 `cdi_leaf_priv` 就把它说成 raw UDS、HUK 或能重建五层 DICE 的根 seed。

但也不要走到另一个极端：它已经足够签 proper-DICE 的 outer request，新成功就是直接证据。为完成当前 CTF，不需要再挖更底层 root seed。

## 9. 乱改 DICE hash 或伪造五层链

DICE 每层负责签下一层。任意改 payload/hash 会破坏签名链，除非持有对应前级私钥并重签后续全链。当前 final leaf scalar 只能签 outer request，不能反向修改早期 DICE 层。

而且本次已证明原样 modified DICE 可以获批，没有继续伪造 DICE 的必要。

## 10. 认为必须先刷回 fully stock 才能得到 clean Google 证书

这个命题被本次 host-only 成功推翻。

正确分流：

- 要已有参考机的 hybrid 成功三件套：不需要先修手机。
- 要 fresh fully-stock same-run provenance：仍需要恢复手机、stock log、same-run DeviceInfo+DICE。
- 要修好手机日常使用：这是另一个恢复任务，不能把本次证书成功写成手机已修复。

文档 59–64 的双 AVB mismatch、locked Fastboot 和 BROM 事实仍有效，只是不再是使用本次已有成功包的前置条件。

## 11. 将 `PASS_CLEAN_HYBRID` 写成赛事方已接收

两个状态必须分开：

```text
Google / crypto / PI class      PASS_CLEAN_HYBRID
raw FINAL_RESULT.status          PASS_CLEAN
organizer acceptance receipt    PENDING / not recorded
```

新 run 自标 `research_only_semantically_hybrid=true`；这是正确的证据边界，不能为了“结题”把该字段删掉或重解释。

## 12. 重跑已成功的 one-shot

全局 claim 状态：

```text
CONSUMED_NO_RETRY
```

成功目录已有 fetch/sign 各一个 NETWORK_STARTED 和 `SUCCESS.json`。

不得：

- 换目录重跑；
- 删 claim；
- 删 marker；
- 把新 key 当旧 key 的 retry；
- 见到证书过期就未经新授权自动重签。

## 13. 把文件 SHA 和内容 SHA 混在一起

典型例子：

```text
clean DeviceInfo canonical CBOR SHA  19f9f9b0...8fd921
clean_device_info.json file SHA      843cddbb...94336
```

两者语义不同。报告必须标明是“规范编码内容”还是“实际文件字节”。

## 14. 秘密处理坑

禁止：

- `cat`/`xxd`/`hexdump`/`base64` 私钥或 scalar；
- 把私钥放到 Markdown code block；
- 公开 Git 提交；
- 上传到公开网盘；
- 在 shell 开 `set -x`；
- 为“方便”在多处复制私钥。

允许记录：

- 绝对路径；
- mode/owner/size；
- 私钥文件 SHA-256；
- 派生 SPKI SHA-256；
- 关系验证布尔值；
- 新 nonce PoP 验证结果。

## 15. 故障树

```text
Google 返回证书
|
+-- HTTP 不是 200
|   +-- 429/quota/abuse -> 保存证据，暂停外部请求
|   +-- 超时/结果未知 -> 本 attempt 按已消耗，不重放
|   +-- 444 DeviceNotRegistered -> 身份/profile 结构不被接受
|
+-- HTTP 200
    |
    +-- 证书链/公钥关系失败
    |   +-- 不是可交付包，保留 raw response 离线调查
    |
    +-- PI 解析错误
    |   +-- FAIL，不能忽略未知字段
    |
    +-- PI 中 NOT_APPROVED
    |   +-- 该 attempt 失败；对照 DICE/DeviceInfo 精确差分
    |
    +-- PI 中 APPROVED，NOT=0
        +-- 检查 private=request=leaf、四证书、Google root pin
            +-- 全通过 -> PASS_CLEAN_HYBRID 候选，进入离线交付
```

## 16. 最终十问

任何 AI 在声称本包可交付前，必须回答：

1. identity scalar 派生 SPKI 是否等于本次 DICE leaf？
2. DICE 是否恰好五层且 5/5 签名通过？
3. outer 签名是否通过？
4. DeviceInfo 是否精确等于历史 clean 值和类型？
5. 新 software key 是否为 P-256，且在联网前保存？
6. private SPKI = request 唯一 key = Google leaf SPKI 是否全部成立？
7. software key 是否与 identity key 不同？
8. 链是否恰好四张、签名和 Google root pin 全通过？
9. 全链 `NOT_APPROVED=0` 和 PI parse error=0 是否成立？
10. 是否正确区分了 `PASS_CLEAN_HYBRID`、原始 `PASS_CLEAN` 字段与尚未记录的赛事方回执？

本次前 9 项全部为是；第 10 项必须持续保留边界。


---

## 原始记录段 3 / Source section 3: 55_K70E_CTF_NOT_APPROVED与stock路线踩坑记录_20260906.md

# K70E CTF NOT_APPROVED 与 stock 路线踩坑记录

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 增量覆盖：**本文的旧工程/恢复坑仍有价值，但凡把 modified DICE 当成 `NOT_APPROVED` 充分原因、把 stock 当成唯一必须路线的表述已过时。最新因果坑和故障树见文档 67。

> **2026-09-06 18:05 新增覆盖：** 本文旧恢复边界已被实机推翻；完整新增坑见文档 61，当前暂停与证据链见文档 59、62。尤其禁止把 `501ec32c…` 当 stock vendor_boot 或把 `9d5d12a7…` 当 approved factory init_boot。

> 目标：让下一位 AI 不再重复 2026-08-28 至 2026-09-06 的错误  
> 原则：每个坑都写“错误想法、证据、正确处理、当前 ATTEMPT 如何处置、调查是否继续”；ATTEMPT 停止不等于项目停止
> 历史快照（已失效）：下述“ADB 稳定、尚未刷写、以文档 58 为准”已被后续实机事件推翻。当前先读文档 59–63；旧八步不可重跑，设备模式 UNKNOWN，旧三份 manifests 不具执行权威。

---

## 1. 把密码学闭环误当赛事 PASS

错误想法：

    私钥匹配 leaf，证书链验签通过，所以提交一定合格。

事实：

旧 20260905_2244 包的私钥、公钥、CSR 和四级 Google 链全部闭合，但 leaf 的 Google Provisioning Info 含 NOT_APPROVED。赛事方明确拒绝。

正确处理：

- 链验签与 Provisioning Info 是两个独立门；
- 全链逐张扫描 OID 1.3.6.1.4.1.11129.2.1.30；
- 对 raw CBOR 做 exact-one-item、canonical、重复键安全解析；
- 任何精确文本 NOT_APPROVED 都失败；
- 缺 leaf 扩展或畸形扩展也失败；
- 只有 ctf_no_not_approved=true 才可 SUCCESS。

本次结果处置：

    NOT_APPROVED hit count > 0 -> 当前结果 REJECTED，当前 ATTEMPT 不得重放；继续离线根因调查

## 2. 只读取已知 Provisioning Info 键

错误想法：

    Android 文档只定义键 1、3、4，未知键可以忽略。

事实：

旧代码只投影 1、3、4，恰好丢掉赛事方拒绝的键 5。

正确处理：

- 保留所有键、值和类型；
- 扫描 map key、map value、array、tag；
- 原始 CBOR hash 和 JSON-safe tree 都落盘；
- 不把“公开 schema 未定义”解释为“没有意义”。

## 3. Python dict 掩盖重复 CBOR key

错误想法：

    cbor2.loads 后在 dict 中没看到 NOT_APPROVED，就说明没有。

事实：

恶意或非规范 CBOR 可以用重复键、true 与整数 1 的 Python 等值碰撞覆盖前值。

正确处理：

- raw bytes 必须等于确定性 canonical 重编码；
- 拒绝尾随 item；
- 拒绝重复/碰撞键；
- parse_error 必须 fail-closed。

## 4. 认为计数 32 就是次数风控

错误想法：

    Provisioning Info 键 1 等于 32，所以尝试太多被封。

反证：

- 对工作区 DER 证书按证书 SHA-256 去重后，共有 27 张带 Provisioning Info 的不同证书：25 张干净、2 张含 NOT_APPROVED、0 张解析失败；
- 25 张干净证书中有 12 张同样为 `{1:32,3:"Xiaomi"}`，另有 13 张为 count=8；
- 两个失败请求都是 HTTP 200，不是 429；现有元数据没有 `quota` 或 `abuse`；
- Google 公开说明中该计数是近似获发量，不是公开的拒绝码。

正确结论：

在现有样本内，简单尝试次数/键 1 计数风控已经排除。环境/请求语义差异是当前必须继续追查的主因。

正确处置：

- NOT_APPROVED：烧毁并保存同一失败 ATTEMPT，禁止原样重放；继续离线差分、启动链恢复和门禁修复；
- 新 controlled attempt：只有找到具体差异、修复后 fresh boot、重新采集且通过全部新门才允许；
- 429、明确 `quota` 或 `abuse`：暂停外部请求，但仍可继续只读和离线调查；
- 绝不能把“同一 ATTEMPT 不重试”写成“整个 CTF 调查停止”。

## 5. 认为 host 模拟请求不被认可

错误想法：

    google-rkp-sw 是 host 拼包，换成真机 Binder 就会正常。

事实：

同一 modified 环境的真机 Binder 请求和 host 请求得到完全相同的 NOT_APPROVED raw CBOR。

协议对照还显示：approved native、modified native、modified host 三次运行使用相同官方 fetch URL；fetch body 均为 101 字节，SHA-256 都是：

    fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2

三份 response 中 canonical EEK chains 均为 613 字节，SHA-256 都是：

    11dc72f46af10129d6a2584ebbd1c6e44ca2d26322f534606435808da42e9305

signCertificates endpoint 相同；查询串中的 fresh challenge/request_id 按设计不同。modified native 与 modified host 的五层 DICE raw payload 又完全相同。因此 URL、fetch body、EEK chain 和 host framing 都不是现有证据支持的主因。

正确处理：

先修服务器可见的 signed DICE/DeviceInfo 测量，而不是继续微调 host 请求编码。

## 6. 用 HLOS ro.boot.* 代表 TEE 签名状态

错误想法：

    adb getprop 显示 green/locked，因此 signed DeviceInfo 也一定 green/locked。

事实：

参考机历史已获认可 stock 请求的 signed DeviceInfo 是 orange/unlocked；HLOS 属性可被启动链伪装。相反，modified 失败请求的 TA 签名 DeviceInfo 才是 green/locked。

精确对照：

    approved
      DeviceInfo canonical SHA-256  19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921
      vb_state / bootloader_state    orange / unlocked
      vbmeta_digest                  acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9

    modified
      DeviceInfo canonical SHA-256  82e42dd801204a814823be7f14a5912501dc5ffee4c0323c748e5618eaecd1ad
      vb_state / bootloader_state    green / locked
      vbmeta_digest                  b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744

正确处理：

- HLOS 属性只记录；
- approval gate 以 AuthenticatedRequest 内 signed DeviceInfo 为准；
- 所有字段逐类型比较；
- 五层 DICE claim 同时比较。

## 7. patched TEE 路线虽然能取 key，但污染测量

错误想法：

    只要能绕过 TA 签名并提取 scalar，就完成了题目。

事实：

Fenrir/SProvider/patched TEE 路线改变 DICE 第 1、2、4 层，Google 以 HTTP 200 返回 NOT_APPROVED。

measurement claims 和 security claims 的逐层匹配向量都是：

    [false, false, true, false, true]

不要把这误读为“第 3、5 层完整 payload 相同”。五层完整 COSE_Sign1 payload 全部不同，因为前层变化还会级联改变派生 subject key 和 issuer/subject。approved 与 modified 的 raw payload SHA-256 分别为：

    approved
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

正确处理：

- patched TA、TEE、Fenrir 只保留历史研究；
- 不再用 3990a8...、7ea594...、5b7405... 做合格签发；
- 主路线改为 stock TA 自带 MiTEE 日志。

## 8. 误以为 stock TA 不会输出 CDI_Leaf

错误想法：

    dump_to_hex 调用图只有 KAK、失败候选和 UUID，所以日志路线已死。

事实：

旧静态分析漏掉了活动 CSRv2 SignWithDeviceKey 链：

    get_attest_cdi -> P256KeypairFromCDI -> x26 -> dump_to_hex

正确处理：

- zero-key CSRv2 触发设备身份签名；
- 捕获精确 private_key(15)/private_key(31) 两行；
- 只接受与同轮最终 DICE leaf SPKI 匹配的唯一候选。

## 9. 把日志中任何 private_key 当目标

错误想法：

    grep private_key，取第一组 32 字节。

事实：

同一日志可能有 MIKEYMINT KAK、KDF 中间候选或别的调用者。

正确处理：

- 不手工 grep 作为最终证据；
- 用冻结 parser；
- 对每个候选派生 P-256 SPKI；
- 与同轮 CSR 最终 DICE leaf 匹配；
- 唯一匹配才 PASS。

## 10. 混淆四种 key

必须区分：

1. raw CDI：KDF 输入，不是最终 P-256 scalar；
2. CDI_Leaf P-256 scalar：设备身份，赛事第 1 项核心；
3. native GenerateRkpKey scalar：真机每把待签 key，不是 google-rkp-sw 软件私钥；
4. google-rkp-sw 新软件 P-256 key：赛事第 2 项，leaf 必须绑定它。

KeyBlob、MacedPublicKey、SPKI、COSE_Key、签名、KAK 都不能代替私钥。

## 11. 用旧身份或别的 K70E 材料拼包

错误想法：

    同型号手机的 UDS、CDI leaf 或私钥可以复用。

事实：

UDS 和 CDI 链是设备身份；另一台 K70E 是新目标。

正确处理：

- 新 serial；
- 新 profile；
- 新 stock baseline；
- 新 scalar；
- 新软件 key；
- 新 Google response；
- 关系验收而不是固定 hash 验收。

## 12. 把 EXACT_REFERENCE_FAST_PATH 当联网许可

错误想法：

    TA/TEE hash 与参考相同，所以可以直接 POST。

事实：

EXACT_REFERENCE 只说明二进制兼容；不能证明目标设备自己的 UDS、signed DeviceInfo、五层 DICE 和 Google 风险状态已认可。

正确处理：

    structural_and_portability PASS
    approval_environment ELIGIBLE
    network_issuance_allowed true

三个结论必须分开。

## 13. 没有已认可基线却承诺不会 NOT_APPROVED

错误想法：

    全 stock 就一定得到认可。

事实：

Google 策略不可完全从公开代码推导。当前基线来自同一参考机历史已获认可证书；另一台设备若没有这种证据，只能证明结构正确。

正确表述：

代码保证坏结果不会被写成 SUCCESS；不能预言服务端一定签发合格证书。

## 14. 忽略 lk/preloader，只检查 TA/TEE

错误想法：

    NOT_APPROVED 只与 patched TEE 有关。

事实：

DICE 第 1、2 层也变化。preloader 和 Fenrir BL2_EXT 都可见。

参考机 stock 门：

    lk_a
      size 16777216
      SHA-256 9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35

    preloader_raw_a
      size 4190208
      SHA-256 33ef65d9560e92990e5d6bbf7dc8e161e57346e7f9434082b59d31366a638d1f

正确处理：

捕获前和 point-of-no-return 前都检查完整 early-boot 分区；发行前再检查。

## 15. OTA payload hash 与整分区 hash 混用

错误想法：

    OTA 中 lk/preloader 文件 hash 应等于整分区 hash。

事实：

- OTA lk size 3395584，与保存的 16 MiB lk_a 不是同一字节范围；
- OTA preloader size 749568，只等于保存 preloader 分区前缀；
- 整分区包含容器、尾部或其他区域。

正确处理：

明确记录比较范围、size 和来源。不要因为前缀相同就伪造整分区结论。

## 16. preloader by-name 与实际启动 LU 的歧义

坑：

MTK UFS 的 preloader A/B 或 LU 映射可能与简单 by-name 理解不同。

正确处理：

- 把 by-name 全分区 hash 作为前置锚；
- 不把它当唯一授权；
- 同轮 signed DICE 五层匹配才是最终证据；
- 未确认映射前不要随意写 preloader；
- 恢复必须先验证 BROM 能力和目标自己的备份。

## 17. 为了“更 stock”盲目刷官方包

错误想法：

    全量线刷最省事。

风险：

- 覆盖 userdata；
- 改写身份/持久分区；
- relock；
- 触碰 RPMB/efuse/校准；
- 失去现有 root 或恢复路径；
- 刷错 preloader 变砖。

正确处理：

stock 日志路线本身零刷写。只有 live exact gate 不符时，才针对已确认的必要分区恢复目标自己的已知原版，并逐项验证。

## 18. 账号“无解锁权限”被误当技术阻塞

事实：

设备过去能 fastboot、root 和运行所需环境；账号 UI 授权与题目证据不是同一个概念。

正确处理：

不争论账号状态，以实际能力、live hash、root 和 signed DICE 为准。也不要因为用户说“已解锁”就跳过防砖检查。

## 19. Wi-Fi 打不开就反复重启

风险：

stock zero-key capture 与 issuance 要求同一 boot ID。为了网络重启会使捕获失效。

正确处理：

- 捕获阶段手机离线；
- 捕获成功、preflight PASS 后，用已经验证的电脑共享网络；
- 不重启、不刷写；
- 在线 wrapper 再次验证同一 boot。

## 20. 捕获前就让手机联网

风险：

无法证明 zero-key 阶段没有后台 RKPD 或其他网络活动。

正确处理：

捕获器要求手机飞行模式、Wi-Fi off、零可转发默认路由。AOSP netd 无条件配置的严格 `dummy0/table 1002`、无 `via` 默认项是黑洞 sink，单独记录而不当作外网；任何 `ccmni`/`rmnet`/`wlan`、其他 table、重复字段或未知尾缀仍 fail-closed。preflight 完成后只需 host 电脑保持互联网；手机继续离线。

## 21. 把 zero-key CSR 当一次 Google keygen

事实：

zero-key 调用的 KeysToSign 数量为 0，只生成身份 AuthenticatedRequest 并触发设备签名日志；它不创建赛事软件 key，不联系 Google。

正确处理：

zero-key 捕获和 online one-key issuance 使用不同一次性状态。

## 22. 重复运行 zero-key client

风险：

日志窗口会混入多个候选，破坏同轮唯一性；不能再证明标量来自哪次 CSR。

正确处理：

- 新输出目录；
- 调用前写 DISPATCHING_NO_RETRY；
- 每个输出最多一次；
- 超时或状态未知也不自动重试；
- 保存完整 baseline/post 日志。

## 23. 日志轮转用“看起来像”来拼

错误想法：

    last_mitee.log 加 current mitee.log 大概就是增量。

正确处理：

只有 post last_mitee.log 逐字节以前一份 baseline current 为前缀时，才能重建跨轮转增量。任何不确定性输出 PARSER_REQUIRED，禁止重触发。

## 24. parser 路径可替换或解释器漂移

风险：

私钥 parser、profile helper 或 Python 环境如果从可写路径无锚导入，可能改变安全语义。

正确处理：

- 固定 canonical venv interpreter；
- 固定实体 realpath、size、SHA；
- O_NOFOLLOW；
- lstat 与 fstat 对比；
- 读后检查 dev、ino、size、mtime、ctime；
- 私有 snapshot；
- consumer 独立重算 scalar、CSR、DICE 和 profile，不盲信 collector summary。

发布时 manifest 必须固定最终脚本和运行时依赖。

## 25. client 验证后被替换

风险：

校验源 client 后再从原路径 push，存在 TOCTOU。

正确处理：

- 先冻结到私有 snapshot；
- 校验 snapshot；
- 从 snapshot push；
- 本地和远端多次 hash；
- 固定 size 和 SHA。

## 26. 把旧 portable capture contract 塞给新 consumer

事实：

旧 patched-TA 路线有 restore、ARM/ALLOW、Binder-keygen latch 等不同合同。stock 日志路线没有这些字段。

正确处理：

- capture_method 必须 stock_mitee_log_v1；
- schema 必须 k70e-rkp-ctf-stock-mitee-log-capture-contract-v1；
- 只用 rkp_sw_stock_log_once.py；
- 不伪造 legacy 字段去通过 rkp_sw_portable.py。

## 27. preflight 报告覆盖或重复生成

风险：

使在线 attempt 无法证明消费的是哪次离线检查。

正确处理：

- preflight report 使用 exclusive create；
- 必须是 capture 目录直属 JSON；
- 在线阶段重算 semantic report 并逐类型比较；
- 不覆盖，不 symlink。

## 28. 在 live preflight 之前就烧 host attempt

风险：

瞬时 ADB 断线或 state_dir 尚未建立，会在零网络请求时永久消耗 attempt。

正确设计：

- 所有纯只读、可重复的 live approved-baseline 检查应尽量在 reservation 前完成；
- device state_dir 缺失时，在 reservation 前安全、幂等创建并核验；
- 真正不可重试边界前才创建 host ATTEMPT；
- 设备 latch 和 NETWORK_STARTED 仍必须在 core 调用前耐久写入。

如果最终工具版本明确选择更早烧 attempt，也必须文档化；人工不得通过删除 attempt 绕过。

## 29. 用错误的 core response 文件名

风险：

wrapper 期待 sign_certificates_response.cbor，而核心实际保存 response.cbor，会导致 Google 已成功返回后独立审计找不到文件、永久烧毁。

该问题已在当前 wrapper SHA-256 `99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3`（size 121031）中修复，并加入真实输出文件名回归。

正确处理：

- wrapper 与 allowlisted core 的输出合同必须做真实 fixture 回归；
- 严格审计读取 core 实际文件名；
- 单测必须构造一套成功输出树，走到 SUCCESS；
- 不只测试失败分支。

## 30. 把 android_schema_current_strict 设成硬门

错误想法：

    当前 Android 文档要求键 4="TEE"，没有键 4 就失败。

事实：

历史已获认可真实 Google leaf 为 {1:8,3:"Xiaomi"}，没有键 4。

正确处理：

    ctf_no_not_approved              硬门
    android_schema_current_strict    报告

测试必须覆盖 CTF true / Android false 的成功样本。

## 31. 只检查叶证书

风险：

NOT_APPROVED 或畸形扩展也可能出现在链中其他证书。

正确处理：

全链逐张扫描；leaf 必须有可解析扩展；其他出现的扩展也必须可解析且无命中。

## 32. 收到 HTTP 200 就写 SUCCESS

错误想法：

    200 代表 Google 接受。

事实：

两次 NOT_APPROVED 都是 200。

正确顺序：

    raw response durable save
      -> parse
      -> one chain
      -> four certs
      -> signatures/root
      -> private/request/leaf relation
      -> Provisioning Info audit
      -> SUCCESS

## 33. 解析失败前没保存 raw response

风险：

一旦 parser 报错，服务端唯一证据丢失，又不能重试。

正确处理：

fetch/sign 的 body 与 HTTP metadata 都先耐久保存，再解析。

## 34. Ctrl-C 或超时后重跑

风险：

无法知道 request 是否已到 Google。

正确处理：

只要 NETWORK_STARTED 已写，或者网络调用状态未知，就视为消耗；保留 output 和 attempt，禁止重试。

## 35. 手工删除 device issuance latch

风险：

破坏“一次性”证据，无法向赛事方证明没有挑结果。

正确处理：

设备 latch、host attempt、NETWORK_STARTED、BURNED、SUCCESS 都不可删除、覆盖或重建。

## 36. 输出树里留下额外秘密副本

风险：

临时 scalar、parser staging、stdout 或旧 key 混入提交。

正确处理：

- 最终目录只保留合同列出的身份、单一软件 key、单一链和审计；
- attempt 内临时 scalar 在 finally 删除；
- package 前拒绝 symlink/hardlink/special file；
- manifest 最后生成；
- 不把原始 MiTEE 全日志放入对外提交目录。

## 37. 文档版本优先级错误

危险文档：

- 44 第 9/11 节保存 patched 路线历史；
- 45–51 正文大量旧 PASS；
- 46 有可复制的 patched TEE 命令；
- 50 是旧 portable 六入口移植方案。

正确阅读顺序：

    README
      -> 52 事故复盘
      -> 53 完整流水线
      -> 54 傻瓜教程
      -> 55 本文
      -> 56 报告
      -> 57 Skill

早期文档只作证据，不作当前命令源。

## 38. 为了“保证”而降低门

错误做法：

- 把 NOT_APPROVED 从 audit 里忽略；
- 把 known-approved baseline 改成当前失败身份；
- 把五层匹配改为任意三层；
- 把 HLOS green/locked 当相等；
- 改 server URL；
- 接受本地签名证书；
- 手工创建 SUCCESS。

正确保证：

程序保证任何不合格结果不能成为 SUCCESS。服务端最终决定能否签出无 NOT_APPROVED 的链。

## 39. 不要把“阶段停止词”误成“调查停止词”

以下文本表示当前阶段、当前输出目录或当前 ATTEMPT 必须 fail-closed，不能原样继续或重放：

    SAFE_ABORT
    PARSER_REQUIRED
    REJECTED_NOT_APPROVED
    ProvisioningInfoRejected
    NOT_APPROVED
    BURNED
    hash mismatch
    PORT_REQUIRED
    network_issuance_allowed=false
    approval_environment=INELIGIBLE
    DISPATCHING_NO_RETRY with unknown outcome

看到这些词后的正确动作是：保存证据，停止当前危险动作或同一 ATTEMPT，继续离线定位具体差异；修复后必须用 fresh boot、新捕获和全部新门建立新的 controlled attempt，不能删除 marker 或盲目重放。

只有以下明确服务端节流/滥用信号要求暂停新的外部请求：

    HTTP 429
    explicit quota error
    explicit abuse error

即使暂停外部请求，也不等于停止只读证据审计、离线差分、代码修复和 stock 环境恢复。

## 40. 最终五问

提交前必须能回答：

1. 身份 scalar 是否由同轮 stock CSR 最终 DICE leaf SPKI 证明？
2. 软件私钥是否由本轮 google-rkp-sw 新生成且匹配 leaf？
3. 是否只有一个 key、一个 request、一个 Google chain？
4. 全链 raw Provisioning Info 是否零个 NOT_APPROVED 命中？
5. SUCCESS 是否由独立重算写出，而不是人工声明？

任一回答不是明确“是”，就不是最终提交。

## 41. 只检查“直接字符串 map key”

风险：

CBOR map key 可以是可 hash 的复合对象。旧 gate-v4 虽然递归扫描 value，但对 key 只检查 `isinstance(key, str)`，因此如下 canonical CBOR 可漏报：

    {("NOT_APPROVED",): 7}
    {CBORTag(42, "NOT_APPROVED"): 7}
    {FrozenDict({"nested": "NOT_APPROVED"}): 7}

正确处理：

- 对每个 map key 本身递归，再对 value 递归；
- path 显式标记 `<key:...>`；
- tuple、CBORTag、FrozenDict 三种证书 fixture 都必须 `ctf=false / hit=1`；
- 旧 gate-v4 工具链保留为历史离线身份，禁止联网；gate-v5 虽修复复合 map key，但直接 core 未锁定五层完整身份 payload，也只作历史离线身份。gate-v6 同样只保留为升级轨迹；当前唯一联网门为 gate-v7、stock-log-only toolchain V5。

## 42. 把本地 marker 当成服务端 freshness 证明

事实：

ATTEMPT、NETWORK_STARTED、HTTP JSON 和 SUCCESS 都是本地状态。独立 verifier 能检查它们的 hash、时序、唯一性和与包内请求/证书的关系，但不能把本地文件变成 Google 签名的“本次网络交易回执”。持有旧链及对应私钥的人理论上可以离线重建一套内部自洽 marker。

正确表述：

- Google 证书签名证明链的真实性和 key 关系；
- 本地 marker 是可审计操作证据，不是不可伪造的 fresh/exactly-once 证明；
- 若赛事方要求密码学防重放，需要赛事 nonce、服务端签名 receipt 或不可变外部日志；
- 报告不得把离线 verifier 夸大为这种外部证明。

## 43. zero-key 最终状态覆盖 DISPATCHING 预状态

当前 capture 先 exclusive 创建 `zero_key_invocation.json` 的 `DISPATCHING_NO_RETRY`，调用结束后会用同名文件原子替换为最终结果。因此：

- 若调用中崩溃，DISPATCHING 留存并且 fail-closed；
- 若调用完成，目录中只保留最终状态，不保留独立的预状态文件；
- 这不会开放重试，也不改变单调用的程序逻辑，但会降低“同时保留 pre/post 两份不可变证据”的取证强度；
- 报告必须把它列为 P2 局限，不得声称有两份独立不可变 marker。

如果赛事后续要求更强取证，新版 schema 应使用两个 exclusive 文件（例如 `ZERO_KEY_DISPATCHING.json` 和 `ZERO_KEY_RESULT.json`），版本化合同并全量重测，不能在已有 capture 上补造。

## 44. 在同一 boot 中恢复磁盘 stock，不会倒转已经完成的 DICE

错误想法：

    先用 patched TEE/init_boot/TA 开机和取 key，签发前把磁盘恢复 stock，就等价于 stock 请求。

事实：

- `device_preflight.json` 已看到 `tee_a` 磁盘为 stock `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d`，但 init_boot 磁盘仍是 candidate `4d83cd26f02c585dce733f81d05faf38ec5c8f247f89fbaa9fcf46b70d2b4d85`，tee-supplicant namespace 中 TA 仍是 patched `6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0`；
- 后续 `04_postrestore_stock_preflight.json` 虽看到 TEE/TA 磁盘回到 stock、init_boot 回到 pinned known-good Magisk 锚，但这发生在当前 boot 的 early-chain DICE 已派生、TA 已加载之后；
- 同轮 AuthenticatedRequest 已把 modified DeviceInfo/DICE 签死，后来改磁盘内容不能修改已生成请求；
- 结果正是 modified native Binder 请求 HTTP 200 + NOT_APPROVED。

正确处理：

1. 先把目标设备的原厂 `lk_a`/实际启动 preloader/TEE/TA、pinned known-good Magisk init_boot 和 early-bind 状态全部恢复到 approved-baseline 组合；
2. 确认下次 early boot 不会再替换或 bind patched 组件；
3. 执行 fresh boot；
4. 在这个新 boot 中重新采集 zero-key AuthenticatedRequest；
5. 要求五层完整 payload、measurement/security claims、signed DeviceInfo 和 live hashes 全部通过 approved baseline 门；
6. 之后才允许新的 controlled Google attempt。

“磁盘当前符合认可锚”只是必要条件，不是“本次 boot 的 signed DICE 已符合 approved baseline”的充分条件。特别注意：参考锚 `init_boot_a=9d5d12…` 是 known-good Magisk，不是 factory-stock。

## 45. 把一次性 ATTEMPT 烧毁误写成整个项目停止

错误想法：

    NOT_APPROVED 或 BURNED 后，为了避免风控，所有工作都必须停止。

事实：

同一请求/同一 marker 不可重放是取证和 one-shot 约束；它不证明服务端在按次数风控。本项目已有 12 张 clean count-32 证书，两坏请求均 HTTP 200 且无 429/quota/abuse。

正确处理：

- 保留并烧毁失败 ATTEMPT；
- 不用相同环境盲试；
- 继续离线比较 clean native control 与失败路径；
- 找到具体差异并修复，fresh boot 后通过新门；
- 再创建全新的 controlled attempt；
- 只有明确 429/quota/abuse 才暂停外部请求。

在尚未取得新的 `ctf_no_not_approved=true` Google 链之前，只能写“根因修复待现场验证”，绝不能写“已经解决”或“已有合格新链”。

## 46. 只升级 core gate，发行/验收合同仍停在旧版

冻结后独立审计曾发现：核心、portable loader 和 capability 都已要求 gate-v6，但专用发行器仍在 preflight 中写死 `core_rkp_gate_version=5`，验收器也把这个旧值当作合法值；合成 fixture 进一步将错误固化为回归期望。manifest 全 PASS 只能证明“错误被一致冻结”，不能证明语义正确。

这是 gate-v5 到 v6 时发现的历史错误。随后对 CBOR 语义对象和持久化边界的复查又将当前门升到 v7。当前必须整体满足：

- 发行器从 `portable.REQUIRED_RKP_ISSUANCE_GATE_VERSION` 取值，并硬要求严格整数 `7`；
- preflight 写入 `core_rkp_gate_version=7`；
- durability 合同使用无版本误导的 `installed_after_allowlisted_core_load=true`，并另存 `core_gate_version=7`；
- 独立 verifier 同时要求 preflight 和 durability 的 v7；
- 当前 profile 的 toolchain 必须是 `k70e-portable-macos-host-20260906-v5`，且 V5 是 stock-log-only，不继承 V4 的 patched/candidate 执行面；
- fixture 与回归断言同步，并明确禁止旧 `installed_after_allowlisted_gate_v5_load` 字段。

通用教训：每次升级 gate，必须同时全局扫描代码、报告 schema、verifier、fixture、文档和 manifest；不能只看核心常量或测试总数。

## 47. 把 `cbor2.loads()` 的返回值当作只有 dict/list/string/bytes

`cbor2` 会对部分 tag 自动转成 Python 语义对象。已复现的两个绕过是：

    tag 258 -> set / frozenset
    tag 35  -> re.Pattern

如果递归器只认 `dict/list/tuple/CBORTag`，然后对未知对象做 `str(value)`，就可能漏掉容器里的精确 `NOT_APPROVED`，或把对象的非稳定字符串表示当成安全语义。

gate-v7 的处理原则：

- Provisioning Info 只接受明确允许的原始类型；
- tag 258 产生的 `set/frozenset`、tag 35 产生的 `re.Pattern` 等所有自动解码语义对象全部 fail-closed；
- 所有显式 `cbor2.CBORTag` 也全部 fail-closed，不因 tag 号看似无害而放行；
- 不使用 fallback stringification 作为安全扫描；
- 测试必须包含 tag 258 和 tag 35。

## 48. 以为通用 `CBORTag` 只是一层可递归包装

tag 24 的 value 可以是“另一段已编码 CBOR”的 bytes，例如内部再藏 `{1:"NOT_APPROVED"}`。外层 canonical round-trip 完全正常，如果扫描器只看 tag value 的 bytes 本身，仍然会漏报。其他 tag 也可引入自动语义转换。

当前规则是更小的可信语法：Provisioning Info 中任何显式 `cbor2.CBORTag` 都拒绝，不尝试猜测其业务语义。tag 24（内嵌 encoded CBOR）和普通 tag 42 都必须有独立负向 fixture；这与 tag 258/tag 35 自动转换后语义对象的拒绝门同时生效。

## 49. 只禁用 CLI，却保留裸的 keybox 构造 API

`cmd_keybox` 返回 SAFE_ABORT 不等于所有导出路径都关闭。旧 `build_keybox_xml()` 可直接接收私钥和任意证书链，既不扫 Provisioning Info，也不验证 leaf SPKI 与私钥。已实测它能对现有 `NOT_APPROVED` 链生成 XML。

对本 CTF 发行 core，裸 builder 不属于必需功能，应 fail-closed 退役。若未来真需导出，必须使用只能由“全链签名 + 可信根 + leaf/private-key + raw PI”最终审计产生的一次性能力，不得恢复纯函数入口。

## 50. 源码已修，但旧 `.pyc` 仍是可执行在线旁路

Python 可以显式加载与当前 `.py` 不一致的 bytecode。本轮真实发现：

- `third_party/google-rkp-sw/__pycache__/rkp_sw.cpython-314.pyc` 仍嵌入旧 arm/fetch/submit/cmd_provision；
- 旧 tx2 采集器也有残留 pyc；
- 删除/改写 `.py` 不会自动清除这些文件。

当前发行前必须扫描项目树和 core 树的非 venv `*.pyc`/`__pycache__`，全部删除；测试使用 `PYTHONDONTWRITEBYTECODE=1`，并用回归断言没有过期 core bytecode。

## 51. 把“请求里的 KTS 公钥等于干净 leaf”当成服务器评估了该 DICE 请求的证明

离线派生设备 evidence 存在 mix-and-match 攻击：攻击者可将借来的 clean leaf 公钥填入另一份由目标 CDI_Leaf 签名的 request KeysToSign，再配上借来的 clean chain。DICE 签名、leaf/KTS 公钥、Google 链可各自成立，但这些关系不证明 Google 曾对该 DICE 请求做出 clean 决定。

所以：

- 自动派生 evidence 默认仅用于诊断；
- 它不得通过“自己包含的 digest”自我授权联网；
- 只有被 core 代码中独立审阅的“完整 evidence canonical hash + 全安全 expectations”投影 allowlist 明确收录后，才能作为新设备权威基线；
- 当前 allowlist 为空，参考机使用内置已审批 evidence。

## 52. 让调用者提供 profile helper，再在 core 里 `exec`

即使 helper 旁边有“调用者自报 SHA-256”，也不会变成权威。恶意 helper 可在任何授权校验之前执行顶层副作用，并伪造 `load_profile()` 结果。同样，将认可常量保存为运行时 module globals，会被同解释器调用者重绑。

gate-v7 的正确边界：

- gate factory 创建时把内置参考 evidence hash、curated derived set 和 reference expectations 复制进闭包；
- core 自己严格解析 profile/evidence JSON、校验 exact keys、typed value 和 profile self-hash；
- helper snapshot 只是取证材料，不导入、不执行、不决定授权；
- ticket 封存 canonical expectation bytes，authorization 再深快照，不读取可变 globals。

## 53. 只验证 wrapper 的 ATTEMPT/NETWORK 文件，没有绑定 core dispatch claim 和真机 latch

新 core 会在 attempt 目录 exclusive 创建 `CORE_DISPATCH_CLAIM.json`；stock wrapper 另有 `DEVICE_LATCH.json`、profile/evidence/helper 快照。若独立 verifier 的 exact file set 忘记这些文件，真实成功运行反而必定失败；若 core 不绑定它们，又可以绕过 wrapper 自造 host marker。

每次 dispatch 合同升级必须同时修改：

1. wrapper 写入的 exact key set、path 和 SHA；
2. core arm 的参数、重读、跨文件关系和 bound-files 快照；
3. stock verifier 的 ATTEMPT_ALLOWED_FILES/NETWORK exact schema；
4. 合成 fixture；
5. 真实 wrapper→core 集成测试，不能把 arm mock 成空 lambda 后就声称通过。

注意：本地 JSON 和真机目录 latch 仍然不是 Google 签名 receipt，也不能抵抗拥有同 UID/同解释器代码执行权的攻击者。它们的作用是可审计的 fail-closed 操作约束。

## 54. 把“私钥 PEM 写成功”当成“签发后一定可交付”

仅对临时文件 `fsync` 再 `rename`，若不 `fsync` 父目录，崩溃后文件名仍可能丢失。仅用内存私钥生成 KeysToSign，不在 fetch EEK 前重读 PEM，则磁盘换位、损坏或不可解析只会在 Google 消耗签发后才暴露。

正确的 point-of-no-return 顺序是：

1. authorization 内部生成唯一 P-256 私钥；
2. 以 canonical PKCS#8/PEM、mode 0600 持久化唯一私钥及 SPKI/summary，`fsync` 文件、key 目录、run 目录和父目录；SEC1 或任何非 canonical 私钥编码拒绝；
3. `O_NOFOLLOW` 重读 PEM，核对 dev/inode/size/hash；
4. 重新解析为 exact P-256 private key，SPKI 等于已存公钥和 KeysToSign；
5. 对随机 nonce 签名并用公钥验签，证明真正持有私钥；
6. 将 path/hash/dev/inode/SPKI 封存进 authorization state，并要求 capture 及父目录归当前 UID、capture exact mode 0700、path/dev/inode 稳定；
7. 然后才 fetch EEK；
8. fetch 和 signCertificates 的网络边界前后都重验 capture、PKCS#8、SPKI、PoP 和精确 request bytes；
9. dispatch ticket 与 authorization state 绑定 creator PID，constructor 期间或此后 fork 出的子进程不得复用能力。

duck object 只实现 `.public_key()` 不能作为私钥证明。这个门必须在网络前，不能只交给最终验包器。

## 55. “复制进归档”不等于“已从活动执行面退役”

旧 tx2、任意 KeysToSign tx4、patched 采集器、旧 online core 和诊断 APK 即使已打包，只要原路径还有脚本/二进制/APK/pyc，后续 AI 仍可误运行。

当前隔离合同：

- 原始 18 个目标成员保存在 `06_历史危险能力隔离/legacy_online_capabilities_20260906.tar.xz`；
- archive SHA-256 为 `6cb0f03628b4140a8860ad6d6c89e09a83ae50d565f8e6051dcb22c1cfc24842`，权限 0600，不含 `._*` AppleDouble；
- 每个成员必须符合 `ORIGINAL_SHA256SUMS.txt`；
- 旧 Python/shell 原路径仅留 rc=78 无副作用 tombstone；
- tx2 ELF、任意 tx4 ELF 和两个 APK 已移出活动树；
- 必需的 zero-key tx4 仅保留为 `<PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload`，mode 0600，SHA-256 `acbfb63134cc87290f7b49c959e074bf3b531a87ff4905501012606c348b8858`；
- 旧拒绝包中的两个 proof `.py` 从文件树删除，验证器只按固定 archive/member hash 读其惰性字节，严禁执行。

## 56. 把 Python 模块内的“不可绕过”写成敌对代码安全边界

同一 Python 解释器内的恶意代码可重绑 module globals、替换公开函数、修改 `__globals__`。闭包、WeakKeyDictionary 和 exact-type check 能阻断普通误用和不带代码执行权的 API 绕过，但不能在 CPython 中建立真正隔离边界。

因此威胁模型必须如实写：

- 受信 wrapper、core、profile/evidence 快照在一个无任意插件的本地进程中执行；
- 调用者不在 arm 与网络之间获得任意 Python 代码执行；
- 拥有同 UID 文件改写或同解释器代码执行权的攻击者在安全边界外；
- 若要防这类攻击，必须用单用途隔离进程、最小 IPC、只读代码映像和 OS 权限边界，不能再加一个 Python boolean。

报告可以写“直接 CLI/普通 API 误用 fail-closed”，不能写“同解释器敌对代码无法绕过”。

## 57. 看到 NOT_APPROVED 就猜“尝试次数过多”

本项目的全量本地样本是 125 张 DER、27 个唯一 Provisioning Info：25
个 clean、2 个含 `NOT_APPROVED`，且零解析错误。关键反证是同一
count-32 集合里同时有 12 个 clean 和 2 个 bad；两个 bad 的 fetch/sign
都是 HTTP 200，无 `429`/`Retry-After`/quota/abuse。

与此同时，bad 请求的 signed DeviceInfo 从 orange/unlocked 偏离到与
approved 基线不同，五层完整 DICE payload 全部不同；modified native 与
host google-rkp-sw 在同一身份、DeviceInfo、测量和五层 payload 上一致，
排除了“host 模拟天生不被接受”。因此当前根因排序是 modified
boot/DICE 环境远高于次数风控。未见明确节流信号时，不得用“可能风控”
停止环境修复。

## 58. 新软件私钥和 CDI 身份钥可以相同

CTF 交付的“一次成功产生物私钥”必须是本轮 google-rkp-sw 新生成的
KeysToSign 私钥，不是 CDI_Leaf 身份私钥的另一份拷贝。

gate-v7 现在在首次 fetch 前强制：

- 持久化后重读的软件 SPKI 与封存 CDI identity SPKI 必须不同；
- fetch、build、request verify 和 submit 每次重读私钥都重复 distinct 断言；
- capture 目录必须由当前 UID 拥有、mode 0700，且 path/dev/inode 在私钥持久化前后不变；
- dispatch ticket 和 authorization 都绑定 creator PID，fork 后的子进程不能沿用父进程的一次性能力。

## 59. 文件名里有 readonly/probe 就当成无副作用

本轮复查找到三个反例：

- `k70e_rkp_ta_readonly_probe` 允许环境变量选择任意 TA UUID/命令；
- `oemcrypto_csr_probe` 真正调用 OEMCrypto CSR；
- `k70e_rkp_inprocess_readonly_injector` 使用 ptrace/process_vm_writev、改寄存器并选命令。

三个活动 ARM64 二进制均已删除，同名 C 只留 rc=78 tombstone。
原始字节可从两个 mode-0600 归档恢复：

- `legacy_active_probes_20260906.tar.xz` = `c21aa52edaacfb4e0dad13194577cb49a909b6b4fa23d8b5c1d47cb63f0bcd04`；
- `legacy_inprocess_injector_20260906.tar.xz` = `56e33646a11a9ea1ba75c073a4ac57b5181fe3255a416f92961d73ece3895c5b`。

以后判断“只读”必须看实际 syscall/API/命令 allowlist，不能看文件名或注释。
这些 probe/injector 与旧联网能力一样，已从活动执行面禁用并隔离，不存在“临时备用”例外。

## 60. 保留旧 portable 联网 CLI 作为“备用”

旧 portable 路线可以在 patched TA/TEE/init_boot 捕获物上继续走 Google，这正是
本次环境偏离的重复入口。当前规则：

- `rkp_sw_portable.py` 仅保留离线 preflight、resume-finalize 和供 stock wrapper 使用的库函数；
- 它的直接联网分支永久 SAFE_ABORT，不得恢复；
- 唯一受支持的新签发入口是 `rkp_sw_stock_log_once.py`；
- current toolchain/profile 是不继承 V4 的 stock-log-only V5，只能绑定 stock-log 所需文件，不得再把 tx2 keygen、candidate TA/TEE、patched init_boot 或 restore builder 列为当前信任集。

## 61. 离线门全 PASS 就宣布 NOT_APPROVED 已经解决

离线工作可以证明旧结果是环境偏离、新管线不会在已知偏离上联网、不合格链无法发布；它不能代替 Google 对 fresh stock boot 的新决定。
截至最新冻结点，Pixel 已移除且唯一 K70E ADB 已稳定；工作停在已实证的 `b9b1d867…` 拒绝环境和待执行 CN304 恢复。本轮 fresh-stock zero-key Binder 与 Google one-shot 都未消耗。因此尚未取得新的无 `NOT_APPROVED` 证书链，不得把“离线 178/178 PASS”写成“真机终验已解决”。

最终“已解决”的唯一验收是 K70E 回到精确 approved-baseline 组合后，在
fresh boot 中新捕获五层 stock request，执行一次 controlled attempt，并产生：

1. 同轮 CDI_Leaf 身份数据；
2. 同轮新软件私钥；
3. 与该私钥 SPKI 匹配、Google 签名可验、全链 raw Provisioning Info 零 `NOT_APPROVED` 的唯一证书链。

## 62. 把 `dummy0/table 1002` 黑洞路由当成手机外网

错误做法：

    ip route 输出里只要有以 default 开头的行，就判定手机可上外网。

事实：

AOSP netd 会无条件安装 `default dev dummy0 table 1002` 类型的直连 sink。它没有 `via`，是丢包黑洞，不是可转发的外网通道。旧的 `^default` 计数会把参考机正常离线状态误报成 FAIL。

正确处理：

- 只忽略当前代码严格 token grammar 认可的、无 `via` 且 `dev=dummy0/table=1002` 的 IPv4/IPv6 sink；
- `forwarding_default_route_count` 必须严格为 `0`；
- `ignored_dummy_sink_default_route_count` 单独记录，不得与可转发路由混数；
- 缺 table、错 table、重复 `dev/table`、`via/nexthop/nhid/encap`、未知尾缀和跨 IPv4/IPv6 语法全部 fail-closed。

不能为了消除误报而宽泛放行所有 `dummy0` 或所有无 `via` 路由。

## 63. 路由查询失败被空输出掩盖

错误做法：

    ip -4/-6 route 查询失败，但 shell 最后的 echo 返回 0；
    parser 看到空路由后误判“零 default，所以离线”。

正确处理：

- IPv4/IPv6 路由查询分开边界和分开记录 RC；
- `ipv4_route_query_succeeded` 和 `ipv6_route_query_succeeded` 必须都为严格布尔 `true`；
- 任一 RC 非 0、marker 重复/错位、查询结果无法解析，都必须在 Binder/ATTEMPT/设备 latch 前 SAFE_ABORT；
- 不得把“空 stdout”当成“查询成功且无路由”。

## 64. 只在早期检查手机离线，到 latch 时不复核

风险：

手机在 live preflight 后到 host `ATTEMPT`/设备 latch 之间可能恢复 Wi-Fi、移动数据或反向共享，从而与 host 的唯一 Google 运行并发。

当前专用 wrapper 有两道手机离线门：

1. 在 host `ATTEMPT` 之前的 live preflight 先用严格唯一 ADB inventory 解析器验证全局 transport，通过后才允许任何 serial-scoped shell；随后检查飞行模式、Wi-Fi、IPv4/IPv6 查询 RC 和严格 default-route grammar，结果绑入 `LIVE_STOCK_PREFLIGHT.json`；
2. `reserve_device_latch()` 也先独立重做全局 ADB inventory，在该阶段任何设备 shell 和 latch 创建之前拒绝第二记录、重复记录、非 `device` 状态或畸形行；通过后才使用 `set -eu`、显式查询失败退出和同语义严格 AWK 再做手机离线门。

两道都允许严格 AOSP dummy sink，但任何可转发 default 都拒绝。第二道失败必须阻止 latch 消耗，不得用 AWK 反向退出码把解释器错误当成通过。

## 65. ADB 旧 daemon/libusb 卡顿、多设备和休眠被当成可重试小问题

本次现场已观测到：旧 ADB daemon/libusb 路径可卡住约 4 分钟后才超时。这不是 K70E 身份或 Google 风控证据，也不能在一次性边界后盲目重跑。

现场正确顺序：

1. 先用 IORegistry/外部 USB 端口 inventory 确认物理层，再拔掉 Pixel（历史 serial `<DEVICE_SERIAL>`）和其他 Android 设备；`adb --one-device` 会把其他物理设备隐藏在 daemon 视图之外，所以它不能取代外部物理 inventory 和断开；
2. 只使用 profile 锁定的官方 platform-tools ADB，清理旧 server 后以 `ADB_LIBUSB=0 adb --one-device <DEVICE_SERIAL> start-server` 启动；
3. 再确认 `adb devices -l` 只有目标 serial，不接受 offline/unauthorized/第二设备；
4. 操作员在手机开发者选项开启 **Stay awake**，USB 供电期间保持屏幕/授权上下文稳定；
5. 在任何 Binder point-of-no-return 之前处理 ADB 问题。一旦已有 `DISPATCHING_NO_RETRY`、`ATTEMPT`、device latch 或 `NETWORK_STARTED`，就不能把 USB 超时当成“再试一次”的理由。

截至最新冻结，Pixel 已不在场，唯一 K70E ADB 已稳定；但因当前仍是拒绝环境，本轮尚未执行 fresh-stock zero-key Binder 或 Google one-shot，没有消耗真机 one-shot。

## 66. 用宽松文本处理 `adb devices -l`

错误做法是只搜索目标 serial，或在多行输出中取第一个 `device`。这会放过第二设备、同 serial 重复行、`offline`/`unauthorized`、控制字符、非 ASCII、异常 CR 换行、多余头尾空白和重复/畸形 detail token。

当前 collector 和 wrapper 各自内置严格唯一 parser：输出必须恰好是标准 header 加一条记录，记录必须是 pinned serial、状态严格为 `device`，每个后续 token 必须是唯一且合法的 `key:value`。任何偏离都在首个设备 shell 之前 SAFE_ABORT。

## 67. inventory 在 shell 之后才做

serial-scoped `adb -s $SERIAL shell` 不能替代全局 transport inventory；如果先做 shell，另一设备已在场的事实会被绕过。

当前顺序是：

1. collector 基线阶段：全局 inventory 必须是该阶段第一个设备操作，通过后才允许 stock/offline/log shell；
2. collector 最终 dispatch 阶段：再次全局 inventory，通过后才允许本阶段的任何 shell，然后才写 `DISPATCHING_NO_RETRY` 并唯一调用 Binder；如果第二轮 inventory 相对基线漂移，必须做到零后续 shell、零 Binder、零 invocation marker；
3. wrapper live preflight：全局 inventory 先于所有 live shell；
4. wrapper latch 阶段：在 host `ATTEMPT` 已耗用后重做全局 inventory，通过后才运行原子的 stock/offline/latch shell。

collector 在第二轮 inventory 失败时也不得用“清理”为名对设备再发 shell。已分发的远端临时目录保留，host 在 `remote_cleanup.json` 记录 `removed=false`、远端路径和“final exclusive ADB inventory failed”原因。只能在之后重新从 IORegistry/外部 USB 端口和严格 ADB inventory 确认唯一目标后手工清理；清理不授权 Binder 重跑。

## 68. `--attended` 在预检后才验证

`--attended` 是人在机旁的现场授权，不是普通配置字段。如果到 build preflight、创建输出目录或任何 one-shot 副作用后才发现未提供它，就会把未授权的调用带进现场逻辑。

当前两个 CLI 都在任何 preflight/输出创建/设备操作之前验证：collector 必须同时指定 `--attended --execute-zero-key-once`；wrapper 只有 `--execute-google-once` 可以与 `--attended` 配对，实际发行缺少它立即 SAFE_ABORT，`--preflight-only --attended` 也拒绝。

## 69. `pidof tee-supplicant` 多 PID 被当成一个 PID

`pidof` 可以返回空、一个 PID 或空格分隔的多个 PID。把整串直接交给 `nsenter -t` 不能证明命名空间唯一，而且 shell/解析差异可以让验证变得含糊。

collector、wrapper live preflight 和 latch 前原子 shell 现在都要求返回值恰好是一个非空 ASCII 十进制 PID；空值、空格、多 PID、符号或其他字符全部在 namespace TA 验证/latch 之前拒绝。

## 70. ATTEMPT v1 的 future-latch 预承诺被误写成 SUCCESS 绕过

当前 `k70e-rkp-ctf-stock-log-issuance-attempt-v1` 会先耗用 host `ATTEMPT.json`，其中预承诺稍后将创建的 `DEVICE_LATCH.json` 路径、内容哈希和设备 latch 关系，然后才重做 ADB/stock/offline 门并消耗设备 latch。这是 v1 的 future-latch precommit 语义局限，不是 SUCCESS 绕过：

- 如果 latch 前 ADB inventory 失败，当前 attempt 必须写 `BURNED.json`，不存在 `DEVICE_LATCH.json`、`NETWORK_STARTED.json` 或 POST；
- SUCCESS verifier 必须看到实际 `DEVICE_LATCH.json`，且它必须与 `ATTEMPT.json` 的预承诺逐字节关系一致；只有 future hash 不能成为 SUCCESS；
- 不能用“先在设备上创建 latch，再在 host 写 ATTEMPT”来表面修复；一旦 host marker 创建失败，会留下已消耗的设备 latch 而没有 host attempt 证据；
- 如要改变这个跨 host/device 提交协议，必须设计新 schema，同步更新 core/wrapper/verifier/fixture/manifest，并整体迁移到 gate-v8。当前冻结执行面仍是 gate-v7，不允许在 v7 内静默改序。

## 71. 把 `adb --one-device` 当成物理唯一性证据

`--one-device SERIAL` 限制的是新 ADB daemon 接管的 transport；它会让其他已物理插入的 Android 设备不出现在随后的 `adb devices -l` 视图中。因此“严格 ADB parser 只看到 K70E”只能证明 daemon 视图唯一，不能证明 USB 物理层唯一。

现场必须在启动 `--one-device` server 前和 one-shot 紧前使用 IORegistry/外部 USB 端口 inventory，确认 Pixel 和其他 Android 设备已物理移除。当前 Pixel 已移除且 ADB 已稳定，但这不覆盖拒绝环境门；在 CN304 恢复/post-boot 全门通过前，真机 one-shot 仍不授权、也未消耗。

## 72. 把 zero-key marker 当成跨目录全局 latch

`zero_key_invocation.json` 及其 `DISPATCHING_NO_RETRY`/最终态只属于当前 capture 目录。它能阻止同一目录原地重跑，但不能在新目录中自动发现历史 dispatch，也不是设备签名的 exactly-once receipt。

所以跨目录不重放仍依赖操作纪律：执行前盘点所有私有 capture 目录/交接记录，一旦任何目录出现 dispatch 或不确定结果就视为已消耗，禁止换目录重跑。如需强跨目录防重放，需要设备端全局 latch、组织者 nonce/签名 receipt 或外部不可变日志，不能在文档中将目录级 marker 夸大为这些保证。

## 73. `PREPARED.json` 只验主键，把持久证据当作装饰字段

旧恢复器只复核 target、工具/源哈希和少数 snapshot 字段。已实证将 `network_used: false` 改为整数 `0`、将 `forbidden.network: true` 改为整数 `1`、将 SHA/nonce 字符串改成 64 位十进制整数，甚至增加未知顶层字段，都会进入八步 mock flash。

当前 `prepared-v2` 在 execute 和 reboot 共用同一 exact validator：

- 顶层、target、ADB audit、transport、offline、snapshot、battery、raw baseline、B 链、legacy、forbidden、source、plan 的键集必须完全相等；
- JSON `bool`/`int`/`float`/字符串不允许 Python 弱类型相等或 `str(...)` 强制转换；
- 未知、缺失、多余、重复键、非 canonical JSON、时间/UUID/boot-session 或 nested identity 偏移均在 global claim 和首个 flash 之前拒绝。

## 74. 只看 `FLASH_COMPLETE` 摘要就重启

旧 reboot 路径只看步数/status，已实证篡改 `completed_steps`、STARTED/OK 的 step 类型、裁剪 claim reference，或删掉 `execution_claim_sha256`/`automatic_retry`/`completed_epoch` 仍会发出 mock reboot。

当前唯一 reboot 前必须完整重放：global claim 和 exact local ref、post-claim full gate、8 组 STARTED/OK、每步 raw stdout/stderr 哈希及独立重解析、full/critical Fastboot gate 及哈希、时间顺序、claim 绑定的 exact `FLASH_COMPLETE`。目录必须恰好只有预期文件；任何 PARTIAL、额外或缺项都在 TTY 和 `fastboot reboot` 之前停止。

## 75. 用“看起来像 OKAY”的宽松 Fastboot 文本解析

最终审计找到三类真问题：

- pinned `super.img` 明确是 Android sparse，但旧 parser 接受 raw `Sending 'super'`；现在 step 1 必须是从 `1/N` 到 `N/N` 的连续 sparse 序列，后 7 步必须 raw；
- `getvar` 和 reboot 旧实现只计数，倒序 `Finished` 仍可通过；现在顺序必须分别是 assignment→Finished 和 Rebooting→Finished；
- Fastboot status 用 `OKAY [%7.3fs]`，Finished 用 `%.3fs`。任意空格既会错收不可能 frame，也会错拒合法 `[100.001s]`。当前分开两套 grammar，拒绝错误 padding、前导零、非 3 位小数、错 target、`NOT_OKAY`、未知行和倒序。

仅保留两条已观测、逐字节固定的 macOS `e0005000` IOKit cleanup warning，input/output 各最多一次。Fastboot 报告的 KB 数只作语法证据，端到端正确性仍由 pinned binary/source、exact argv 和 post-boot 全分区 SHA-256 闭环。

## 76. 长哈希后查过离线，但 transport 盘点后留了窗口

只在 9.1 GB 哈希后复核 offline 还不够；后续 IORegistry/ADB/Fastboot transport inventory 期间仍可发生网络状态变化。当前 post-boot 顺序是：初始 offline→长哈希后 offline→boot-id→transport inventory→第三次 offline→terminal boot-id。三份 offline 证据必须 typed-equal，最后 boot-id 覆盖第三次查询窗口，然后才能原子写 host marker。

## 77. 2026-09-06 当前唯一冻结快照

以下是当前执行面，不得从上文历史升级记录回退：

    toolchain          k70e-portable-macos-host-20260906-v5 (stock-log-only)
    core gate          v7
    core               619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  193161
    profile helper     724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  134026
    portable library   0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c   76113
    stock collector    732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c   75305
    stock wrapper      99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3  121031
    verifier           f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357  120223
    profile internal   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
    profile file       5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81   17803
    collector tests    67e38a25a96c026595ca6a3157c3bc4a5639c6cf969609b461348b7d3bfdfd2d   50002
    wrapper tests      d2a6bc8fe54eef5b36fc8bf15e4ece71b82061d9eaec6eb979939094cf399793   99075
    verifier tests     13a4e5383595753def31d1c301c01f119898558982936a224baa20193886e20e   67504
    host-only tests    8 groups, 178/178 PASS (23+13+12+31+10+10+42+37)
    recovery tool      3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9   109993
    recovery tests     15bb1201dcb4180b37ff3f776393aca98a4b9f6b33748f83f1c508741054adc7   43802; 35/35 PASS
    postboot verifier  c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add   99185
    postboot tests     c13433501cdb3870852e2494e5055b556a11b565e9ad19d58bf3e04e9a7c476b   42736; 24/24 PASS

`portable library` 的 hash 仅表示 stock wrapper 调用的受限库代码，不表示允许直接 portable 联网；该入口已永久禁用。上述门可防普通 CLI/API 误用和已覆盖的文件换位，但拥有同 UID 恶意改写权或同一 Python 解释器任意代码执行权的攻击者仍在安全边界外。

这个冻结快照是“可继续现场终验的发行候选”，不是赛事 PASS。当前 core 仍为 gate-v7；ATTEMPT v1 若修订必须整体迁移 gate-v8，不得在此冻结身份上局部改序。Pixel 已移除且唯一 K70E ADB 已稳定，但当前仍是 `b9b1d867…` 拒绝环境。必须先按文档 58 恢复并由独立工具写出 `POSTBOOT_VERIFIED.json`，再执行新 stock zero-key capture 和一次 controlled attempt，并得到全链 raw Provisioning Info 零 `NOT_APPROVED` 才能终验。恢复固定八步不含 TEE/boot/顶层 vbmeta/init_boot；whole `super` 是唯一跨槽例外，任何失败停 Fastboot且不自动重试。


---

## 原始记录段 4 / Source section 4: 22_K70E_活动GenerateRkpKey_私钥生成路径静态闭合_20260830.md

# K70E 活动 `GenerateRkpKey` 私钥生成路径静态闭合

日期：2026-08-30（Asia/Taipei）  
设备：Redmi K70E / `duchamp`  
范围：原厂 Mitee KeyMint TA 的离线静态分析；设备下班后保持不动，不执行刷写、重启或在线探测。

## 结论

当前活动 RKP 路径已经可以静态闭合到“P-256 私钥被序列化为 KeymasterBlob”的边界：

```text
活动命令 0xc94d8
  └─ BL 0x61960   GenerateRkpKey
       ├─ 0x610e8  GenerateKey/工厂分发
       │    └─ factory vtable +0x10
       │         └─ 0xa2fd0  EcKeyFactory::GenerateKey
       │              ├─ 0xfb0f0   EVP_PKEY_new（P-256 分支）
       │              ├─ 0x114fe0  选择 P-256 group
       │              ├─ 0x116770  EC_KEY_set_group
       │              ├─ 0x116c28  EC_KEY_generate_key
       │              ├─ 0x116a28  EC_KEY_check_key
       │              ├─ 0xfb3e0   EVP_PKEY_set1_EC_KEY
       │              ├─ 0xa79d0   EvpKeyToKeyMaterial（私钥材料序列化）
       │              └─ 后续 vtable  CreateKeyBlob（生成 opaque key blob）
       └─ 0xa7b88  GetEcdsa256KeyFromCert（只取证书公钥 X/Y）
```

因此，`0xa7b88` 不是私钥比较器，也不是 `CDI_Leaf` 提取点。此前在该处导出的两个 32 字节值应标记为错误分支：它们是证书 EC 公钥坐标/内部大整数对象相关数据，不能作为 scalar、seed 或 IDC。

## 证据链

### 1. 活动入口到密钥工厂

原厂 TA（整体 SHA-256：
`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`）中：

* `0xc94d8` 直接 `BL 0x61960`；
* `0x61960` 保存上下文、请求和响应结构，并经上下文 vtable `+0xb8` 取得活动对象；
* `0x61960` 在 `0x61c78` 调用 `0x610e8`；
* `0x610e8` 从上下文取得算法工厂，并在 `0x6124c` 通过工厂 vtable `+0x10` 分发到具体 `GenerateKey` 实现。

这条调用图与 Android Keymaster 的 `GenerateRkpKey → GenerateKey → key_blob + MacedPublicKey` 结构一致；官方实现会从生成证书取出 EC 公钥 X/Y，并把 key blob 与 MacedPublicKey 分开返回（参见 [Android Keymaster GenerateRkpKey](https://android.googlesource.com/platform/system/keymaster/%2B/master/android_keymaster/android_keymaster.cpp)）。

### 2. P-256 生成的非 25519 分支

`0xa2fd0` 与 AOSP `EcKeyFactory::GenerateKey` 的控制流逐段对应。曲线字段不为 25519 时：

| TA 地址 | 静态对应 | 作用 |
|---|---|---|
| `0xfb0f0` | `EVP_PKEY_new` 包装 | 创建 EVP_PKEY 容器 |
| `0x114fe0` | `ChooseGroup`/曲线组选择 | P-256 的 group/NID 映射 |
| `0x116770` | `EC_KEY_set_group` 包装 | 绑定 P-256 group |
| `0x116c28` | `EC_KEY_generate_key` 包装 | 生成随机私钥 scalar 与公钥点 |
| `0x116a28` | `EC_KEY_check_key` 包装 | 检查 EC key 一致性 |
| `0xfb3e0` | `EVP_PKEY_set1_EC_KEY` 包装 | 将 EC_KEY 放入 EVP_PKEY |

`0x116c28` 是私钥 scalar 首次确定存在于 EC 对象内的生成边界；但此时仍在 TA 内存中，不能把该地址本身当作可读私钥。

### 3. 私钥材料进入 KeymasterBlob

生成成功后，`0xa2fd0` 在 `0xa3210` 取回 EVP_PKEY，并在 `0xa32ac` 调用 `0xa79d0`：

```text
0xa3210  ldr x0, [sp,#0x40]   // EVP_PKEY
0xa32ac  mov x1, x25          // KeymasterBlob*（本地输出结构）
0xa32b4  BL  0xa79d0
0xa32b8  str w0, [error]
```

`0xa79d0` 的第一步是调用 `0xfb218` 读取 EVP 对象的类型字段；随后 EC 分支通过 `0xee7c0`、`0xf91c8` 和 `0xee918` 取得私钥材料指针/长度，分配新缓冲区并复制到输出 `KeymasterBlob`。其中 `0xf91c8` 读取 `EVP_PKEY` 内部方法表 `+0x30` 并间接跳转，正是私钥 DER 编码的动态分发边界；`0xa7aa4` 明确调用 `memcpy`，把该临时编码复制到 `x19` 指向的输出 blob。对应的 AOSP [`EvpKeyToKeyMaterial`](https://android.googlesource.com/platform/system/keymaster/%2B/eb51e7fc8367d59061fc8970d5c1f519995b0029/km_openssl/openssl_utils.cpp) 使用 `i2d_PrivateKey` 将 `EVP_PKEY` 序列化为 DER（EC 通常是 `ECPrivateKey`，不是 32 字节裸窗口）。在 `0xa32b4` 返回之后，`x25` 指向的结构已经包含序列化私钥材料；紧接着的后续 vtable 调用才把它包装为 opaque key blob。

这给出了下一次在线验证的最小、确定性观测点：在**原始 `BL 0xa79d0` 完成后、进入 CreateKeyBlob 前**，读取 `x25` 指向的 `(data, length)`，然后只把这段材料保存到诊断输出；绝不扫描任意 32 字节窗口，也不改写生成逻辑。若输出是 PKCS#8/DER，应直接解析；若输出是原始 32 字节大端 scalar，则转成 PKCS#8 前必须通过同次 `MacedPublicKey` 的 X/Y 精确匹配。

### 4. `0xa7b88` 的正确语义

`0xa7b88` 的反汇编明确显示：

* 强制 `x2 == 0x20`、`x4 == 0x20`；
* 从证书/密钥对象取出两个字段；
* 经 `0x1157d0` 和 `0xee560` 处理两个 32 字节输出；
* 调用位置紧邻字符串 `GenerateRkpKey GetEcdsa256KeyFromCert`。

这对应“从证书提取 P-256 公钥 X/Y”，不是私钥 scalar。现有诊断目录中的 `comparison_value_0.bin`、`comparison_value_1.bin` 和 275 字节对象前缀因此只能作为排错记录，不得提交为私钥。

## 主机侧严格匹配工具

已新增：

`02_脚本与补丁/verify_rkp_private_matches_maced.py`

输入为一个候选私钥（接受 32 字节大端 scalar，或未加密 EC 私钥 PEM/DER，包括 `i2d_PrivateKey` 产生的传统 ECPrivateKey DER）和同次 `maced_public_key.bin`。工具会：

1. 解码 COSE_Mac0 载荷并确认 `P-256 / ES256 / crv=1`；
2. 从候选私钥推导公钥 X/Y；
3. 对 X、Y 做逐字节精确比较；
4. 只有匹配时才写出 PKCS#8 PEM，且以 `0600` 权限保存；
5. 拒绝 275 字节 opaque KeyMint handle，并且从不打印私钥字节。

已用现有材料验证门禁行为：

* `private_key_blob_opaque.bin`（275 字节）→ `FAIL: opaque KeyMint handle`；
* 外来 FF06 候选 PKCS#8 → `FAIL: public_x_match=false, public_y_match=false`；
* 内存合成的 P-256 正例 → `SELFTEST PASS`。

## 设备恢复后的最小验证顺序

设备重新在线后，先只读确认原厂启动链和 TA 哈希；清理此前未使用的 `.armed` 诊断标记；确认 `ro.boot.verifiedbootstate=green`、`tee-supplicant` 与 `vendor.keymint-mitee` 正常。之后再由用户在场、逐步验证一个“只捕获 `a79d0` 返回后 KeymasterBlob”的诊断构建。

判定标准固定为：

```text
私钥材料存在
  AND 长度/格式可解析
  AND 推导的 P-256 X/Y == 同次 MacedPublicKey 的 X/Y
  AND 用该私钥生成/提交 CSR 后 Google HTTP 200
```

在四项全部满足前，工作区仍不能声称已经取得赛事要求的“私钥 + Google 证书”最终产物。当前原生目录中的证书链和 275 字节 opaque blob 仍是半成品，不改变这一结论。

## 相关文件哈希

```text
原厂 TA：facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
MacedPublicKey：cc5025fffaa8696e6dbe085988e851f31591629c78b86c4b7407ff8fd95db45d
匹配工具：a77aeebbc22adbdc8d9efdb4e19cdd2ee24477152c9c0b9a7131016ee18fcd15
```


---

## 原始记录段 5 / Source section 5: 11_K70E_P256KeypairFromCDI_32字节路径提取计划_20260829.md

# K70E CSRv3 CDI/UDS 路径追踪与 IDC 定位记录（2026-08-29）

## 当前状态

当前设备为 `duchamp`，ADB 序列号 `<DEVICE_SERIAL>`，系统属性保持
`ro.boot.verifiedbootstate=green`、`ro.boot.flash.locked=1`。运行中的原厂 Mitee TA
SHA-256 为
`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`。

此前导出的固定地址值和 0x158900 窗口均不能重建原生 UDS SPKI，因此不再使用。

## 静态定位结果

在 TA ELF 中，字符串和调用关系把 `P256KeypairFromCDI` 路径定位到：

- 包装器 `0xdb330` 将参数重排后调用 `0xda938`；
- `0xda938` 保存第三参数到 `x21`，随后以 `ldrb [x21, index]` 遍历 0x20 个字节；
- `0xda520` 被同一路径调用，第二参数为该 32 字节输入，负责产生 P-256 key pair；
- DICE/BCC 生成路径在 `0xdd898` 调用包装器，第三实参来自同一次 TA 调用的临时缓冲区。

因此不能把任意 32 字节文件或 KeyMint opaque blob 前缀称为 IDC；必须采集上述真实
输入，并用已知原生 UDS SPKI 做独立门控。

## 2026-08-29 第三轮活跃路径采集（当前开机）

第三轮使用当前一次性诊断 TA（TA SHA-256：
`6b543ac9eafa4486f170404129dead628e5287d37cc11f77f2bc77a19d72bfb8`）完成一次本地采集，
没有刷写分区、没有修改 BL、没有向网络签发端提交。设备状态为 `PowerKey`、slot `_a`、
`verifiedbootstate=green`、`vbmeta.device_state=locked`，KeyMint 与 tee-supplicant 均在线。

原始结果目录：
`../03_提取结果/K70E_活跃种子诊断第三轮本地CSR与keygen_20260829/`。

- `cmd remote_provisioning csr` 返回 Base64 3385 字节，解码 CBOR 2536 字节，
  SHA-256 `6383b3343a19749fadf4453994a1b73803c40ccb56dc9b264af46d01491e191e`；
- Binder keygen 返回 `private_blob=275`、`maced_public_key=119`；private blob SHA-256
  `640d7a48804201c8a14d0fafe0b8354ad448db6d047784b946a3f87e45b82a0e`；
- 诊断结果出口预期在 `private_blob+0x20` 写入 `c7c70000`，实际为 `06df138b`，标记未出现；
- 独立 Open-DICE 门控扫描窗口 `[0:256]` 的 225 个 32 字节候选，
  `match_count=0`（窗口 SHA-256 `3ef62ed8625390500b72ea0c0ce1b6a17677081c4a15c2c69749656c32da5802`）。

结论：本轮证明 Binder 调用本身成功，但没有证明 `0x62320` 是当前 CSRv3/keygen 的可读
结果出口，也没有得到可供 `google-rkp-sw` 使用的 32 字节 IDC。该 blob、其前缀和任何
窗口均不得提交或当作种子；下一步应定位实际 CSRv3 CDI 结果对象/出口，而不是继续重启或
提交网络请求。

## 新诊断 TA（仅主机生成）

脚本：
`../02_脚本与补丁/patch_mitee_keymint_p256_cdi_capture_diag.py`

脚本在现有 0x1366cc 可执行零洞中放入两个入口：

1. `0xda938` 入口把 `x2[0:32]` 复制到 RW 段未引用的 `0x164100` 暂存区；
2. `0x6236c` 返回路径把暂存区复制到诊断 private blob，`MacedPublicKey` 不改写。

静态反汇编验证：

```text
0x1366cc: adrp x8, #0x164000
0x1366d0: add  x8, x8, #0x100
0x1366d4: ldp  q0, q1, [x2]
0x1366d8: stp  q0, q1, [x8]
0x1366dc: b    0xda93c
0x1366e0: adrp x8, #0x164000
0x1366e4: add  x8, x8, #0x100
0x1366e8: ldp  q0, q1, [x8]
0x1366ec: ldr  x9, [x25, #0x10]
0x1366f0: stp  q0, q1, [x9]
0x1366f4: str  wzr, [x25, #0xc]
0x1366f8: b    0x62370
```

源 TA SHA-256：
`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`

诊断 TA SHA-256：
`68c58aad8e70a5d85f1376582d60c03d4acb39ccf0332d9f593e9de86274b232`

诊断 TA 只允许做一次本地采集；返回的 private blob 不得提交到 KeyMint/RKP 服务。

## 采集顺序

`capture_k70e_p256_cdi_seed_after_csr.py` 先发起一次本地
`cmd remote_provisioning csr`，让真实 TA 走 DICE/BCC 路径，再调用一次 Binder keygen
把暂存区导出。随后由 `opendice_p256_seed_gate.py` 从候选 32 字节独立派生 UDS SPKI，
只有与原生基线
`d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9` 完全一致才接受。

当前只完成主机静态构建，未启用模块、未重启、未刷写分区、未改变 BL。启用诊断 TA
前必须确认一次性重启风险，并保留自动禁用标记以回到原厂 TA。

## 2026-08-29 受控采集记录

本轮所有操作均在刷写前建立备份，未改动分区、BL 或启动链。备份目录：

- `../03_提取结果/K70E_P256_CDI诊断重启备份_20260829_110725/`
- `../03_提取结果/K70E_P256_CDI诊断重启备份_20260829_第二次_加载前/`
- `../03_提取结果/K70E_P256_CDI诊断重启备份_20260829_第三次_结果出口加载前/`
- `../03_提取结果/K70E_P256_CDI诊断重启备份_20260829_第四次_错误字通道加载前/`

四次诊断启动都使用 KernelSU 一次性 bind；每次重启后模块自动创建
`/data/adb/modules/k70e_bcc_seed_diag/disable`，最终已重启回原厂 TA：

`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`。

### 结果向量出口实验

`patch_mitee_keymint_p256_cdi_export_pair.py` 在 `0x62320` 的结果向量出口复制
暂存区到新分配的结果缓冲，诊断 TA 哈希为 `ca8f6ab2a77eaf8cb7b632fb2aac093e934c5bef3962bfb09637b9c9fe87e9cf`。

- 仅 keygen：`../03_提取结果/K70E_P256_CDI结果向量导出_20260829_第四轮/`
- 先 CSR 后 keygen：`../03_提取结果/K70E_P256_CDI结果向量导出_20260829_第五轮_CSR后/`

两次均返回 275 字节 private blob、119 字节 MacedPublicKey，但 244 个 32 字节窗口均未通过
原生 UDS SPKI 门控。第五轮的 CSR 原始输出为 3369 字节，SHA-256 为
`5a66071edb262cf5b680713c65f9cb2715a076dabac215b52a64e91ba805c4be`；这证明结果向量
不是 `P256KeypairFromCDI` 暂存区的可读出口。

### Binder 错误字通道实验

`patch_mitee_keymint_p256_cdi_error_word.py` 将 `db330` 的状态映射改为返回暂存区首字，
诊断 TA 哈希为 `df358ace5e6473f2cccc45b7a1e810c7e5a00a5fb399ec7834c374e169e28f25`。

- 当前 CSRv3/V2 客户端：成功返回 2608 字节 CSR，未触发该错误通道；
- legacy v1 事务 3：直接返回 `remote exception=-8 service_error=6 status=0`，未进入
  `P256KeypairFromCDI`。

因此，K70E 当前实际使用的 CSRv3 调用路径并不经过旧 legacy v1 的 `db330 → da938` 出口。
本轮没有得到可供 `google-rkp-sw --seed` 使用的 32 字节材料，也没有向任何签发端提交请求。

## 当前开机后的静态定位补充

对保存的原始 TA ELF 重新做 AArch64 只读反汇编，确认以下事实：

- 原 legacy `P256KeypairFromCDI` 包装器仍为 `0xdb330 → 0xda938 → 0xda520`；
- `0xda520` 的直接 `BL` 调用点只有 `0xd89f4` 与 `0xdad0c`；
- 当前 CSRv3 入口为 `0x626c8 → 0x925c8`，其内部主要通过函数表取址后 `blr`，在该入口区没有直接 `BL 0xda520`；
- `0xdd898` 虽然会调用 `0xdb330`，但它属于旧的 DICE/legacy 包装分支，不能据此断定它是当前 `generateCertificateRequestV2` 的实际出口。

因此，第三轮诊断 TA 只 hook `0xda520` 并在 `0x62320` 读取结果，未出现 `c7c7` 标记是符合静态调用图的：这证明 hook 选择没有覆盖当前 CSRv3 的真实 CDI 结果对象，而不是证明设备没有稳定身份。下一轮若继续，只能先定位 `0x925c8` 使用的实际函数表/结果对象；在此之前不再启用新的 TA bind，不重启、不刷写。

### 安全收尾

诊断 TA 已从安全世界实例中移除，当前 vendor TA 哈希恢复为原厂值；`flash_or_bootloader_modified=false`。
此前所有诊断 blob 仅作失败实验记录，不得当作生产 KeyMint 私钥、BCC 或 CSR 输入。

## 2026-08-29 设备已开机后的继续静态复核

用户确认设备已提前开机；本次没有再次重启。只读状态为：ADB `device`、启动原因
`PowerKey`、槽位 `_a`、`verifiedbootstate=green`、`vbmeta.device_state=locked`，
`vendor.keymint-mitee` 与 `tee-supplicant` 均为 `running`。KernelSU 模块仍存在
`/data/adb/modules/k70e_bcc_seed_diag/disable`，因此下次启动不会主动重新 bind。

对当前可见文件的哈希复核为：

`6b543ac9eafa4486f170404129dead628e5287d37cc11f77f2bc77a19d72bfb8`

该值对应本次运行中残留的诊断 bind 视图，不作为原厂 TA 证据；安全世界已经缓存的实例
也不能仅凭 `/vendor` 文件哈希判断是否重新加载。`cmd remote_provisioning dump default`
仍返回 `hwVersion=3`、`rpcAuthorName=mitee`、`uniqueId=Xiaomi Mitee Keymint 3.0`、
`supportedNumKeysInCsr=20`。因此本次只确认原生 Binder 服务在线和已有库存可读，未生成新的
CSR、未提交签发请求，也未把当前诊断输出解释为 IDC。

对活动 CSRv3 函数 `0x925c8` 的只读反汇编显示：该函数在 `0x92ad4` 调用
`0x94d08`，其余关键步骤大量使用对象函数表的间接 `blr`；在活动入口区没有直接
`BL 0xda520`。这与旧路径 `0xdb330 → 0xda938 → 0xda520` 相互独立，进一步说明
此前针对旧 wrapper 的 hook 不能覆盖当前 CSRv3 的 CDI 结果出口。下一步若继续，仍只能
先解析 `0x925c8` 使用的实际函数表和结果对象，不能凭 275 字节 blob 或任意窗口拼出
`google-rkp-sw --seed`。

## 2026-08-29 活动 CSRv3 的 32 字节分支复核

继续对活动入口做了局部反汇编，发现此前容易误读的两个“32 字节”操作并不是
IDC/UDS 导出：

- `0x94d08` 先分配对象并写入小端字节 `4d 41 43 30`（`"MAC0"`），随后构造
  COSE_Mac0 相关对象；它不是 `P256KeypairFromCDI` 或 `DiceKeypairFromCDI`。
- `0x925c8` 在 `0x92ad4` 调用 `0x94d08` 后，于 `0x92b14–0x92b24` 只检查长度
  是否为 `0x20`，再调用 `0x1003d8`。同样的序列在 `0x93350` 的
  `0x93918–0x93928` 再出现一次。
- `0x1003d8` 的实现是逐字节 XOR 后 OR 累积并返回相等标志的常量时间比较，
  不是 `memcpy`：`0x1003d8–0x100464`。因此这两个 32 字节分支是 MAC/签名
  校验，不是把 32 字节秘密复制到 Binder 输出。

这条证据排除了“在活动 CSRv3 入口已经存在一个可直接读取的 IDC 缓冲区”的推断。
当前原生路径对外已证明的仍是 UDS/CDI 公钥、DICE/BCC 和 Google 证书链；尚未找到
一个把对应私有 seed 返回给主机的调用或结果对象。若要继续，必须定位函数表中真正的
安全世界结果承载对象，并先证明其值可重建原生 UDS SPKI，再考虑离线材料。

## 2026-08-29 MiTEE 远程配置上下文函数表复核

继续沿 `GenerateCsr` 的函数表追踪，确认保存的原始 TA 在 `0x148390` 处有一组
MiTEE 远程配置上下文 vtable：

```text
0x1483a0 -> 0x000bbf40   （上下文/持久化读取辅助）
0x1483a8 -> 0x000bc410   （boot_os_version / DeviceInfo 路径）
0x1483b0 -> 0x000be710   （WHI MAC 签名路径）
0x1483b8 -> 0x000beb18   （Signed MAC 组装/错误处理）
0x1483c0 -> 0x000bec48   （返回清理/状态辅助）
0x1483c8 -> 0x000bec98   （`hwbcc_get_protected_data` 路径）
```

这组地址与字符串交叉引用一致：`0xbc410` 附近引用
`remote_provisioning_context.cpp` 的 `boot_os_version:%s`，`0xbe710` 附近引用
`Failed to sign the MAC key on WHI`，`0xbeb18` 附近引用 `Error signing MAC`，
`0xbec98` 附近引用 `Failed hwbcc_get_protected_data()`。它们是协议运行时的
**签名/MAC/ProtectedData 生成接口**，不是把 UDS/CDI 私钥或 32 字节 seed 返回给
主机的接口。

在 `0xbeb18` 的成功分支，函数调用 `0x94c18` 生成 32 字节 MAC/tag 后立即把该
结果作为 Signed MAC 继续封装；在该成功分支的已解析参数中尚未定位独立的 host-visible
seed 输出。`0xbe710`
则把输入缓冲和长度整理后调用 `0xc2e18`；`0xc2e18` 首先限制输出长度小于
`0x201`，再把参数转发到 `0xdd9b0`/`0xdcf90` 的厂商安全接口，返回的是
ProtectedData 操作状态，而不是密钥导出结果。

因此，活动 CSRv3 路径目前能证明的是：安全世界接受主机请求并生成 DICE/UDS
公钥链、MAC 和 ProtectedData。函数表中没有发现可把对应私有 CDI/UDS seed
复制到 Binder 输出的分支；任意 32 字节缓冲、MAC tag 或 275 字节 KeyMint
private blob 都不能据此改称 IDC，也不能直接作为 `google-rkp-sw --seed`。

本轮仍未启用 TA bind、未重启、未刷写，也未向签发端提交新的请求。若要继续，
下一步必须取得一条能重建已保存 UDS SPKI
`d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9` 的真实私有
材料；在此之前继续猜测输出窗口只会重复旧诊断误读。

## 2026-08-29 活动路径固定 32 字节常量的语义复核

对 `0x91a40` 在 `0x91cb8–0x91ce4` 使用的固定地址再次追踪：
`ldr x12, [x12, 0x448]` 取得的指针指向 `0x1e480`，该处前 32 字节为：

```text
99b9eedd5ee452f685c64c62dc3e61ab57487d753729ad768032d2b3cb6358d9
```

该值在活动 CSRv3 的固定校验分支中被作为 32 字节信任锚比较值使用；它没有进入
`MacedPublicKey`、DICE subject 公钥或返回 CSR 的私密字段。常量之后紧邻字符串
`AES-256-GCM-HKDF-SHA-256, version 1`，说明该分支属于 EEK/会话加密参数校验，
而不是设备 UDS/CDI 材料。K70E 工作区没有以此常量作为 IDC 的本地证据。

因此，活动路径中看起来像“32 字节输出”的比较实际上是在确认会话加密参数，不能
解释成 IDC、UDS seed 或 CDI seed。它也解释了为什么把该值交给
`google-rkp-sw --seed` 不会得到设备身份：这只是 EEK 信任锚的公钥坐标，主机没有
对应私钥，且它不能重建已保存的原生 UDS SPKI。

本节新增证据：

- TA ELF：`02_脚本与补丁/duchamp_Mitee_TA_ELF分析_20260828/dba51a17-0563-11e7-93b16fa7b0071a51.elf`
- 常量偏移：`0x1e480`；调用点：`0x91cb8–0x91ce4`
- 固定比较值 SHA-256：`5b51321d935f06544c8ed54b8cc8f99538f7e75d98f5b0e738d701a1cb10380b`
- 说明：本记录不使用 xaga、Nothing 或其他设备的 EEK 文件作为 K70E 身份证据。

这一步仍未导出任何秘密、未启用诊断 TA、未重启设备，也未提交网络请求；当前可
验证结论是“原生 CSRv3 可用且 Google 证书库存存在，但 IDC 的主机可见出口尚未定位”。

## 2026-08-29 生成器与 CSR 返回对象边界

对命令分发器和返回对象做了补充定位：

```text
command dispatcher 0xCB31C
  -> GenerateCsr 0x626C8
     -> 0x925C8（输入/MAC 校验与对象组装）
     -> 0x94D08（COSE_Mac0 对象）
     -> 0x63498 / 0x635A8（只负责把字节串追加到返回 vector）
     -> 0x91A40（DICE/证书链结果校验与序列化）
```

`0x63498` 和 `0x635A8` 的反汇编都在长度检查后调用 `memcpy`，其职责是把已经
得到的字节串放入 C++ vector；没有任何从安全世界私有区读取 seed 的调用。另一路
`GenerateRkpKey 0x61960 -> 0xA7B88` 只在独立的密钥生成命令中出现，`0xA7B88`
接收两个 32 字节输出缓冲，随后交给 `GetEcdsa256KeyFromCert`/内部对象管理，
并不把原始标量作为 Binder 返回值。

这使“把 CSR 返回 vector 中任意 32 字节窗口当成 IDC”的做法失去代码依据：返回
vector 的写入发生在 `0x63498/0x635A8`，而私有 CDI/UDS 的生命周期留在
`0x61960`/厂商上下文对象内部。现有 275 字节 `private_key_blob` 仍是 opaque
KeyMint handle；在没有额外、可重复的安全世界导出点前，不能离线重建主机可用的
`google-rkp-sw --seed`。

## 2026-08-29 CDI/UDS 字符串调用图的范围确认

为避免把“二进制中出现了 `P256KeypairFromCDI` 字符串”误写成“活动 CSRv3 已有
可导出接口”，对相关字符串的所有静态引用做了汇总：

```text
P256KeypairFromSeed       -> 0xD9F88（日志/旧生成包装）
P256KeypairFromCDI        -> 0xDA938（旧生成包装）
DiceGenerateCertificate   -> 0xD8FB8（旧 DICE/legacy 分支）
CDI_Attest / CDI_Seal     -> 0xD9AA8、0xDD438（旧 DICE 辅助）
DiceKeypairFromCDI errors  -> 0xD8FB8、0xC2E18（错误日志/安全接口包装）
```

反汇编得到的实际调用边为：

```text
0xD9AA8 -> 0xD8FB8 -> 0xDB330 -> 0xDA938 -> 0xDA520
0xDD438 -> 0xDB330
0xD87F0 -> 0xDA520
```

而活动 CSR 入口 `0x626C8` 的直接边是 `0x925C8`、`0x94D08`、`0x63498`、
`0x635A8` 和 `0x91A40`；在该入口及其已确认的直接调用区没有到
`0xD8FB8/0xDA938/0xDA520` 的静态边。故旧 wrapper 中的日志和 keypair 名称不能
作为当前 CSRv3 私密材料出口证据。

截至本轮，候选值只有：

1. 固定 EEK 公钥 X（已证明不是 IDC）；
2. COSE_Mac0/MAC tag（已证明是完整性字段）；
3. 返回 vector 的临时 32 字节缓冲（只有 `memcpy` 入 vector 的证据）；
4. 275 字节 KeyMint opaque private blob（不是 PKCS#8/raw seed）。

这四类候选均无法用独立 P-256 派生重建已知 UDS SPKI
`d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9`，因此全部标记
为“当前候选失败”。这只说明这些已检查的候选不成立，**不等同于证明设备没有
IDC，也不等同于证明私有 CDI/UDS 材料永远不可导出**。当前正式状态为：
**尚未定位**；停止任意 32 字节窗口扫描，下一步只允许解析 CSRv3 的实际安全世界
函数表和结果对象。

独立门控的失败记录（用于复核而非推测）：

| 记录 | 关键结果 | SHA-256 |
|---|---|---|
| `K70E_活跃种子诊断第三轮本地CSR与keygen_20260829/round3_manifest.json` | `match_count=0` | `cc01a1a88243f387b7eb62a785eb94c4eb61b5ae471f7af8fd17b8522f1d42b7` |
| `K70E_P256_CDI实机输出缓冲区采集_20260829_第三轮/manifest.json` | `accepted_window=null`, `native_uds_gate_passed=false` | `61761d433a4f869ce06c35971e49b8ad5f123a8455ae1ff70a43e8daac6ea665` |
| `K70E_P256_CDI结果向量导出_20260829_第五轮_CSR后/keygen/manifest.json` | `accepted_window=null`, `native_uds_gate_passed=false` | `f18c066ffe6fcfabe67c105dac73c5bd9c26ae0257cfadc4f86d67d97a237cb2` |
| `K70E_BCC_seed诊断实机采集_20260829_第二启动_最终采集/manifest.json` | `candidate_is_accepted=false` | `62fdcd7751329f247cb0abe767508c1b1340c3d56f44458000e7dd333b27be7a` |

## 2026-08-29 一次完整 GenerateCertificateRequestV2 调用反向追踪（仅 K70E）

本节只复核保存的 K70E 原始 TA ELF、原生 Binder 客户端和一次完整 CSRv3 捕获，
不重启、不刷写、不替换 TA、不联网。目标是区分“安全世界使用的私密 CDI/UDS
材料”与“Binder 可见的 CSR 字节”，并记录 IDC 的当前定位状态。

### 1. 主机输入与 Binder 边界

主机调用程序
`02_脚本与补丁/rkp_binder_csr_v2_client.cpp` 固定使用
`IRemotelyProvisionedComponent/default`，事务号 `4`，依次写入：
`keysToSign` 数量、每个 `MacedPublicKey` 的 sized byte-array，以及 0..64 字节
`challenge`（源文件第 14–18、91–116、143–164 行）。TA 返回单个 byte-array，
客户端原样写入 `certificate_request_v2.cbor`（第 166–168 行）。这条边界没有
任何参数可承载 UDS/CDI 私钥或 32 字节 IDC。

原生捕获文件：
`03_提取结果/K70E_CSRv3_设备原生Binder闭环_20260828/device_capture/certificate_request_v2.cbor`

- 长度：2614 字节；SHA-256：`cb3dd32fab44899aa9e912af348e30a2e82fed649bac6b5dad047d40f191d51e`
- 同一次调用的 challenge：32 字节；SHA-256：`5a20fdfa62e77ab6b49a23093396a578cc769381ffc1d079361825ebf4f29900`
- 同一次调用的 MacedPublicKey：119 字节；SHA-256：`cc5025fffaa8696e6dbe085988e851f31591629c78b86c4b7407ff8fd95db45d`
- 同一次 key-generation 保存的 privateKeyHandle：275 字节；SHA-256：
  `ac9ea690b6383af4717fcce3a9f2eb7c0b00f8683c89c696263646aa54d2560e`
- 独立验证报告：`independent_verification.json`，SHA-256
  `daafdfc8fe8cd785c7733d502dc13ca95f3815f83c4aba0236d82fca857bd0ee`

### 2. TA 入口和 CSR 组装链

对原始 ELF
`02_脚本与补丁/duchamp_Mitee_TA_ELF分析_20260828/dba51a17-0563-11e7-93b16fa7b0071a51.elf`
进行 AArch64 只读反汇编，得到如下链路：

```text
Binder dispatcher 0xCB31C (+0x8c)
  -> GenerateCsr 0x626C8
       0x62718: 通过对象函数表取得远程配置上下文
       0x627EC: BL 0x925C8（keysToSign/输入对象校验与中间对象组装）
       0x6293C: BL 0x94D08（COSE_Mac0 相关对象）
       0x62CC8: 上下文函数表间接调用（DeviceInfo/MAC/ProtectedData 侧接口）
       0x62DDC: BL 0x91A40（DICE 链条目处理、校验与结果对象）
       0x63498/0x635A8：把已得到的字节串追加到返回 vector
       -> Binder byte[] CSR
```

`0x925C8` 的关键局部证据：

- `0x927B4 -> 0x92E18`：按对象函数表检索输入 key 项；
- `0x92814 -> 0x92F60`、`0x9282C -> 0x93208`：分配/检索中间对象并检查算法、
  曲线和长度；
- `0x92AD4 -> 0x94D08`：构造 COSE_Mac0 相关对象；
- `0x92B14–0x92B24`：仅检查 0x20 长度并调用 `0x1003D8`，后者是逐字节
  XOR/OR 累积的常量时间相等比较，不是复制或导出；
- `0x92CE4`：调用对象函数表 `+0x88` 的可选回调。该 ELF 中已知默认表由
  `0x155260 -> 0x147AA0`，对应 `+0x88 = 0x66858`（`mov x0, xzr; ret` 空桩），
  没有可见的 seed 导出动作。

`0x63498` 和 `0x635A8` 的实现均为 vector append/copy：长度确认后使用
`memcpy`，源是已经生成的字节串，不能反推出这些字节的安全世界来源，更不能把
它们解释成 IDC。

### 3. DICE/CDI 公钥链和私钥签名证据

`0x91A40` 只接收 DICE 条目容器，逐项调用 `0x958D8`，再把条目的 payload、
状态和指针整理到结果对象；在 `0x91CB8–0x91CE4` 的 32 字节比较是固定信任参数
校验；在该函数体已解析范围内尚未定位向 Binder 返回原始 CDI/UDS 私钥的写入。

捕获 CSR 的 CBOR 结构与 AOSP CSRv3 定义一致：顶层是
`AuthenticatedRequest = [version=1, UdsCerts, DiceCertChain, SignedData]`；
`DiceCertChain` 第一个元素是 UDS 公钥，后五个元素是 COSE_Sign1 DICE 条目；
最后的 `SignedData` 由 CDI leaf 对 `[challenge, CsrPayload]` 签名。独立验证器
对五个 DICE 签名和外层 CSR 签名均验证通过：

```text
uds_spki_sha256       = d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9
cdi_leaf_spki_sha256  = 0684d469c8afecf9d1a7a86cfc67e4996f2712d5edfcfed80745eeb105b1130b
keys_to_sign_spki_sha256 = a7a7555e392b7cd416c89dcaf9b1710fe6cb04e7bd153e0437ed3cb18c0c6cd1
dice_signatures_verified = 5
outer_csr_signature_verified = true
challenge_matches = true
```

这些结果证明：私钥确实在 TA 内被用于 DICE/CSR 签名，主机拿到的是公钥链和签名，
不是 CDI/UDS 私钥。`generateEcdsaP256KeyPair` 返回的 275 字节 `privateKeyHandle`
同样是 opaque KeyMint handle；它与 DICE CDI signing key 不是同一语义。

### 4. IDC 使用方式与主机可见出口

当前 ELF 是 stripped/vendor 实现，活动 `GenerateCsr` 区域没有直接
`BL 0xDA520`（旧 `P256KeypairFromCDI` wrapper 的 key-pair 例程）。活动路径的
上下文调用通过对象函数表和厂商安全接口间接完成；已定位的表项分别落在
`0xBBF40/0xBC410/0xBE710/0xBEB18/0xBEC48/0xBEC98`，对应持久化读取、DeviceInfo、
WHI MAC、SignedMac 组装、状态清理和 `hwbcc_get_protected_data` 包装。它们把结果
作为 MAC、ProtectedData、DICE 公钥或签名继续封装；在已解析的参数和返回槽位中，
尚未定位到原始 seed 的复制路径。

前文的“尚未定位”是诊断窗口阶段的中间状态；在本节把 Binder、活动 V2 入口、
厂商安全接口、DICE 结果对象和返回 vector 串成一次完整调用后，验收结论不再停在
“尚未定位”。对**这次实际执行的 `GenerateCertificateRequestV2` 调用链**，二选一
结论选择第二项：**私密材料始终留在 TEE 内，未形成主机可见的 IDC 出口**。这不是
“设备永远没有任何调试出口”的泛化断言，而是对已保存 stock ELF、已保存 Binder
输入/输出和独立验证结果的闭合证据结论。

### 5. 每阶段输入/输出边界与最终二选一结论

| 阶段 | 输入（长度/来源） | 输出（长度/去向） | 私密材料边界 |
|---|---|---|---|
| Binder `generateCertificateRequestV2` (`0xCB31C+0x8c -> 0x626C8`) | `keysToSign_count=1`；`MacedPublicKey=119` 字节；`challenge=32` 字节（客户端 `rkp_binder_csr_v2_client.cpp:156-168`） | 单个 CSR byte[]；原样写入 `certificate_request_v2.cbor`（客户端 `:170-199`） | 参数表没有 UDS/CDI seed 或私钥槽位 |
| 输入校验/COSE-Mac0 (`0x925C8 -> 0x92E18/0x92F60/0x93208 -> 0x94D08`) | COSE 对象指针、显式长度；`0x92B14-0x92B24` 仅比较 0x20 字节 | 校验状态和 MAC0/公钥对象；`0x94D78-0x94DAC` 初始化 `MAC0` 对象 | 0x20 比较是常量时间比较，不是复制；未见 seed 输出 |
| 32 字节内部预处理 (`0x62DCC -> 0xF5DE0`) | 两个由 TA 分配并清零的 0x20-byte 临时对象；调用 `0x12CD60/0xF2680/0xF18D0/0xF1430` 等内部 helper | 更新内部对象/状态，随后进入 DICE 结果处理；未写入 Binder reply | 这是安全世界临时缓冲和派生前处理，调用返回值没有被当作外部 32 字节材料 |
| 厂商安全上下文 (`0x62CC8` 间接调用；表 `0x148390`) | 内部 vector、DeviceInfo、MAC 输入；调用点把对象/布尔值/内部 vector 放入 `x0..x3` | `0xBBF40/0xBC410/0xBE710/0xBEB18/0xBEC48/0xBEC98` 返回状态、DeviceInfo、MAC/SignedMac 或受限 ProtectedData 对象；结果只留在内部对象槽位 | `0xBEC98 -> 0xC2E18` 对 ProtectedData 分支输出长度强制 `<0x201`；captured V2 Binder 仍只返回 CSR，没有 Binder 私钥出口 |
| 内部 vector/对象封装 (`0x6306C -> 0x93B90`, `0x6308C -> 0x97838`, `0x62ED0 -> 0x98B38`) | 指针+长度范围和对象函数表 | 内部 vector、DeviceInfo/CSR 片段对象；失败则清理并返回状态 | 这些函数只分配、复制或封装已生成对象；没有到 host 的 seed 复制边 |
| DICE/CDI 链 (`0x62DDC -> 0x91A40 -> 0x958D8`) | 安全世界 DICE 条目容器 | 5 个 COSE_Sign1 条目及最终 CDI leaf SignedData；独立验证通过 | 返回的是公钥和签名；私钥只作为签名上下文被消费 |
| CSR 组装/返回 (`0x63498/0x635A8`) | 已生成的长度分隔 byte vector | 2614 字节 CSR；SHA-256 `cb3dd32fab44899aa9e912af348e30a2e82fed649bac6b5dad047d40f191d51e` | 仅 `memcpy` 已生成字节，不是派生或密钥导出 |

独立验证报告 `independent_verification.json`（SHA-256
`daafdfc8fe8cd785c7733d502dc13ca95f3815f83c4aba0236d82fca857bd0ee`）确认：UDS
SPKI `d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9`、CDI leaf
SPKI `0684d469c8afecf9d1a7a86cfc67e4996f2712d5edfcfed80745eeb105b1130b`、5 个 DICE
签名和外层签名全部通过，challenge 与 CSR 绑定，KeysToSign 与保存的 MacedPublicKey
一致。活动 V2 路径对 `DiceSign`/`DiceCoseSignAndEncodeSign1` 的字符串只有旧辅助
路径交叉引用；当前入口通过函数表和安全上下文完成等价操作，不能把旧
`P256KeypairFromCDI` 暂存区当作当前 IDC。

**最终二选一（本轮验收）**：选择二——私密材料始终留在 TEE 内。理由是：

1. 完整 Binder 输入/输出边界只允许主机提供公钥和 challenge，并取回 CSR byte[]；
2. CSR 内可独立验证的对象全部是 UDS/CDI 公钥、DICE 签名、DeviceInfo 和
   `KeysToSign`，没有私钥字节；
3. 活动函数链中可见的返回槽位要么是状态/长度，要么是公钥、MAC、签名或受限
   ProtectedData 对象；`0x63498/0x635A8` 只复制已经生成的公开结果；
4. 275 字节 `privateKeyHandle` 是 KeyMint opaque handle，不能重建 DICE/CDI
   UDS SPKI；工作区所有候选 32 字节值也未通过 UDS SPKI 独立重建门控。

因此本轮不再寻找“隐藏的 32 字节窗口”，也不把公钥、MAC、签名、ProtectedData 或
opaque handle 改名为 IDC。若题目要“完全脱机”材料，当前调用链没有提供该材料；下一步
只能取得厂商明确的安全调试接口或源码级符号，再以重建同一 UDS SPKI 为门槛。
