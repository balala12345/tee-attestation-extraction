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
