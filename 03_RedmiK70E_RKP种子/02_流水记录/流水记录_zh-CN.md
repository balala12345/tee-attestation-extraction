# Redmi K70E：全量研究流水账（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 本文件按原始文档合并保留：原生 CSR 基线、CDI/BCC/活动密钥诊断、静态闭合、失败补丁、恢复、NOT_APPROVED 差分、clean DeviceInfo hybrid 实验、APPROVED 结果与最终离线交付。没有把失败过程压成一句“未完成”。

---

## 原始记录段 1 / Source section 1: 45_K70E_CTF_最终完整流水线记录_20260905.md

# K70E CTF 最终完整流水线记录

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **后续覆盖（2026-09-06 20:00）：**本文的 2026-09-05 包仍是 `REJECTED_NOT_APPROVED`，不得提交。新的独立 run 已以 modified DICE + clean DeviceInfo 取得 `APPROVED`；请先读文档 65–70，不要把新结果倒灌到本旧包。

> CURRENT ROUTE OVERRIDE：当前唯一操作手册是文档 52–57 的 stock MiTEE 日志路线。本文正文不得作为命令源。

> **2026-09-06 失效更正：** 本文记录的旧轮次叶证书含 `Provisioning Info {5:{1:"NOT_APPROVED"}}`，赛事方不接受。本文的“最终状态 PASS/题目完成”已被文档 52 推翻；保留全文仅作历史流水线和失败证据，禁止提交旧包或照旧联网。当前权威结论见 `52_K70E_CTF_Provisioning_Info_NOT_APPROVED事故复盘与修复状态_20260906.md`。

> 本文是原目标设备的完整事实流水线，不是把原 serial/UDS/镜像/token/latch 复制到另一台手机的手册。新 K70E 从文档 50 的 per-device profile 和兼容门入口。

> 项目：Redmi K70E / duchamp / MiTEE / Android Remote Key Provisioning  
> 收口日期：2026-09-05（Asia/Taipei）  
> 历史状态：旧验证器曾判 PASS；2026-09-06 因 `NOT_APPROVED` 撤销，设备已恢复安全基线  
> 记录原则：最大化保留决策、哈希、门禁、动态证据和失败边界；不记录私钥原文

---

## 0. 最终题目口径

最终提交不是“任意一把 K70E native RKP 私钥和证书”，也不是“能让 Google 返回 200”就算完成。严格交付物是：

1. 用户 `google-rkp-sw` 的身份数据；
2. 一次 `google-rkp-sw` 成功运行中新生成的一把软件私钥；
3. Google 在同一次运行中为这把私钥返回的证书链。

最终三者的关系必须同时成立：

```text
同轮 native zero-key CSR 的最终 CDI_Leaf 公钥
        == 身份标量直接派生的 P-256 公钥
        == google-rkp-sw 对 fresh CSR/SignedMac 的签名身份

google-rkp-sw 新生成的 KeysToSign 公钥
        == 保存的 PKCS#8 私钥公钥
        == Google 返回证书链的叶证书公钥
```

旧结果目录 `K70E_scalar_final_google_provision_20260905_2206` 是 native RKP 每把密钥的成功旁证，不是最终严格提交。最终提交目录为：

`03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/`

---

## 1. 最终结果摘要

| 项目 | 最终值 |
|---|---|
| 设备 | Redmi K70E / `duchamp` |
| ADB 严格序列号 | `<DEVICE_SERIAL>` |
| 活动槽 | `_a` |
| 身份语义 | Open-DICE 派生后的 CDI_Leaf P-256 私钥标量，32-byte big-endian |
| 身份文件 SHA-256 | `ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c` |
| CDI_Leaf SPKI SHA-256 | `64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2` |
| 原目标设备稳定 UDS SPKI SHA-256 | `d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9` |
| native DICE | 5 段 ES256，全验通过 |
| native source KeysToSign | 0，把 source 限定为身份 CSR |
| source DeviceInfo | `green` / `locked` / 同轮 canonical map |
| 软件生成私钥文件 SHA-256 | `f9981ef88503d812c4d57fa61072f5fe1c9167b3f85504736cdae6315bf70fbd` |
| 软件生成公钥 SPKI SHA-256 | `a6397c1a8fd2c1e765e616c24b69c436224d429a3392c110e361fe2bcfcd481d` |
| fetchEekChain | HTTP 200 |
| signCertificates | HTTP 200 |
| 软件请求 SHA-256 | `029c2bae4fdf94b461ff343d8a67e5106a76d9a3a515dae38e5d5b4953c5f4c4` |
| Google 原始响应 SHA-256 | `ab9b9481b38e81a116e7138bd01ffb9423771ce0958472d2a5a3a11c35fe9039` |
| 返回链 | 1 条，4 张证书 |
| ordered chain SHA-256 | `b3f62232ef434859392833b26cf5bdfdc949cd509637552a555fd6c38febd6bb` |
| 叶证书 SHA-256 | `8d1eeefd7ad252ec78c53859be595b935faa2cdb5f1bff597f6a817351d22553` |
| 叶公钥与私钥 | 完全一致 |
| 证书链 | DER 全消费、逐级签名有效、根自签有效 |
| 最终设备 | 原厂 `tee_a` + 已知良好 Magisk `init_boot_a`，正常启动 |

---

## 2. 项目边界与安全约束

用户明确授权为完成 CTF 使用设备、刷机和漏洞路径，唯一硬边界是尽量避免不可恢复变砖。实际执行仍遵守以下边界：

- 只操作明确在范围内的 K70E，所有 ADB/Fastboot 命令钉死序列号 `<DEVICE_SERIAL>`。
- 实验只写 `init_boot_a` 与 `tee_a`；未触碰 `preloader`、`seccfg`、`proinfo`、`persist`、`nvram`、`nvdata`、`efuse`、RPMB、`userdata`。
- 不 relock，不运行 `fastboot flashing lock`、`oem lock` 或 MiFlash `clean all and lock`。
- 候选 TEE 启动前，设备旁有人、Fastboot 物理按键可用、原厂 `tee_a` 已预置到设备并经大小/哈希校验。
- 任何动态门失败立即停止；不把“可能成功”当作继续刷写的理由。
- 私钥不进入命令行参数、不打印到终端；目录 0700、秘密文件 0600。
- Google HTTP 444 不盲目重试；先本地修正身份/DICE/DeviceInfo 结构。

---

## 3. 初始基线与最终恢复基线

### 3.1 动态实验前基线

```text
device=duchamp
serial=<TARGET_SERIAL>
sys.boot_completed=1
slot=_a
root=/debug_ramdisk/magisk su -c
tee_a=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
init_boot_a=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
global/namespace stock TA=facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
```

设备同时连接了另一台 Pixel 4 XL，因此任何不带 `-s <DEVICE_SERIAL>` 的命令都可能误操作其他设备。

### 3.2 原厂恢复件

```text
host stock tee_a:
  设备备份_只读_20260831_preflash/tee_a.bin
  size=5242880
  sha256=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d

host known-good Magisk init_boot_a:
  out/k70e_v6_prebind/init_boot_a_backup_20260901.img
  size=8388608
  sha256=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4

device staged tee recovery:
  /data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img
  size=5242880
  mode=0444
  sha256=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

### 3.3 最终恢复后的实机状态

```text
sys.boot_completed=1
uid=0(root), Magisk 正常
tee_a=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
init_boot_a=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
tee-supplicant namespace TA=facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
vendor.teefs_state=ready
```

---

## 4. 历史探索如何收敛到最终方案

### 4.1 2026-08-28：原生 RKP 与 Google 链路基线

- 证明 K70E 原生 CSRv3 能拿到真实 Google 返回链。
- 建立 `AuthenticatedRequest -> DiceCertChain -> SignedData -> DeviceInfo -> KeysToSign` 的解析基线。
- 保存原生证书、CSR、MacedPublicKey、私钥 opaque blob 和服务器响应。
- 关键认识：原生 opaque blob 不是可导出的软件私钥，也不是 `google-rkp-sw` 身份标量。

### 4.2 2026-08-29：CDI、BCC、重复 CSR 与 active-path 诊断

- 多轮诊断尝试区分 raw CDI、BCC seed、中间向量、活动 RKP 私钥对象与 opaque KeyBlob。
- 证明 CDI leaf 会随启动测量变化，不能硬编码历史 leaf；UDS 根保持稳定。
- 证明“某个 32-byte 窗口”不等于私钥，必须用同轮最终 leaf SPKI 做密码学验真。
- 建立 zero-key native CSR 作为身份观测器的思路。

### 4.3 2026-08-30 至 09-01：KeyMint 私钥路径与 Fenrir/TEE 边界

- 静态闭合 `GenerateRkpKey`、P-256 生成、KeyBlob 创建与清理路径。
- 多版 hook 因 ABI、寄存器、时序、缓存或导出语义问题失败。
- Fenrir 对 K70E 的旧假设被推翻；上游/旧设备路径不可直接移植。
- 原先得到“TEE 补丁会卡 logo”的结论，但当时修改同时破坏了压缩帧/加载契约，不能推出所有最小补丁都不可能。

### 4.4 2026-09-03：失败结论与恢复基础设施

- 记录 logo 循环、原厂 `tee_a` 恢复、Fastboot/preloader-catch 路径。
- 明确错误候选不可重复尝试。
- 文档 42 的“不要再碰 tee_a”是对当时旧候选的安全结论，后来被 exact-frame 最小补丁的动态实验证据覆盖，不能脱离版本继续引用。

### 4.5 2026-09-05：SProvider exact-frame 与 native scalar 成功

- 定位 SProvider 中 RSA 结果分支，证明 body/header digest 仍可保留。
- 工程化构建压缩长度完全不变的 `tee_a` 候选。
- 先成功导出 native RKP 每把密钥 scalar 并取得 Google 200，证明动态加载和网络链路均可用。
- 随后用户重新明确最终口径，发现 native per-key scalar 不是 `google-rkp-sw` 身份，转向 CDI_Leaf `x26`。

### 4.6 2026-09-05 22:41–22:45：最终 CDI_Leaf 身份、软件签发与恢复

- 部署最终 CDI_Leaf TA/early-bind。
- 动态抓取同轮 zero-key native CSR 与 CDI_Leaf 标量。
- 改造 `google-rkp-sw`，复用同轮 proper DICE/DeviceInfo。
- Google fetch/sign 均 200，得到一把软件私钥和对应四证书链。
- 整理提交包、恢复 `init_boot_a`，确认设备回到安全基线。

---

## 5. 最终技术链路总览

```text
stock K70E / Magisk root
  │
  ├─ host-only 构建并审计三件套
  │    ├─ CDI_Leaf capture TA 7ea594...
  │    ├─ exact-frame SProvider TEE 3990a8...
  │    └─ one-shot early-bind init_boot 5b7405...
  │
  ├─ 先只刷 init_boot，stock TEE 下未武装启动
  │    └─ 验证 fail-closed、内置 TA、root、服务和分区哈希
  │
  ├─ 预置 stock TEE 恢复件，创建 ALLOW，最后创建 ARM
  │
  ├─ 只刷 tee_a 候选并启动一次
  │    ├─ on fs：验证 tee hash/size/slot/token → 消耗 marker → bind 新 TA
  │    └─ boot_completed：将磁盘 tee_a 自动恢复 stock，不重启
  │
  ├─ 同一 secure-world boot 内严格串行
  │    ├─ native zero-key CSR
  │    ├─ 验 UDS + 5 段 DICE + outer + challenge + KeysToSign=[]
  │    ├─ dd934:x26 抓取 CDI_Leaf scalar
  │    ├─ 恰好一次 GenerateRkpKey 导出 32B
  │    └─ direct P-256 SPKI == 同轮 native leaf 才保存身份
  │
  ├─ 主机 google-rkp-sw
  │    ├─ seed-file=身份 scalar
  │    ├─ source=同轮完整 native AuthenticatedRequest
  │    ├─ 复用 proper DICE/UdsCerts/green-locked DeviceInfo
  │    ├─ 新生成 1 把 P-256 key
  │    ├─ fetch fresh Google EEK/challenge
  │    ├─ leaf scalar 重签 fresh SignedData/SignedMac
  │    └─ signCertificates → 1 条四证书链
  │
  ├─ fail-closed 验收并打包
  │
  └─ 刷回 known-good init_boot，确认 stock tee/TA/teefs
```

---

## 6. SProvider / TEE exact-frame 最小旁路

### 6.1 没有解决 OEM TEE/TA 签名

最终 TA 的 OEM RSA 签名字节没有改变，RSA-PSS 验证仍失败。成功机制是让 SProvider 继续执行 RSA 验证，但忽略该返回值；body digest 和 header digest 仍必须正确。

```text
SProvider stock instruction:
  ELF+0x343fc / BootFS+0x0e93fc
  80010034    cbz w0, 0x3442c

patched:
  0c000014    b 0x3442c

semantics:
  RSA verifier still executes
  RSA result ignored
  digest verifier/gate untouched
```

### 6.2 TEE 镜像与压缩帧约束

| 项目 | 值 |
|---|---|
| stock `tee_a` SHA-256 | `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d` |
| candidate `tee_a` SHA-256 | `3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da` |
| 镜像大小 | `0x500000` / 5,242,880 |
| BFSB | `0x1c6168` |
| LZ4 frame | `0x1c6188..0x3e076c` |
| frame 长度 | `0x21a5e4` |
| 解压大小 | `0x44c000` |
| block 数 | 69 |
| 目标 block | 14 |
| descriptor offset | `0x23525b` |
| payload offset | `0x23525f` |
| payload 大小 | 38,783，和 stock 完全相同 |

liblz4 HC4 的直接结果是 38,740 字节，比目标短 43。构建器把一条 47-byte match 缩成合法最小 4-byte match，并把剩余 43 字节等价并入下一条 literal，使压缩 payload 恢复到精确 38,783 字节，解压内容不变。

最终解压 BootFS 的变化只在目标 4-byte 指令内；实际逐字节变化为 `0xe93fc`、`0xe93fd`、`0xe93ff` 三个字节。所有非目标压缩 block、descriptor、frame 尾、SPMC DTB/证书尾窗均保持 stock。

构建与验证：

```text
02_脚本与补丁/build_k70e_sprovider_rsa_bypass_exactframe_hostonly.py
out/k70e_sprovider_rsa_bypass_exactframe_hostonly/tee_a_sprovider_rsa_bypass_exactframe.img
out/k70e_sprovider_rsa_bypass_exactframe_hostonly/verify.json
```

---

## 7. CDI_Leaf 身份语义与 KeyMint hook

### 7.1 raw CDI 与最终 scalar 的区别

- `0xdcd10` 是 `get_attest_cdi`，成功时从 `/dev/misc/hwinfo` 写出 32 字节当前 CDI_Attest。
- 该 raw CDI 不是 `google-rkp-sw --curve p256 --seed-file` 应直接使用的最终私钥。
- 活动 ES256 DICE 路径在 `dd888..dd898 -> db330 -> da938` 派生 P-256 身份。
- `da938(seed=x0, public_out=x1, private_out=x2)` 将通过 P-256 阶/BN 门禁的 32-byte 私钥写入 `x2` 指向缓冲区。
- 到 `0xdd934` 时，`x26` 指向已经派生完成、随后会用于 DICE 签名的 32-byte P-256 CDI_Leaf 私钥标量。
- `google-rkp-sw` 的 P-256 `DeviceKeys` 以 big-endian 直接把这 32 字节映射到 P-256 scalar；因此 `dd934:x26` 是精确输入。

### 7.2 最终 TA

```text
builder:
  02_脚本与补丁/build_k70e_cdi_leaf_identity_capture_hostonly.py

output:
  out/k70e_cdi_leaf_identity_capture_hostonly/
  dba51a17-0563-11e7-93b16fa7b0071a51.cdi_leaf_identity_capture.ta

size:
  1,401,936 / 0x156450

sha256:
  7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48

embedded ELF/body sha256:
  65dae20d235651357c5775b8e880ef1ae161be462a0da5f346ab783e119f2c54
```

### 7.3 identity cave

```text
hook site:      0xdd934
cave:           0x141400..0x141448
captured data:  [x26 : x26+32]
resume:         0xdd938
publication:    data → len → dmb ishst → 8-byte marker
scratch:        0x164400..0x164430
```

只在 CDI 派生成功后捕获；重放原被替换指令；不改 SP；只破坏该点已死的 caller-saved 寄存器/向量寄存器。

### 7.4 RKP-only export cave

```text
hook site:      0xa3324
cave:           0x141500..0x14159c
resume:         0xa3328
success gate:   w22 == 0
caller LR:      0x61c7c（GenerateRkpKey 调用链）
response ptr:   保存的 caller x19
key_blob:       response + 0x10
acquire:        marker match → dmb ishld → len/data
export:         覆盖 privateKeyBlob 为精确 32-byte scalar
cleanup:        marker/len/data 清零
```

该 caller/LR gate 排除了普通 `GenerateKey` 路径。全局 scratch 不是并发原子队列，因此动态流程必须是 attended strict serial：native CSR 后紧接恰好一次 keygen；任何后台消费者抢先取走都应导致长度或同轮 leaf 门失败，而不是尝试恢复猜测。

### 7.5 ELF 内存布局

```text
RX: 0x5f000 + 0xe3000，精确延伸到 0x142000
RW: 起始 0x142000
RW filesz: 0x13d78，不变
RW memsz:  0x222f8 → 0x22430
scratch:   正式落入扩展 BSS，仍在同一最终页 0x165000 内
W+X:       无
```

验证报告 `out/k70e_cdi_leaf_identity_capture_hostonly/verify.json` 的 22 项检查全部为 true。OEM signature bytes 保持不变，所以该 TA 必须与 SProvider RSA-result bypass 同时使用。

---

## 8. one-shot early-bind 与自动恢复

### 8.1 构件

```text
builder:
  02_脚本与补丁/build_k70e_cdi_leaf_earlybind_initboot_hostonly.py

source init_boot:
  9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4

output:
  out/k70e_cdi_leaf_earlybind_initboot_hostonly/
  init_boot_a_cdi_leaf_identity_capture_one_shot.img

output sha256:
  5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517
```

### 8.2 注入内容

原 37 条 CPIO 记录和 3 个 device node 全部保留，增加 4 条：

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `overlay.d/00_k70e_cdi_leaf_earlybind.rc` | 633 | `46ad0f7e70718454b4d2f2fcd07990e0f166520dd1c7144b288af73e38201713` |
| `overlay.d/sbin/k70e_cdi_leaf_earlybind.sh` | 4,756 | `f79174385b1b868201ff24db3ab35801f878f6c16b8cde394fd7e1e61a0d773f` |
| `overlay.d/sbin/k70e_cdi_leaf_restore_tee.sh` | 1,957 | `62de92b8b258fe5f7fccb8e742c67d16919d737ea49dd74cbaccb49c45589551` |
| embedded CDI_Leaf TA | 1,401,936 | `7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48` |

AVB algorithm-NONE descriptor 已按新 image size/digest 重算，footer 和分区描述均通过独立验证。

### 8.3 触发状态

```text
state dir: /metadata/watchdog/k70e_cdi_leaf_identity
ARM:       .../ARM
ALLOW:     .../ALLOW
token:     K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT
latch:     .../once_7ea5948e
log:       .../earlybind.log
restore:   .../tee_restore.log
```

`on fs` helper 在消耗 marker 前依次检查：设备、双 marker、精确 token、latch 不存在、槽 `_a`、TEE 大小 `0x500000`、TEE SHA `3990a8...`、内置 TA SHA `7ea594...`。任何一项失败都不消费 marker、不 bind TA。

通过后，将 ARM/ALLOW 移入 latch；把内置 TA 复制到 `/dev/k70e_cdi_leaf_identity/active.ta`，设置 MiTEE 可读的 SELinux type，再 bind 到 `/vendor/mitee/ta/<UUID>.ta`。必须发生在 tee-supplicant 首次加载前；普通 Magisk `post-fs-data` 太晚。

`sys.boot_completed=1` 后的 helper 仅在当前磁盘 TEE 是候选、恢复件和块设备大小/哈希全部精确匹配时执行一次 `dd`，只恢复 `tee_a`。它不重启，因此当前 secure world 仍是候选启动出来的实例；下次启动回到 stock TEE。

---

## 9. 主机只读预检

执行：

```bash
python3 <DEVICE_WORKSPACE>/02_脚本与补丁/preflight_k70e_cdi_leaf_deployment_hostonly.py
```

最终状态：`PASS`。

门禁包括：

- TA body/header digest 自洽；
- RSA invalid 是预期状态；
- exact-frame TEE 结构契约；
- init_boot CPIO/LZ4/AVB roundtrip；
- early-bind fail-closed 顺序；
- stock TEE 自动恢复约束；
- capture 与 `rkp_sw.py` 编译；
- 严格动态范围：zero-key native CSR 后恰好一次 Binder keygen。

结题阶段另做了三路只读交叉审计，分别复核 hook/ABI/寄存器、exact-frame/ELF 映射和 CDI/DICE/software identity 语义，结论均为 PASS。它们属于结题 QA，不冒充设备原始动态证据；可复核证据仍以本文件引用的构件、JSON、CBOR、哈希和最终提交包为准。

---

## 10. 动态部署证据与重建顺序

最终 CDI 轮没有另存完整逐行 fastboot transcript。下列顺序由成功构件、设备状态、early-bind/restore 记录和文档 44 的动态证据重建；代码块是经证据约束的摘要，不应标成逐行原始终端输出。

### 10.1 预置原厂 TEE 恢复件

主机与设备文件均验证：

```text
size=5242880
sha256=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
mode=0444
```

### 10.2 只刷 init_boot，未武装启动

记录到的 Fastboot 关键状态摘要：

以下是关键状态摘要，不是完整 fastboot transcript：

```text
product: duchamp
current-slot: a
Sending 'init_boot_a' (8192 KB) OKAY
Writing 'init_boot_a' OKAY
```

启动后检查：

```text
tee_a=182277... stock
init_boot_a=5b7405... candidate
embedded TA=7ea594...
namespace TA=facdfe... stock
ARM/ALLOW/latch=absent
root/service/teefs=healthy
```

这一步证明新 init_boot 本身能启动，且 stock TEE 下不会误绑定 RSA-invalid TA。

### 10.3 创建 marker

顺序为：先写临时 ALLOW、chmod 0600、原子 `mv`；再写空 ARM、chmod 0600、最后原子 `mv`。ARM 是最后出现的触发信号。

```text
ALLOW content=K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT
ALLOW size=39 mode=600
ARM size=0 mode=600
```

### 10.4 只刷 exact-frame `tee_a`

```text
product: duchamp
current-slot: a
Sending 'tee_a' (5120 KB) OKAY
Writing 'tee_a' OKAY
```

Fastboot 的 `skip copying tee_a image avb footer` 提示来自该分区/镜像没有可复制 footer，不等于写入失败；实际 `Sending` 和 `Writing` 均为 OKAY。

### 10.5 候选启动与自动回滚证据

```text
preconsume_tee_hash=3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
preconsume_tee_size=5242880
src_hash=7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
target_hash=7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
BIND_OK
restore_final=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

此时：

```text
磁盘 tee_a=stock 182277...
当前 secure world=由 candidate 3990a8... 启动的实例
tee-supplicant 私有 namespace TA=7ea594...
init_boot_a=5b7405...
latch COMMITTED=present
TEE_A_RESTORED_STOCK=present
```

不能把磁盘 `tee_a=stock` 误判为候选没有运行；自动回滚正是设计目标。

---

## 11. 同轮身份捕获

### 11.1 捕获器

```text
02_脚本与补丁/capture_k70e_google_rkp_sw_identity_once.py
keygen client sha256=79dc5f2bd523e5c35a77f34c46bbb345c22e7b79c245e2eee4b5bef0fbcb1cef
keygen client size=51280
```

输出目录：

`03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/`

### 11.2 捕获前动态门

- 严格 ADB serial 在线；
- `device=duchamp`、slot `_a`、`boot_completed=1`；
- Magisk root 可用；
- 磁盘 `tee_a=182277...` 已自动恢复；
- 磁盘 `init_boot_a=5b7405...`；
- tee-supplicant namespace TA=`7ea594...`；
- early-bind 日志包含 exact candidate hash/size、target hash 和 `BIND_OK`；
- COMMITTED 与 stock TEE restore marker 存在；
- keygen client 大小/哈希与审计版本一致。

### 11.3 zero-key native CSR

捕获器生成 32-byte 随机 challenge，调用：

```text
cmd remote_provisioning csr --challenge <base64> default
```

这一步只生成本地 zero-key CSR，不联系 Google。最终 source：

```text
challenge length=32
CSR length=2534
CSR sha256=c8f7eb8d20474a549aa73a301a8ca1780586853c057e9b5421307057f8566b47
KeysToSign count=0
UDS SPKI sha256=d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9
DICE signature count=5
outer SignedData signature=valid
challenge match=true
final leaf SPKI sha256=64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

5 段 subject SPKI SHA-256：

```text
1 54b49c8e218ecae2e087b843d4cac6e59f10edba9108d38b597e579b72d898f0
2 e5c3bc558897b5b3af05c4547145d1771866acedb149dd04146a2ebd50c66129
3 abcec5b3c7cd84a23bbb5c3eb5148525eb967649214c2f860e611a1942fff938
4 f613d1ebd77605b3280fc0779d0ae59b90e2bb1591751db73d8c4ab6d6a67c65
5 64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

### 11.4 恰好一次 Binder keygen 与 scalar 验收

- 创建随机远程临时目录；
- push 钉死的 keygen client；
- 调用一次 `GenerateRkpKey`；
- pull `privateKeyBlob` 和 MacedPublicKey；
- 只接受 `privateKeyBlob` 恰为 32 字节；
- big-endian 整数必须满足 `1 <= d < n(P-256)`；
- 用 `ec.derive_private_key(d, SECP256R1)` 派生 SPKI；
- 派生 SPKI SHA 必须常数时间比较等于刚才同轮 native CSR leaf；
- little-endian 只允许写失败诊断，绝不能自动接受；
- 只有全部通过才将标量写入身份目录；
- finally 精确删除随机远程临时目录。

结果：

```text
status=PASS
identity length=32
identity sha256=ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c
identity SPKI sha256=64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
same-run native leaf match=true
private material printed=false
network submitted=false
```

---

## 12. google-rkp-sw 的最终修正

源码：`third_party/google-rkp-sw/rkp_sw.py`。最终使用版本已复制到提交包 `04_proof/rkp_sw_used.py`。

### 12.1 为什么不能用原版 degenerate DICE

原版 `google-rkp-sw` 会构建 `[软件 UDS 公钥, 软件自签 leaf]` 的 degenerate DICE。K70E 是 Google 已登记的 proper DICE 设备：稳定 UDS 根后有 5 段受测量和 authority 约束的 ES256 DICE chain。只用 leaf 身份生成 degenerate chain 会丢失 Google 识别的 K70E 根与测量证据，容易得到 HTTP 444。

### 12.2 正式 source 必须是完整 zero-key AuthenticatedRequest

`--dice-chain-file` 最终不接受 bare chain，只接受完整 native AuthenticatedRequest，因为 DeviceInfo 在 source outer SignedData 内由最终 leaf 签名；bare chain 没有可信 DeviceInfo。

source 验证包括：

- 单一 CBOR 对象，无尾随数据；
- AuthenticatedRequest version 1；
- K70E `UdsCerts == {}`；
- 原目标设备 baseline 中的 UDS SPKI hash（不得当作跨设备常量）；
- 恰好 5 段 DICE；
- 每段 ES256 签名、issuer/subject 连续且不自签；
- K70E AP Boot ROM、Preloader、BL2_EXT_CFG、BL2_TFA_TEE、MiTEE_KEYMINT claim profile；
- mode `01`、key usage `20`、固定 config descriptor/authority profile；
- code hash 只校 32/64-byte 形状，不钉死值，允许 patched-TEE 测量变化；
- 最终 leaf SPKI 必须等于 seed-file 身份；
- source outer leaf 签名有效；
- source CSRPayload 是 canonical CBOR、version 3、`keymint`；
- source challenge 1..64 bytes；
- source KeysToSign 必须为空；
- DeviceInfo 必须是精确 K70E CSRv3 字段集。

### 12.3 DeviceInfo 修正

旧配置文件记录的是历史 `orange/unlocked/acaa...`，而同轮 native CSR 是：

```text
vb_state=green
bootloader_state=locked
vbmeta_digest=b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744
```

正式请求以 source outer signature 内的同轮 DeviceInfo 为权威，配置只用于 fetchEekChain fingerprint。稳定身份字段必须与配置一致；三个启动状态字段允许 source 覆盖。DeviceInfo map 经过 RFC 8949 canonical CBOR 排序，避免服务器因 map 编码顺序拒绝。

### 12.4 seed 与秘密门禁

- proper-chain 模式强制 `--curve p256`；
- 强制使用 `--seed-file`，禁止 `--seed` 把秘密暴露在 argv；
- 文件必须 regular、模式 0600、恰好 32 raw bytes；
- scalar 严格 `1 <= d < n`，不再 `% n` 或把 0 改成 1。

### 12.5 fresh request 预提交验证

软件生成新 P-256 key 后，fetch Google EEK/challenge，构建 fresh request。写盘并 read-back 后、网络提交前再次验证：

- UdsCerts 与 source 完全相同；
- DICE chain 与 source canonical bytes 完全相同；
- outer SignedData 由 CDI_Leaf 身份签名；
- fresh Google challenge 完全匹配；
- source DeviceInfo 精确复用；
- KeysToSign 恰为新软件公钥；
- 每把新软件私钥派生公钥与对应 KeysToSign 完全相同。

任何失败都不能进入 signCertificates。

### 12.6 服务器响应与证书严格门

- 请求和 raw response 必须先持久化再解析；
- fetch 失败不再退回“本地测试模式”继续提交；
- signCertificates CBOR 必须单一对象、无尾随；
- DER 拼接必须每字节都被解析，截断/尾随立即失败；
- 拒绝重复 DER、重复 subject、多个 leaf、issuer 缺失、环、断链或额外游离证书；
- 必须从唯一 leaf 走到唯一 self-signed root，且消费全部证书；
- 叶公钥必须匹配生成的私钥；
- 只有请求数=返回链数、以上全部为 true，run 才能标记 `complete`。

---

## 13. Google 正式软件签发实录

命令使用身份文件与同轮 native source；请求 1 把软件 P-256 key。

输出目录：

`03_提取结果/K70E_google_rkp_sw_provision_20260905_2244/`

### 13.1 fetchEekChain

```text
URL=https://remoteprovisioning.googleapis.com/v1:fetchEekChain
HTTP=200
challenge length=29
challenge sha256=03f4dbcb6ba7ecfc264d22b8a0ebcf8743088ad52dfec8ad99a9143d3d8e650f
EEK curves=2
server config:
  time_to_refresh_hours=72
  num_extra_attestation_keys=12
```

### 13.2 software CSR

```text
length=2608
sha256=029c2bae4fdf94b461ff343d8a67e5106a76d9a3a515dae38e5d5b4953c5f4c4
request_id=7719a808-c73d-4cd7-b652-f22a1b7208a6
preflight=PASS
source DICE exact match=true
source DeviceInfo exact match=true
source UdsCerts exact match=true
outer leaf signature=true
KeysToSign count=1
private/public match=true
```

### 13.3 signCertificates

```text
HTTP=200
response length=2432
response sha256=ab9b9481b38e81a116e7138bd01ffb9423771ce0958472d2a5a3a11c35fe9039
received chain count=1
run status=complete
```

### 13.4 生成私钥

```text
file=key_00/private_key_pkcs8.pem
format=PKCS#8 PEM
mode=0600
file sha256=f9981ef88503d812c4d57fa61072f5fe1c9167b3f85504736cdae6315bf70fbd
public SPKI sha256=a6397c1a8fd2c1e765e616c24b69c436224d429a3392c110e361fe2bcfcd481d
```

### 13.5 四证书链

| 顺序 | Subject | Issuer | SHA-256 |
|---:|---|---|---|
| 0 | `CN=5c392290e5b2912295d237ac6fa3fcb9,O=TEE` | `CN=Droid CA3,O=Google LLC` | `8d1eeefd7ad252ec78c53859be595b935faa2cdb5f1bff597f6a817351d22553` |
| 1 | `CN=Droid CA3,O=Google LLC` | `CN=Droid CA2,O=Google LLC` | `6910e24049eec0cce94c97658631cfe5f98d5f42437b697b894b22c2226fa105` |
| 2 | `CN=Droid CA2,O=Google LLC` | `CN=Key Attestation CA1,OU=Android,O=Google LLC,C=US` | `b8b0741e7a5ad98c996cf81eb46ac2d3fb1c28a3bdb2b89eaa930a64ad871632` |
| 3 | `CN=Key Attestation CA1,OU=Android,O=Google LLC,C=US` | self | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` |

叶证书有效期：2026-09-03 15:11:10 UTC 至 2026-09-17 10:16:02 UTC。终验时处于有效期内。

```text
certificate count=4
all DER bytes consumed=true
leaf public == generated private public=true
signature links valid=true
root self signature valid=true
OpenSSL verify=OK
ordered chain sha256=b3f62232ef434859392833b26cf5bdfdc949cd509637552a555fd6c38febd6bb
```

---

## 14. 最终提交包结构

```text
K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/
├── 01_identity/
│   ├── google_rkp_sw_cdi_leaf_p256_scalar.bin
│   ├── cdi_leaf_public_spki.der
│   ├── native_identity_authenticated_request.cbor
│   ├── native_identity_challenge.bin
│   ├── identity_verification.json
│   ├── native_identity_verification.json
│   ├── verified_dice_chain.cbor
│   ├── verified_dice_chain.json
│   ├── verified_native_device_info.json
│   └── verified_uds_certs.cbor
├── 02_generated_key/
│   ├── private_key_pkcs8.pem
│   ├── public_key_spki.der
│   └── key_summary.json
├── 03_certificate_chain/
│   ├── ordered_certificate_chain.pem
│   ├── ordered_certificate_chain.der
│   ├── ordered_cert_00..03.{pem,der}
│   ├── ordered_untrusted_intermediates.pem
│   └── chain_summary.json
├── 04_proof/
│   ├── capture/provision/preflight JSON
│   ├── software certificate request
│   ├── raw fetch/sign request and response
│   ├── exact rkp_sw/capture script snapshot
│   └── device config snapshot
├── FINAL_VERIFICATION.json
├── README.md
└── SHA256SUMS.txt
```

所有目录为 0700，所有文件为 0600。`SHA256SUMS.txt` 不自包含；清单逐项验证通过。

---

## 15. 动态实验后的恢复

身份和 source CSR 保存后，主机软件签发不再依赖当前 tee-supplicant namespace。Google 成功返回后：

1. 再次确认磁盘 `tee_a` 已自动恢复 `182277...`；
2. 进入 Fastboot，确认 `product=duchamp`、`current-slot=a`；
3. 只刷 `init_boot_a=9d5d12...`；
4. 正常重启并等待 `sys.boot_completed=1`；
5. 验证 Magisk root、`tee_a`、`init_boot_a`、namespace stock TA、`vendor.teefs_state=ready`。

最终实机全部通过。一次性 latch/log 保留为证据，但恢复后的 init_boot 不会再执行该 helper。

---

## 16. 验收矩阵

| 门 | 结果 |
|---|---|
| TA body/header digest 自洽 | PASS |
| OEM signature 保持无效、SProvider bypass 必需 | PASS |
| TEE exact-frame、非目标 block/tail 不变 | PASS |
| init_boot CPIO/LZ4/AVB roundtrip | PASS |
| stock TEE 下未武装 fail-closed | PASS |
| candidate TEE preconsume hash/size | PASS |
| early-bind target hash与 BIND_OK | PASS |
| boot-complete 磁盘 TEE 自动回 stock | PASS |
| namespace TA 为最终 7ea594 | PASS |
| native zero-key CSR | PASS |
| 固定 UDS + 5 段 DICE + claims/profile | PASS |
| source outer signature/challenge/canonical DeviceInfo | PASS |
| scalar raw32 / BE / P-256 range | PASS |
| scalar SPKI == 同轮 native leaf | PASS |
| proper DICE/UdsCerts/DeviceInfo 精确复用 | PASS |
| fresh request 落盘后预提交验证 | PASS |
| Google fetch/sign | 200 / 200 |
| 新软件私钥 == KeysToSign == leaf cert | PASS |
| DER 全消费/唯一链/签名/root | PASS |
| 最终提交清单和权限 | PASS |
| 设备恢复安全基线 | PASS |

---

## 17. 关键证据索引

```text
最终 TA:
  out/k70e_cdi_leaf_identity_capture_hostonly/

最终 TEE:
  out/k70e_sprovider_rsa_bypass_exactframe_hostonly/

最终 init_boot:
  out/k70e_cdi_leaf_earlybind_initboot_hostonly/

身份捕获:
  03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/

软件签发:
  03_提取结果/K70E_google_rkp_sw_provision_20260905_2244/

最终提交:
  03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/

核心脚本:
  02_脚本与补丁/build_k70e_cdi_leaf_identity_capture_hostonly.py
  02_脚本与补丁/build_k70e_cdi_leaf_earlybind_initboot_hostonly.py
  02_脚本与补丁/preflight_k70e_cdi_leaf_deployment_hostonly.py
  02_脚本与补丁/capture_k70e_google_rkp_sw_identity_once.py
  third_party/google-rkp-sw/rkp_sw.py
```

---

## 18. 最终结论

本项目最终完成的不是 native KeyMint 私钥导出，而是：从 K70E 同轮 proper DICE 路径提取并密码学确认 CDI_Leaf P-256 身份；让 `google-rkp-sw` 使用该身份和同轮受签名保护的完整 K70E DICE/DeviceInfo 构建 fresh 请求；新生成一把软件私钥；从 Google 取得与该私钥匹配的四证书链；最后恢复设备并形成可审计的最小提交包。

题目已完成。后续默认只做成品验证、文档审计或备份，不再重复一次性刷写和签发。

---

## 19. 2026-09-06 portable release 附录：另一台 K70E 的流水线验收

本节只补充跨设备交付，不改写前文这台参考机的 2026-09-05 原始事实。任何 AI 接手**另一台物理 K70E** 时，都必须把它当成新目标：先完整阅读文档 50，为该机创建独立 profile、run ID、stock 备份、baseline zero-key CSR、输出目录和一次性状态；不得复制参考机的 serial、UDS、DeviceInfo、scalar、软件私钥、证书、challenge、marker 或恢复镜像。

portable release 的唯一六入口及顺序是：

```text
02_脚本与补丁/k70e_portable_profile.py
02_脚本与补丁/build_k70e_portable_batch.py
02_脚本与补丁/capture_k70e_identity_portable.py
02_脚本与补丁/confirm_k70e_portable_restore.py
02_脚本与补丁/rkp_sw_portable.py
02_脚本与补丁/package_verify_k70e_portable.py
```

执行前从项目根目录核验 `SHA256SUMS_PORTABLE.txt`；本轮还要把现场核验结果保存到目标私有 manifest。该清单同时固定六入口和它们依赖的安全敏感底层工具，不能用“文件名相同”代替哈希一致：

```bash
cd <PROJECT_ROOT>/<DEVICE_WORKSPACE>
shasum -a 256 -c SHA256SUMS_PORTABLE.txt
```

### 19.1 portable 流水线的硬门

1. 收集新机自己的 serial、`duchamp` product、slot、fingerprint、root 入口、stock TA/TEE、known-good 同固件 init_boot，以及同机 stock 状态下的 zero-key AuthenticatedRequest 与 exact challenge。
2. 用 profile 入口执行 `create` 和 `check`。只有 stock TA/TEE 与已审计 device reference 精确匹配且所有结构门通过，分类才是 `EXACT_REFERENCE_FAST_PATH`；任一固件构件不匹配即为 `PORT_REQUIRED`，在完成并独立审计语义移植前禁止写设备。
3. Exact 路线由 batch builder 产生该目标专属的 candidate init_boot、runtime profile、state directory、token、恢复路径和 one-shot 合同；刷写前必须再次对 **runtime profile** 执行 `check`。
4. 按文档 50 的有人值守两阶段流程，先在 stock TEE、未武装状态验证新 init_boot 和恢复件；只有全部门通过，才创建本轮 ARM/ALLOW 并只写 candidate `tee_a`。
5. capture wrapper 必须在同一 capture boot 内完成完整 proper-DICE/profile 验证，然后原子消费 Binder keygen latch，并且只执行一次 Binder keygen。latch 同时保存 profile SHA、run ID、capture boot ID 和随机 remote staging path。
6. identity 与同轮 CSR/challenge/验证报告必须先在主机耐久落盘；随后精确删除远端秘密 staging 目录并证明不存在，最后才完成 canonical identity 与 summary。`remote_cleanup_status.json` 是最终包必需证据。
7. 恢复该目标自己的 stock TEE 和 known-good init_boot，干净重启；只读 restore verifier 必须证明新的、与 capture 不同的 restored boot ID、stock 哈希、健康服务，以及前述 Binder latch 的 profile/run/boot/staging 绑定。
8. 先且只创建一次 immutable `--preflight-only` 报告；真实 `google-rkp-sw` 运行必须复用它，消费设备 issuance latch 与主机 attempt latch，只向固定官方端点请求恰好一把 P-256 软件私钥和一条证书链。
9. package 入口重算 identity→native leaf、software private→request key→Google leaf、HTTP、DER、链序、固定 Google root、权限、清单和全部 latch 关系；verify 必须使用包外 profile 副本或独立保存的 expected profile SHA，包内 `TARGET_PROFILE.json` 不能自证。

仅有两个**越过 one-shot 后**的收尾恢复例外：capture 已消费 keygen 后的 `--resume-cleanup`，以及 Google 已成功返回完整结果后的 `--resume-finalize`。它们都不产生新 key、不重新联网，也不能修补失败证据；精确判定和命令见文档 46 第 17 节。若 live Binder latch 明确为 `ABSENT`、不存在任何 host post-latch 证据且 wrapper 分类为 `PRE_KEYGEN_SAFE_ABORT`，说明 keygen 尚未发生：保留失败目录，可在同一仍有效的 profile/run 下换全新 capture 输出叶重新执行普通 capture。`ABSENT` 但已有 post-latch 证据必须升级为 `UNKNOWN`，禁止 keygen。其余跨过一次性边界后的失败保留全部现场并创建新 profile/run。

### 19.2 2026-09-06 主机验收结果

最终 host-only golden runtime profile SHA-256 为：

```text
2e39f1fabe0c660844296cbdf8542e666ce615f5df58a452db537f49b911d759
```

同一 synthetic/replay portable bundle 分别使用两个独立信任入口验证：包外 `--trusted-profile` 与离线记录的 `--expected-profile-sha256`，两次均为 `PASS / 469 passed / 0 failed`。这个数字只描述该版本 golden 测试，不是未来版本合同；验证器增加或删除检查后数字会改变，现场只认当前已核验入口哈希下的 `status=PASS`、`failed_checks=0` 与关系重算结果。

参考机冻结提交包仍由原机专用验证器独立得到 `PASS / 51 / 0`。portable 的 469 项回放不能替代原包 51 项验证，原包 PASS 也不能替另一台设备背书。

最后的诚实边界是：六入口、fail-closed 分类、窄恢复和关系型打包已完成主机 golden 回放及负向审计，但截至 2026-09-06 尚未在第二台实体 K70E 上完成整套前向写入、捕获、恢复、联网签发和打包闭环。跨机现场是否可走 Exact 路线必须由那台机器自己的 profile 决定。


---

## 原始记录段 2 / Source section 2: 47_K70E_CTF_最终踩坑与故障树_20260905.md

# K70E CTF 最终踩坑记录与故障树

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **后续覆盖（2026-09-06 20:00）：**新实验已证明 exact modified five-layer DICE + clean DeviceInfo 可得 `APPROVED`。与该事实冲突的旧因果归纳已过时；最新踩坑和故障树见文档 67。

> **2026-09-06 18:05 最高覆盖：** 新故障树见文档 61，暂停证据见文档 59、62。旧恢复合同已造成 OrangeFox vendor_boot + Magisk init_boot 双重 AVB mismatch；BROM fresh challenge 后在线卡密耗尽，未进 DA、无分区 I/O。本文不得作为恢复执行指南。

> CURRENT ROUTE OVERRIDE：本文正文是旧路线记录。当前故障树和禁止事项见文档 55；本文的提交优先级、已完成和旧哈希结论全部失效。

> **2026-09-06 新增最高优先级踩坑：** 旧解析器丢弃 Provisioning Info 未知键 5，导致含 `{5:{1:"NOT_APPROVED"}}` 的 Google 叶证书被误判为 PASS。旧最终答案、哈希和“无需重签”结论均不可用于提交；先读文档 52。任何后续成功必须全链 `ctf_no_not_approved=true`。

> 项目：Redmi K70E / `duchamp` / MiTEE / `google-rkp-sw`  
> 收口日期：2026-09-05（Asia/Taipei）  
> 目的：把已发生的问题、易误判点、危险组合和恢复分支一次写全，避免后来者重复踩坑。  
> 最终事实优先级：最终提交包与 2026-09-05 成功证据 > 文档 45–48 > 文档 42/44 的最终增补 > 更早的阶段性判断。
> 另一台 K70E 必须从文档 50 入口；本文中所有 serial、UDS、TA/TEE/init 哈希和 one-shot 路径都只属于原目标/原固件，不是型号常量。

---

## 0. 先记住最终正确答案

本题最终不是“拿到任意 KeyMint 私钥”，也不是“Google 返回过一次 200”。严格三件套是：

1. 用户 `google-rkp-sw` 的身份数据：Open-DICE 派生完成后的 32-byte big-endian P-256 `CDI_Leaf` 私钥标量，以及同轮 native zero-key AuthenticatedRequest 中的 proper DICE/UDS/DeviceInfo 证明；
2. 一次 `google-rkp-sw` 软件运行中新生成的一把 P-256 PKCS#8 私钥；
3. Google 在同一次软件运行中为第二项公钥返回的四证书链。

最终提交目录：

```text
03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/
```

最终关键哈希：

```text
identity scalar       ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c
identity leaf SPKI    64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
原目标 UDS SPKI       d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9
software private file f9981ef88503d812c4d57fa61072f5fe1c9167b3f85504736cdae6315bf70fbd
software public SPKI  a6397c1a8fd2c1e765e616c24b69c436224d429a3392c110e361fe2bcfcd481d
Google response       ab9b9481b38e81a116e7138bd01ffb9423771ce0958472d2a5a3a11c35fe9039
ordered DER chain     b3f62232ef434859392833b26cf5bdfdc949cd509637552a555fd6c38febd6bb
```

如果只是验收现有答案，验证提交包即可；不要为了“再确认一次”重复刷写、取钥或向 Google 重签。

---

## 1. 口径与密码学语义坑

### 1.1 native 逐把 RKP 私钥不是 `google-rkp-sw` 身份

旧 `6abe6d…` TA 捕获的是 native `GenerateRkpKey` 每次生成的 P-256 scalar。它能与相应 MacedPublicKey/Google 叶证书闭环，因此是重要旁证，但它不是 Open-DICE `CDI_Leaf` 身份。

对应旧结果：

```text
K70E_scalar_final_google_provision_20260905_2206/
```

正确处理：标注为“native per-key scalar 补充结果”，不得作为最终三件套中的第一项。

### 1.2 两把最终钥匙不应互相相等

最终包中有两类私钥：

- 身份标量：签 `google-rkp-sw` 请求的 SignedMac/SignedData；
- 软件生成私钥：其公钥出现在 `KeysToSign`，最终必须等于 Google 叶证书公钥。

身份公钥 `64c672…` 与软件公钥 `a6397c…` 不同是正确现象。错误地要求二者相等，会把正确结果判成失败。

### 1.3 raw CDI 不是最终 CDI_Leaf scalar

`get_attest_cdi` 在 `0xdcd10` 从 `/dev/misc/hwinfo` 取得的 32 字节是 DICE 输入。最终活动 P-256 路径还会执行 `P256KeypairFromCDI`；成功点 `0xdd934` 的 `x26` 才是可直接交给当前 `google-rkp-sw` P-256 实现的 leaf scalar。

正确语义：

```text
raw CDI → DICE 派生 → 0xdd934:x26 → 32-byte big-endian P-256 CDI_Leaf scalar
```

不能抓 raw CDI 后再凭感觉做一次或少做一次 KDF。

### 1.4 275-byte blob、KeyBlob、MacedPublicKey 都不是私钥

已验证的 275-byte `privateKeyBlob`/KeyBlob 是 opaque KeyMint handle。MacedPublicKey 是公钥封装。随机观察到某个 32-byte 窗口，也不能仅凭长度把它叫私钥。

只有同时满足以下门才可接受：

- 精确 hook 语义已确认；
- 输出恰好 32 raw bytes；
- scalar 在 P-256 合法范围 `1 <= d < n`；
- big-endian 直接派生的 SPKI 与同轮 native leaf 一致。

### 1.5 leaf 会变，同一目标设备的 UDS 相对稳定

历史 CDI leaf SPKI 是 `0684d469…`，最终补丁测量态下是 `64c672…`；在这一台目标上 UDS SPKI 仍为 `d1a3f13b…`。leaf 受启动测量影响，不能把历史 leaf 硬编码为永久常量；UDS 也未被证明是所有 K70E 共享的型号常量，新机必须从自己的 stock zero-key CSR 建立 baseline。

正确门是“同轮 native leaf = 同轮捕获 scalar 派生 leaf”，不是“必须等于历史哈希”。

### 1.6 HTTP 200 不是完成

`fetchEekChain=200` 或 `signCertificates=200` 只能说明服务端响应成功。还必须验证：

- 请求发送前已保存且预检 PASS；
- source 是同轮 zero-key AuthenticatedRequest；
- 一把新私钥与 `KeysToSign` 公钥匹配；
- 只返回一条预期链，且含四张证书；
- 叶公钥与该私钥匹配；
- DER 全消费，无尾随或截断；
- 每一级签名有效、根自签有效、OpenSSL verify OK。

### 1.7 `validated_attested_entity=null` 不能夸大

最终叶证书的 ProvisioningInfo 中 `manufacturer_legacy_field=Xiaomi`，近 30 天数量约为 32，`validated_attested_entity=null`。这不能被写成“Google 明确验证设备实体为 Xiaomi”；只能如实报告字段。

### 1.8 证书有时效

本次叶证书有效期为：

```text
notBefore 2026-09-03T15:11:10Z
notAfter  2026-09-17T10:16:02Z
```

过期不抹掉本次历史成功，但以后做实时有效性判断时必须区分“当时签发有效”和“当前仍在有效期内”。

---

## 2. 解锁、账号、属性与实际能力的误判

### 2.1 小米账号无解锁授权，不代表 fastboot 一定不能写

本机有 Fenrir/既有启动链背景：账号授权、开发者选项 OEM 解锁开关、bootloader UI 文案、Android 属性和 fastboot 实际写入能力不是同一个层次。

项目最终动态事实是候选 `init_boot_a` 与 `tee_a` 均被 fastboot 写入并启动。以后不能仅凭“账号没内测资格”推断“设备绝对未解锁”，也不能仅凭某个 UI 开关推断所有分区都可安全写。

### 2.2 `green` / `locked` 属性不等于原厂链完全未修改

最终 native DeviceInfo 报告 `green/locked`，Fenrir 日志同时有 `img_auth_required = 0`。属性是启动链向 Android 暴露的状态，不是对物理写入能力或底层实现的完整证明。

正确做法：

- 用实际只读 fastboot/分区/启动证据判断当前能力；
- 不再为“到底算不算官方解锁”阻塞 CTF；
- 仍按最危险情形准备恢复路径。

### 2.3 OEM unlock 开关不是授权证明

开发者选项中的 OEM 解锁开关只是一项配置/许可状态，不能代替 boot chain、fastboot 写入和签名门的实测。不要从单个开关推导完整安全状态。

---

## 3. 主机、ADB、Fastboot 与 shell 坑

### 3.1 多设备必须钉死 serial

当时同时连接过 K70E 和 Pixel 4 XL。裸 `adb shell`、裸 `adb reboot bootloader` 或裸 `fastboot flash` 都可能选错目标。

硬规则：

```text
ADB/Fastboot 目标 serial = "<TARGET_SERIAL>"
product                  = duchamp
slot                     = _a
```

每次写入前重新查 `devices`、`product`、`current-slot`；所有命令带 `-s`。

### 3.2 正确 root 入口不是普通 `su`

本机构建的可靠 root 入口为：

```text
/debug_ramdisk/magisk su -c
```

普通 `su`、`su -p -c` 或假设 `/system/xbin/su` 存在可能失败。脚本和教程必须统一使用已验证入口。

### 3.3 host shell 会提前展开 `$pid`

曾出现把远端命令写在双引号里，导致 host 先展开 `$pid`，远端得到空 PID；后续输出又出现 `markers=absent`，整段看起来像成功。

正确模式：

1. 单独执行 `adb -s $SERIAL shell pidof tee-supplicant`；
2. 去除 CR、取首个 PID；
3. 主机执行 `test -n "$PID"`；
4. 再把字面 PID 放进单引号保护的远端 `nsenter` 命令。

空 PID 不能被“后续某行输出正常”掩盖。

### 3.4 `boot_completed=1` 不代表早期服务状态一定正确

`sys.boot_completed` 只能说明 Android 已完成大部分启动。还必须分别确认：

- root 可用；
- `tee-supplicant` PID 非空；
- `vendor.teefs_state=ready`；
- mount namespace 内 TA 哈希正确；
- early-bind/restore marker 和日志完整。

### 3.5 Fastboot AVB footer warning 不是自动失败或成功

Fenrir fastboot 可能无法正确报告 `tee_a` 分区大小，并提示跳过 AVB footer。不能只看 warning 下结论。

写入成功必须同时看到：

```text
Sending ... OKAY
Writing ... OKAY
Finished.
```

任何 `FAILED` 都停止并恢复 stock。

### 3.6 USB 授权、线材、电量、电脑睡眠都是实质风险

长流程中 ADB 掉线不一定是 TEE 问题。先区分：

- 屏幕上的 USB 调试授权；
- 线材/接口接触；
- 主机休眠；
- 设备低电量；
- Android 未启动；
- 真正的 secure-world/boot failure。

不要在原因未明时连续重启或扩大刷写范围。

### 3.7 手机上 Wi-Fi 不可用不阻断最终网络提交

身份捕获发生在设备；`google-rkp-sw` 的 Google provisioning 在电脑端完成，使用电脑网络。无需为了登录或手机 Wi-Fi 改动更多系统组件。

---

## 4. TEE 镜像与 SProvider 坑

### 4.1 这次没有解决 TA OEM RSA 签名

修改后的 TA body/header digest 自洽，但 OEM RSA-PSS 签名仍无效。最终成功靠 exact-frame TEE 中 SProvider 的单指令逻辑修改：RSA verifier 仍运行，但失败结果不再阻止加载；body/header digest 验证仍保留。

因此不能再写“我们伪造/解决了 TEE 签名”，也不能把补丁理解成“任意 TA 都能加载”。

### 4.2 v4 卡 logo 的根因不是 Fenrir 永久阻断

旧 v4 全量重压 TEE 时截断了 LZ4 frame 后的 `cert1/cert2/spmc_dtb` 尾部，因此卡 logo。它曾诱发“Fenrir 无法启动修改 TEE”的错误结论。

最终 exact-frame 方法：

- 保持 frame 总长度不变；
- 保持所有 descriptor 不变；
- 只重压目标 block 14 的 payload；
- 保持其余 68 个 block、frame 后证书和 DTB 逐字节一致；
- 解压后只改变 `svchost` 的一条四字节指令。

### 4.3 不能混用任意 TA、TEE、init_boot

最终配套是：

```text
TA        7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
TEE       3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
init_boot 5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517
```

旧 exact-frame README/`pairing_contract` 仍点名 `scalar_rkp_selfconsistent`，属于陈旧文本；最终 CDI preflight 已独立证明同一 loader 与 `7ea…` 配对成立。以后以哈希和 preflight 为准，不以旧标题为准。

### 4.4 TA body/header digest 仍是硬门

SProvider 只旁路 RSA 结果门，未旁路 body/header digest。TA 修改后必须重新计算内部 digest，并由主机独立重构验证。随手 patch 四字节、忘记 digest 更新仍会加载失败。

### 4.5 老补丁污染必须隔离

历史 `tee_a_dump.img` 含两个来历不明旧 patch，不能拿来当 stock。任何新构建必须从已验证 stock `182277…` 出发，并通过差异 allowlist。

### 4.6 ELF 扩展要同时满足加载语义

TA 新代码与 scratch 不能只看“文件里有空洞”。本次正确做法包括：

- RX 覆盖扩展到 `0x142000`；
- RW `p_memsz` 扩展以包含正式 BSS scratch；
- RW `p_filesz` 不变；
- 无 W+X segment；
- hook cave 和 scratch 地址都在合法加载映射；
- allowlist 外无额外差异。

### 4.7 跨调用 scratch 有并发与内存序风险

writer 必须 scalar/length 先写、`dmb ishst`、marker 最后写；reader 看到 marker 后 `dmb ishld`，复制后清 marker/length/scalar。缺少顺序或清零可能读取半写数据或泄露旧秘密。

本次实现并不是通用多线程队列。复现时必须保持单一、顺序调用，不允许并行 keygen。

### 4.8 caller/LR gate 不能省

仅凭输出长度或 `w22==0` 不足以限定调用来源。最终导出同时要求保存 caller LR=`0x61c7c`，只允许 `GenerateRkpKey` 的调用点。省掉 gate 会把其他路径的 32 字节错误暴露成“成功”。

---

## 5. TA 可见性、mount namespace 与启动时序坑

### 5.1 全局文件看到 candidate，不代表 tee-supplicant 看到它

Android 服务可能在独立 mount namespace 中看到不同的 `/vendor/mitee/ta/...`。主机/global namespace 的 SHA 正确，不能证明服务实际加载的 TA 正确。

必须使用当前非空 tee-supplicant PID：

```text
nsenter -t <pid> -m -- sha256sum /vendor/mitee/ta/<uuid>.ta
```

### 5.2 `post-fs-data` 太晚，最终必须 `on fs`

早期实验在 post-fs-data 后 bind，tee-supplicant 可能已经打开或缓存 stock TA。最终 early-bind 放在 init `on fs`，早于 vendor service 启动。

### 5.3 TA cache 会制造“文件变了但行为没变”

已经加载过的 TA/secure-world 状态可能缓存。不能在同一启动中反复换文件期待重新加载。最终使用唯一一次干净启动、早绑和严格调用顺序。

### 5.4 SELinux label 不是装饰

bind 源被设置为 `mitee_data_file`。只复制文件、忘记 context，可能在 shell 下可读但服务打不开。验证时同时看文件哈希、context、namespace 和服务状态。

### 5.5 磁盘 TEE 已恢复 stock 是成功现象

候选启动后，boot-complete helper 会把磁盘 `tee_a` 自动恢复为 stock，但当前 secure world 继续运行本次已加载的候选。看到磁盘 `182277…` 不能误判“候选没运行”。

正确证据组合：

```text
preconsume_tee_hash=3990...
target_hash=7ea...
BIND_OK
COMMITTED
namespace TA=7ea...
restore_final=182277...
```

### 5.6 one-shot latch 已消费，不能删 marker 硬重放

最终 `once_7ea5948e/COMMITTED` 表示一次性部署已用。删掉 latch 并重用同一 token/构件会破坏证据语义，也可能与残留状态竞争。

如确需全新复现，应新建一轮构件、token、目录和 latch；现有最终题目无需重放。

### 5.7 ARM/ALLOW 的创建不是严格事务

虽然采用临时文件 + `mv`，两个 marker 仍非单个原子事务。写完后必须逐一校验名字、大小、模式和 token；半成品状态下不得普通重启。

### 5.8 旧 executable hook 会抢时序

历史 `/data/adb/post-fs-data.d/00_k70e_v6_bind.sh` 或旧 Magisk 模块若仍启用，会与新 early-bind 竞争。开始前要禁用/隔离，不是只看文件名“应该没运行”。

---

## 6. 身份捕获坑

### 6.1 zero-key native CSR 必须先完成

身份来源使用 `cmd remote_provisioning csr ... default` 的 zero-key AuthenticatedRequest，要求 `KeysToSign=0`。如果 source 已包含待签公钥，就混淆了“身份证明”和“最终软件新密钥”。

### 6.2 keygen 恰好一次

身份 TA 将跨调用保存的 leaf scalar 放入紧接着一次 Binder `GenerateRkpKey` 的 blob 载体。多执行一次、后台服务抢先 keygen 或手工再试，都可能消费/清零 scratch，破坏同轮绑定。

捕获窗口内：

- 手机保持空闲；
- 不运行 RKPD、Play Integrity、Key Attestation 或其他 CSR/keygen；
- 不手工调用第二次 `cmd remote_provisioning csr`；
- 捕获失败不原地再点一次。

### 6.3 Binder client 要钉死二进制哈希

最终 arm64 client：

```text
SHA-256 79dc5f2bd523e5c35a77f34c46bbb345c22e7b79c245e2eee4b5bef0fbcb1cef
```

换 client/ABI/服务名可能改变 parcel 布局或调用路径。不能把“能编译”当成“和 hook ABI 相同”。

### 6.4 big-endian 是最终语义

当前 `rkp_sw.py` 使用 `int.from_bytes(..., big)` 并直接 `ec.derive_private_key`。big-endian SPKI 必须同轮匹配。little-endian 只能作为诊断，不得把“另一端序碰巧落在范围内”作为接受理由。

### 6.5 输出目录必须全新

复用旧目录会把旧 CSR、旧 key、旧 response 与本轮结果混在一起。每次运行先 `test ! -e`，以 0700 创建新目录；失败目录保留原样，不覆盖为“成功”。

### 6.6 私钥不能出现在 argv、日志或屏幕

身份使用 raw 0600 `--seed-file`，不能用 hex 命令行参数。禁止 `set -x`、`cat`、`xxd`、`base64`、截图或把秘密粘贴进聊天。

### 6.7 捕获脚本双 pull 是无害重复，不是两次 keygen

历史脚本对同一个 remote blob 连续 `adb pull` 两次，属于同一文件覆盖，不会触发第二次 Binder keygen。不要把它误报为身份重复生成；但未来可清理以减少困惑。

---

## 7. proper DICE、DeviceInfo 与 CBOR 坑

### 7.1 上游默认 degenerate DICE 不适合本机身份

原始 `google-rkp-sw` 默认可生成 `UDS=CDI_Leaf` 的退化/自签 DICE。K70E 实际有固定 UDS 和五段 proper DICE。退化链是历史 HTTP 444 的候选结构性风险之一，但 444 本身不能证明究竟是 DICE、ProtectedData、seed、DeviceInfo 还是其他字段被拒；不得把候选归因写成已证实根因。

最终必须使用冻结的修改版：

```text
04_proof/rkp_sw_used.py
SHA-256 54e886ce80cfbdfa88e76cad075bad0e5ac949eb9ea5ec1246553bc673271401
```

### 7.2 `--dice-chain-file` 必须是完整 AuthenticatedRequest

只给裸 DICE 数组，拿不到由 leaf 签过的 DeviceInfo 和 source 外层签名，无法证明三者同轮。最终实现明确拒绝裸链，要求完整 native AuthenticatedRequest。

### 7.3 UdsCerts 必须为空 map

不能省略成错误类型，也不能注入伪证书。最终 source `UdsCerts={}`，其 canonical bytes/hash 被保存并在新请求中精确复用。

### 7.4 五段不是只数数量

每段还必须验证：

- COSE/ES256 签名；
- issuer/subject 连续性；
- canonical subject key；
- mode=`normal`；
- key usage=`certificate_signing`；
- claim profile、descriptor、authority hash/code hash 形状；
- 最终 subject SPKI 等于身份 scalar 派生 leaf。

### 7.5 code hash 不能硬编码为原厂值

补丁会改变测量态，最终 leaf 和某些 code hash 随之变化。应验证字段长度、结构、签名与链关系，而不是要求历史 code hash 常量。

### 7.6 source 外层 SignedData 也必须验证

只验五段内部 DICE 签名不够。完整 native AuthenticatedRequest 的外层签名要由 final leaf 验证，challenge 要与本轮生成值一致。

### 7.7 DeviceInfo 以同轮签名数据为准

配置文件中仍残留 `orange/unlocked` 和旧 vbmeta；最终请求实际使用 source 中签名的：

```text
vb_state=green
bootloader_state=locked
vbmeta_digest=b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744
```

mutable boot 字段必须由 source 覆盖。brand/model/device/product/manufacturer 和 patch level 等非 mutable 字段仍需与配置一致。

### 7.8 canonical CBOR 和全消费不可省

map 顺序、整数/字节串类型、嵌套标签和尾随字节都可能让“看起来一样”的 JSON 语义在签名层不同。验证必须针对原始 canonical CBOR，并要求解析器消费全部输入。

### 7.9 fresh challenge 长度必须合法

Google software request 使用新的 challenge，与身份 source challenge 不是同一个目的。challenge 要随机、长度 1–64 字节，并在发送前保存哈希。

### 7.10 请求必须发送前落盘并复读验证

正确顺序：

```text
生成一把软件私钥
→ 构造请求
→ 原始 request 保存
→ 从磁盘重新解析
→ 验证 source chain/UdsCerts/DeviceInfo exact match
→ 验证 outer leaf signature 和 KeysToSign/私钥匹配
→ 才发送
```

不能先发、后补报告。

### 7.11 不能只相信 verification JSON 里的 `true`

报告字段只能是索引，不能替代原始证据复算。终检必须重新解析冻结的 native AuthenticatedRequest，直接验证外层签名，并把签名 payload 内的 challenge 与 `native_identity_challenge.bin` 精确比较、把签名 payload 内的 DeviceInfo 与保存 JSON 逐字段、逐类型比较。Python 中 `True == 1 == 1.0`，普通字典相等不足以做类型门。否则一个陈旧或手工修改的 `challenge_matches=true` / `source_device_info_exact_match=true` 会制造假闭环。

---

## 8. Google 响应和证书解析坑

### 8.1 HTTP 444 不要盲目连点

444 更可能是身份/DICE/DeviceInfo 不被接受，而非普通网络抖动。重复提交会增加配额和审计噪音，还可能生成更多无法配对的新私钥。

先离线检查：UDS、五段签名、leaf/seed、zero-key source、outer、canonical DeviceInfo 和请求精确复用。

### 8.2 失败时不要切到本地伪证书当“完成”

题目要求 Google 成功产生的证书链。自签、本地 CA 或缓存的旧链只能用于调试，不能作为最终交付。

### 8.3 请求与原始响应必须在解析前保存

服务端返回可能含不同 wrapper/CBOR 结构。先保存 raw body、HTTP metadata 和 SHA，再解析；否则解析器报错时会丢失唯一证据。

### 8.4 DER 解析要拒绝尾随、截断和拼接错误

“OpenSSL 能打印第一张证书”不代表整条响应正确。每张 DER 必须精确全消费，组合链要按叶→中间→根排序，不能把尾随垃圾默默忽略。

### 8.5 不能只按 subject 字符串拼链

相同 subject、重复证书、断开的中间证书或循环都可能骗过简单逻辑。要结合 issuer/subject、签名验证、唯一 DER 哈希和根自签构建唯一无环链。

### 8.6 重试可能产生另一把私钥

如果重新运行 `provision`，通常会生成新 key。严禁把 A 轮私钥与 B 轮证书链拼在一起。每轮输出目录、request、response、key summary 和 chain summary 必须封闭自洽。

---

## 9. 打包、权限和文档坑

### 9.1 SHA256SUMS 不能包含自身

清单若包含自身会形成不可满足的自引用。正确做法是枚举其他文件、排序、计算后再原子安装清单。

### 9.2 改 README/FINAL 后清单会陈旧

任何经过授权、来源明确且完成全套复核的包内变更，最后都要重建 `SHA256SUMS.txt` 并完整验证。旧 `_2206` 清单曾因此失效，现已重建；未来不要把“曾经 PASS”当当前 PASS。若只是现有包校验失败，不得先重建清单来掩盖损坏，必须先查明内容为何变化。

### 9.3 目录与文件模式是交付门

最终包目录应为 0700、所有文件为 0600。不能因为 PEM 看似常见就把 PKCS#8 设为 0644；身份 scalar、私钥、CBOR 和派生报告都按敏感材料处理。

### 9.4 live 工作树不是最终冻结证据

`third_party/google-rkp-sw` 可能处于 dirty 状态。复核时优先使用提交包 `04_proof/rkp_sw_used.py` 和对应 SHA，不假设当前工作树仍与成功运行完全一致。

### 9.5 旧 README 标题和 pairing 文本可能误导

已知陈旧元数据：

- exact-frame TEE README/`pairing_contract` 仍点名旧 scalar TA；
- CDI init_boot README 标题残留 “final scalar one-shot”；
- `device_prop` 仍写 `orange/unlocked`；
- `rkp_sw.py` 部分 docstring 把直接 P-256 scalar 称作 seed。

最终判断以内容、哈希、preflight 和同轮签名数据为准。

### 9.6 最终提交包不是完整 raw fastboot transcript

最终包保存了精简设备预检、捕获/请求/响应/链证明，但未保存 `7ea…` 轮逐行 fastboot transcript 或完整 raw earlybind/restore log。文档 45 中部署顺序有一部分是由构件与状态证据重建的实操顺序，不能伪称“逐行原始终端记录”。

旧 `2206` raw log 属于 `6abe…` native scalar 轮次，不能移花接木为最终 CDI 轮次。

### 9.7 不要公开上传秘密

身份 scalar 与 PKCS#8 私钥不得进 Git、公开网盘、聊天、截图、工单或公开报告。对外报告只给哈希、SPKI、证书和验证结论；原文件只交给明确授权的比赛平台/评审。

### 9.8 验证器不能从候选包父目录寻找解释器

严格复核 helper 会收到 scalar 和 PKCS#8 的文件路径。如果验证器从 `<候选包祖先>/third_party/.../.venv/bin/python` 自动挑解释器，攻击者可以把完整真包放在恶意父目录下，让伪解释器先读走秘密，再伪造 `network=false` 输出。运行时和 OpenSSL 都必须来自验证器自身固定、可信的 allowlist；绝不能由待验证目录、其祖先或调用者 PATH 控制，子进程还应使用最小环境，避免 `PYTHONPATH`/OpenSSL 配置类环境注入。最终 Skill 已按此修正。

### 9.9 复核本身不能修改提交包

动态 import 包内冻结 Python 源可能生成 `__pycache__/*.pyc`，导致“验证前完整，验证后多文件”、权限变化或秘密包内容被意外修改。helper 必须设置 `sys.dont_write_bytecode=True` 或等价禁用字节码写入；终检后再次确认包内无 `__pycache__`/`.pyc` 且固定文件集合未变化。

---

## 10. 恢复与防砖坑

### 10.1 必须有人在设备旁

候选 TEE 启动是本项目最高风险点。只有设备旁有人、按键可进 Fastboot、stock TEE 已验证并预置、BROM tee-only 恢复已准备时才允许执行。

### 10.2 先刷未武装 init_boot，再刷 TEE

正确阶段顺序：

```text
stock TEE + candidate init_boot（无 ARM）启动验收
→ 预置/验证 stock TEE 恢复件
→ 最后创建 ALLOW/ARM
→ 只刷 candidate tee_a
→ 唯一实验启动
```

跳过未武装验收会把 init 逻辑错误和 TEE 启动错误叠在一次风险里。

### 10.3 候选 TEE 失败时只恢复 TEE

若写入 candidate `tee_a` 后 Android 不回来但 Fastboot 可进：只刷回精确 stock `tee_a=182277…`。candidate init_boot 检测到 stock TEE 会在消费 ARM 前 fail-closed。设备启动后再恢复 known-good init_boot。

### 10.4 自动恢复不会重启

boot-complete helper 只把磁盘 TEE 写回 stock，不重启；这正是让当前 secure world 继续完成捕获、下一次启动回到 stock 的设计。不要看到无自动重启就判失败。

### 10.5 BROM 只允许 tee-only

Fastboot 不可用时才走已审计的 BROM 文档；flash list 必须只有 `tee_a`，输入只能是大小 5,242,880、哈希 `182277…` 的 stock 镜像。绝不运行 `write_efuse.xml`，不扩大到 preloader/gz/seccfg 等分区。

### 10.6 不 relock

修改启动链环境下 relock 可能直接把可恢复问题变成难恢复问题。结题不需要官方解锁状态“好看”，不要执行任何 lock/clean-all-and-lock 操作。

### 10.7 收尾要验证服务，不只验证分区

最终恢复门：

```text
boot_completed=1
tee_a=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
init_boot_a=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
namespace TA=facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
vendor.teefs_state=ready
```

---

## 11. 已被最终证据覆盖的历史判断

以下内容保留作为过程记录，但不能继续当结论：

| 历史判断 | 最终事实 |
|---|---|
| 无 root，不能继续 | `/debug_ramdisk/magisk su -c` 已验证可用 |
| locked/Fenrir 使 fastboot 修改镜像不可用 | 候选 init_boot/TEE 已实际写入并成功启动 |
| 修改 TEE 必然卡 logo | exact-frame TEE `3990…` 成功；旧卡 logo 根因是 frame 后尾部被截断 |
| 必须解决 OEM TA RSA 私钥/签名 | 未解决签名；最小旁路 RSA 结果门并保留 digest 门即可 |
| `6abe…` per-key scalar 是最终身份 | 它只是 native 补充；最终身份是 `7ea…` 捕获的 CDI_Leaf |
| 配置里的 orange/unlocked 是最终请求值 | 最终取同轮 signed native DeviceInfo：green/locked |
| 磁盘 TEE 变回 stock 说明补丁未运行 | 自动恢复是设计行为；当前 secure world 和 namespace 证据证明候选已运行 |

---

## 12. 分阶段故障树

### 12.1 主机预检失败

```text
preflight != PASS
├─ 文件不存在 → 找回精确构件，不用同名替代品
├─ 大小/哈希不同 → 停止；确认是否被重建或污染
├─ TA digest 不自洽 → 重建 TA，不刷写
├─ exact-frame diff 合同失败 → 重建 TEE，不刷写
├─ init_boot/CPIO/AVB 合同失败 → 重建 init_boot，不刷写
└─ shell/script 编译失败 → 修复主机工具，仍不碰设备
```

### 12.2 未武装 init_boot 启动失败

```text
刷 candidate init_boot 后 Android 不正常
├─ Fastboot 可进 → 只恢复 init_boot_a=9d5d12...
├─ ADB 有但 root/服务异常 → 不 ARM，不刷 TEE；保存日志后恢复 init_boot
└─ Fastboot 不可见 → 先排查线材/按键/端口，不扩大刷写范围
```

### 12.3 ARM/ALLOW 检查失败

```text
marker 名称/大小/权限/token 不符
├─ TEE 尚未刷 → 不重启到实验态；清理半成品并重新只读核验
└─ 状态不确定 → 保持设备当前态，先保存目录和日志，不盲目补 marker
```

### 12.4 candidate TEE 写入失败

```text
fastboot flash tee_a 出现 FAILED
└─ 保持 Fastboot → 立即只刷 stock tee_a=182277... → 启动 → 恢复 init_boot
```

### 12.5 candidate TEE 启动后 ADB 不回来

```text
ADB 长时间不可用
├─ Fastboot 可进 → 只恢复 stock tee_a → 启动
├─ Fastboot 不可进但 BROM 可用 → 严格 tee-only BROM 恢复
└─ 均不可确认 → 停止反复通电，按硬件恢复预案处理
```

### 12.6 Android 回来但 early-bind 不完整

```text
缺 BIND_OK / COMMITTED / namespace TA=7ea...
├─ 磁盘 TEE 已 stock → 不捕获；保存日志；恢复 init_boot
├─ 磁盘 TEE 仍 candidate → 先执行带哈希门的 restore helper
└─ restore 失败 → Fastboot 只恢复 stock TEE
```

### 12.7 身份捕获失败

```text
capture SAFE_ABORT/failed
├─ native CSR/DICE/outer 失败 → 不 keygen、不提交 Google
├─ 导出长度/范围失败 → 不把 blob 当身份
├─ scalar SPKI != same-run leaf → 拒绝；检查端序/路径/竞争
├─ one-shot 已消费 → 不原地重跑；保存证据并恢复设备
└─ 任何失败 → 不覆盖输出目录，不公开秘密
```

### 12.8 Google 提交失败

```text
fetch/sign 非 200
├─ 444 → 优先审计身份/DICE/DeviceInfo，禁止盲重试
├─ 400 → 审计 CBOR/challenge/请求结构
├─ 429 → 保存本轮，不连点，等待配额
├─ 5xx/网络 → 保存 request/key/raw response；后续新轮不得混配
└─ 本地 preflight 未 PASS → 根本不应发送
```

### 12.9 返回证书但本地验证失败

```text
有响应/有证书，综合门失败
├─ leaf pub != private pub → 本轮失败，禁止拼旧 key
├─ cert count != 4 → 记录实际响应，本轮不按预期完成
├─ DER 尾随/截断 → 本轮失败
├─ link/root verify 失败 → 本轮失败
└─ chain disconnected/duplicate/cycle → 本轮失败
```

### 12.10 打包验证失败

```text
SHA/mode/报告不一致
├─ SHA 清单陈旧 → 查明改动后从可信源重建清单
├─ 缺文件 → 从原 identity/provision 目录补，不伪造
├─ mode 过宽 → 收紧为目录0700/文件0600
├─ FINAL 与底层 JSON 冲突 → 以底层证据为准，修正报告
└─ key/leaf OpenSSL 不匹配 → 不得提交
```

---

## 13. 最终“不再犯”检查表

- [ ] 不再把旧 `_2206` native scalar 当最终题解。
- [ ] 不再把 raw CDI、KeyBlob、MacedPublicKey 或任意 32 字节窗口叫身份。
- [ ] 不再要求身份公钥等于软件生成公钥。
- [ ] 不再把 HTTP 200 当作唯一完成条件。
- [ ] 不再说“TA 签名已解决”；实际是 SProvider RSA 结果门旁路。
- [ ] 不再全量重压或截断 TEE LZ4 frame 后尾部。
- [ ] 不再混用 TA/TEE/init_boot 版本。
- [ ] 不再只看 global TA；必须查 tee-supplicant namespace。
- [ ] 不再把自动恢复后的 stock 磁盘 TEE误判为候选未运行。
- [ ] 不再用 post-fs-data 抢早绑时序。
- [ ] 不再使用普通 `su` 或 `su -p -c`。
- [ ] 不再运行无 `-s` 的 ADB/Fastboot 命令。
- [ ] 不再在 host 双引号里让 `$pid` 被提前展开。
- [ ] 不再删除 one-shot latch 试图重放。
- [ ] 不再在捕获窗口触发第二次 keygen 或后台 attestation。
- [ ] 不再使用裸 DICE 或 degenerate DICE 替代完整 AuthenticatedRequest。
- [ ] 不再相信 stale `device_prop` 的 orange/unlocked 值。
- [ ] 不再先发送请求后补 preflight。
- [ ] 不再把不同运行的私钥、请求和证书链拼接。
- [ ] 不再让 SHA 清单包含自身，或修改包后忘记重建。
- [ ] 不再公开输出/上传身份 scalar 与 PKCS#8 私钥。
- [ ] 不再 relock，不扩大恢复分区范围。
- [ ] 已有最终 PASS 包时，不再为“确认”重复刷写或签发。

---

## 14. 历史关闭路线与低频边缘坑补录

本节补录主流程之外仍可能误导后续工作的已关闭路线和边缘条件。它们不应被重新解释为“还有一个没试完的捷径”。

### 14.1 跨设备、跨项目和卖家环境污染

- 项目早期曾同时出现 Pixel 4 XL、xaga、Nothing/Pacman、Samsung keybox、`ctf_artifacts` 和误放的 `emerald` 材料。现成私钥、HTTP 200、镜像或证书“看起来能用”不代表属于 duchamp。必须以 serial、product、固件代号、证书时间、SPKI 和同轮 raw response 交叉识别；来源不明立即拒绝。
- 卖家所谓“环境全过/证书通过”不等于原生 RKP 成功。TrickyStore 注入的 Samsung 2018 keybox 已出现 REVOKED/KEY_COMPROMISE；KeyAttestation APK 痕迹只证明有人运行过检查，不证明本机 native identity 正确。不得导出或传播第三方 keybox 私钥。
- 官方 attestation status JSON 中出现 `REVOKED` 枚举字符串，不代表本机全部叶证书都被吊销。必须按具体 serial/status 映射，并查看 `revoked_or_suspended` 的实际内容。
- GMSCore 被禁用时，RKPD 的 `Network communication consent not provided` 是组件/许可/网络问题，不等于设备不支持 RKP 或身份错误。最终 host-side 软件签发不依赖手机 GMSCore；不要因此改 TA/seed。

### 14.2 HAL、CSR 版本与 KeyMint 封装

- K70E IRPC v3 使用 `generateCertificateRequestV2` 和 CSRv3，不是 v1/v2 legacy EEK + ProtectedData。旧 xaga/Nothing transaction number、wrapper 和 wire shape 不能硬套；先读 `getHardwareInfo`，版本不符即停。
- 当前 AuthenticatedRequest v1 的 top-level 第三槽是 DiceCertChain。不能把 legacy ProtectedData/COSE_Encrypt0 放进去；内部函数名 `build_protected_data` 不能代替实际 wire-format 审计。
- MacedPublicKey 的公钥和 32-byte MAC 绑定。历史上替换 X/Y 而保留 MAC 返回 service error 2；不能用 host 临时公钥伪装 native key，也不能把 MAC 本身叫身份。
- `private_key_blob=275` 是 opaque handle。逐窗口大小端扫描没有得到同轮 SPKI 闭环；改扩展名为 DER/PEM 不会把 handle 变成私钥。native per-key 路线若从 `EvpKeyToKeyMaterial` 导出，应解析完整 ECPrivateKey 并与同次 Maced 公钥比较；本题最终身份则是另一层的 `0xdd934` CDI leaf。

### 14.3 明确关闭的身份/侧信道路线

- `0xa7b88` 是 `GetEcdsa256KeyFromCert` 的 public X/Y 路径，不是私钥比较器；来自证书坐标的候选一律不能当 identity。
- FF06、cpu_fid、可打印映射、MAC、EEK X 坐标及其反转/换端序变体只因长度相似被尝试过，均无 active leaf 闭环，路线关闭。
- `testMode=true` 并不会自动暴露测试私钥；实测 remote exception -8 / service_error=6。相同固件上不要重复消耗状态。
- 旧 c186/HBP/ptrace 路线存在 HBP ctrl0、4-slot SETREGSET 和 secure-world 边界问题，最终已由 TA hook 取代，不再重跑。
- `/proc/mitee_log`、`/proc/mitee_log_key` 为只读侧，相关 dump caller 与目标私钥路径无交集。不要写 proc、提级日志或把调试日志当导出通道。
- normal-world 内存扫描未见明文，只能证明该样本/时刻/命名空间未见，不能外推 secure TA 从未持有 scalar。
- ECDSA nonce 恢复必须有重复 `r`；历史多份 CSR 未观察到重复 `r`。无重复即关闭，不做幻想式私钥恢复。
- 捕获器的轻量 native verifier 只做基本 shape、逐段签名、outer、challenge、zero-key 和 same-run leaf 门；固定 UDS、恰好五段、完整 claim profile 与 canonical DeviceInfo 由下一阶段 `rkp_sw.py load_verified_dice_chain()` 严格审计。不能只凭轻量 PASS 提交。

### 14.4 Fenrir、LK 和社区包低频坑

- 全 16 MiB `lk_a` SHA 与 Fenrir 发布文件不同时，先解析有效前缀。当前有效前 3,395,824 bytes SHA 为 `615d437f…bf19`；分区尾部填充可使 whole-partition SHA 不同。
- 旧版 duchamp/Fenrir 静态偏移、pattern 和 LTO/BOLT 布局不能套当前运行 binary。目标模式命中数不是恰好 1 或当前 hash 不同，就禁止 patch。
- 历史 LK 重建曾比容器大 80 bytes 后强行截成 16 MiB，导致尾部损坏。任何输出需要“最后截断修尺寸”都应直接废弃。
- Fenrir 仓库 `flash.sh` 会写或擦 `expdb`；现有 expdb 是关键运行证据，禁止直接跑仓库脚本。只使用手工、单目标、已审计命令。
- 社区 DyperOS 包是混合工程 preloader/Fenrir LK/global AVB 指纹，缺独立 anti-version/scatter/完整签名链。“ZIP hash 对”不证明 anti-rollback 兼容或设备正在运行它。
- 社区 `tee.img/gz.img` whole-file hash 不同，可能只是相同有效 payload 的封装/截断差异。只有解析有效内容和指令 diff 后才能声称存在认证旁路。
- Fenrir 只解决前级启动/镜像放行，不自动产生 RKP 身份，也不自动旁路 MiTEE TA 认证。必须分清三层：BL、TEE 内 loader、TA 内捕获逻辑。
- 旧 xaga `bad_io_uring` 硬编码 Linux 5.10.66 的 `task_struct` 偏移和 34,104-byte ELF；K70E 为 6.1.138、LTO/BOLT、USER_NS disabled，布局不同。仅恢复 symbols/BTF 不代表 CVE 可用；未经重新确认不得 push/执行。
- OTA、跨区 ROM、降级和 clean-all 会改变测量态、leaf、slot 或 anti-rollback；结题后没有必要，统一停止。

### 14.5 exact-frame 数字级陷阱

- 旧 v1 全量重压把 stock LZ4 BD 语义从 `0x40` 改成 `0x70`，69 个 64 KiB blocks 变成 2 blocks，loader 报 `bad lz4 flag`。最终必须保留 BD、69-block 表和所有非目标 descriptor。
- 旧 v4 frame 在 `0x3e0573` 提前结束；stock 终点是 `0x3e076c`，frame 后五条目含 cert1/cert2/spmc_dtb 被零化。post-frame tail 任一字节不同都不能刷。
- block 14 canonical 重压曾得到 38,740 bytes，但 stock descriptor 要求 38,783 bytes。最终用等价 LZ4 token 变换把 47-byte match 改成 4-byte match，并把 43 bytes 移入下一 literal，精确维持 38,783；不能用不明 padding。
- AArch64 指令从 `80 01 00 34` 变为 `0c 00 00 14`，是完整 4-byte 指令替换；逐字节只有 3 个位置改变，因为第三字节原本和现在都是 `00`。不能据“3-byte diff”误判 patch 不完整。
- SProvider 精确门位于 ELF `0x343fc` / BootFS `0x0e93fc`；digest verifier/gate 位于 `0x34430/0x34438`，必须保持。目标原字节、路径或命中数不符即停。
- RSA 算法是 RSA-PSS SHA-256/MGF1-SHA256/salt32，不是 PKCS#1 v1.5；旧地址 `0x233c0` 是 SFS save，version checker 为 `0x22d98`。用错算法或地址得到的“验证失败”没有结论力。

### 14.6 TA ABI、hook 与内存布局细节

- `0x141400/0x141500` 历史上超出 stock RX PT_LOAD 末端 `0x141390`；文件里有字节不等于运行时映射。最终显式延 RX 到 `0x142000`，并要求无 W+X。
- scratch 位于 `0x164400..0x164430`，必须通过 RW `p_memsz` 从 `0x222f8` 扩到 `0x22430` 显式覆盖；“同一页可能顺带映射”不能作安全依据。
- AArch64 `x0..x17` 是 caller-saved，NZCV 也不能跨 BL 当持久状态。旧 v5 复用 `x8/x10` 和未重设 flags 会随机失败；每个 trampoline 必须做 live-register/NZCV 审计。
- 旧 `0x62358` cleanup hook 不是强制执行路径；97b7 版本只有 export hook、没有 capture hook。最终只认 `0xdd934` mandatory success point + `0xa3324` export + LR `0x61c7c` 闭环。
- export 必须同时要求成功状态、caller LR、RKP-only 调用、capacity>=32、marker 和 length。任何一门缺失，都可能污染普通 GenerateKey 或泄露错误数据。

### 14.7 init、模块与服务生命周期细节

- early-init 过早 bind 会被后续 `/vendor` mount 覆盖；post-fs-data 又太晚。最终 `on fs` 选择必须同时证明 vendor 已挂载、tee-supplicant 尚未首次 open。
- init `.rc` 中的 `${MAGISKTMP}` 不是普通 shell 环境变量；未定义会导致 action 不执行。最终使用固定 `/debug_ramdisk`，并离线做 init 语法检查。
- KernelSU/Magisk initrc 目录内备份文件若仍以 `.rc` 结尾也会被合并。禁用备份必须改为非 `.rc` 后缀，并扫描实际加载目录。
- module `disable` 不会覆盖独立 `/data/adb/post-fs-data.d/*` 和 `service.d/*` hook；必须分别检查可执行旧脚本。
- 早期模块曾在 post-fs-data 过早写自身 `disable`，导致 overlay 根本没建立。看到模块文件存在，不等于 TA 已生效。
- `tee-supplicant -d` 只是 daemon 选项，不是 disable-auth/debug-verify 开关；日志 `launch OK` 也不能替代 namespace + same-run 密码学证据。
- 重启 KeyMint/tee-supplicant 不保证 secure TA unload，还可能因 SELinux/组权限进入 restart loop。不要用服务重启代替受控整机启动。
- `adb reboot`、`reboot -p` 或 `svc power shutdown` 的 bootreason 仍可能是 reboot，不能证明真正 cold power cycle。最终正确性不依赖未经证明的冷断电假设。
- hash 门必须早于 ARM/ALLOW 消费；日志缺 `preconsume_tee_hash/size` 或 marker 已移动但无 `BIND_OK` 时，状态不可信，立即停。

### 14.8 BROM / SP Flash Tool V6 细节

- MT6897 hwcode `0x1203`、SLA/DAA/SBC 不能套旧 mtkclient、旧平台 generic bypass 或高通 EDL/firehose 教程。
- 每次 BROM reconnect/E3 都有 fresh challenge；SPFT auth response 不能跨重插/重启复用。先审核 XML，再消耗授权。
- Windows 路径使用 ASCII；V6 XML 要求 `conn_stage="2nd DA"`、`com_port_name=""`，child 顺序为 flash-xml/auth-file/cert-file，DA 由 flash.xml 的 `<dagent>` 提供，不能随意增加 `<da-file>`。
- 只用 Download Only，Auto Reboot off；flash list 必须恰好 `tee_a [1/1]`。出现 Format、Firmware Upgrade、write_efuse 或其他分区立即退出。
- 不能改名运行 `Auth.exe`；历史静态审计显示改名分支可能进入 `SPFlashToolV6.exe -b -i write_efuse.xml`。
- auth HTTP 成功、GUI 显示连接、shell pipeline exit 0 都不等于写入成功。完整状态机至少要有 A0→5F、enter DA、目标 1/1、100%、tool success、exit 0，之后还要 readback/hash。
- `grep/head` 等 pipeline 可能吞掉目标进程退出码；必须保存原始日志并直接检查目标 return code。
- 未签名/VMProtect 第三方救砖工具的网站型号列表和商业声明不构成 MT6897 成功证据。未经用户明确接受信任与 credits 成本，不运行、不上传设备唯一数据。

### 14.9 HTTP、response wrapper 与链排序边缘项

- EEK challenge 和 UUID request_id 必须 fresh；历史重放可能返回 403。每轮 fetch→build→sign 封闭执行，不能跨轮复用。
- HTTP 444 只表示服务拒绝/未注册类结果，不能单独定位到某一个字段；其他 4xx、429、5xx 也要分型。缺 raw body/status/headers 时不得对身份下确定根因。
- 合法 sign response 可能是 `[shared,[unique...]]`，也可能外包一层 `[[...]]`；严格 parser 只兼容已知两种形状，规范化链为 `unique + shared`。其他 shape 或 trailing CBOR 保存原文后失败，不猜。
- raw response 外层是 CBOR，链体可能是 concatenated DER，不是可直接给 OpenSSL 的单张 PEM。必须按 ASN.1 SEQUENCE 长度逐张全消费。
- server order 不自动等于 leaf-first。必须拒绝 duplicate DER/subject、多 leaf、missing issuer、cycle、disconnected，并从唯一 leaf 走到 self-signed root。
- “收到 1 条链”和“链含 4 张证书”是两个计数：一把软件 key → 一条 chain → 四张 cert。不能把四张证书写成签了四把 key。
- 证书 `notBefore` 可由 CA 回拨/取整；最终叶为 09-03、请求为 09-05 不否定同轮。同轮性以 fresh private/request/raw response/leaf SPKI 绑定为准。
- `certificates_issued_last_30_days_approx` 是滚动 30 天近似值；RKPD `google_count` 是客户端请求计数；历史 inventory 又是另一维度。三者不能互相换算。

### 14.10 文件、命令和临时目录边缘项

- request 必须 atomic write、fsync/rename、readback byte-exact 后才 POST；成功或 HTTPError raw response 都要先耐久保存再解析。存储失败即禁止联网。
- 输出目录若已存在必须拒绝，不能清空复用。失败目录也是 one-shot/HTTP 是否消费的证据，应 0600 保留。
- CSR stdout/stderr 分开保存；Base64 去纯空白后用严格模式解码，再做 CBOR EOF/shape 检查。宽松解码出“某些字节”不能通过。
- 远端 root 命令要把完整命令作为一个字符串做一次安全 quote；不要用 `shell=True` 拼多层引号，也不要让 awk braces 或 `$pid` 在主机展开。
- 设备临时目录使用随机 UUID 和固定 K70E 前缀，0700；finally 只能删除本次精确前缀。变量为空、目标为根或前缀不符时严禁 `rm -rf`。
- `cmd remote_provisioning certify/csr` 不是普通只读命令：certify 会分配 key，CSR/keygen 会改变 TEE/RKPD 状态。只有 help/list/dump 可按低风险只读处理；计划外调用视为并发污染。
- 小米 `oem get_token` 的 61-byte token 可随重启失效，原文不落盘。官方 API 登录成功不等于有 flash/unlock 权限；ahaFlash 40001、unlock 20031/30001 应分开解释。

---

## 15. 当前结论

本题已完成，设备已恢复 stock TEE 和 known-good init_boot。后续正常动作只有：只读复核、按比赛格式提交、保护秘密材料、保留原始证据。除非有新的明确比赛要求或现有提交包验证失败，否则不应再次进入动态刷写流程。

---

## 16. 2026-09-06 portable release 新增踩坑：另一台 K70E 必读

本节的优先级高于前文的粗略失败概括，并精确区分 keygen 前 safe-abort、两个受证据约束的幂等收尾模式和真正烧毁的轮次。另一台 K70E 必须先完整阅读文档 50，按六入口为该机新建 profile/run，并在项目根执行 `shasum -a 256 -c SHA256SUMS_PORTABLE.txt`。不要把这里的恢复说明理解为允许重放 keygen、重放 Google 请求或复用参考机秘密。

### 16.1 preflight boot 到 Binder latch 之间的重启漂移

**坑：** 捕获 preflight 在 boot A 验证 candidate TA/TEE/init、early-bind、自动回滚和服务后，如果设备在真正消费 Binder latch 前偷偷重启到 boot B，旧实现可能把 boot A 的验证套到 boot B 的 keygen。

**硬门：** portable wrapper 记录 preflight boot ID，在完整 same-run proper-DICE/profile 验证通过后、创建 latch 之前再次读取 `/proc/sys/kernel/random/boot_id`，必须仍完全相同。latch 随即耐久写入 `PROFILE_SHA256`、`RUN_ID`、`CAPTURE_BOOT_ID` 和 `REMOTE_STAGING_PATH`，后续 native verification、restore confirmation、provision preflight 和最终包全部交叉绑定这些值。

**处置：** latch 创建前发现 boot 漂移必须 safe-abort；不得忽略、重写 preflight 或只凭 `boot_completed=1` 继续。latch 已消费后状态不明则进入同轮 `--resume-cleanup` 证据判断，绝不能普通 capture 第二次 keygen。

### 16.2 底层 collector 的 `finally` 会过早删除远端 scalar

**坑：** 原 collector 自己管理随机 remote temp 目录，并在 `finally` 删除。如果 portable wrapper 只在底层返回后才做额外检查，主机可能在 canonical identity、同轮证明和目录元数据尚未 fsync 时失去远端唯一副本；崩溃或断电就既无法交付，也无法安全重做 keygen。

**硬门：** portable wrapper 必须预先创建精确 `/data/local/tmp/k70e_cdi_leaf_once_<32hex>` 目录、上传并验证固定 Binder client，然后把底层 mkdir/push/chmod/cleanup 行为收窄为对这一路径的验证与延迟收尾。不得直接运行底层 `capture_k70e_google_rkp_sw_identity_once.py` 代替 portable wrapper，也不得在重构时恢复其抢先清理语义。

**处置：** keygen latch 已消费而主机尚无可验证 scalar 时，宁可保留远端目录并报告 UNCONFIRMED，也不能先删再想办法恢复。

### 16.3 host duplicate 与 canonical identity 的崩溃窗口

**坑：** 底层首先产生 `private_key_blob_capture.bin`，最终 canonical 文件是 `identity/google_rkp_sw_cdi_leaf_p256_scalar.bin`。在 pull、校验、canonical 写入、生成 public SPKI 或删除 duplicate 的任一瞬间崩溃，可能只剩其中一个，或两个同时存在。手工删 duplicate、盲信 canonical、从别轮复制文件都会破坏可归因性。

**硬门：** `--resume-cleanup` 只接受本轮目录中的 regular non-symlink 文件；对 32-byte big-endian P-256 范围、同轮 CSR/challenge、CDI leaf SPKI 和 profile 全部重算。若只有 duplicate，它从该字节幂等重建 canonical、公钥与 identity verification；若两者都有，必须 byte-exact；最后 fsync 后才删除 duplicate，并再次证明不存在。

**处置：** 不要自行合并目录或删除任何一个候选。让 wrapper 决定可恢复性；不一致即失败并保留现场。

### 16.4 MacedPublicKey 不是 identity，而且是可选传输证据

`capture_maced_public_key.bin` 只用于辅助记录 Binder 传输结果。它不是 CDI_Leaf scalar，不是恢复 scalar 所需的秘密，也不是最终三件套的一部分。远端清理恢复时，wrapper 会尽力拉取；若它缺失，但 scalar→同轮 native leaf 的密码学闭环完整，恢复仍可成功。不得因为 maced 文件缺失而再次 keygen，更不能把 MAC、X/Y 或整个 MacedPublicKey 当 identity。

### 16.5 remote cleanup 的安全顺序和 fsync 不可倒置

正确顺序是：

1. 从 host canonical/duplicate 或 latch 绑定的精确远端目录取得 scalar；
2. 用同轮 CSR/challenge/profile 验证 scalar→CDI leaf SPKI；
3. 对 scalar、CSR、challenge、native verification、device preflight、summary 逐文件 fsync，并 fsync identity/capture/父目录；
4. 只删除正则精确匹配本轮随机前缀的 remote staging path，并从设备证明该路径不存在；
5. 耐久写入 profile/run/serial/path 绑定的 `remote_cleanup_status.json`；
6. 幂等完成 canonical/public/verification，核对后删除 host duplicate，再写最终 complete summary。

先删远端再 fsync 主机、用宽泛 `rm -rf /data/local/tmp/*`、凭 ADB 命令返回 0 就声称删除成功、或手工伪造 cleanup status 都是 P0。若主机没有一份已通过同轮验证且耐久的 identity，wrapper 必须延迟远端删除。`remote_cleanup_status.json` 不是装饰，后续 restore、RKP preflight 和 package 都必须按 hash/字段绑定它。

### 16.6 SUCCESS 截断与双副本 commit 窗口

RKP 成功收尾有两个 SUCCESS：capture-local host attempt 目录中的权威 `SUCCESS.json`，以及 provision 输出中的 `portable_issuance_success.json`。崩溃可能发生在权威副本写完之后、输出副本写入之前；也可能遇到预存、截断、篡改或两份字节不同的 marker。

规则是：输出副本存在但权威副本不存在，直接拒绝；权威副本存在时必须先做 schema、official URL、profile/run、attempt/network/summary hash、one-key/one-chain、strict audit、auditor/helper、device evidence 与 output evidence 全核对，然后输出副本只能安装 byte-identical 内容。两目录都要 fsync。只有 Google 结果本身已完整成功时，`--resume-finalize` 才能幂等补齐这个双副本窗口；绝不能从输出副本反向制造权威成功。

### 16.7 issuance output 路径绑定不是可忽略的元数据

真实 issuance attempt 会把 provision 的规范绝对路径及其父目录 `st_dev`/`st_ino` 写进 attempt、NETWORK 和 SUCCESS 证据。这样即使有人把成功前的半成品复制到另一目录，或通过更换挂载点/符号链接绕过“输出必须全新”，resume/package 也会失败。

因此不要在 attempt 后移动、重命名或复制 provision 目录，不要换 `--output-dir`，也不要先在临时盘运行再搬回。确需长期归档，应在完整 SUCCESS 和最终 package PASS 后复制最终包，而不是搬动仍需 finalize 的工作目录。

### 16.8 resume 证据不能把失败洗白

`--resume-cleanup` 只做本轮已消费 Binder keygen 后的 identity 耐久化、精确远端删除和 canonical 收尾；`--resume-finalize` 只对本轮**已经取得完整官方成功响应**的一 key/一 chain 结果重新严格审计并提交 SUCCESS。后者不访问设备、不联网、不生成 key；前者不调用 keygen。

以下都不能 resume 成功：HTTP/网络失败、缺少或截断 raw response、链不完整、没有 `NETWORK_STARTED.json`、profile/run/boot/path/output 绑定不一致、marker 被编辑、auditor/helper 哈希变化、私钥与 request/leaf 不匹配。不要创建缺失 marker、复制旧 SUCCESS、改 JSON 中的 `status`、删除设备 latch/host attempt，或把另一轮 response 拼入本轮。唯一不属于“烧毁”的普通重开情形，是 live Binder latch 明确 `ABSENT`、没有任何 host post-latch 证据且 wrapper 已分类 `PRE_KEYGEN_SAFE_ABORT`：保留失败目录，在同一仍有效 profile/run 下换全新 capture 输出叶即可；`ABSENT` 伴随 post-latch 证据必须视为 `UNKNOWN`。除此两个窄恢复窗口及这一 keygen 前 safe-abort 外，跨过一次性边界的失败必须保存证据并开新 profile/run。

### 16.9 包内 profile 自证与硬链接假独立

`TARGET_PROFILE.json` 位于候选包内，攻击者若能改包就能同时改它，所以它不能给自己授权。portable verify 必须恰好选择一个包外信任入口：打包前独立保存的 `--trusted-profile`，或经独立渠道记录的 `--expected-profile-sha256`。

把包内 profile 做一个 hard link 放到包外仍是同一 inode，不是独立信任锚；多链接文件也可能在核验窗口被另一名字修改。验证器对 profile 使用 no-follow regular-file 读取，拒绝包内路径、相同 device/inode 的硬链接和 `st_nlink != 1`。最稳妥做法是在打包前把 64 位 profile SHA 写入只读的外部记录，然后用 expected hash 验证；不要从候选包现算 hash 再声称“外部可信”。

### 16.10 同型号、同 ROM 名称仍可能是 `PORT_REQUIRED`

另一台也是 K70E/duchamp、fingerprint 看似相同、能 root 或能 fastboot 写入，都不证明 stock TA/TEE 与 Exact device reference 相同。OTA 小版本、区域包、卖家改机、有效 payload 与容器差异都可能改变 SProvider、TA ABI、测量态或 exact-frame 布局。

profile 只在目标自己的 stock TA/TEE size/SHA 和全部结构门精确命中时给出 `EXACT_REFERENCE_FAST_PATH`。任一不匹配就是 `PORT_REQUIRED`：停止写入，重新定位 TA/SProvider/boot 语义、生成独立版本化 reference/builder，并完成独立审计。修改 JSON classification、放宽 allowlist、复用旧 offset、照抄参考 candidate 或因“能启动”就跳过同轮 DICE 门，均不叫移植。

### 16.11 portable 验收数字的正确读法

2026-09-06 host golden runtime profile SHA-256 是 `2e39f1fabe0c660844296cbdf8542e666ce615f5df58a452db537f49b911d759`。同一 synthetic/replay 包用包外 trusted profile 和独立 expected profile SHA 两种锚分别得到 `PASS / 469 / 0`；这是当前代码快照的测试结果，不是固定检查数量合同。参考机冻结包仍由原验证器得到 `PASS / 51 / 0`，两者不能互相替代。

截至 2026-09-06 没有第二台实体 K70E 的完整前向闭环。portable release 的目标是让下一位 AI 依靠每机 profile、六入口和关系证据安全执行或精确停在 `PORT_REQUIRED`，不是承诺任意 K70E 都能直接刷参考镜像一次成功。


---

## 原始记录段 3 / Source section 3: 50_K70E_CTF_跨设备复现与移植手册_20260905.md

# K70E CTF 跨设备复现与移植手册

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **后续覆盖（2026-09-06 20:00）：**参考机 exact modified DICE + clean DeviceInfo 已获 `APPROVED`，但这不授权将参考机 UDS/scalar/私钥/证书复制给另一台 K70E。新机仍须有 target-owned identity 和 one-shot；最新移植口径见文档 66、69。

> CURRENT ROUTE OVERRIDE：本文主体是旧 patched TA/TEE 六入口路线，禁止作为新设备当前手册。另一台 K70E 必须先按文档 53 第 12 节和 Skill 的 stock-mitee-log-route.md 做目标专属 port。

> **2026-09-06 强制补丁：** 旧 portable profile 忽略三个 signed boot security 字段和五层 DICE 测量，可能把 patched 环境放进联网阶段。必须结合文档 52 使用 profile schema v3；只有 `approval_environment=ELIGIBLE` 且 `network_issuance_allowed=true` 才能联网，最终链还必须 `ctf_no_not_approved=true`。旧冻结包不是成功参考答案。

> 适用对象：没有历史聊天、第一次接手本工作区的 AI 或人工操作者  
> 目标设备：另一台 Redmi K70E / `duchamp`  
> 文档日期：2026-09-05（Asia/Taipei）  
> 最后一致性修订：2026-09-06（portable profile v3 / stock approval gate / Provisioning Info 硬门）  
> 目标：在不复用原机秘密和设备身份的前提下，为新目标机重新取得本题三件套，并留下可独立审计的证据  
> 硬边界：尽量避免不可恢复变砖；不把“完成 CTF”理解为可以跳过哈希、恢复和密码学门禁

---

## 0. 零上下文接手时先读这里

本文件解决的是“换另一台 K70E 后怎样重新完成题目”。原机已完成的提交包只能作为格式和审计参考，不能当成新设备的答案，也不能把其中任何私密材料复制给新设备。

### 0.1 本题的严格交付物

新目标机必须重新产生并证明下列三项：

1. 该目标机 `google-rkp-sw` 身份：活动 proper-DICE 路径派生后的 32-byte big-endian P-256 `CDI_Leaf` 私钥标量，以及同轮 native zero-key AuthenticatedRequest、UDS、完整 DICE 链和受签名保护的 DeviceInfo；
2. 一次新的 `google-rkp-sw` 软件运行中生成的一把 P-256 私钥；
3. Google 在同一次软件运行中为第 2 项公钥返回的证书链。

必须同时证明：

```text
目标机同轮 native zero-key CSR 的最终 DICE leaf 公钥
    == 目标机现场捕获标量直接派生的 P-256 公钥
    == fresh software request 的身份签名公钥

本次 google-rkp-sw 新生成的 KeysToSign 公钥
    == 本次保存的 PKCS#8 私钥公钥
    == 本次 Google 返回链的叶证书公钥
```

以下都不是替代品：raw CDI、历史 leaf、opaque KeyBlob、MacedPublicKey、native 每把 RKP key 的 scalar、原机身份、旧软件私钥、旧证书链、缓存响应或本地自签链。

### 0.2 文档阅读顺序与证据优先级

先按顺序阅读：

1. 项目根 `README_给其他AI的唯一入口_20260829.md` 和本文件；
2. `00_文档/45_K70E_CTF_最终完整流水线记录_20260905.md`；
3. `00_文档/47_K70E_CTF_最终踩坑与故障树_20260905.md`；
4. 涉及动态设备操作时，再读 `00_文档/46_K70E_CTF_傻瓜式复现教程_20260905.md`；
5. 需要理解原机 Fenrir/SProvider 证据时读 `00_文档/44_K70E_Fenrir实锤与SProvider最小补丁_20260905.md`；
6. 结果语义和限制读 `00_文档/48_K70E_CTF_最终结题报告_20260905.md`；
7. Skill 使用读 `00_文档/49_K70E_CTF_Skill交付与使用说明_20260905.md`，可移交 Skill 源码在 `05_Skill/k70e-rkp-ctf/`；
8. 发布验收事实读 `00_文档/51_K70E_CTF_可移植发布验收记录_20260906.md`；
9. `00_文档/42_K70E_项目交接与踩坑记录_20260903.md` 只作时间线参考；其 2026-09-05 最终补充和 44–51 优先于早期“Fenrir 不可用/不要再碰 TEE”等旧判断。

首次接手先在项目根验证 `SHA256SUMS_PORTABLE.txt` 和 `SHA256SUMS_HANDOFF.txt`。前者固定可执行链，后者固定入口文档、45–51、portable 清单和项目内 Skill 导出。

发生冲突时：

```text
新目标机本轮原始证据与目标专属验证报告
  > 本文件的跨设备规则
  > 原机冻结提交证据与文档 45–49
  > 文档 42/44 的最终补充
  > 更早的探索性结论
```

### 0.3 原机冻结包绝对不改

原机冻结包：

```text
<DEVICE_WORKSPACE>/03_提取结果/
K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/
```

它包含原机私密身份和软件私钥。不得修改、合并、覆盖、抽取秘密给新设备、提交 Git、公开上传或拿它做新设备输出目录。新目标机必须使用全新目录、全新 manifest、全新 challenge、全新 one-shot namespace/token/latch、全新身份、全新软件私钥和全新 Google 响应。

---

## 1. 可移植性承诺：三条路径，不作虚假保证

“另一台 K70E”不等于“所有二进制布局都相同”。先分类，再执行。

### 1.1 路径 P1：参考固件完全匹配的快速路径

只有以下核心条件全部通过，才允许复用参考 TA/TEE 候选的字节：

- `ro.product.device=duchamp`；
- 活动槽和脚本一致；当前已审计实现只覆盖 `_a`；
- 目标机干净 stock KeyMint TA 大小、SHA-256 与参考值完全一致；
- 目标机 stock `tee_a` 大小、SHA-256 与参考值完全一致；
- BootFS、SProvider、LZ4 frame 和 TA ELF 的结构检查也一致，不能只信文件名或版本号；
- 目标机自己的 baseline zero-key CSR 已建立自己的 UDS/DICE profile；
- 已证明存在可写的 Fastboot 和 Fenrir/等价 TEE 放行链，且 portable profile v3 固定的 `/debug_ramdisk/magisk su -c` 可重复返回 root；注意该放行链会改变 DICE 1/2/4，不能授权联网；
- 目标机自己的 stock TEE 与 known-good init_boot 恢复件已备份并校验；
- 为目标机重新构建 early-bind init_boot 和捕获/签发配置，绝不复用原机 one-shot 状态。

即使 P1 通过，也只能复用不含设备秘密的静态 TA/TEE 补丁。序列号、UDS、DeviceInfo、identity、init_boot 状态机、latch、challenge、软件私钥和证书仍必须现场生成。

### 1.2 路径 P2：同型号但布局或固件不同的语义移植路径

任一关键哈希或结构不同就进入 P2。不得关闭 hash check、篡改常量“让脚本跑过”，也不得把参考 offset 硬套到新二进制。

P2 必须重新完成：

- 从目标 stock TA 重新定位活动 ES256 DICE `CDI_Leaf` 派生完成点；
- 从目标 stock TA 重新定位 `GenerateRkpKey` 成功返回对象和安全导出点；
- 重新选择合法 code cave/BSS，证明 ABI、寄存器、内存段和并发语义；
- 从目标 stock TEE 重新解析 BootFS，定位 SProvider RSA verifier/result gate 和后续 digest verifier/gate；
- 从目标自己的 working Magisk init_boot 重建 `on fs` early-bind、一次性触发和 stock TEE 自动恢复；
- 从目标 baseline CSR 生成目标专属 UDS/DICE profile，并让 `rkp_sw.py` 严格钉死该 profile；
- 生成目标专属 capture、preflight、verify 报告。

只有“语义等价 + 结构自洽 + host-only 全门通过”后才能进入动态阶段。

### 1.3 路径 P0：无可写 Fastboot/root/Fenrir 的前置阻塞路径

出现以下任一情况，CTF 主流水线尚不能开始：

- 只有 Fastboot UI，但没有证据证明目标分区可写；
- 没有 root，无法可靠备份/核验活动 `tee`、`init_boot`、LK 和 tee-supplicant namespace；
- 没有能放行修改 TEE 子镜像的 Fenrir/等价启动链；
- 无目标固件精确 stock 恢复件；
- 活动槽、anti-rollback 或分区布局不明；
- 人不在设备旁或无法进入物理 Fastboot/BROM 恢复。

本工作区证明了原机上的一种可行链路，但不保证能为任意未解锁 K70E 自动获得写权限，也不把混合社区刷机包当作普适解锁器。P0 必须先单独解决“能力取得和恢复验证”；未解决前禁止用写 `tee` 或 `preloader` 来“测试”。

### 1.4 决策树

```text
新 K70E
  |
  +-- 无法证明 root + 可写 Fastboot + Fenrir/等价 TEE 放行？
  |      `-- P0：停止 CTF 动态链，先解决前置能力
  |
  +-- stock TA/TEE/结构与参考全部字节级匹配？
  |      +-- 是：P1，复用静态 TA/TEE，重建目标专属其余部分
  |      `-- 否：P2，按语义重新移植 TA/TEE/init/capture/provision
  |
  `-- P1/P2 host gate 全 PASS + 现场恢复就绪？
         +-- 否：停止，不刷
         `-- 是：attended deployment -> capture -> 先恢复 -> host provision
```

---

## 2. 哪些东西可复用：四级数据分类矩阵

| 对象 | 分类 | 新设备处理 | 允许直接复制吗 |
|---|---|---|---|
| 题目语义、证据关系、验证算法 | 可复用 | 原样采用 | 是 |
| P-256 阶、COSE/DICE/CBOR/DER 规范 | 可复用 | 原样采用 | 是 |
| Binder keygen client 的审计二进制 | 可复用工具 | 先核大小/哈希，再使用 | 条件允许 |
| 参考构建器的算法与 fail-closed 顺序 | 可复用设计 | 参数化并重新审计 | 是，不能跳门 |
| stock TA/TEE 的 offset、指令和压缩布局 | 每固件 | 只有输入哈希和结构全同才复用，否则重定位 | 否，除非 P1 |
| patched TA/TEE 候选 | 每固件 | P1 可复用；P2 必须重建 | 条件允许 |
| stock/known-good init_boot | 每固件/安装状态 | 从目标自己备份或精确 OTA 重建 | 否 |
| early-bind init_boot | 每固件 + 每轮 | 用目标源镜像、目标哈希和新状态机重建 | 否 |
| build fingerprint、patch level、DeviceInfo 稳定字段 | 每固件/设备 | 从目标本轮 signed source 及系统只读信息生成 | 否 |
| ADB/Fastboot serial | 每设备 | 现场发现并固定 | 否 |
| UDS 公钥/SPKI hash | 每设备身份 | 从该设备 stock baseline CSR 提取并钉死 | 否；即使碰巧相同也须独立证明 |
| DICE 固定 descriptor/authority profile | 每固件/设备族 | 从目标 baseline 生成，逐字段审计 | 不假设 |
| CDI_Leaf、公钥和 scalar | 每启动测量/每轮 | 实验启动现场捕获并同轮验真 | 绝对不复用 |
| native challenge/AuthenticatedRequest/DeviceInfo | 每轮 | 本轮随机生成和保存 | 否 |
| one-shot namespace/token/early-bind latch/log | 每轮 | 使用不可与历史冲突的新标识 | 否 |
| 设备端 Binder keygen 持久闩锁 | 每 profile/run | 在唯一 keygen 前原子创建，精确写入 profile/run/capture boot/remote staging path，恢复确认时重验 | 否；不得删除重放 |
| 设备端 Google issuance 持久闩锁 | 每 profile/run | 所有纯主机门通过后、真实联网前在恢复后设备上原子创建 | 否；不得删除重放 |
| 主机签发 attempt/network/success 标记 | 每 profile/run | 真实签发前保留；绑定规范 output path 及其父目录 device/inode | 否；换 output-dir 不能重试；只有完整一把链已落盘时可用 `--resume-finalize` 修复 SUCCESS 提交 |
| 软件私钥、请求、Google challenge/响应/证书链 | 每次签发 | 新运行生成 | 绝对不复用 |
| 原机冻结提交包 | 原机敏感证据 | 只读格式参考 | 绝对不作为新答案 |

判断原则：任何含“目标机是谁、目标机当前测量是什么、这一轮是否已消费、服务器为哪把 key 签发”的数据都不能跨设备或跨轮复制。

---

## 3. 参考实现坐标、哈希与明确的禁止复用项

以下值用于识别参考固件和验证 P1，不是把原机身份移植到新手机的参数。

### 3.1 参考 stock 和静态候选

| 对象 | 工作区路径 | 大小 | SHA-256 |
|---|---|---:|---|
| 参考 stock KeyMint TA | `<DEVICE_WORKSPACE>/01_设备输入/duchamp_Mitee_TA与KeyMint用户态_20260828/ta/dba51a17-0563-11e7-93b16fa7b0071a51.ta` | 1,401,936 | `facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32` |
| 参考 stock `tee_a` | `设备备份_只读_20260831_preflash/tee_a.bin` | 5,242,880 | `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d` |
| 参考 working Magisk init_boot | `out/k70e_v6_prebind/init_boot_a_backup_20260901.img` | 8,388,608 | `9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4` |
| 参考 CDI_Leaf capture TA | `out/k70e_cdi_leaf_identity_capture_hostonly/dba51a17-0563-11e7-93b16fa7b0071a51.cdi_leaf_identity_capture.ta` | 1,401,936 | `7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48` |
| 参考 exact-frame candidate TEE | `out/k70e_sprovider_rsa_bypass_exactframe_hostonly/tee_a_sprovider_rsa_bypass_exactframe.img` | 5,242,880 | `3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da` |
| 参考 one-shot init_boot | `out/k70e_cdi_leaf_earlybind_initboot_hostonly/init_boot_a_cdi_leaf_identity_capture_one_shot.img` | 8,388,608 | `5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517` |

参考 TA/TEE 候选不嵌入原机 CDI/UDS 私密字节；它们在运行时捕获当前设备、当前测量派生的值。因此 P1 可以复用这两个静态二进制。参考 one-shot init_boot 则嵌入原轮 state/token/latch/hash 路径，新设备必须重建，不能直接刷。

### 3.2 核心脚本的当前哈希

| 脚本 | SHA-256 | 跨设备用途 |
|---|---|---|
| `02_脚本与补丁/build_k70e_cdi_leaf_identity_capture_hostonly.py` | `925a97d0b7185c325dc8468184db814b138525ee0d58af58841ff17abdee3714` | P1 参考构建；P2 语义移植模板 |
| `02_脚本与补丁/build_k70e_sprovider_rsa_bypass_exactframe_hostonly.py` | `4a8ed588c677658026027803f4e7b54bd8ec8c8f41b0031cda111f1cd9e587d8` | P1 参考构建；P2 exact-frame 模板 |
| `02_脚本与补丁/build_k70e_cdi_leaf_earlybind_initboot_hostonly.py` | `83519e9ece1144eac636ab82c36c68c5bad6681efab110666a65442ecb006726` | 只作参考；硬编码原轮状态，须目标化 |
| `02_脚本与补丁/build_k70e_scalar_final_earlybind_initboot_hostonly.py` | `dee8bb00431a2995ee65ed45288742f1ffc176910e1eb03e2054000024a1dac6` | early-bind 基础模板，须目标化 |
| `02_脚本与补丁/preflight_k70e_cdi_leaf_deployment_hostonly.py` | `d0d5516ffc25a961428b5d98786b20d7f7928b69cd9b5ab0a2b1883cb64d3bd2` | 只验证原参考 pairing；新目标需专属 preflight |
| `02_脚本与补丁/capture_k70e_google_rkp_sw_identity_once.py` | `a5ad5158190a53e133b71b3f0eff8ed3a966acd3dfdd739014d4287e4679ce72` | 原机捕获器；硬编码 serial/state/hash，不可原样运行 |
| `02_脚本与补丁/rkp_binder_keygen_client_arm64` | `79dc5f2bd523e5c35a77f34c46bbb345c22e7b79c245e2eee4b5bef0fbcb1cef` | 可复用审计 client；大小必须为 51,280 |
| `third_party/google-rkp-sw/rkp_sw.py` | `54e886ce80cfbdfa88e76cad075bad0e5ac949eb9ea5ec1246553bc673271401` | 逻辑基线；硬钉原机 UDS/profile，须目标化 |

每次目标化后必须重新记录脚本 SHA-256，并把运行时真正使用的脚本快照放进新提交包。不能继续引用上表哈希冒充目标版。

### 3.3 原机专属值：只用于侦测误复用

以下值在新目标 manifest、命令或 output 中出现时默认判定为错误，除非它只是“reference denylist”字段：

```text
原机 serial:
  <DEVICE_SERIAL>

原机观测到的 UDS SPKI SHA-256:
  d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9

原机 state dir:
  /metadata/watchdog/k70e_cdi_leaf_identity

原机 token:
  K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT

原机 latch:
  /metadata/watchdog/k70e_cdi_leaf_identity/once_7ea5948e
```

新设备若现场独立导出的 UDS hash 恰好相同，只能记录为“目标 baseline 实测相同”，仍不得把原机常量直接抄入。原机 scalar、PKCS#8 内容和任何私钥原文在本文件中不记录，也不得打印。

### 3.4 Fenrir 参考资产不是自动刷机方案

工作区的社区候选：

```text
刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate_extract/images/lk.bin
size=3,395,824
sha256=615d437f33fb9addea9b9bd56d8fbd5a8d17bc35b13546815a673248a8e0bf19

刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate.zip
sha256=4ac1fcb60ad845177308a56ded891203c33d4a4e852c112b2dc8714e541a244e
```

文档 44 证明原机运行 `lk_a` 的有效前缀与该 Fenrir LK 匹配。这不证明另一台 K70E 可以安全整包刷入。该包混有工程/启动链相关组件；不得默认写 `preloader`，不得 wholesale flash，不得忽略 anti-rollback、DRAM/PMIC/区域/固件兼容性。P0 下先做独立启动链审计和恢复演练，本手册不保证这一前置问题可自动解决。

### 3.5 已交付的跨设备自动化入口

下列六个入口是本文的可执行实现。必须使用工作区虚拟环境；系统 `/usr/bin/python3` 缺少本流程所需的 `cbor2` 等依赖，不能作为 portable 命令解释器。不要再通过手改原捕获器常量来换机：

| 入口 | 作用 | 网络/设备边界 |
|---|---|---|
| `02_脚本与补丁/k70e_portable_profile.py` | 严格验证目标 baseline zero-key CSR，提取目标 UDS/DICE/DeviceInfo，绑定 stock 备份并分类 P1/`PORT_REQUIRED` | 主机离线 |
| `02_脚本与补丁/build_k70e_portable_batch.py` | 从目标自己的 working Magisk init_boot 生成新 run-id/state/token/latch 的批次 | 主机离线；仅 P1/`_a` |
| `02_脚本与补丁/capture_k70e_identity_portable.py` | 读取 runtime profile，在唯一 keygen **之前**完成 UDS + 5 DICE + claims + canonical CBOR + outer + DeviceInfo 全门 | 访问已就绪目标；不联网、不刷机 |
| `02_脚本与补丁/confirm_k70e_portable_restore.py` | 身份保存后，在另一次干净启动上只读证明 stock TEE、known-good init、双 namespace stock TA、服务及 Binder 闩锁 | 访问已恢复目标；只读、不联网、不刷机 |
| `02_脚本与补丁/rkp_sw_portable.py` | 在内存中应用目标 UDS/profile；先离线预检；真实签发前在已恢复设备写持久 issuance latch，再恰好签发一把软件密钥 | preflight 纯主机；实际 provision 需恢复后设备 ADB/root 在线并联网，但不写分区/服务 |
| `02_脚本与补丁/package_verify_k70e_portable.py` | 生成新机三件套+证据+清单，不预知新私钥/证书哈希地重算所有关系 | 主机离线 |

项目根目录现已提供发布一致性清单 `SHA256SUMS_PORTABLE.txt`。在读 profile、调 builder 或连设备之前，必须从项目根目录先完整校验；任一项失败都停止，不只校六个 wrapper：

```bash
PROJECT='<workspace>/<DEVICE_WORKSPACE>'
(cd "$PROJECT" && shasum -a 256 -c SHA256SUMS_PORTABLE.txt)
```

根清单是本次发布的完整性记录，不取代 profile 内的独立 toolchain allowlist，也不取代带外 profile hash。校验 PASS 后，每个 run 仍要把这份清单复制到自己的 `00_manifest/`，并现场记录本轮真正调用的六入口哈希：

```bash
S="$PROJECT/02_脚本与补丁"
test ! -e '<run>/00_manifest/SHA256SUMS_PORTABLE.release.txt'
install -m 0600 "$PROJECT/SHA256SUMS_PORTABLE.txt" \
  '<run>/00_manifest/SHA256SUMS_PORTABLE.release.txt'
test ! -e '<run>/00_manifest/portable_entrypoints.actual.sha256'
shasum -a 256 \
  "$S/k70e_portable_profile.py" \
  "$S/build_k70e_portable_batch.py" \
  "$S/capture_k70e_identity_portable.py" \
  "$S/confirm_k70e_portable_restore.py" \
  "$S/rkp_sw_portable.py" \
  "$S/package_verify_k70e_portable.py" \
  > '<run>/00_manifest/portable_entrypoints.actual.sha256'
```

动态阶段结束后对同六文件再计算一次并与本轮 `portable_entrypoints.actual.sha256` 比较；任一入口在不可逆点前已变化则先停止并重建新轮，不可逆点后发现变化则保留全部证据，且只能按第 13.9/15.5 节的窄恢复条件判定，不得直接重做 keygen 或联网签发。

`device_reference_id=duchamp-cn304-mitee-exactframe-v1` 与 `toolchain.allowlist.id=k70e-portable-macos-host-20260906-v2` **独立版本化**：前者钉 stock/candidate TA、TEE、sidecar、大小和 Exact 边界；后者钉含 Provisioning Info 硬门的新 `rkp_sw.py`、keygen、ADB、init/capture/restore builder、`lz4` 等主机工具。更新主机工具 allowlist 不得暗改设备参考，新增固件参考也不得默许任意工具。

实际命令骨架如下。`<...>` 必须换成当前目标事实。只预建父目录，`PROFILE`/同名 `.conf`、`BUILD`、`CAPTURE`、`restore_confirmation.json`、`portable_provision_preflight.json`、`PROVISION`、`BUNDLE` 这些输出叶节点在各自首次调用前必须完全不存在且不是 symlink：

```bash
set -euo pipefail
umask 077
PY='<workspace>/third_party/google-rkp-sw/.venv/bin/python'
S='<workspace>/<DEVICE_WORKSPACE>/02_脚本与补丁'
RUN='<run>'
PROFILE="$RUN/04_target_profile/target_profile.json"
BUILD="$RUN/05_build/batch_<new-id>"
RUNTIME_PROFILE="$BUILD/runtime_profile.json"
CAPTURE="$RUN/08_capture/capture_<new-id>"
PROVISION="$RUN/10_provision/provision_<new-id>"
BUNDLE="$RUN/11_submission/bundle_<new-id>"
ADB='<audited-absolute-path-to-adb>'
SERIAL="<new-target-serial>"
FINGERPRINT="$("$ADB" -s "$SERIAL" shell getprop ro.build.fingerprint | tr -d '\n')"
test -n "$FINGERPRINT"
test "$("$ADB" -s "$SERIAL" shell getprop ro.product.device | tr -d '\n')" = 'duchamp'

mkdir -p "$RUN/00_manifest" "$RUN/04_target_profile" "$RUN/05_build" \
  "$RUN/08_capture" "$RUN/10_provision" "$RUN/11_submission"
for NEW_LEAF in "$PROFILE" "${PROFILE%.json}.conf" "$BUILD" "$CAPTURE" "$PROVISION" "$BUNDLE"; do
  test ! -e "$NEW_LEAF" && test ! -L "$NEW_LEAF"
done

"$PY" "$S/k70e_portable_profile.py" create \
  --serial "$SERIAL" \
  --fingerprint "$FINGERPRINT" \
  --baseline-csr "$RUN/03_baseline_csr/authenticated_request.cbor" \
  --baseline-challenge "$RUN/03_baseline_csr/challenge.bin" \
  --stock-ta "$RUN/02_stock_backup/stock_keymint.ta" \
  --stock-tee "$RUN/02_stock_backup/tee_a.stock.img" \
  --source-init-boot "$RUN/02_stock_backup/init_boot_a.known_good_magisk.img" \
  --adb "$ADB" \
  --magisk-path '/debug_ramdisk/magisk' \
  --output "$PROFILE"

"$PY" "$S/k70e_portable_profile.py" check --profile "$PROFILE"
"$PY" "$S/build_k70e_portable_batch.py" --profile "$PROFILE" --outdir "$BUILD"
"$PY" "$S/k70e_portable_profile.py" check --profile "$RUNTIME_PROFILE"

# 下一条只能在第 13 节的候选启动、自动恢复和动态门全 PASS 后运行。
"$PY" "$S/capture_k70e_identity_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --output-dir "$CAPTURE"

# 身份落盘后，先把手机恢复为 stock tee_a + profile 中的 known-good source init_boot，
# 正常重启到与 capture 不同的 boot；第 14 节的只读确认必须在 preflight 前生成默认文件。
test ! -e "$CAPTURE/restore_confirmation.json" && test ! -L "$CAPTURE/restore_confirmation.json"
"$PY" "$S/confirm_k70e_portable_restore.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE"

# 只有 restore_confirmation.json PASS 才运行纯主机预检。
test ! -e "$CAPTURE/portable_provision_preflight.json" && test ! -L "$CAPTURE/portable_provision_preflight.json"
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --preflight-only

# 只有上一条 PASS 才许一次实际联网运行。
test ! -e "$PROVISION" && test ! -L "$PROVISION"
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --output-dir "$PROVISION"

test ! -e "$BUNDLE" && test ! -L "$BUNDLE"
"$PY" "$S/package_verify_k70e_portable.py" package \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --provision-dir "$PROVISION" \
  --output-dir "$BUNDLE"

"$PY" "$S/package_verify_k70e_portable.py" verify \
  --bundle "$BUNDLE" \
  --trusted-profile "$RUNTIME_PROFILE"
```

`--adb` 必须指向与当前 `toolchain.allowlist` 的 size/SHA 完全一致、已受审的 ADB。当前 allowlist 记录的是原主机 `<HOST_SDK>/platform-tools/adb`，size `19,993,936`，SHA-256 `9fdf861259dc807937b13afdd5f053c7fda9f3b7726933fe0e0f45130ecb8dc7`；路径本身可不同，但内容必须命中。另一台主机或不同 SDK 版本不匹配时，应换入受审版本或发布新的独立 allowlist，不能绕过门。profile v3 同样固定 `_a` 分区布局和 `/debug_ramdisk/magisk`；传别的 `--magisk-path` 会拒绝，其他 root 布局须发布并审计新的 portable 版本。

`k70e_portable_profile.py` 只以目标 stock TA/TEE 的 size/SHA 决定 Exact 设备参考；目标 fingerprint 是从该设备现场读出的自身值，用来绑定后续 capture/restore，不要求等于原机 fingerprint。任一 stock TA/TEE 不同即只生成 `PORT_REQUIRED`；slot、Magisk 路径、toolchain 或结构门不受支持则安全中止，不能把它伪装为 Exact。P2 必须完成第 11 节语义移植，再为新固件和布局增加经独立审计、独立版本化的 device reference/builder/profile 支持；禁止修改 `ready_for_automated_build` 强行过门。

最终 golden host replay 的 runtime profile SHA-256 为 `2e39f1fabe0c660844296cbdf8542e666ce615f5df58a452db537f49b911d759`。对同一份关系型 bundle，外部 `--trusted-profile` 和带外 `--expected-profile-sha256` 两种信任锚验证都得到 `status=PASS`、`passed_checks=469`、`failed_checks=0`。这证明 profile、strict CSR/scalar、构建、capture 恢复完成、offline issuance finalize、稳定快照打包和外部信任锚路径在主机证据上可重放。

`469` 只是该次 golden 运行的观测值，**不是合同常量**；验证器增减检查后数字可以变，完成口径仍是当前入口/清单全命中且实时 `status=PASS`、`failed_checks=0`。该 host replay 也没有替代第二台实体 K70E 的完整前向实测；截至本文修订，第二台实体机尚未跑完写入、捕获、恢复、联网签发和打包闭环。

---

## 4. 每台目标机都要建立独立运行目录

不要在 `out/k70e_*` 参考目录或原机 `03_提取结果` 内覆盖文件。建议：

```text
<DEVICE_WORKSPACE>/03_提取结果/
K70E_PORT_<UTC时间>_<随机8位>/
├── 00_manifest/
├── 01_onboarding/
├── 02_stock_backup/
├── 03_baseline_csr/
├── 04_target_profile/
├── 05_build/
├── 06_host_preflight/
├── 07_deployment_logs/
├── 08_capture/
├── 09_restore_logs/
├── 10_provision/
└── 11_submission/
```

创建时 `umask 077`，目录 0700，文件 0600。目录名使用时间和随机标识，不必公开 serial。上述只表示允许预建的父容器：profile JSON/同名 `.conf`、build/capture/provision/bundle 的具体输出叶节点，以及 capture 内的 `restore_confirmation.json`、`portable_provision_preflight.json` 都必须由相应入口首次创建；调用前若已存在或是 symlink，立即停止。不要用空目录占位，也不要在已消费闩锁后另换 `--output-dir` 伪装成新尝试；唯一例外是正常 capture 在 Binder latch 精确 `ABSENT` 且主机无后闩锁证据时，可保留原失败目录并用新的不存在叶目录重试。

### 4.1 `target_manifest.json` 最少字段

```json
{
  "schema": "k70e-port-v2",
  "run_id": "<new random id>",
  "state": "S0_NEW",
  "target": {
    "serial": "<live discovered; never reference serial>",
    "product": "duchamp",
    "slot_suffix": "<live>",
    "build_fingerprint": "<live>",
    "root_entry": "/debug_ramdisk/magisk",
    "write_capability_evidence": "<path or null>",
    "fenrir_evidence": "<path or null>"
  },
  "stock": {
    "keymint_ta": {"path": "", "size": 0, "sha256": ""},
    "tee": {"path": "", "size": 0, "sha256": ""},
    "init_boot": {"path": "", "size": 0, "sha256": ""},
    "lk": {"path": "", "size": 0, "sha256": ""}
  },
  "baseline": {
    "challenge_sha256": "",
    "authenticated_request_sha256": "",
    "uds_spki_sha256": "",
    "dice_profile_sha256": ""
  },
  "route": "P0_BLOCKED|P1_EXACT|P2_SEMANTIC",
  "artifacts": {},
  "write_events": [],
  "capture": {
    "keygen_invocations": 0,
    "binder_keygen_latch": "<profile-derived persistent device path>",
    "status": "not_started"
  },
  "restore": {"status": "not_started", "confirmation_path": ""},
  "provision": {
    "status": "not_started",
    "device_issuance_latch": "<profile-derived persistent device path>",
    "attempt_marker": "",
    "network_started_marker": "",
    "success_marker": ""
  }
}
```

JSON 中不保存 scalar 或 PKCS#8 原文。秘密只以相对路径、大小、SHA-256 和公钥关系引用。

### 4.2 状态必须单向推进

```text
S0_NEW
 -> S1_INVENTORIED
 -> S2_STOCK_BACKED_UP
 -> S3_BASELINE_PROFILED
 -> S4_ROUTE_SELECTED
 -> S5_HOST_ARTIFACTS_PASS
 -> S6_UNARMED_INIT_PASS
 -> S7_EXPERIMENTAL_BOOT_PASS
 -> S8_IDENTITY_CAPTURED
 -> S9_DEVICE_RESTORED
 -> S9R_RESTORE_CONFIRMED
 -> S10_PROVISION_PREFLIGHT_PASS
 -> S10I_ISSUANCE_COMMITTED
 -> S11_SUBMISSION_VERIFIED
```

故障进入相应 `FAILED_*` 或 `BLOCKED_P0`，不要伪造跳转。`target_profile.json` 已存在本身**不是**“任何错误都烧毁”的分界；真正分界是设备/主机持久闩锁和网络事实。不可逆点前的参数、权限、空间、输出父目录或 host-only 验证失败，在证明闩锁未消费后可修正原因再执行。

本实现只定义两个不会再产生私钥/联网的窄恢复模式：

1. capture `--resume-cleanup`：仅用于 Binder 闩锁已是 `CONSUMED` 或状态曾一度不确定、需恢复已产生的同一份 identity 并完成远端清理的情况；该模式本身的 Binder keygen 调用数恒为 0。正常 capture 在点火前安全中止且严格判定设备 Binder latch=`ABSENT`、主机也无任何跨过闩锁的证据时，保留原失败目录，可使用新的不存在 output 叶目录重试正常 capture；`CONSUMED` 或 `UNKNOWN` 则绝对禁止再 keygen。
2. RKP `--resume-finalize`：仅用于 Google 返回的完整一把/一链输出已耐久落盘，且同轮 `attempt.json` + `NETWORK_STARTED.json` 完整存在，但严格审计或 SUCCESS 双副本提交被主机崩溃打断的情况。它绝不访问设备、绝不访问网络，不得用于 HTTP 非 200、网络中断、响应不完整或链验证失败。

两种模式都是对已发生事实的幂等完成，不是获得“第二次机会”。设备端 Binder/Google issuance 闩锁和主机 issuance attempt 目录一旦出现就永久保留，不得删除、重命名或复制旧证据来伪造重试。看到 `S8_IDENTITY_CAPTURED` 时不再重复 Binder keygen；看到 `S9R_RESTORE_CONFIRMED` 后不再刷机或触发 RKP，但第一次真实签发仍要求恢复后的设备在线以消费 issuance latch；看到 `S10I_ISSUANCE_COMMITTED` 后不因想“确认一下”重签一把。

---

## 5. P0 前置能力矩阵

| 现状 | 允许动作 | 禁止动作/结论 |
|---|---|---|
| write-capable Fastboot + Fenrir + Magisk root | 可进入 onboarding/P1/P2 | 仍须备份和 host gate |
| write-capable Fastboot + Fenrir，但无 root | 先从目标精确 stock init_boot 制作/验证 Magisk init_boot，取得 root 后再进入主线 | 没有精确 recovery 时不刷；不能用原机 init_boot |
| root，但 Fenrir/TEE 子镜像放行未知 | 只读备份和静态审计 | 不写 candidate TEE；普通 root 不等于 secure boot 放行 |
| Fastboot 界面可进，但写能力未知 | 读取 getvar、核查历史写入证据和 LK | 不用随机 flash 测试；`green/locked` 也不能单独定性 |
| 小米账号没有官方解锁资格，但已存在 Fenrir/可写链 | 以实测能力和 LK/写入证据为准 | 不因账号权限反复停工，也不因此跳过恢复门 |
| 无 root、无 write proof、无 Fenrir | 标记 `BLOCKED_P0` | 本工作区不能承诺自动解锁；禁止先刷 TEE/preloader |

`OEM unlocking` 开关、`ro.boot.flash.locked`、`verifiedbootstate` 和账户 UI 都只是属性，不是完整能力证明。原机 Fenrir 会表现为 `green/locked`；反过来，另一台显示相同属性也不证明已装 Fenrir。

活动槽若为 `_b`，现有脚本、恢复器和分区名都不适用。不能为了沿用命令而盲目写 `_a`。先把所有 slot、block path、init 脚本和恢复门目标化；在完成前按 P2 处理。

---

## 6. S1：目标机只读 onboarding

本阶段不写分区、不触发 native keygen、不联系 Google。允许读取属性和生成本地清单；即使需要在 `/data/local/tmp` 暂存备份，也不改启动分区。

### 6.1 固定工作区和现场 serial

示例只展示模式；`SERIAL` 必须从本机 `adb devices -l` 现场选择：

```bash
set -euo pipefail
umask 077
WORKSPACE='<PROJECT_ROOT>'
adb devices -l
SERIAL="<the new target serial>"
test "$SERIAL" != '<DEVICE_SERIAL>'
```

如果确实在审计原参考机，上述否定门可改为显式 `mode=reference_device`；跨设备任务默认必须拒绝原 serial。

以后每一条 ADB/Fastboot 命令都带 `-s "$SERIAL"`。先保存：

```bash
adb -s "$SERIAL" get-state
adb -s "$SERIAL" shell getprop ro.product.device
adb -s "$SERIAL" shell getprop ro.product.model
adb -s "$SERIAL" shell getprop ro.boot.slot_suffix
adb -s "$SERIAL" shell getprop ro.build.fingerprint
adb -s "$SERIAL" shell getprop ro.boot.verifiedbootstate
adb -s "$SERIAL" shell getprop ro.boot.flash.locked
adb -s "$SERIAL" shell getprop sys.boot_completed
adb -s "$SERIAL" shell getprop vendor.teefs_state
```

要求至少 `duchamp`、`boot_completed=1`，并把所有原始 stdout/stderr 写入 `01_onboarding/`。不要只在报告里手抄结果。

### 6.2 证明实际 root 入口

portable profile v3 有意把 root applet 固定为 `/debug_ramdisk/magisk`，并把该路径写入版本化 contract；自动路径只接受它。保存能重复返回 `uid=0` 和 SELinux context 的原始输出：

```bash
adb -s "$SERIAL" shell 'test -x /debug_ramdisk/magisk && /debug_ramdisk/magisk su -c id'
```

UI 中显示“已 root”不算。其他入口即使能证明设备一般意义上已有 root，也不满足当前 v3；不要只把 `--magisk-path` 改成别的值或删除检查，应为新布局发布并审计新的 profile/toolchain 版本。没有 v3 所需的可重复 root 命令就留在 P0/版本移植状态。

### 6.3 清除“看到的是 stock”的歧义

在 baseline 前检查：

- `/vendor/mitee/ta/<UUID>.ta` 的全局可见文件；
- `tee-supplicant` mount namespace 内同一路径；
- `/metadata/watchdog/` 下是否有旧 CTF state；
- Magisk 模块、`post-fs-data`、旧 preinit/overlay 是否仍在改 TA；
- 当前 `tee`/`init_boot`/LK 是否为已知状态。

不要删除未知状态来“清干净”；先完整备份、记录来源，再决定恢复到 stock。全局 `/vendor` 为 stock 而 tee-supplicant namespace 为 candidate，属于污染，不能做 baseline。

### 6.4 只读 Fastboot 信息

人在手机旁并且 Android 证据已保存后，可进入 Fastboot 读取：

```bash
adb -s "$SERIAL" reboot bootloader
fastboot -s "$SERIAL" devices
fastboot -s "$SERIAL" getvar product 2>&1
fastboot -s "$SERIAL" getvar current-slot 2>&1
fastboot -s "$SERIAL" getvar unlocked 2>&1
fastboot -s "$SERIAL" getvar all 2>&1
fastboot -s "$SERIAL" reboot
```

`getvar unlocked` 不是 Fenrir 下的最终真相；它只是一条证据。写能力应由已知成功写入的可信历史、运行 LK 鉴定和可恢复的启动链共同证明，不能用 candidate TEE 作为探针。

---

## 7. S2：目标 stock 备份与双端哈希

### 7.1 必备备份

每台目标至少保存：

```text
目标活动槽 stock tee 分区完整镜像
目标活动槽当前 working init_boot 完整镜像
目标精确官方 stock init_boot（若当前是 Magisk patched，二者都要）
目标活动槽 LK 完整镜像
目标干净 stock KeyMint TA
目标 boot/vbmeta/fingerprint/patch level/slot 属性快照
tee-supplicant namespace TA 哈希和全局 TA 哈希
分区大小、块路径和 by-name 映射
```

如果当前不是 stock，stock 恢复件必须来自与目标 build fingerprint 精确对应的官方包，并证明与设备期望版本/anti-rollback 相容；不能拿原机备份冒充。

`--source-init-boot` 的语义不是“任意能解析的 8 MiB 镜像”，而是该目标**当前已经开机验证过**的 known-good Magisk `init_boot_a`：

1. 它必须是目标自己的完整 8 MiB 分区转储，设备当前正由它启动；
2. 在该启动上，`/debug_ramdisk/magisk su -c id`、Android、TEE/KeyMint/RKP 服务均已验证健康；
3. 设备端分区 size/SHA 与 pull 后主机文件 size/SHA 必须一致；
4. 只有上述证据落盘后，才可把 `init_boot_a.current.img` 复制/重命名为 `init_boot_a.known_good_magisk.img` 并传给 profile；
5. 若当前不是这种状态，须从**该目标精确官方 stock init_boot**开始，用受审 Magisk 工作流 patch，只刷 `init_boot_a`，开机验证 root/服务，再重新转储实际运行中的分区；刚生成但未启动验证的 patch 不算 known-good；
6. 若目标当前镜像已 patch，仍要另外保留精确官方 stock init_boot，二者不可混淆。

这个 known-good source 同时是构建基底和捕获后的恢复目标。`confirm_k70e_portable_restore.py` 会在一个不同于 capture 的后续 clean boot 上重新核对其 size/SHA 和 root；因此不能事后换文件或拿原机 init 代替。

### 7.2 推荐的只读分区备份模式

用已验证的 `ROOT_ENTRY` 将分区读到随机的 `/data/local/tmp/<run-id>/`，随后 `adb pull`。这是读取分区、写临时普通文件，不是写分区。示意：

```bash
REMOTE='/data/local/tmp/k70e_port_<new_run_id>'
ROOT_ENTRY='/debug_ramdisk/magisk'

adb -s "$SERIAL" shell \
  "$ROOT_ENTRY su -c 'umask 077; mkdir -p $REMOTE; chmod 0700 $REMOTE; \
  dd if=/dev/block/by-name/tee_a of=$REMOTE/tee_a.stock.img bs=1048576; \
  dd if=/dev/block/by-name/init_boot_a of=$REMOTE/init_boot_a.current.img bs=1048576; \
  dd if=/dev/block/by-name/lk_a of=$REMOTE/lk_a.current.img bs=1048576; \
  sha256sum $REMOTE/*.img; stat -c \"%n %s %a\" $REMOTE/*.img; sync'"

adb -s "$SERIAL" pull "$REMOTE/tee_a.stock.img" '<run>/02_stock_backup/'
adb -s "$SERIAL" pull "$REMOTE/init_boot_a.current.img" '<run>/02_stock_backup/'
adb -s "$SERIAL" pull "$REMOTE/lk_a.current.img" '<run>/02_stock_backup/'
```

`_a` 必须替换为现场活动槽；现有实现不支持 `_b` 时停止进入 P2，而不是只改文件名继续。

KeyMint TA UUID：

```text
dba51a17-0563-11e7-93b16fa7b0071a51
```

从干净全局路径和 tee-supplicant namespace 分别保存哈希。需要复制文件时由 root 放到临时目录再 pull；不要通过 shell 文本通道打印二进制。

### 7.3 主机/设备双端一致性

对每个文件记录：

```text
device block/file path
device-reported byte size and SHA-256
host pulled path
host byte size and SHA-256
capture UTC
serial/product/slot
```

两端大小和 SHA 必须相同。任何短读、全零尾、sparse/expanded 差异或路径不一致都停止。备份后先制作只读副本，后续 builder 只从副本读取。

### 7.4 Fenrir 鉴定

参考证据是 `lk_a` 前 3,395,824 字节的 SHA-256 等于 `615d437...bf19`，不是整个 16 MiB 分区哈希。对新目标：

1. 保存完整 LK；
2. 记录全分区哈希；
3. 按候选真实长度计算前缀哈希；
4. 同时读取 expdb/启动日志中的 TEE `img_auth_required`/DICE 记录；
5. 把结果归入 write/Fenrir capability evidence。

只匹配一个前缀仍不等于所有启动链组件都相容，也不授权刷入社区 preloader。

---

## 8. S3：先建立目标自己的 stock baseline zero-key CSR

这是跨设备移植最重要的新门。必须在目标处于干净 stock TEE + stock KeyMint TA namespace、无实验 bind、无后台 keygen 的状态下完成。

### 8.1 生成并保存随机 challenge

```bash
openssl rand 32 > '<run>/03_baseline_csr/challenge.bin'
chmod 0600 '<run>/03_baseline_csr/challenge.bin'
CHALLENGE_B64="$(openssl base64 -A -in '<run>/03_baseline_csr/challenge.bin')"
```

不要把 challenge 当秘密，但必须保存原始 32 bytes 和哈希，后续验证 outer SignedData 的 challenge 完全相同。

### 8.2 调 native zero-key CSR

```bash
adb -s "$SERIAL" shell cmd remote_provisioning csr \
  --challenge "$CHALLENGE_B64" default \
  > '<run>/03_baseline_csr/authenticated_request.base64.txt' \
  2> '<run>/03_baseline_csr/authenticated_request.stderr.txt'

openssl base64 -d -A \
  -in '<run>/03_baseline_csr/authenticated_request.base64.txt' \
  -out '<run>/03_baseline_csr/authenticated_request.cbor'
```

这条命令不应联系 Google，也不应请求 KeysToSign。保存返回码、stdout/stderr 和 CBOR 原件。若 native 工具版本/参数不同，先静态确认帮助和 HAL 版本，不要反复触发 keygen。

### 8.3 baseline 必须完整验证，而不是只提 UDS

目标 profile 生成器必须 fail-closed 完成：

- 输入恰好一个 CBOR 对象，无尾随字节；
- AuthenticatedRequest version 为 1；
- `UdsCerts` 类型正确；本项目参考 K70E 为精确空 map `{}`，新目标若不同必须解释并重新审计，不能忽略；
- DICE 第一项是有效 P-256 UDS COSE_Key；从目标输入实际派生 UDS SPKI SHA-256；
- 逐段验证 ES256 COSE_Sign1，issuer/subject 连续、不得 self-issued、subject key canonical；
- 记录并钉死目标实际 entry count、claim set、config descriptor、authority hash/descriptor、mode、key usage、code/config hash 长度；
- 最终 DICE leaf 验证 outer SignedData；
- outer payload challenge 与保存的 32-byte challenge 精确相同；
- CSRPayload 是 `version=3`、`keymint`；
- KeysToSign 精确为空数组；
- DeviceInfo 来自该 outer signature，保存 canonical 表示、键集合和值；
- 保存每段 subject SPKI hash、原始 request hash、profile hash和验证报告。

baseline leaf 代表 Google 已认可的 stock 启动测量身份。更正后，最终捕获 scalar 必须派生回同一个 stock baseline leaf；任何实验态 leaf 漂移都令 `network_issuance_allowed=false`。baseline 的用途不仅是结构约束，也是 issuer approval 比较基准。

### 8.4 `target_profile.json` 中的 `dice_profile`

当前入口不会另造一个游离的 DICE profile 文件。`k70e_portable_profile.py create` 输出 schema `k70e-rkp-ctf-target-profile-v3`，其中至少包含下列目标绑定字段，并在旁边生成 `target_profile.conf`：

```json
{
  "schema": "k70e-rkp-ctf-target-profile-v3",
  "target": {
    "serial": "<this target>",
    "build_fingerprint": "<live target fingerprint>"
  },
  "compatibility": {
    "classification": "EXACT_REFERENCE_FAST_PATH|PORT_REQUIRED",
    "device_reference_id": "duchamp-cn304-mitee-exactframe-v1"
  },
  "toolchain": {
    "id": "k70e-portable-macos-host-20260906-v2"
  },
  "approval_baseline": {
    "eligible_as_network_comparison_baseline": true
  },
  "dice_profile": {
    "baseline_request": {"path": "...", "size": 0, "sha256": "..."},
    "baseline_challenge": {"path": "...", "size": 32, "sha256": "..."},
    "uds_spki_sha256": "<derived from this target, never copied>",
    "entry_count": 0,
    "config_descriptors_hex": [],
    "boot_authority_hash_hex": "...",
    "keymint_authority_hash_hex": "...",
    "keymint_code_descriptor_hex": "...",
    "keymint_authority_descriptor_hex": "...",
    "baseline_device_info": {},
    "baseline_device_info_canonical_sha256": "..."
  }
}
```

不要把“profile 从输入自动学习”实现成接受任意实验输入。profile 只能从已知 stock baseline 生成并冻结；实验轮只允许明确列出的测量变化，不能让攻击后的 request 自己定义可信 UDS/authority。

---

## 9. S4 路径选择门

生成 `compatibility_report.json`，逐项比较目标备份与参考，不允许凭 ROM 名称判断。

### 9.1 P1 必须命中的参考值

```text
stock KeyMint TA:
  size=1,401,936
  sha256=facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32

stock tee_a:
  size=5,242,880
  sha256=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

P1/Exact 路由只由目标 stock TA/TEE 的规定 size/SHA 命中参考 device contract，再由 candidate/sidecar/结构门确认；**不要求目标 fingerprint 等于原机**。`--fingerprint` 必须是此目标现场读取的完整 `ro.build.fingerprint`，profile 会把它绑定到后续 capture/restore。目标系统升级或 fingerprint 改变时必须新 profile/run。

还要运行参考 builder 的完整结构解析，确认 TA 外头/ELF、BFSB/LZ4/BootFS/SProvider 都与预期一致。若 stock TA/TEE 哈希不同但“看起来 offset 一样”，仍是 `PORT_REQUIRED`；不能靠 fingerprint 相同或 ROM 名称相同升级为 Exact。

### 9.2 P1 的复用范围

P1 可复用：

```text
capture TA 7ea5948e...bb48
candidate TEE 3990a801...3da
audited Binder client 79dc5f2b...1cef
```

P1 仍必须重建：

```text
目标专属 early-bind init_boot
目标专属 state namespace/token/latch
目标 serial、目标自身 fingerprint 和 v2 固定 root contract
目标 stock recovery paths/hashes
目标 baseline UDS/DICE profile
目标 runtime profile/capture full proper-DICE gate
目标恢复确认、provision preflight、issuance 闩锁和关系型 final validator
```

### 9.3 进入 P2 的任一触发条件

- stock TA/TEE hash 或 size 不同；
- `svchost` hash、BootFS entry、frame end、block descriptor/offset 不同；
- TA hook 原指令、call graph、PT_LOAD、cave/BSS 不同；
- active slot 不是 `_a`；
- target init_boot format/AVB/CPIO 与参考不同；
- DICE entry/profile/authority 结构不同；
- 参考构建器因任何 pinned check 拒绝目标输入。

进入 P2 是安全结论，不是失败。错误做法是把构建器的预期哈希改成新值但不重做语义审计。

---

## 10. P1：参考固件完全匹配时的构件流程

### 10.1 静态 TA/TEE 可以重建或复用

在工作区根运行参考 host-only builder：

```bash
/usr/bin/python3 \
  '<DEVICE_WORKSPACE>/02_脚本与补丁/build_k70e_cdi_leaf_identity_capture_hostonly.py'

'third_party/google-rkp-sw/.venv/bin/python' \
  '<DEVICE_WORKSPACE>/02_脚本与补丁/build_k70e_sprovider_rsa_bypass_exactframe_hostonly.py'
```

第二个构建器依赖 `lz4`；参考验证记录为 `liblz4 4.4.5`。输出必须重新得到第 3.1 节 TA/TEE 哈希，并且各自 `verify.json` 全 PASS。不要仅比较最终 SHA；同时审计 diff contract。

### 10.2 必须重建目标专属 init_boot

当前：

```text
build_k70e_cdi_leaf_earlybind_initboot_hostonly.py
build_k70e_scalar_final_earlybind_initboot_hostonly.py
```

硬编码了原机 source init、slot、state dir、token、latch、TA/TEE/stock 恢复哈希。新目标不能直接运行后刷输出。P1 使用 `build_k70e_portable_batch.py --profile ... --outdir ...`，由受审 wrapper 从 runtime profile 注入：

- 目标自己已验证的 working Magisk init_boot；
- 目标 slot 和实际 block path；
- 本轮随机 `state_dir`，由 profile 精确派生为 `/metadata/watchdog/k70e_cdi_leaf_<run-id>`；
- 本轮高熵 ALLOW token；
- 本轮唯一 latch，例如 `once_<run-id>`；
- 本轮 candidate TA hash；
- 本轮 candidate TEE hash/size；
- 目标自己的 stock TEE hash/size和设备恢复路径；
- 目标 product；
- `on fs` 早期 bind 和 `sys.boot_completed=1` 只恢复 TEE 的动作。

必须保留这些顺序：

```text
核 product/slot
 -> 核 ARM + ALLOW + token
 -> 核 latch 不存在
 -> 核当前磁盘 candidate TEE 大小/hash
 -> 核 embedded TA hash
 -> 原子消费 marker 到 latch
 -> 将 TA 复制到 /dev tmpfs
 -> chcon 为 mitee_data_file
 -> 在 tee-supplicant 首次加载前 bind
 -> 记录 BIND_OK/COMMITTED
```

恢复 helper 只在当前磁盘仍为本轮 candidate TEE、stock source 和 block size/hash 全匹配时，单次写回目标自己的 stock TEE；不得恢复 init_boot、不得重启、不得写其他分区。

### 10.3 必须目标化捕获器

现有 `capture_k70e_google_rkp_sw_identity_once.py` 硬编码：

- 原机 serial；
- `_a`；
- 原 TA/TEE/init hash；
- 原 state/latch/log；
- 固定 Magisk 路径；
- 只在 keygen 前做基本 DICE 链验证，完整 target profile 门原来推迟到 provision。

不要手工复制或改写它。P1 唯一入口是 `capture_k70e_identity_portable.py --profile <runtime_profile.json> --output-dir <全新叶目录>`；wrapper 从只读 profile 注入目标值，并在 Binder keygen 之前完成第 13 节完整 proper-DICE 门。P2 若现有 wrapper 拒绝，须发布新的受审实现，不能只替换 `SERIAL` 后运行。

### 10.4 必须目标化 `rkp_sw.py`

当前 `third_party/google-rkp-sw/rkp_sw.py` 包含原参考 profile 逻辑：

- `K70E_UDS_SPKI_SHA256`；
- 五个 `K70E_DICE_CONFIG_DESCRIPTORS`；
- boot authority hash；
- KeyMint authority hash；
- entry count 和 KeyMint descriptor/authority descriptor；
- 原机配置逻辑。

P1 只能经 `rkp_sw_portable.py` 运行。profile 创建器会在 JSON 旁生成 `target_profile.conf`；wrapper 读取 runtime profile，在内存中绑定目标 baseline UDS/profile/config，并保存实际使用的 `rkp_sw_used.py` snapshot。必须保留所有严格签名、claim、canonical CBOR、outer、challenge、DeviceInfo、KeysToSign、DER 和 key-match 门；绝不能为了兼容新 UDS 而删除验证。P2 需要新逻辑时应修改并审计 portable wrapper/版本化 allowlist，而不是散落一次性脚本。

---

## 11. P2：不同固件的语义移植流程

参考 offset 只作“寻找相同语义”的路标，不能直接写入目标。

### 11.1 KeyMint TA 重新定位

参考固件语义坐标：

```text
outer ELF offset:              0x150
identity hook:                 0xdd934
identity private pointer:      x26
identity resume:               0xdd938
identity cave:                 0x141400
GenerateRkpKey export hook:    0xa3324
export resume:                 0xa3328
RKP caller return:             0x61c7c
scratch BSS:                   0x164400..0x164430
```

目标固件需要重新证明：

1. 找到 active ES256 DICE 路径实际调用的 P-256 keypair-from-CDI 函数；
2. 找到成功返回后、私钥仍为 32-byte big-endian scalar 的准确点；
3. 证明寄存器/缓冲区生命周期；不能因反编译器变量名相似就假设仍为 `x26`；
4. 找到只属于 `GenerateRkpKey` 的成功出口，区分普通 `GenerateKey`；
5. 找到 Binder response 中 privateKeyBlob 的真实布局；
6. 设计 caller/LR 或等价调用来源门，防止普通密钥路径泄漏；
7. 选择未占用 code cave 和正式落在 PT_LOAD/BSS 内的 scratch；
8. RX 只能扩到合法边界，RW `p_memsz` 必须覆盖 scratch，禁止 W+X；
9. publication 必须 data -> len -> barrier -> marker，consumer 必须 marker -> acquire barrier -> len/data -> 清零；
10. 重放被替换指令，保持 SP、callee-saved registers、vector registers 和异常路径语义；
11. 重算 TA body/header digest；OEM RSA 签名字节保持原样且预期失效；
12. 输出逐字节 diff、反汇编、ELF segment map、hook reachability 和所有失败门。

如果没有足够空间或无法证明调用唯一性，不要降低门禁，换安全导出点或停止。

### 11.2 SProvider/TEE 重新定位

参考固件坐标：

```text
stock tee size:              0x500000
BFSB:                        0x1c6168
LZ4 frame:                   0x1c6188..0x3e076c
decompressed BootFS size:    0x44c000
block count:                 69
bin/svchost BootFS offset:   0xb5000
RSA verify call:             ELF+0x343f8 -> 0x33bd8
RSA result gate:             ELF+0x343fc
digest verify call:          ELF+0x34430 -> 0x338f8
digest result gate:          ELF+0x34438
reference patch:             80010034 -> 0c000014
reference target block:      14
```

目标固件必须从容器头重新解析，而不是搜索单个 4-byte 模式后盲改：

1. 解析顶层 TEE 条目、BFSB header、LZ4 frame、所有 block descriptor 和 frame 后条目；
2. 从 BootFS directory 找到真实 `bin/svchost`；
3. 解析 ELF PT_LOAD 并确认调用/分支均为可执行映射；
4. 通过控制流和参数语义识别 RSA verifier；
5. 证明紧邻条件分支只处理 RSA 返回值，并找到同一 success target；
6. 证明后续 body/header digest verifier 和 gate 独立存在；
7. 只把 RSA 结果 gate 改为无条件跳向原 success target；RSA verifier 仍执行，digest verifier/gate 不改；
8. 重新压缩时保持每个 descriptor、payload offset、frame end 和 post-frame `cert/spmc_dtb` 尾段；
9. 若目标 block 无法做同长度等价 LZ4 表示，停止。不要截断尾段、移动后续条目或用未经启动链证明的 padding；
10. 验证 whole-frame 和逐 block 解压一致，解压差异只在预期指令，所有非目标 block/tail byte-exact。

原机旧 v4 卡 logo 的根因是重建后丢失 frame 后证书和 `spmc_dtb`，不是“签名一定无法绕过”。P2 最容易重犯的错误就是全量重压后只看能否解压，不看 frame boundary 和尾段。

### 11.3 init_boot 重新移植

从目标自己的 working Magisk init_boot 开始，重新验证：

- boot header/page size/ramdisk offset；
- legacy LZ4 或实际压缩格式；
- newc CPIO record、alignment、trailer和 device node；
- 所有原 record 和 device node 保留；
- 新 ramdisk 不越过分区容量；
- vbmeta/AVB algorithm、descriptor、image_size、digest、footer按目标格式重算；
- `on fs` helper 先于 tee-supplicant 首次读 TA；普通 `post-fs-data` 太晚；
- SELinux type 对 MiTEE 可读；
- state/token/latch/hash/slot/recovery 全为本轮值；
- 未武装时绝不 bind、绝不消费 marker、绝不写 TEE；
- boot-complete 恢复只写目标活动 `tee` 分区且有 current-candidate + stock-source + size 三重门。

### 11.4 P2 的等价性产物

至少输出：

```text
stock_ta_analysis.json
patched_ta_verify.json
ta_disassembly_before_after.txt
stock_tee_layout.json
sprovider_control_flow.txt
patched_tee_verify.json
tee_binary_diff.json
init_boot_roundtrip_verify.json
target_capture_source_snapshot.py
target_rkp_sw_source_snapshot.py
target_profile.json（含 dice_profile、device reference 与 toolchain allowlist）
target_preflight.json
```

所有 report 必须列出输入/输出 path、size、SHA、工具版本和失败项，不能只有 `pass=true`。

---

## 12. S5：写入前的统一 host-only 门

无论 P1/P2，目标专属 preflight 必须在完全不访问设备、不联网的模式下验证：

| 门 | 必须结果 |
|---|---|
| profile schema/self-hash | `k70e-rkp-ctf-target-profile-v3`，自哈希、路径和权限正确 |
| device reference | `device_reference_id` 只约束固件/构件 contract；Exact stock TA/TEE size/SHA 命中 |
| toolchain allowlist | 独立 `toolchain.allowlist.id` 与 keygen/rkp/ADB/build/capture/restore/lz4 size/SHA 全命中 |
| 目标 stock 来源 | 双端 size/SHA 与 manifest 一致 |
| TA 输入 | 与 route 允许的 target stock 完全一致 |
| TA digest | body/header 自洽 |
| TA signature | 修改后 RSA invalid 属预期，且需要 SProvider bypass |
| TA hook | 语义、ABI、caller gate、same-run scratch、one-shot cleanup 全通过 |
| ELF | segment bounds 正确、scratch covered、无 W+X |
| TEE container | 所有顶层条目、frame 边界和尾段完整 |
| SProvider | 只绕 RSA result；RSA 调用仍在；digest verifier/gate 未变 |
| LZ4 | block/whole-frame roundtrip；非目标 byte-exact |
| init_boot | 源为目标自己的 working image；CPIO/LZ4/AVB roundtrip |
| early-bind | product/slot/token/latch/hash 检查先于 consume/bind |
| auto-restore | 只写目标活动 TEE；current/stock/size 全钉死；不 reboot |
| capture | serial/目标自身 fingerprint/固定 root/state/hashes 来自目标 profile；keygen 前 full proper-DICE gate |
| device Binder latch | profile 派生的持久路径尚不存在；捕获入口会在唯一 keygen 前原子创建并写入 profile SHA/run-id |
| keygen client | size 51,280，SHA `79dc5f2...1cef` |
| rkp_sw | 目标 UDS/stock CDI leaf、所有 signed DeviceInfo、五层 DICE、seed-file、num-keys=1，且 `network_issuance_allowed=true` |
| recovery | host stock TEE 和 working init_boot 可读，hash/size已冻结 |
| denylist | 无原 serial、原 state/token/latch、原 UDS 常量误入目标配置 |

preflight 顶层至少包含：

```json
{
  "status": "PASS",
  "mode": "host-only; no adb, fastboot, reboot, device I/O or network",
  "target_manifest_sha256": "...",
  "failed": [],
  "dynamic_scope": "attended; zero-key CSR -> full proper-DICE gate -> exactly one Binder keygen"
}
```

现有 `preflight_k70e_cdi_leaf_deployment_hostonly.py` 的 PASS 只证明参考 pairing，不证明新目标。新 preflight 必须读取目标 manifest 和目标构件；不能把参考 `verify.json` 复制过来。device reference 与 host toolchain allowlist 是两个独立审计域：任何一方更新都应生成新 ID 和审计记录，不得用“另一方未变”跳过。

---

## 13. S6–S8：现场部署与身份捕获

本节有分区写入。必须有人在手机旁、USB/供电稳定、电量充足、物理 Fastboot 可用，且 exact stock TEE/working init_boot 同时在主机和设备可用。全过程保持严格 serial。

### 13.1 写前五分钟检查

立即重新读取：

```text
serial = "<TARGET_SERIAL>"
product == duchamp
slot == target manifest and supported
root == uid 0
boot_completed == 1
current tee hash == target stock
current init_boot hash == target known-good source
global + namespace TA == target stock
ARM/ALLOW/latch absent for this new run
profile 派生的 binder_keygen_latch 不存在
stock TEE recovery file == target stock size/hash/mode
host preflight == PASS and manifest hash unchanged
```

任何一项不同，回到静态分析；不要“先刷了再说”。

### 13.2 先在设备预置目标自己的 stock TEE 恢复件

不要手写或猜目录。直接读取 runtime profile 的 `run.remote_stock_tee`；profile v3 当前精确派生为：

```text
/data/local/tmp/k70e_cdi_leaf_recovery_<run-id>/tee_a.stock.img
```

push 后先核大小/SHA，再原子改名，目录 0700、文件 0444、`sync`。early-bind restore helper 中的路径和 SHA 必须与此精确一致。绝不能使用 `设备备份_只读_20260831_preflash/tee_a.bin`，除非目标现场备份独立证明它就是同一字节；即使相同，也应使用目标自己的副本和 provenance。

### 13.3 第一写：只刷未武装的目标专属 init_boot

`fastboot_target_gate` 必须现场检查 serial/product/slot。然后只写目标活动 `init_boot`，不写 TEE：

```text
reboot bootloader
read product/slot again
flash only init_boot_<slot> target_candidate_init
reboot
```

启动后必须证明：

```text
Android + root + teefs/RKP/KeyMint healthy
disk TEE 仍为 target stock
init_boot 为本轮 candidate
embedded TA hash正确
tee-supplicant namespace 仍为 target stock TA
本轮 ARM/ALLOW/latch 不存在
没有 BIND_OK
```

这一步失败只恢复目标 known-good init_boot，禁止继续写 TEE。

### 13.4 最后才创建 ALLOW 和 ARM

人在场并重新通过所有门后：

1. 写 `ALLOW.tmp`，内容为本轮精确 token，无换行；
2. chmod 0600；
3. 原子 rename 为 `ALLOW`；
4. 创建空 `ARM.tmp`；
5. chmod 0600；
6. 最后原子 rename 为 `ARM`；
7. `sync`；
8. 读回 size/mode/content hash，不在日志打印 token 全文也可以用 token SHA 校验。

ARM 必须最后出现。若 latch 已存在，视为本轮已消费；不删除 latch 强行重放，而是新建 run、重建 init 和重新审计。

### 13.5 第二写：只刷本轮 candidate TEE

重新进入 Fastboot、重跑 exact target gate，然后只写活动 `tee`。如果 `Sending` 成功但 `Writing` 失败，留在 Fastboot，立即只刷目标 stock TEE。AVB footer warning 不能替代 `Writing OKAY` 的判断。

### 13.6 候选启动的动态 PASS

Android 回来后必须同时证明：

```text
earlybind preconsume TEE == 本轮 candidate size/hash
embedded source TA == 本轮 candidate hash
namespace target TA == candidate hash
BIND_OK
latch COMMITTED present
disk TEE 已由 helper 自动恢复为目标 stock
TEE_A_RESTORED_STOCK marker present
当前 secure world 仍来自 candidate boot
KeyMint/RKP/teefs healthy
```

必须进入 `tee-supplicant` 的 mount namespace 核 TA；全局 `/vendor` 看到 stock 不足以证明 bind。磁盘 TEE 已回 stock 是设计成功，不表示 candidate 没运行。若磁盘仍是 candidate，禁止捕获，先恢复并调查 helper。

### 13.7 keygen 前先完成完整 target proper-DICE 门

这是原机流程需要加强的地方。目标专属捕获器执行顺序必须是：

```text
严格设备/namespace/restore动态门
 -> 生成新的32-byte challenge
 -> native zero-key AuthenticatedRequest
 -> 保存 raw Base64/stderr/CBOR
 -> 用冻结 runtime profile 内的 `dice_profile` 做完整验证
 -> 验本轮 UDS == target baseline UDS
 -> 验所有 DICE signatures/claims/outer/challenge/canonical DeviceInfo
 -> 验 KeysToSign == []
 -> 验 final leaf 为本轮 signer
 -> 只有全部 PASS 才允许一次 Binder keygen
```

进入这一窄窗口前，目标 profile、解析库和 verifier 应已在主机加载并完成自检；手机保持离线、屏幕和应用静止，不触发设置页、attestation、rkpd 补货或其他 RKP 消费者。不要粗暴停掉 KeyMint/remote-provisioning 必需服务；应通过捕获前进程/服务基线确认没有意外消费者，并让完整验证在内存中立即完成。验证耗时和 CSR 完成到 keygen 开始的时间间隔也要写入日志。scratch 不是并发队列，任何后台 `GenerateRkpKey` 都可能先消费它。

实验 source 与 baseline 的比较规则：

- UDS、entry 数、claim schema、config descriptor、authority、mode/key usage等 profile 固定项必须匹配；
- code/config measurements 只在 profile 明确允许的字段和长度内变化；
- 最终 leaf 预计因 patched measurement 变化，不能要求等于 baseline leaf；
- signed DeviceInfo 以实验同轮 outer payload 为权威；稳定 identity 字段须与目标配置匹配，`vb_state`、`bootloader_state`、`vbmeta_digest` 可由受签名 source 覆盖；
- 任何未知 claim 增删或 authority 变化都停止，不能自动“学习”实验值。

现有原机捕获器只做基础链签名/outer/zero-key/same-run 检查，不能直接满足此跨设备前置门。必须先完成目标化增强。

### 13.8 恰好一次 Binder keygen

keygen client 固定为：

```text
<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_binder_keygen_client_arm64
size=51,280
sha256=79dc5f2bd523e5c35a77f34c46bbb345c22e7b79c245e2eee4b5bef0fbcb1cef
```

调用前将 `keygen_invocations` 从 0 原子记录为 `planned=1`；调用开始即记录为 1，无论命令成功与否都不在同一轮第二次调用。要求：

- portable capture 在调用 Binder 前先原子创建 profile 派生的持久设备目录 `/metadata/watchdog/k70e_cdi_leaf_<run-id>/binder_keygen_used_<run-id>`；
- 在闩锁前已把精确 Binder client 预置到唯一随机路径 `/data/local/tmp/k70e_cdi_leaf_once_<32-lowercase-hex>/keygen`，并核对 client 大小、SHA-256、执行权限和 `out/` 子目录；这些可预见的 ADB/存储失败不得留到闩锁之后；
- 目录内写入并 `sync` 本轮 `PROFILE_SHA256`、`RUN_ID`、`CAPTURE_BOOT_ID` 和 `REMOTE_STAGING_PATH`；`CAPTURE_BOOT_ID` 必须等于设备 preflight 记录且在创建闩锁的同一 root transaction 中重核，`REMOTE_STAGING_PATH` 必须等于上述预置路径；任一预存目录、错误绑定、重启漂移或创建失败都拒绝 keygen；
- 闩锁属于设备事实，不在 capture 输出目录中；删除本机输出、改 `--output-dir` 或重跑主机脚本都不能合法重置它；

- 只请求 1 把；
- 完整保存 stdout/stderr/return code；
- pull privateKeyBlob 和 MacedPublicKey 后，先完成同轮 CSR/profile/SPKI 验证、原子保存和多层 `fsync`，只在已有耐久主机副本时才删除闩锁里记录的那一个精确远程目录；
- privateKeyBlob 必须精确 32 bytes；
- 按 big-endian 解读，`1 <= d < n(P-256)`；
- 由 `d` 派生的 SPKI 必须常数时间等于刚才同轮 native DICE leaf SPKI；
- little-endian 只能作为失败诊断，绝不能自动接受；
- 只有所有门通过才把 scalar 保存到 mode 0600 的正式 identity 路径；
- 必须写入 `remote_cleanup_status.json`，并要求 `status=PASS`、`remote_secret_cleanup_confirmed=true`、profile/run/serial/path 与闩锁及 capture summary 全部一致；该文件是 restore、provision 和 final bundle 的必需证据，不是可选日志；
- 不在 stdout、argv、报告、截图、剪贴板或 Git 中打印 scalar。

不能仅根据进程退出码判断是否烧毁；必须查设备 Binder latch 的三态。闩锁 `ABSENT` 且主机无任何后闩锁证据时，说明本次没有调 keygen；保留失败输出，修正原因后可用新的不存在 output 目录重试正常 capture。闩锁 `CONSUMED` 或 `UNKNOWN` 则一律禁止第二次 keygen；先使用下节的窄恢复稳固已产生 identity，再决定是否能继续后续流程。

### 13.9 capture 唯一窄恢复：`--resume-cleanup`

只能对**原 capture 目录**运行：

```bash
"$PY" "$S/capture_k70e_identity_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --output-dir "$CAPTURE" \
  --resume-cleanup
```

该模式不生成新 native CSR、不调 Binder keygen、不创建新 scalar，本次 `binder_keygen_invocations_this_run=0`。它只重验已保存的同轮 CSR。它要求 profile 固定的 serial/product/fingerprint/root 仍可验证，然后从设备 Binder latch 读回 `PROFILE_SHA256`、`RUN_ID`、`CAPTURE_BOOT_ID`、`REMOTE_STAGING_PATH`；四者必须与 runtime profile、已保存的 `device_preflight.json` 和 `native_identity_verification.json` 精确一致，远程路径还必须匹配固定格式。

崩溃恢复顺序必须是：

```text
核闩锁四元绑定
 -> 优先验证已有正式/中间主机 scalar
 -> 主机若缺 scalar，只从闩锁的固定 remote path 拉取 out/rkp_01_private_key_blob.bin
 -> 以同轮 native CSR + challenge + frozen profile 验证 32-byte big-endian scalar 及 derived SPKI
 -> 原子保存并 fsync 秘密文件、identity 目录、capture 目录及其父目录
 -> 只删除闩锁里的精确 remote staging 目录，sync 并读回证明 absent
 -> 原子写 remote_cleanup_status.json
 -> 幂等完成 canonical identity/public/profile match/run summary，删除字节相同的中间副本
```

如果主机没有可验证的 identity 副本且远程拉取失败，它会写 `UNCONFIRMED`、**保留远程目录**并要求修复 ADB 后再跑同一条 `--resume-cleanup`；绝不会为了“试一次”先删远端，也绝不会再 keygen。只有 `remote_cleanup_status.json` 是 PASS、正式 identity 与同轮 leaf 相符且中间 duplicate 已删除时，capture 才可进入 S8。

---

## 14. S9：身份保存后先恢复设备，再做网络 provision

一旦以下文件安全落盘：

```text
identity scalar（秘密，0600）
same-run experimental AuthenticatedRequest
same-run challenge
target full proper-DICE verification
identity-derived public SPKI
capture summary and one-keygen evidence
```

后续 request/identity 计算不再依赖 candidate secure world，但真实签发仍会访问已恢复手机来消费设备 issuance latch。此时先恢复手机，减少 candidate init 长时间驻留和误触发风险。

恢复顺序：

1. 确认磁盘活动 TEE 已是目标 stock；若不是，不重启到未知状态，使用 hash-gated helper或 Fastboot只恢复目标 stock TEE；
2. 进入 Fastboot，严格确认 serial/product/slot；
3. 只刷目标自己的 known-good init_boot；
4. 正常启动，等待 `boot_completed=1`；
5. 验证活动 TEE hash、init_boot hash、全局/namespace stock TA、root、`vendor.teefs_state=ready`、KeyMint/RKP 服务；
6. 保存恢复 transcript、before/after hash、服务状态；
7. 确认当前 boot ID 与 capture boot ID 不同，然后运行六入口中的恢复确认器：

   ```bash
   test ! -e "$CAPTURE/restore_confirmation.json"
   "$PY" "$S/confirm_k70e_portable_restore.py" \
     --profile "$RUNTIME_PROFILE" \
     --capture-dir "$CAPTURE"
   ```

8. 只接受默认输出 `capture/restore_confirmation.json` 的 `status=PASS`，将 manifest 推进 `S9R_RESTORE_CONFIRMED`。

确认器是只读门，必须同时核对目标 serial/product/slot/目标自身 fingerprint、later boot、stock TEE size/SHA、known-good source init size/SHA、全局与 tee-supplicant namespace stock TA、root/服务、restore marker/log、one-shot `COMMITTED`，以及设备 Binder keygen 闩锁路径和下列四元绑定：`PROFILE_SHA256`、`RUN_ID`、`CAPTURE_BOOT_ID`、`REMOTE_STAGING_PATH`。`CAPTURE_BOOT_ID` 必须同时等于 capture device preflight、native verification 和 run summary 中的值，而 `restored_boot_id` 必须是另一次 clean boot；`REMOTE_STAGING_PATH` 必须同时等于 native/run summary 与 `remote_cleanup_status.json` 的精确路径，且 cleanup 必须 PASS。确认器不刷分区、不重启、不删除闩锁。

确认器即使判 FAIL 也会独占写入报告，且绝不覆盖已有文件。只有恢复确认 PASS 后才允许 `rkp_sw_portable.py --preflight-only`，更不能提前网络 fetch/sign。若确认器已耐久写出 FAIL，优先完成设备安全恢复并保留该报告；此阶段没有专用 resume 模式，不得通过 `--output` 换一个报告名、删除旧报告或编辑 JSON 绕门。这种已有 FAIL 证据的 profile/run 不能进入联网签发；修复原因后以新 profile/run/capture 重新开始。

---

## 15. S10：目标专属 `google-rkp-sw` 签发

### 15.1 不能使用原机冻结 `rkp_sw_used.py` 和 config

原机冻结脚本 SHA `54e886...` 和 config SHA `b009a0...` 钉死原机 UDS/profile/fingerprint。它们是原机证据，不是新目标通用客户端。

目标版必须：

- 从 runtime profile 的 `dice_profile` 读取目标 baseline UDS、descriptor、authority 和 claim schema；
- 接受完整实验同轮 AuthenticatedRequest，而不是 bare chain；
- 用捕获 scalar 文件派生 identity，先验 SPKI 必须等于实验 source final leaf；
- source UdsCerts/DICE/DeviceInfo 进入 fresh request 时 byte/canonical 等价；
- target config 的稳定 DeviceInfo 字段匹配 signed source；
- fetch fingerprint 来自目标实际 build；
- 只允许 `--curve p256`、`--seed-file`、`--num-keys 1`；
- 第一次真实签发只输出到全新目录；设备/host issuance 闩锁或 NETWORK 一旦已消费，不得用同一 profile/run 换目录重试。

### 15.2 命令形态

```bash
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --preflight-only

test ! -e "$PROVISION" && test ! -L "$PROVISION"
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --output-dir "$PROVISION"
```

wrapper 没有子命令，也不接受手写 `--seed`、`--curve`、`--dice-chain-file`、`--config` 或 `--num-keys`；这些都从 runtime profile 与 capture 证据严格派生。禁止绕过 wrapper 直接调用底层 provisioning 脚本。禁止 `set -x`。运行前记录六入口/profile/capture/restore report/seed file 的 hash 和权限；seed 只记录 hash/size，不读出内容。真实运行必须复用先前 `--preflight-only` 创建的同一份 `capture/portable_provision_preflight.json`；wrapper 会重新计算语义并逐字段比较，既不覆盖旧报告，也不接受另造一份内容漂移的报告。

`--preflight-only` 不消费任何签发闩锁。如果它在创建签发闩锁前因主机输入、权限或输出叶目录问题安全中止，先保留证据、修正原因并确认 device issuance latch 和固定 host attempt 目录均不存在；这不是一次已消费签发。真实运行时，同一台已恢复、被 profile 固定的手机必须继续 ADB/root 在线；wrapper 会再次核 serial/product/slot/目标自身 fingerprint/boot-completed、恢复报告 boot ID、stock TEE、known-good init、双 namespace stock TA，以及 capture Binder latch 中的 profile/run/capture boot/remote staging 四元绑定，然后才在设备原子创建：

```text
/metadata/watchdog/k70e_cdi_leaf_<run-id>/google_issuance_used_<run-id>/
├── PROFILE_SHA256
├── RUN_ID
└── RESTORED_BOOT_ID
```

这会改 `/metadata` 普通状态但不写分区、不停止服务。在此之前，wrapper 已要求 output 叶不存在，验证父目录可写/空间，并把 `provision_output_path`、`provision_output_parent_device`、`provision_output_parent_inode` 作为不可更换的输出绑定；后续 attempt、NETWORK、run summary 和 SUCCESS 全部必须重复并命中三值。换名、移动输出或让父目录指向不同 inode 都不是合法恢复。

设备 issuance latch 成功后，wrapper 再在 capture 目录内原子创建固定的主机隐藏目录 `.provision_attempt_<run-id>_<profile-sha前12位>`，不受 `--output-dir` 影响，其中：

```text
attempt.json          RESERVED；真实签发一开始即存在
NETWORK_STARTED.json  STARTING；调用受审 rkp_sw、即将联网前写入
SUCCESS.json          仅在恰好一个官方证书链成功后写入
```

三种 marker 都以“写完临时文件 -> file `fsync` -> `link(2)` 原子 no-replace 发布 -> 目录 `fsync`”创建，因此崩溃最多留下完整临时文件，不能把截断最终 marker 当作状态。调用 pinned `rkp_sw` 前会写 NETWORK；返回后立即对输出树所有普通文件执行 `fsync`，再按子目录由深到浅递归同步目录，最后同步 output 父目录；长时间严格审计发生在这次耐久化之后。SUCCESS 先在 attempt 目录发布权威副本，再向 provision output 安装字节完全相同的副本，并分别 `fsync` 两个父目录。

任何预存 device issuance latch 或 host attempt 目录都会拒绝第二次真实运行。设备 latch/host attempt 创建后，如果网络、HTTP、解析或链验证失败，必须保留所有状态并以全新 profile/run 重来；如果唯一失败是 Google 完整一把/一链输出落盘后的严格审计或 SUCCESS 双副本提交被崩溃打断，只能走第 15.5 节 `--resume-finalize`。严禁删除闩锁、编辑 marker、复制旧 `SUCCESS.json`、拔掉手机后绕过检查或更换 `--output-dir` 重试。

### 15.3 网络发送前的最终本地门

fresh request 必须先原子写盘、`fsync`、重新读回，然后验证：

- target UDS 与 baseline profile 精确一致；
- proper DICE 和 UdsCerts 与实验 source 精确复用；
- fresh outer SignedData/SignedMac 的签名由目标 CDI_Leaf identity 验证；
- Google fresh challenge 完全匹配；
- DeviceInfo 是实验同轮 signed source；
- KeysToSign 恰好 1 把；
- 保存的软件私钥公钥等于该 KeysToSign；
- CBOR canonical/单对象/无尾随；
- request 文件 read-back hash 与即将 POST 的 bytes 相同。

任何一项失败都不 POST。

本地 preflight 在任何 issuance 闩锁创建前失败时绝不 POST；保留失败证据并修正可预见的主机原因，确认 device issuance latch 和固定 host attempt 目录都不存在后再重跑 host-only 门。若失败显示 profile/capture/identity/DeviceInfo 语义本身不一致，不得原地编辑证据“修过”，而应建立新 profile/run 并重新 capture。

### 15.4 服务器与证书接受门

```text
fetchEekChain HTTP == 200
signCertificates HTTP == 200
requested key count == 1
returned chain count == 1
本题参考 contract 下 certificate count == 4
每段 DER 精确全消费，无截断/尾随
唯一、连通、无环、无重复的 leaf-to-root 路径
software private SPKI == request key == leaf certificate SPKI
逐级签名有效
root self-signature有效
root DER SHA-256 == 6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
root SPKI SHA-256 == 3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec
OpenSSL verify 在签发时刻通过
```

这两个 pin 是对独立审计过的 Google Key Attestation CA1 root 的 DER 与 SPKI 双钉扎；subject 名、HTTPS metadata 或自签成功本身不构成信任。Google root 轮换时必须独立取得并审计新 DER/SPKI，再发布新的 allowlist/验证器，不能现场放宽。

原始 request/response 必须在解析前保存。HTTP 200 只是必要条件，不是完成。HTTP 444 或任何非 PASS 时停止，不连续重试；先检查 target UDS/profile、zero-key source、signed DeviceInfo、canonical CBOR、leaf/seed 和 fingerprint。issuance attempt 已预留的失败轮必须保留三态证据，并以新 profile/run 重来；失败轮软件私钥不得悄悄与下一轮响应混用。

Google 协议和返回链长度未来可能改变；若不再是四证书，不能擅自放宽本题冻结 contract，也不能直接宣告失败。应保存原始响应，区分“服务器政策变化”与“本地链错误”，再由赛事验收口径决定是否更新 contract。

### 15.5 issuance 唯一窄恢复：`--resume-finalize`

只对原来的 `CAPTURE` 和**原来的 `PROVISION` 路径**运行：

```bash
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE" \
  --output-dir "$PROVISION" \
  --resume-finalize
```

不得附加 `--server-url`。该模式的先决条件是：

- `PROVISION` 已是 mode 0700 的完整旧目录，`run_summary.json` 已明确 `status=complete`、requested=1、received chain=1、official endpoint；
- 固定 host attempt 目录已是 mode 0700，`attempt.json` 和 `NETWORK_STARTED.json` 均为完整普通文件；
- attempt/NETWORK 的 profile/run、device issuance latch、restored boot、preflight/restore/scalar/native CSR/config 哈希、package auditor SHA-256、profile helper SHA-256 全部命中；
- 当前 `PROVISION` 规范路径和当初记录的父目录 filesystem device/inode 精确一致；
- 原始 request/HTTP evidence/Google response/软件私钥/唯一证书链已全部落盘，且能从这些文件重做完整 strict issuance audit。

它首先对现有 output 树执行“全文件 `fsync` -> 子目录由深到浅 `fsync` -> 父目录 `fsync`”，再只安装缺失且与冻结输入字节完全相同的 proof 文件。attempt 目录如果遗留冻结 identity 副本，只在它与 canonical identity 字节相同时删除并同步目录。然后离线运行当前受审 package auditor，只有 `status=PASS`/`failed_checks=0` 才允许创建或完成 SUCCESS。

SUCCESS 提交是幂等的：权威 `attempt/SUCCESS.json` 不存在时才以原子 no-replace 方式创建；存在时必须先全量验证。然后安装或验证 `PROVISION/portable_issuance_success.json` 的字节级同一副本。两者都存在且正确时可幂等重跑；只有 output SUCCESS 而没有权威 attempt SUCCESS 会直接拒绝，不会倒推伪造权威证据。

`--resume-finalize` 中没有 ADB/Fastboot/Binder 操作，没有 fetch/sign HTTP，也不会新建软件私钥。如果原运行死在 DNS/TLS/HTTP、服务器非 200、raw response 不完整、received chain 不是 1 或任一密码学关系失败，该模式必须拒绝；保留本轮闩锁/网络证据，以新 profile/run 重来，绝不得把它当联网重试器。

---

## 16. S11：新目标包和通用语义验收

### 16.1 当前 packager 的精确包结构

```text
K70E_CTF_SUBMISSION_google-rkp-sw_<new-run>/
├── TARGET_PROFILE.json
├── 01_identity/
│   ├── google_rkp_sw_cdi_leaf_p256_scalar.bin
│   ├── cdi_leaf_public_spki.der
│   ├── native_identity_request.cbor
│   └── native_identity_challenge.bin
├── 02_generated_key/
│   ├── private_key_pkcs8.pem
│   └── public_key_spki.der
├── 03_certificate_chain/
│   ├── server_certificate_chain.der
│   ├── ordered_certificate_chain.der
│   ├── ordered_certificate_chain.pem
│   ├── ordered_cert_00.der / ordered_cert_00.pem
│   ├── ordered_cert_01.der / ordered_cert_01.pem
│   ├── ordered_cert_02.der / ordered_cert_02.pem
│   └── ordered_cert_03.der / ordered_cert_03.pem
├── 04_proof/
│   ├── software_certificate_request.cbor
│   ├── request_preflight_verification.json
│   ├── fetch_eek_response.cbor
│   ├── fetch_eek_response_http.json
│   ├── sign_certificates_response.cbor
│   ├── sign_certificates_response_http.json
│   ├── provision_run_summary.json
│   ├── capture_device_preflight.json
│   ├── capture_run_summary.json
│   ├── native_identity_verification.json
│   ├── portable_profile_match.json
│   ├── remote_cleanup_status.json
│   ├── restore_confirmation.json
│   ├── portable_provision_preflight.json
│   ├── portable_issuance_attempt.json
│   ├── portable_network_started.json
│   ├── portable_issuance_success.json
│   └── rkp_sw_used.py
├── FINAL_VERIFICATION.json
└── SHA256SUMS.txt
```

若上游确实生成，packager 还会复制下列可选文件到 `04_proof/`：`verified_dice_chain.json`、`verified_native_device_info.json`、`device_info_csr_v3.json`、`software_certificate_request.json`。不得手工补造。`native_identity_verification.json` 和 `remote_cleanup_status.json` 都是当前必需项，不是 optional。当前实现没有 `00_target/`、`README.md`、`key_summary.json` 或 `chain_summary.json`；也不要把 `native_identity_request.cbor` 改成旧文档中的其他名字。`package --output-dir` 指向的 bundle 叶目录必须尚不存在。

### 16.2 原机 exact validator 不能验证新设备

Skill 中的：

```text
<CODEX_HOME>/skills/k70e-rkp-ctf/scripts/verify_submission.py
```

SHA-256 为 `56fbb4d59bce34fe7138f4967d9e13485d55027d8159da959c54b76620def453`，它钉死原机最终包的动态哈希和 UDS，只用于原机冻结包。新目标必须有“profile 驱动、关系驱动”的 verifier，不能把原机 expected hashes 改成新值后继续声称是同一 validator。

### 16.3 新目标通用 verifier 必查

- 外部验证必须提供独立信任锚：首选 `verify --bundle "$BUNDLE" --trusted-profile "$RUNTIME_PROFILE"`；这里的 profile 必须是打包前单独保存/带外传递的副本，绝不能指向 `$BUNDLE/TARGET_PROFILE.json`。verifier 会无跟随读入并冻结 trusted profile，拒绝与包内 profile 同 device/inode 的 hardlink，也拒绝 link count 不是 1 的所谓“外部副本”。离线移交时可改用**在运行/打包前已经带外记录**的 `--expected-profile-sha256 <64位小写hex>`，不能从待验 bundle 现抄；二者必须恰选一个，包内 profile 不能自我授权；
- 输入目录无 symlink；
- 在 manifest 和语义验证前，verifier 先将整个 mode-0700 bundle 复制到私有临时稳定快照；快照期间会比较源树的 file set 以及每个文件的 device/inode/size/mode/SHA-256，任何 TOCTOU 漂移都拒绝，后续所有检查只针对冻结快照；
- 文件清单无绝对路径、`..`、重复或漏项；
- 所有目录 0700、文件 0600；
- `SHA256SUMS.txt` 不包含自身并在最后生成；
- scalar file 恰 32 bytes、P-256 范围合法，不打印值；
- scalar-derived SPKI == saved identity SPKI == experimental source leaf SPKI；
- source challenge、zero KeysToSign、outer signature、canonical CSRv3、signed DeviceInfo 全部从 raw CBOR重验；
- source UDS == 该目标 baseline profile UDS，而不是原机 UDS；
- 每段 DICE signature/continuity/claim/profile重验；
- software PKCS#8 可解析且 public SPKI == request KeysToSign == Google leaf；
- exact sent request hash、raw response hash和报告一致；
- DER全消费、唯一链、逐级签名、根自签、时间验证；
- fetch/sign 都为 200，requested=received=1；
- capture `keygen_invocations==1`；
- capture 的 Binder device latch 已消费，路径/profile SHA/run-id/capture boot ID/remote staging path 与 runtime profile、device preflight、native verification 和 capture summary 一致；
- `remote_cleanup_status.json` 为 PASS，profile/run/serial/remote path 绑定正确、远端私密目录已确认不存在，且没有额外 scalar 副本进入 bundle；
- target device `restore_confirmation.json` 为后来一次 clean boot 的 PASS，并重新证明同一 device latch 的四元绑定仍存在且正确；
- `portable_issuance_attempt.json`、`portable_network_started.json`、`portable_issuance_success.json` 三份齐全、状态/哈希/profile/run/restore-preflight 关系一致，并都证明同一设备 issuance latch 的 path/profile SHA/run-id/restored boot ID 和同一 provision output path/父目录 device/inode；
- NETWORK 与 SUCCESS 同时绑定运行当时的 package auditor SHA-256 和 portable profile helper SHA-256，防止用不同审计语义补写成功 marker；
- root DER/SPKI 同时命中第 15.4 节固定 pin，且 root 自签/链/时间有效；
- verifier 只从自身 allowlisted runtime 加载库，不从候选包或父目录寻找解释器；
- 验证过程禁止生成 `__pycache__` 或修改包，验证前后整包 file set/hash不变。

最终报告使用 path/hash/SPKI hash/证书 subject 等非秘密元数据，不打印 scalar 或 PKCS#8 内容。不要在文档中冻结某个 `passed_checks` 数字：它会随当前验证器与 bundle contract 演进，且生成 manifest 前的内嵌验证与 manifest 后的外部 `verify` 检查集合可能不同。完成口径是使用记录了 SHA-256 的**当前**验证器现场得到 `status=PASS`、`failed_checks=0`，所有必需关系与 manifest 均通过。

---

## 17. 分阶段恢复矩阵

| 失败点 | 正确恢复 | 禁止动作 |
|---|---|---|
| host preflight/输出探针在任何闩锁前失败 | 不接触设备，保留失败报告；修正可预见主机原因，用新的不存在输出叶重跑；profile 语义/输入需改变时才建新 profile/run | 关闭检查或伪造 PASS |
| 未武装 candidate init 启动失败 | 只刷目标 known-good init_boot，保留日志并重建新 run | 接着刷 TEE或在未知状态重试 |
| marker 创建不完整 | 不刷 TEE；记录并用新 run/state 重建 | 手工拼补半套 marker |
| candidate TEE Fastboot 写失败 | 保持 Fastboot，只刷目标 stock TEE；恢复 init 后新 run | reboot 到半写状态、刷其他分区 |
| candidate TEE 后 ADB 不回来但 Fastboot 可用 | 只恢复目标 stock TEE，启动后再恢复 init；新 run | 重复刷 candidate |
| Android 回来但 BIND/COMMITTED 不全 | 不捕获；确认磁盘 stock并恢复 init；新 run | 运行 keygen碰碰运气 |
| Android 回来但磁盘仍是 candidate | 不重启/不捕获；hash-gated 恢复 target stock TEE，再恢复 init；新 run | 依赖 helper“迟早会跑” |
| full proper-DICE/预置失败且 Binder latch 精确 `ABSENT` | 不 keygen；保留 request/失败输出。主机无后闩锁证据时，修正原因并用新不存在 output 叶重试正常 capture | 放宽 UDS/authority/outer 门、删改失败证据 |
| capture 异常后 Binder latch=`CONSUMED` | 绝不 keygen；在原 capture 目录运行 `--resume-cleanup`，恢复/验证已有 identity、多层 fsync、精确清理远端并生成 PASS cleanup 证据 | 删除 device latch、再 keygen、换 capture output-dir 伪造新轮 |
| capture 异常后 Binder latch=`UNKNOWN` | 保留 remote 和 host 证据，恢复同一设备 ADB/root 后只跑 `--resume-cleanup`以解析精确闩锁 | 把 UNKNOWN 当 ABSENT、任何 keygen |
| keygen 已调用但 scalar/leaf 不匹配 | 本轮失败，禁止第二次 keygen；恢复并新 profile/run | 尝试 little-endian 自动接受 |
| 身份已捕获但恢复/确认失败 | 优先完成设备恢复；保存闩锁与报告；放弃本轮 | 改名输出另一份 PASS JSON 后联网 |
| provision preflight 在所有 issuance 闩锁前失败 | 不联网；修正可预见主机原因并在双闩锁均 absent 时重跑 host-only 门；若需改 capture/profile 语义则新 run | 编辑已签名/已冻结证据来过门 |
| device issuance latch/host attempt/NETWORK 已预留，HTTP/网络/响应/链失败 | 保存设备闩锁及 attempt/network/success 实际状态，停止网络重试，新 profile/run | 删除任一闩锁、换 provision output-dir、用 `--resume-finalize` 发起网络 |
| Google 完整一把/一链已耐久落盘，审计/SUCCESS 提交崩溃 | 保持原 output path 与父目录 device/inode，运行 `--resume-finalize`；它只做离线严格审计和双副本幂等提交 | 连设备、再网络、移动 output、手工补 SUCCESS |
| Google 444/非 200 | 保存 raw evidence，停止重试，离线诊断并新 run | 本地伪证书冒充完成 |
| 证书链本地验证失败 | 保留原响应并判失败 | 只按 subject 字符串重排后强行接受 |
| final bundle verifier 失败 | 保留整个 issued run 证据并诊断；若 provision 本身 strict PASS、只是无秘密的 package/output 构造问题，可从不变上游用新 bundle 叶重新打包/验证；若发现 identity/链语义失败则新 profile/run | 原地改秘密证据、删除 issuance marker、重用语义失败轮私钥 |

Fastboot 不可用时，只允许已审计的 MT6897/SP Flash Tool V6 `tee-only` 恢复分支，并使用目标自己的 exact stock TEE。禁止 format/firmware-upgrade/write-efuse XML，禁止扩大分区集合。该分支不是普适保证，使用前须独立验证目标 DA/auth/partition map。

永远不要 relock；不要触碰 `preloader`、`seccfg`、`proinfo`、`persist`、`nvram`、`nvdata`、`efuse`、RPMB、`userdata`。P0 为取得能力所需的启动链改动若确实不可避免，必须作为独立项目重新审计和授权，不能借本 CTF 文档自动扩大范围。

---

## 18. 跨设备故障树

### 18.1 一开始就没有 root/write/Fenrir

```text
确认不是 adb 授权/线材问题
 -> 保存只读属性和 fastboot getvar
 -> 能从精确官方包取得 stock init/tee/LK？
 -> 是否有已知可信 write/Fenrir 安装证据？
 -> 否：BLOCKED_P0
```

不要把 OEM 开关打开当作完成，不要因账户没资格就否定已经存在的 Fenrir，也不要因 Fastboot 可进就假设可写。

### 18.2 TA/TEE 哈希不匹配

```text
确认备份没有短读/overlay/错误槽
 -> 确认 fingerprint 和官方包
 -> 仍不同：P2
 -> 重新做 TA call graph + SProvider exact-frame
```

禁止只改 builder 中 `EXPECTED_SHA256`。

### 18.3 baseline CSR 验证失败

```text
检查 stdout 是否严格 Base64、CBOR是否全消费
 -> 验 challenge/zero keys/outer
 -> 检查是否 stock TA namespace
 -> 检查 HAL/CSR version
 -> 仍失败：保存证据，停止动态移植
```

baseline 不可信就不能建立 UDS/profile。

### 18.4 P1 builder PASS 但 target init 不同

TA/TEE 的 P1 不自动使 init 成为 P1。必须从目标 working init 重建并独立验证 CPIO/LZ4/AVB；参考 init hash不同不是理由去刷原机镜像。

### 18.5 experimental DICE UDS 与 baseline 不同

先排查错误设备、错误 source、错误 namespace、CBOR解析和 corrupted chain。不要更新 profile 接受实验 UDS。UDS 锚变化属于根信任异常，停止。

### 18.6 DICE profile只有 code/config measurement 变化

如果变化位于预先 allowlist 的测量字段、长度正确、签名/authority/descriptor完整，可继续；其他 claim/authority变化进入人工审计。不能写“patched 所以什么都可变”。

### 18.7 source full gate PASS，keygen 返回非 32 bytes

说明 TA export 没触发、被其他消费者抢先消费、response layout不同或 hook失效。不要解析 opaque KeyBlob 猜私钥，不要第二次 keygen。保存 stdout/stderr/blob hash，恢复后回 P2。

### 18.8 scalar range正确但 SPKI 不匹配

先确认 big-endian、同轮 request、没有后台 CSR/keygen、leaf取的是最后一段 subject key。little-endian若碰巧匹配也不自动接受；参考实现的正式语义是 big-endian。任何不一致均判本轮失败。

### 18.9 Google 返回 444

按顺序离线检查：

```text
target UDS/profile是否来自 stock baseline
experimental source是否完整 AuthenticatedRequest而非 bare chain
source是否 zero-key
identity SPKI是否等于 experimental final leaf
outer signature/challenge是否正确
DeviceInfo是否为同轮 signed source且 canonical
fingerprint是否为目标 build
fresh request是否落盘复读后发送同一 bytes
```

修复结构前不再次生成软件 key/请求。只要隐藏 issuance attempt 目录已创建，本轮就不可重试；诊断结论进入下一份全新 profile/run。

### 18.10 “换一个输出目录就能重试”

```text
先读设备 binder_keygen_latch
 -> ABSENT 且主机无后闩锁证据：本次没有 keygen，可保留失败目录并换新不存在输出叶重试正常 capture
 -> CONSUMED：永久不能第二次 keygen，只能对原目录跑 --resume-cleanup
 -> UNKNOWN：不得假定 ABSENT，恢复同一设备连接后只跑 --resume-cleanup/只读审计
再读设备 google_issuance_used latch
 -> 已存在：真实 issuance 权限已消费，本 profile/run 永久不能第二次联网签发
再读 capture/.provision_attempt_<run-id>_<profile-sha-prefix>
 -> 已存在：真实 issuance 已预留，禁止第二次联网
 -> 若 attempt + NETWORK + 原路径完整一把/一链输出均在：只能跑 --resume-finalize
 -> 若网络/HTTP/响应/链不完整：新 profile/run
```

三个闩锁故意位于输出叶目录之外或采用固定 capture-local 名称。删除/更名 `08_capture/capture_*`、`10_provision/provision_*` 或 `11_submission/bundle_*` 都不会合法重置资格；删除设备/主机闩锁属于破坏审计事实。已跨过不可逆点后只有本节列出的两个窄恢复：保住已产生 identity 的 `--resume-cleanup` 和完成已落盘一把/一链证据提交的 `--resume-finalize`。其他情况先安全恢复设备，然后创建新 profile/run。

---

## 19. 命令、日志和证据的最低记录规范

让下一位 AI 能无聊天续接，必须保留事实而不是只写“成功了”。

### 19.1 每条动态命令记录

```text
UTC timestamp
run_id
phase/state before
exact tool path + tool SHA/version
target serial（对外报告可脱敏，内部原始日志保留）
product/slot preflight result
command（秘密参数必须替换为 file path/hash）
stdout path + sha256
stderr path + sha256
exit code
phase/state after
operator physically present yes/no
```

涉及 `fastboot flash` 时额外记录：

```text
partition exact name
image absolute path/size/sha256
stock recovery absolute path/size/sha256
pre-write getvar product/slot transcript
Sending/Writing完整 stdout/stderr
post-boot block hash
recovery branch ready yes/no
```

涉及 capture/restore/issuance 时额外记录（只记录路径、状态和绑定，不打印秘密）：

```text
runtime profile path + SHA-256 + run-id
SHA256SUMS_PORTABLE.txt 校验 transcript + 本轮复制件 SHA-256
capture output leaf 在调用前不存在的证明
Binder keygen device latch path / PROFILE_SHA256 / RUN_ID / CAPTURE_BOOT_ID / REMOTE_STAGING_PATH
binder_keygen_invocations 与 requested_key_count
capture boot ID / restored boot ID
remote_cleanup_status path + SHA-256 + status + exact remote path
restore_confirmation path + SHA-256 + status
device Google issuance latch path / PROFILE_SHA256 / RUN_ID / RESTORED_BOOT_ID
host fixed attempt directory
attempt / NETWORK_STARTED / SUCCESS marker 的存在性、SHA-256 和状态
provision output leaf 在调用前不存在的证明
provision 规范 output path + 父目录 filesystem device/inode
NETWORK/SUCCESS 绑定的 package auditor SHA-256 + profile helper SHA-256
当前 verifier path + SHA-256 + trusted profile 或独立 expected profile SHA
```

### 19.2 不允许出现在日志里的内容

- identity scalar 原文/hex/base64；
- PKCS#8 私钥正文；
- `--seed <literal>`；
- shell `set -x` 展开的秘密；
- 读取 secret file 后的 command substitution；
- 屏幕截图中的私钥或 clipboard 内容。

对秘密只记录 path、mode、size、SHA-256 和 derived public SPKI hash。

### 19.3 区分原始日志与重建说明

没有保存的命令不能事后伪装成 raw transcript。报告中明确标注：

```text
raw: 当时工具实际 stdout/stderr
derived: 从 raw CBOR/DER/hash 重新计算
reconstructed: 根据 builder/state/artifact 推断的顺序
operator note: 人工说明
```

原机最终 CDI 轮缺完整逐行 fastboot transcript 是已知限制；新目标必须补齐这一证据缺口。

---

## 20. 给下一位 AI 的交接状态机

每次停止前更新 `00_manifest/HANDOFF.md` 和 `target_manifest.json`。HANDOFF 只需回答：

```text
1. 当前 state 是什么？
2. 目标 route 是 P0/P1/P2，依据哪个 compatibility_report？
3. 哪些动作确实执行过，原始日志在哪里？
4. 是否发生过分区写入？每次 write 的 before/after hash 是什么？
5. 本轮 ARM/ALLOW/early-bind latch 状态是什么？是否已经 COMMITTED？
6. native zero-key source 是否已完整 profile 验证？
7. Binder keygen invocation count 是多少？持久 binder_keygen_latch 是 `ABSENT`/`CONSUMED`/`UNKNOWN` 的哪一种，其 profile SHA/run-id/capture boot ID/remote staging path 是什么？
8. identity 是否已保存且 SPKI 同轮匹配？`remote_cleanup_status.json` 是否 PASS，是否需要 `--resume-cleanup`？
9. 设备是否已恢复 stock TEE + known-good init + stock namespace TA？`restore_confirmation.json` 是否来自不同 boot 且 PASS？
10. 设备 issuance latch 与固定 host attempt 目录是否存在？attempt/network-started/success 三个 marker 各是什么状态？绑定的 provision output path/父目录 device/inode 是什么？
11. Google fetch/sign 是否已发生？对应 request/response hash 在哪里？
12. 当前唯一允许的下一步是正常继续、`--resume-cleanup`、`--resume-finalize`、新 run，还是只读审计？依据是什么？
13. 哪些步骤绝对不能重做？本轮是 pre-keygen 安全中止、窄恢复待完成，还是已烧毁？
```

续接规则：

- `S0–S4`：可重复只读核验，不重复生成 baseline 除非明确新 run；
- `S5`：host 构件变化后必须重跑全部 preflight；
- `S6`：未武装 init 已 PASS，可从 marker 前复核继续；
- `S7`：candidate secure world 活跃但未捕获，只能在现场完整动态门通过后继续；
- `S8`：identity 已捕获、同轮 SPKI 匹配且 remote cleanup 已 PASS，设备 Binder 闩锁必须永久保留，禁止再次 native trigger/keygen，下一步只恢复；如果 cleanup 尚未确认，仍是 `S8_RECOVERY_REQUIRED`，唯一动作是原目录 `--resume-cleanup`；
- `S9`：设备表面已恢复，但没有确认器 PASS 前禁止 host provision；
- `S9R`：恢复报告和 Binder 闩锁绑定已确认，下一步只做 host preflight；
- `S10`：preflight 已 PASS，但真实运行前仍须确认设备 issuance latch 与固定 host attempt 目录均不存在，且恢复后手机仍在线；
- `S10I`：设备 issuance latch/host attempt 任一已预留，禁止再次联网签发。若 HTTP/响应/链未完成则本轮作废；若完整一把/一链已落盘但严格审计/SUCCESS 双副本尚未完成，标记 `S10I_FINALIZE_REQUIRED` 且唯一动作是原路径 `--resume-finalize`；完成后下一步只打包/验证；
- `S11`：结束，只做只读验收和交付。

任何状态发现 profile/output/marker 与上述单向事实冲突，都按失败处理，不向前“修 JSON”。但 HANDOFF 不得把所有异常笼统写成 `BURNED`：必须根据持久闩锁区分 `PRE_KEYGEN_SAFE_ABORT`、`S8_RECOVERY_REQUIRED`、`S10I_FINALIZE_REQUIRED` 和真正不可恢复的 `BURNED`。其中两个 recovery-required 状态也不授权重做 keygen 或联网；只授权对原证据完成第 13.9/15.5 节的幂等收尾。

---

## 21. 最容易跨设备误抄的硬编码清单

开始代码审查时对目标工具运行全文搜索。以下是**原机/原轮专属值**，命中时必须证明只是 denylist 或历史说明，绝不能作为新目标配置：

```text
<DEVICE_SERIAL>
d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9
/metadata/watchdog/k70e_cdi_leaf_identity
K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT
once_7ea5948e
5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517
9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
reference fingerprint OS3.0.304.0.WNLCNXM
```

以下则是 portable profile v3 的**有意固定 contract**，不是原机残留：

```text
product duchamp
slot _a / tee_a / init_boot_a / lk_a
Magisk applet /debug_ramdisk/magisk
device_reference_id duchamp-cn304-mitee-exactframe-v1
toolchain allowlist id k70e-portable-macos-host-20260906-v2
```

如果目标不满足这些固定项，当前 v3 应安全中止并进入版本化移植，不是把固定项临时改成目标值。即使满足 Exact 构建条件，也必须另过 stock approval environment 门；当前 TA/TEE candidate 会改变 DICE，不能用于联网。

---

## 22. 本手册明确不能保证的事项

1. 不能保证每台 K70E 已有或能安全取得 Fastboot 写能力、root 或 Fenrir；
2. 不能保证社区 Fenrir 包与任意生产批次、anti-rollback、preloader/DRAM 配置兼容；
3. 不能保证不同 HyperOS/Android/TEE/TA 版本仍有相同 offset、ABI、压缩布局和 DICE profile；
4. 不能保证 `_b` 槽可直接套用已验证 `_a` 方案；
5. 不能保证 pre-userspace TEE 失败时自动恢复 helper 能执行；它只能在 Android 启动后恢复磁盘 TEE；
6. 不能保证 Fastboot 永远可回；因此 candidate TEE 前必须有人、物理键和目标 exact recovery；
7. 不能保证 Google endpoint、政策、EEK、链长度和证书有效期永久不变；
8. 不能保证原机 UDS 与其他 K70E 相同；必须逐设备 baseline；
9. 不能保证 profile 自动学习安全；可信 profile 只能来自已验证 stock baseline；
10. 不能保证原机 exact validator适用于新动态输出；新目标必须用关系驱动 verifier；
11. 不能把 device reference 与 toolchain allowlist 的某一版视为永久通用；两者必须独立版本化和复审；
12. 不能因证书 root subject、HTTPS 来源或自签成立就信任新根；当前验收还要求独立固定的 Google root DER/SPKI pin，轮换须人工审计；
13. 截至 2026-09-06，六入口虽有主机 replay/静态审计，但尚未在第二台实体 K70E 上完成端到端前向验证；本手册不能保证第一台新机现场一次成功；
14. 不能把本手册当成无风险刷机承诺。它提供 fail-closed 分层流程和恢复边界，但硬件故障、供电中断、未知启动链差异仍可能造成不可恢复损坏。

这些限制不是让工作停摆，而是告诉接手者何时走 P1、何时必须做 P2、何时诚实标记 P0 阻塞。

---

## 23. 最终完成检查表

只有全部为真，另一台 K70E 的题目才算独立完成：

- [ ] 新目标 serial/product/slot/write/root/Fenrir 证据完整；
- [ ] 目标自己的 stock TA/TEE/init/LK 已双端备份和哈希；
- [ ] `source_init_boot` 是该目标已开机、root/服务健康后重新转储的 known-good Magisk init，而非未验证 patch；
- [ ] stock baseline zero-key AuthenticatedRequest 完整验证；
- [ ] 目标 UDS/DICE profile 由该 baseline 冻结，不来自原机；
- [ ] P1/P2 路径有机器可读 compatibility report；
- [ ] 已在项目根运行 `shasum -a 256 -c SHA256SUMS_PORTABLE.txt` 且全 PASS，发布清单与实际六入口哈希已复制到本轮 manifest；
- [ ] device reference 与 toolchain allowlist 的 ID/内容独立记录且全命中；
- [ ] 目标专属 TA/TEE/init/capture/rkp/preflight 全部 host PASS；
- [ ] 原机 serial/UDS/state/token/latch/identity/private key 未复用；
- [ ] candidate init 未武装启动 PASS；
- [ ] candidate TEE 启动、early-bind、namespace 和磁盘自动回 stock 全 PASS；
- [ ] 实验同轮 zero-key source 在 keygen 前通过完整 proper-DICE 门；
- [ ] Binder GenerateRkpKey 恰好调用一次；
- [ ] 设备 Binder keygen 持久闩锁存在，profile SHA/run-id/capture boot ID/remote staging path 四元绑定正确且未删除；
- [ ] 捕获 32-byte big-endian scalar 合法，derived SPKI 等于同轮 DICE leaf；
- [ ] scalar/source/验证证据安全落盘且未打印秘密；
- [ ] `remote_cleanup_status.json` 为 PASS，精确 remote staging 已确认删除，无中间 scalar 副本残留；
- [ ] 设备在联网签发前恢复 target stock TEE + known-good init + stock namespace TA；
- [ ] `restore_confirmation.json` 来自不同 clean boot，含设备 Binder 闩锁复核并 PASS；
- [ ] 目标版 `google-rkp-sw` 新生成恰好一把软件私钥；
- [ ] fresh request 落盘复读后所有本地门 PASS；
- [ ] 真实签发前设备 issuance latch 原子落盘，恢复后手机/boot/profile 绑定正确；
- [ ] 主机 issuance attempt 已唯一预留；attempt/network-started/success 三份 marker 全部进入包，并绑定同一 output path/父目录 device/inode、package auditor 和 profile helper 哈希；
- [ ] fetch/sign HTTP 200，raw request/response 已保存；
- [ ] 返回唯一链，DER全消费，逐级签名、Google root DER/SPKI pin、key-match全 PASS；
- [ ] 新提交包精确布局、权限、清单、无 symlink，并在私有 stable snapshot 上无修改验证全 PASS；
- [ ] 外部 `verify` 以可信 runtime profile 或其独立 SHA 为锚，trusted profile 不是包内 hardlink，实时 `status=PASS` 且 `failed_checks=0`；
- [ ] HANDOFF 状态为 `S11_SUBMISSION_VERIFIED`，明确不再动态重跑。

最终原则只有一句：复用方法和审计，不复用设备身份；复用静态构件必须先证明固件字节相同，任何动态身份、状态或签发结果都必须由新目标机本轮重新产生。


---

## 原始记录段 4 / Source section 4: 53_K70E_CTF_stock日志路线完整流水线记录_20260906.md

# K70E CTF stock MiTEE 日志路线完整流水线记录

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 路线重分类：**stock-log 仍是 fresh fully-stock same-run provenance 的严格路线，但不再是取得 Google clean chain 的唯一必要路线。已有 host-only modified DICE + clean DeviceInfo `PASS_CLEAN` 候选，见文档 65–70。

> **2026-09-06 18:05 状态覆盖：** stock-log 设计仍作离线参考；恢复与当前设备状态以文档 59–63 为准。旧八步恢复、Magisk/OrangeFox approved 锚和“全局 marker 为 0”说法均已撤销。

> 日期：2026-09-06（Asia/Taipei）  
> 文档性质：当前权威工程流水线；取代文档 45–51 的旧 patched-TEE 成功结论  
> 历史快照（已失效）：下述“ADB 稳定、尚未刷写、按文档 58 执行”是恢复前状态。八步后来已经执行并重启，当前模式 UNKNOWN；只允许以文档 59–63 和更新后的 Skill 续接。approved-stock 专用 one-shot 未开始，但 generic/default 负实验已有真实网络 marker。  
> 最终目标：同一台 K70E、同一认可 stock 身份的一份 CDI_Leaf 身份材料、一把新生成的软件 P-256 私钥，以及该私钥同轮取得的 Google 四证书链；整条链不得含精确文本 NOT_APPROVED

---

## 0. 一页结论

旧方案在 Fenrir、engineering preloader 和 patched TEE 环境中成功提取了身份，并分别用真机 Binder 和 host google-rkp-sw 请求了 Google。两张叶证书都由 Google 正常返回 HTTP 200，但 Provisioning Information 都包含：

    {1: 32, 3: "Xiaomi", 5: {1: "NOT_APPROVED"}}

赛事方拒绝该字段。它不是可以从证书中删除的本地标签，因为该扩展位于 Google 签名覆盖的 TBSCertificate 中。

当前证据已排除“尝试次数/计数 32 导致简单限流”：

- 工作区 27 张唯一 Provisioning Info 证书中 25 张干净、2 张带 NOT_APPROVED、0 张解析失败；
- 12 张干净证书的计数同样是 32；
- 两次失败均为 HTTP 200，没有 429、Retry-After、quota 或 abuse；
- native Binder 和 host 软件请求得到逐字节相同的拒绝扩展；
- 已获认可的 stock 请求与失败请求的 DICE 第 1、2、4 层直接测量不同，正好对应 preloader、Fenrir BL2_EXT 和 patched TEE；派生身份变化继续传播，五层完整 payload 全部不同。

因此新路线是：

    认可基线启动测量（原厂 preloader/LK/TEE/TA + pinned Magisk init_boot）
      -> zero-key CSRv2（不生成待签软件 key、不联网）
      -> 原厂 KeyMint TA 自带日志泄露 CDI_Leaf 标量
      -> 标量派生 SPKI 必须匹配同轮 CSR 最终 DICE leaf
      -> 保持同一 boot 和全部 approved-baseline 门
      -> host 在 one-shot 授权内只生成一把软件 P-256 key
      -> 耐久 PKCS#8 重开/PoP，且 software SPKI != CDI identity SPKI
      -> 只运行一次官方 Google RKP 协议流程
      -> 全链独立验签和原始 Provisioning Info 全量扫描
      -> 只有没有 NOT_APPROVED 才能写 SUCCESS

这条路线不修改 TA、TEE、LK 或 preloader。

## 1. 题目语义和三件套

最终交付不是“某张 K70E 证书”，而是三个关系闭合的部分：

1. google-rkp-sw 身份材料
   - 32 字节 big-endian P-256 CDI_Leaf 私钥标量；
   - 同一次 stock zero-key AuthenticatedRequest；
   - 该请求的 challenge、UDS、五段 proper-DICE、signed DeviceInfo；
   - 标量派生 SPKI 必须等于该请求最后一段 DICE subject 公钥。
2. 一次软件运行产生的 P-256 私钥
   - 由修复后的 google-rkp-sw 在唯一在线轮次新生成；
   - 私钥的 SPKI 必须等于请求中唯一 KeysToSign 公钥。
3. 同一次运行返回的 Google 证书链
   - 恰好一条链；
   - 当前参考响应应为四张证书；
   - 叶证书 SPKI 必须等于第 2 项软件私钥；
   - 链签名、根自签、固定 Google 根和 DER 全消费全部通过；
   - 全链任何一处 Provisioning Info 都不得包含精确文本 NOT_APPROVED。

CDI_Leaf 身份标量与软件待签私钥是两把不同的 key。前者用来对 proper-DICE 请求做设备身份签名；后者才是赛事要求保存的“一次 google-rkp-sw 成功产物私钥”。当前核心对这个“不同”做密码学强制：**software key SPKI 必须不等于 CDI_Leaf identity SPKI**；否则在 fetch/sign 之前 fail-closed。

## 2. 事故证据

### 2.1 已拒绝包

    03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/

叶证书 Provisioning Info：

    OID             1.3.6.1.4.1.11129.2.1.30
    raw CBOR hex    a301182003665869616f6d6905a1016c4e4f545f415050524f564544
    raw SHA-256     be1579a137030a4b5ac21f7538a43f6d64c317a3c03ec8f390cbb0f3241de393
    decoded         {1:32, 3:"Xiaomi", 5:{1:"NOT_APPROVED"}}
    hit path        $/5/1

旧验证器只投影键 1、3、4，丢弃键 5，因而误报 PASS。

### 2.2 两条独立失败路径

    native Binder request
      request SHA-256  139aaad1c4ab10901c6d25114c990f06e7e74c0b537ada399ea4d6b699bcd458
      leaf SHA-256     bfd4d433a7679db684caecdc5ced1b766a338205abaf75964aa68424378c3b29
      HTTP             200

    host google-rkp-sw request
      request SHA-256  029c2bae4fdf94b461ff343d8a67e5106a76d9a3a515dae38e5d5b4953c5f4c4
      leaf SHA-256     8d1eeefd7ad252ec78c53859be595b935faa2cdb5f1bff597f6a817351d22553
      HTTP             200

二者的 Provisioning Info 原始字节完全相同。这排除了“只是 host 模拟格式不被认可”。

### 2.3 已认可 stock 基线

    request
      03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/certificate_request.cbor
      SHA-256 f03011311dca791fccca64f1f78323ba113197f56ac368fbdeeb97162c3ccf56

    approved leaf
      SHA-256 1bcc492cd6a5d6661654c98d6aee943ec2e164dae07f1d0c531201c18940ced0

    approved Provisioning Info
      SHA-256 ce487a6a7a687a42df7a2e781fd493b70d342f132258fb65b2485f9c491ef762
      decoded {1:8, 3:"Xiaomi"}

    approved UDS SPKI
      d1a3f13b9fae014e1816a988fe4f611c320f315cc1252e366695f76c63bea3c9

    approved CDI leaf SPKI
      0684d469c8afecf9d1a7a86cfc67e4996f2712d5edfcfed80745eeb105b1130b

注意：历史认可证书没有公开 Android 当前 schema 的键 4。因此 android_schema_current_strict=false 不能自动判赛事失败；赛事硬门是 ctf_no_not_approved=true。

### 2.4 stock 与失败测量差异

    五层完整 DICE measurement equality
      [false, false, true, false, true]

    第 1 层  preloader / early boot 变化
    第 2 层  stock BL2_EXT 与 Fenrir BL2_EXT 变化
    第 3 层  ATF 相同
    第 4 层  stock TEE 与 patched TEE 变化
    第 5 层  KeyMint 层相同

    五层完整 DICE payload equality
      [false, false, false, false, false]

measurement/security 向量表示哪些组件直接改变；完整 payload 向量还包含 issuer、subject 和 subject public key，因此会显示身份派生的级联影响。两者不得混为一个含义。

approved 五层 raw payload SHA-256：

    6d662c12275ea9a0adf35e94e8ba339c0e0a4cc4247cee30289dfc84360dc6ec
    229219105fcb22e2dce684fd424a1d379069e146ef2c75b777d8a08ad4c1de34
    08606b4a703df5252c5d0dc9d57294c0e7722a027b49bf930d303da587c1ff8b
    6b8586445c3c891a8be4026a8384e2a81fd897ac3b217ea9b3c7145ee138f90d
    e4f17a71c000068f62b506d16c0322967b9dd4e58b6cdda9e9e2831fbba72792

异常 native 与异常 host 的五层 payload 逐字节相同，但与上述 approved 五层全部不同。三次路径的 fetch URL/body、EEK chain/config 一致，所以 host framing 不是当前主因。

signed DeviceInfo 精确差异是 approved `orange/unlocked/acaa9258...b6e9` 与失败环境 `green/locked/b9b1d867...9744`。其余 11 个字段值和类型完全相同。HLOS 的 ro.boot.* 可被启动链伪装，只能记录，不能代替 TA 签名的 DeviceInfo。

## 3. stock 原厂 TA 的身份标量出口

目标原厂 TA：

    01_设备输入/duchamp_Mitee_TA与KeyMint用户态_20260828/ta/
      dba51a17-0563-11e7-93b16fa7b0071a51.ta
    size       1401936
    SHA-256    facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
    raw ELF SHA-256 52c61b...44aa

活动调用链：

    Binder generateCertificateRequestV2(keysToSign=[])
      -> MiteeRemoteProvisioningContext::SignWithDeviceKey  0x0be710
      -> hwbcc wrapper                                       0x0c2e18
      -> tee_sign_key                                        0x0dd9b0
      -> hwbcc_sign_key                                      0x0dd438
      -> get_attest_cdi                                      0x0dcd10
      -> P256KeypairFromCDI                                  0x0db330
      -> success, x26 points to scalar                       0x0dd934
      -> mov x5, x26                                         0x0dd94c
      -> dump_to_hex                                         0x0dd954 -> 0x0d87f0

精确日志语法是相邻两行：

    [utee:INFO][dump_to_hex:59]private_key(  15): <16 个小写 hex 字节>
    [utee:INFO][dump_to_hex:59]private_key(  31): <16 个小写 hex 字节>

行首可以有 normal-world 前缀。只靠 private_key 标签不够，因为同轮日志可能还有 KAK 或其他候选。解析器必须：

- 只从严格两行语法构造 32 字节候选；
- 校验 1 <= d < P-256 order；
- 对每个候选派生 DER SPKI；
- 严格解析同轮 zero-key CSR 的 UDS、五段 DICE、outer 签名和 challenge；
- 只接受派生 SPKI 等于最终 DICE leaf SPKI 的唯一候选；
- 0 个或多于 1 个匹配都失败。

日志通道：

    TA printf
      -> MiTEE memlog
      -> /proc/mitee_log
      -> vendor miteelog
      -> /data/vendor/mitee/mitee.log
      -> /data/vendor/mitee/last_mitee.log（轮转）

## 4. 当前代码组件

### 4.1 profile 和认可门

    02_脚本与补丁/k70e_portable_profile.py
    schema k70e-rkp-ctf-target-profile-v4
    toolchain k70e-portable-macos-host-20260906-v5
    SHA-256 724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57
    size 134026

它把三种结论分开：

    structural_and_portability
    approval_environment
    network_issuance

只有 network_issuance_allowed=true 才能进入在线阶段。它要求目标请求与已认可 stock 基线在以下数据上完全匹配：

- 同一 UDS；
- 同一 CDI leaf SPKI；
- signed DeviceInfo 所有字段逐类型相等；
- 五层 DICE measurement claim；
- 五层 DICE security claim；
- 五层完整 verified DICE payload raw SHA-256（包含 issuer/subject/中间公钥，只排除 payload 外的 COSE 签名）；
- stock TA/TEE exact reference；
- 合法 scalar 且派生 SPKI 匹配当前 CSR。

当前参考运行 profile：

    03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json
    internal profile SHA-256
      809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
    file SHA-256
      5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81
    size 17803

配套 config：

    03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.conf
    SHA-256 1134173204aaa22c63c66c25964cff33f95184a79b5742d3ba5c6a4c2db6b564

当前 V5 不继承 V4，是 stock-log-only allowlist：只固定 core、ADB、Python runtime、zero-key 载荷与源码、stock capture、extractor、portable library 以及 stock TA/TEE/源 init/device config。它明确排除 tx2 keygen、candidate TA/TEE/init_boot、restore/build/lz4 和其他 patched-route 执行能力。V1–V4 只作离线历史 profile 解析，不授权当前在线路线。

### 4.2 zero-key 客户端

    02_脚本与补丁/rkp_binder_csr_v2_zero_key_client.cpp
      SHA-256 bec6c3db5ee242c4cfca388e6f85360c53cdeac79ff44ed7a4be439d624b2133

    02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload
      SHA-256 acbfb63134cc87290f7b49c959e074bf3b531a87ff4905501012606c348b8858
      size 216072

受控载荷完整路径：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload

NDK r25.2 重编与冻结二进制 byte-for-byte 相同。反汇编确认：

- KeysToSign count 为 0；
- challenge 长度为 32；
- AIDL transaction code 为 4；
- flags 为 0；
- 只有一处 RKP AIBinder_transact；
- 不调用 Google，不生成一把待签 key。

### 4.3 日志解析器

    02_脚本与补丁/extract_k70e_cdi_leaf_from_mitee_log.py
    SHA-256 7a5992cbe15617347da6400e63ff1d22b0e8cc8802b40e76daba307b98c5c611

特点：

- O_NOFOLLOW、lstat/fstat、读前读后稳定性；
- 精确两行语法；
- strict canonical CBOR；
- UDS、五段 proper-DICE 签名、outer 签名、challenge、zero keys；
- 唯一 scalar-to-leaf-SPKI 关系；
- 私有输出 0700/0600；
- 不在 stdout/stderr 打印 scalar。

### 4.4 stock 捕获器

    02_脚本与补丁/capture_k70e_stock_cdi_log_once.py
    SHA-256 732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c
    size 75305

捕获器完成：

1. 固定 venv、profile、ADB、parser 和 zero-key client；
2. 要求新建 0700 输出目录；
3. 在初始和 point-of-no-return 两阶段分别先做 strict 唯一 ADB inventory，再检查 serial、duchamp、slot _a、fingerprint、root、同一 boot ID、RKP 服务；
4. 检查无可转发 default 路由、飞行模式和 Wi-Fi 关闭；
5. 两次检查 stock TEE、stock TA、known-good Magisk init_boot；
6. 两次检查完整 lk_a 与 preloader_raw_a；
7. 保存 baseline mitee.log 和 last_mitee.log；
8. 写入耐久 DISPATCHING_NO_RETRY；
9. 调用唯一 zero-key CSR；
10. 保存 stdout/stderr、CSR、challenge、post 日志和 delta；
11. 严格处理 append-only 或可证明的轮转；
12. 运行冻结 parser，生成 scalar/SPKI；
13. 重新审计 signed DeviceInfo 和五层 DICE stock 认可态；
14. 写 capture_evidence_contract.json。

两阶段各自的 `adb devices -l` inventory 都必须发生在该阶段任何设备 shell 之前，并且只接受精确表头加一条 pinned serial、状态为 `device` 的规范 ASCII 记录。额外或重复设备、`offline`、`unauthorized`、目标缺失/serial 不符、控制字符/非 ASCII、坏换行、畸形 detail token 或重复 detail key 全部在 shell 前 `SAFE_ABORT`。第二阶段 inventory 一旦失败，不再发送任何 cleanup shell、Binder 调用或 `DISPATCHING_NO_RETRY` 一次性 marker；已经 staged 的远端临时目录安全延期清理，`remote_cleanup.json` 明确留下人工核对要求，且手工清理只能在重新确认 strict inventory 中唯一目标后进行。两阶段还都要求 `tee-supplicant` 经 shell 和 host 双重校验后恰好给出一个 ASCII 十进制 PID；空值、多 PID 或夹杂其他字符时不允许调用 `nsenter`。

手机离线门在捕获准备阶段和 point-of-no-return 前各执行一次，分别落盘为 `offline_gate_before.json` 和 `offline_gate_point_of_no_return.json`。两次都要求飞行模式开启、Wi-Fi 关闭、IPv4/IPv6 route query 返回码均为 0，且 `forwarding_default_route_count=0`。AOSP `netd` 在 dummy 网络上安装的直连 default 是丢包 sink，不是外网路由；本参考 K70E 的 table 1002 来自 dummy0 ifindex + 1000。捕获器只忽略下列两种精确形态：

```text
default dev dummy0 table 1002 proto static scope link
default dev dummy0 table 1002 proto static metric <十进制整数> pref medium
```

任何其他 default，包括 unknown tail、`via`、`nexthop`、`nhid`、`encap`、错表、缺表或重复字段，都 `SAFE_ABORT`。证据分开保存可转发 default 数为 0、已忽略 dummy sink 的数量/专用 inventory hash 和完整 route inventory hash，并保留兼容字段 `default_route_count=0`。任一路由查询失败、分隔符结构畸形或未知 default 都不得进入 Binder。对应 AOSP 一手源码：`DummyNetwork.cpp` 的丢包语义 <https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/DummyNetwork.cpp#30>，`RouteController.cpp` 的路由安装 <https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp#788> 和 table ID 映射 <https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp#149>。

完整 early-boot 锚：

    lk_a
      size       16777216
      SHA-256    9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35

    preloader_raw_a
      size       4190208
      SHA-256    33ef65d9560e92990e5d6bbf7dc8e161e57346e7f9434082b59d31366a638d1f

    tee_a
      size       5242880
      SHA-256    18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d

    KeyMint TA
      size       1401936
      SHA-256    facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32

    init_boot_a known-good Magisk source（非 factory-stock）
      size       8388608
      SHA-256    9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4

本路线名中的 `stock` 专指原厂 MiTEE/KeyMint 日志路径和原厂 preloader/LK/TEE/TA，不表示每个分区都是 factory-stock。参考机为保持 root 使用上述已验证 Magisk init_boot；最终权威不是名称，而是新 boot 中 signed DeviceInfo 和五层完整 DICE payload 与同机 approved baseline 逐字节一致。

### 4.5 一次性 Google 发行器

    02_脚本与补丁/rkp_sw_stock_log_once.py
    SHA-256 99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3
    size 121031

它是 stock_mitee_log_v1 的专用 consumer，不伪造旧 portable patched-TA 所要求的 restore/latch 字段。流程分两次显式调用：

当前 preflight 把 `core_rkp_gate_version` 从运行时 gate-v7 常量写入，并要求 toolchain `k70e-portable-macos-host-20260906-v5` stock-log-only。gate-v6/V4 只是历史身份，不得用于当前在线运行。

    --preflight-only
      零网络；冻结和重验 capture、profile、scalar、CSR、stock approval gate；
      创建唯一 preflight report。

    --attended --execute-google-once
      `--attended` 在 build_preflight() 前强制检查，缺失即无设备/preflight/ATTEMPT 副作用地拒绝；
      在任何 ATTEMPT 保留前先做 strict 唯一 ADB inventory，再重验未变化的 preflight、live approved-baseline、唯一 ASCII 十进制 tee-supplicant PID、飞行模式、Wi-Fi 和零可转发 default；
      保留 host attempt 后，在 device-latch 单 root shell 前再次做 strict 唯一 ADB inventory；随后原子重验 boot/分区/TA namespace/服务/飞行模式/Wi-Fi/IPv4+IPv6 default policy，全部通过才创建设备 issuance latch；
      先耐久写 NETWORK_STARTED；
      调用一次固定 gate-v7 google-rkp-sw；
      先保存私钥、请求、raw response；
      独立验收并仅在赛事门通过后写 SUCCESS。

官方 endpoint 被固定为：

    https://remoteprovisioning.googleapis.com/v1

发行器禁止替代 URL，禁止同一 capture 第二次 attempt，禁止输出目录覆盖 capture 或 attempt。这里的“一次 core invocation”按 Google RKP 协议包含两次必要 POST：一次 fetchEekChain、一次 signCertificates；二者处于同一个持久 NETWORK_STARTED marker 下，没有自动重试。

注意 collector 和 wrapper 的 dummy sink 语法不完全相同：collector 只放行 4.4 节的两条长形态；wrapper 按族分析，IPv4 放行无 gateway 的裸 `default dev dummy0 table 1002` 或 scope-link 形态，IPv6 放行同一裸形态或 decimal-metric/pref-medium 形态。其他 default，包括 `via`/`nexthop`/`nhid`/`encap`、错表、重复字段和未知尾缀，仍全部拒绝。这项门证明飞行模式 + Wi-Fi 关 + 双栈查询成功 + 零可转发 `/0` default，不单独证明所有 host-specific/VPN/fwmark 路径均不存在。

当前 attempt schema 仍是 `k70e-rkp-ctf-stock-log-issuance-attempt-v1`。`ATTEMPT.json` 在真实 `DEVICE_LATCH.json` 创建前即含 `device_latch_consumed=true` 及未来成功 latch 的确定性路径/哈希；这里的 `true` 是对该 attempt 未来只能成功落到这一 latch 的预承诺，不是写 ATTEMPT 当下已经消费设备 latch 的现场事实。若两者之间掉线、inventory 失败或第二原子门失败，attempt 会写 `BURNED.json`，不会写 `NETWORK_STARTED.json` 或 `SUCCESS.json`，因此不会发起 Google 网络；但失败证据的字段语义不直观。正确修订必须让 writer、verifier、marker 哈希链和 attempt schema 一起迁移到 **gate-v8/新 schema**，禁止在 v1 内只把 ATTEMPT/DEVICE_LATCH 简单倒序或暗改 `consumed` 含义。

### 4.6 google-rkp-sw 核心

    ../third_party/google-rkp-sw/rkp_sw.py
    SHA-256 619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822
    size 193161
    portable issuance gate version 7

核心已加入：

- 在 profile-bound one-shot authorization 内生成恰好一把新 P-256 软件私钥；
- 软件私钥 SPKI 必须不同于 CDI identity SPKI，并且必须等于请求唯一 KeysToSign 和返回 leaf SPKI；
- 私钥以 canonical unencrypted PKCS#8 PEM 持久化，连同 SPKI/summary 写入 0600 文件和 0700 目录，同步文件及目录层级；
- 在 fetch 前和 signCertificates 前从落盘 PKCS#8 重开、重解析、重算 SPKI/COSE key，用 fresh nonce 完成 PoP；
- capture 目录要求当前 UID 所有且 mode 精确 0700，并绑定其与 parent 的 resolved path/device/inode/UID/mode；关键阶段反复校验；
- dispatch ticket、authorization 构造和消费都绑定 creator PID，构造前/中/后 fork 不能继承可用授权；
- request 和 raw response 在解析前耐久保存；
- full-chain Provisioning Info 无损/canonical/重复键安全审计；
- 递归扫描允许的 map key、value 和 array；任意显式 `CBORTag`、tag 24 encoded-CBOR、tag 258 自动解码的 `set`/`frozenset`、tag 35 的 `re.Pattern` 和其他 semantic object 全部 fail-closed；
- 任意 NOT_APPROVED、leaf 缺扩展或畸形 CBOR 均非零失败；
- ctf_no_not_approved 与 android_schema_current_strict 分开；
- stock approval gate 无法从 CLI 绕过。
- 直接 core 入口也强制五层完整 same-handset DICE payload 与 approved baseline 逐层一致。

### 4.7 portable 库与历史活动能力的边界

    02_脚本与补丁/rkp_sw_portable.py
    SHA-256 0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c
    size 76113
    direct-online permanently disabled

`rkp_sw_portable.py` 只保留离线 preflight/resume/library 角色，direct-online 必然 `SAFE_ABORT`。可选 TA/TEE/OEMCrypto probes 与 in-process injector 的原始 ELF/源已移入 `06_历史危险能力隔离/`，活动源只是固定失败 tombstone。当前在线执行面只剩 stock wrapper -> pinned core 这一条路径。

### 4.8 stock 离线验收器

    02_脚本与补丁/verify_k70e_stock_log_submission.py
    SHA-256 f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357
    size 120223

验收器不联网、不访问设备，独立重算密钥/请求/证书链/Provisioning Info 与 capture/attempt/marker 合同，并重新要求 software SPKI != CDI identity SPKI。它对 `LIVE_STOCK_PREFLIGHT.phone_offline_gate` 强制 exact typed fields：两个 route query success 都必须是 `true`、`forwarding_default_route_count` 精确为整数 0、dummy sink count 为非负整数，inventory hash 合法，并绑定 `ATTEMPT`/`DEVICE_STATE_DIR_PREPARED`/`DEVICE_LATCH`/`NETWORK_STARTED`/`SUCCESS` 链。第二次原子手机门由成功 latch 合同间接证明；verifier 不重放手机或 Google，device latch 也不是第二份 raw route inventory 或服务端 freshness receipt。

## 5. host-only 验证结果

最终冻结结果为 **8 组 / 178 项，178/178 PASS**，分组映射为 **Provisioning Info/core 23 + profile 13 + device evidence 12 + capture 31 + extractor 10 + legacy quarantine 10 + wrapper 42 + verifier 37 = 178**。这 8 组覆盖 Provisioning Info、profile approval、device approval evidence、stock log extractor/capture、core authorization/durability、stock one-shot issuer、stock verifier 和 legacy capability quarantine。已经完成的关键离线检查：

- zero-key ARM64 客户端 NDK 重编 byte-identical；
- 无产生项目 bytecode 的 compile PASS；
- 红队未发现 capture/extractor 的 P0；
- 旧 NOT_APPROVED fixture 必须拒绝；
- 2026-08-29 已认可历史 fixture 必须接受，即使 Android strict=false；
- 显式 CBORTag/tag24 和 tag258/tag35 semantic object 必须拒绝；
- 软件 key 与 CDI identity 同 SPKI、SEC1/非 canonical PKCS#8、mode/path/inode 替换和 PID/fork 授权继承必须拒绝；
- collector 初始/point-of-no-return 两阶段在任何设备 shell 前都必须通过 strict 唯一 ADB inventory；额外/重复、offline/unauthorized 和畸形 inventory 均拒绝；
- wrapper 在 ATTEMPT 前和 device-latch shell 前分别重做 strict inventory，真实发行缺 `--attended` 必须在 `build_preflight()` 前拒绝；
- collector/wrapper 的 `tee-supplicant` PID 必须是唯一 ASCII 十进制值；
- portable direct-online、隔离 probe 和 injector 必须固定 `SAFE_ABORT`；
- signed DeviceInfo 与 HLOS boot properties 的语义已分离。

这些 PASS 证明实现和离线门禁闭合，不证明已产生新的 clean Google 链。最终发布仍以 SHA256SUMS_PORTABLE.txt、SHA256SUMS_HANDOFF.txt 和文档 56 的最终回归表为准；这些清单必须最后生成并逐项 `shasum -c`。

## 6. 现场阶段 A：准备

以下 one-shot 动作尚未在 2026-09-06 当前轮次执行；已做的只是 USB/ADB 连接诊断，它没有触发 Binder 或 Google。

### 6.1 设备条件

- 只连接目标 K70E，serial 必须为 <DEVICE_SERIAL>；
- 产品必须 duchamp；
- 活动槽必须 _a；
- 操作者在手机旁；
- 电量和 USB 稳定；
- 本机可通过 /debug_ramdisk/magisk su -c id 取得 root；
- 目标保持当前已知可启动 boot，不重启、不插拔；
- 手机飞行模式开启、Wi-Fi 关闭、移动数据关闭；
- host 暂时不需要断网，但捕获器会确认手机无可转发 default 路由；精确的 non-forwarding dummy0/table1002 sink 只记录证据、不要手动删除；
- 另备目标自己的 stock 镜像和已验证恢复路径。

当前现场状态是：Pixel 已不在场，唯一 serial `<DEVICE_SERIAL>` 的 K70E native ADB 已稳定。但不得直接运行 capture：live 只读检查已确认手机仍是 `b9b1d867…` / `<BUILD_HOST>` / crypto unsupported / empty-privapp 拒绝环境。下一步是文档 58 的 CN304 恢复与 post-boot 验收；旧 libusb 超时和本次只读检查都没有消耗 Binder/Google one-shot。

### 6.2 只读连接检查

    <HOST_SDK>/platform-tools/adb devices -l

只允许精确表头加一条目标记录，且状态必须为 `device`。若只有 Pixel 4 XL <DEVICE_SERIAL>、K70E 不在列表、记录为空/额外/重复、serial 不精确，或状态为 `offline`/`unauthorized`，停止。非 ASCII、控制字符、坏换行、畸形 detail token 或重复 detail key 同样拒绝。不要把 libusb 能枚举 USB 设备等同于 native ADB 已稳定。

### 6.3 校验 host 发布件

在项目目录：

    shasum -a 256 -c SHA256SUMS_PORTABLE.txt
    shasum -a 256 -c SHA256SUMS_HANDOFF.txt

任一不是 OK，停止，不要手改常量。

### 6.4 校验 profile

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/k70e_portable_profile.py \
      check \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json

必须输出：

    status PASS
    classification EXACT_REFERENCE_FAST_PATH
    approval_baseline_eligible true

这只是 profile 文件和批准基线可用，不表示 live 设备已经通过。

## 7. 现场阶段 B：唯一 zero-key 捕获

为这次运行选择从未存在的新目录，例如：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_cdi_log_capture_YYYYMMDD_HHMMSS

执行：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/capture_k70e_stock_cdi_log_once.py \
      --serial <DEVICE_SERIAL> \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --output-dir $HOST_ROOT/NEW/PRIVATE/CAPTURE_DIR \
      --attended \
      --execute-zero-key-once

成功必须同时存在：

    run_summary.json                         status PASS
    capture_run_summary.json                 status PASS
    capture_evidence_contract.json           capture_method stock_mitee_log_v1
    native_trigger_csr.cbor
    native_trigger_challenge.bin
    native_identity_verification.json        status PASS
    portable_profile_match.json              network_issuance_allowed true
    identity_validation.json                 status PASS
    offline_gate_before.json                 status PASS
    offline_gate_point_of_no_return.json     status PASS
    identity/google_rkp_sw_cdi_leaf_p256_scalar.bin   exactly 32 bytes
    identity/cdi_leaf_public_spki.der
    remote_cleanup.json

如果是 PARSER_REQUIRED：

- 保留该目录；
- 不重跑同一目录；
- 不再触发 zero-key；
- 只离线处理 logs/baseline、logs/post、logs/delta 和 PARSER_HANDOFF.json；
- 只有可以证明输入窗口且 parser 关系门通过时，才完成合同。

如果 zero_key_invocation.json 已写 DISPATCHING_NO_RETRY 或状态不明确：

- 视为请求可能已触发；
- 不删除 marker；
- 不用新目录“试一次看看”；
- 先审计保存的 stdout、CSR 和日志。

## 8. 现场阶段 C：离线发行预检

保持 K70E 同一 boot，不开 Wi-Fi，不改变分区。运行：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --capture-dir $HOST_ROOT/PRIVATE/CAPTURE_DIR \
      --serial <DEVICE_SERIAL> \
      --preflight-only

默认写入：

    CAPTURE_DIR/stock_log_provision_preflight.json

必须为：

    schema                       k70e-rkp-ctf-stock-log-provision-preflight-v1
    status                       PASS
    capture_method               stock_mitee_log_v1
    source_keys_to_sign_count    0
    dice_entry_count             5
    dice_signatures_verified     5
    scalar_matches_same_run_leaf true
    network_issuance_allowed     true
    requested_software_key_count 1
    expected_certificate_chain_count 1
    network_access               false

预检报告是 exclusive 文件；已存在时不能覆盖。若需要修复一个真正的前置错误，保留整个失败目录并建立一套新 capture/run，不手删预检或 attempt 状态。

## 9. 现场阶段 D：唯一 Google 运行

只有以下全部为真才继续：

- capture PASS；
- preflight PASS；
- K70E 仍为同一 serial、同一 boot ID；
- live TEE、TA、lk_a、preloader_raw_a 为原厂锚，init_boot 为 pinned known-good Magisk 锚；
- signed DeviceInfo 和五层 DICE 与已认可 stock 基线一致；
- host 电脑必须能访问 Google；手机本身不需要联网，必须保持飞行模式、Wi-Fi 关闭和零可转发 default；只有已知 non-forwarding dummy0/table1002 sink 可按实现的严格形态取证放行；
- 没有任何旧 attempt 目录或设备 issuance latch；
- 操作者接受本次失败后不重试。

选择新的、与 capture 不重叠的私有输出目录：

    $HOST_ROOT/NEW/PRIVATE/K70E_CTF_SUBMISSION_STOCK_YYYYMMDD_HHMMSS

执行：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --capture-dir $HOST_ROOT/PRIVATE/CAPTURE_DIR \
      --serial <DEVICE_SERIAL> \
      --preflight-report $HOST_ROOT/PRIVATE/CAPTURE_DIR/stock_log_provision_preflight.json \
      --output-dir $HOST_ROOT/NEW/PRIVATE/K70E_CTF_SUBMISSION_STOCK_YYYYMMDD_HHMMSS \
      --attended \
      --execute-google-once

不要显式传入其他 server URL。

attempt 状态顺序：

    strict unique ADB inventory -> 第一次 live shell（ATTEMPT 之前）
      -> ATTEMPT.json（v1 预承诺未来 DEVICE_LATCH consumed=true）
      -> LIVE_STOCK_PREFLIGHT.json
      -> DEVICE_STATE_DIR_PREPARED.json
      -> strict unique ADB inventory
      -> device-latch 前单个 root shell 原子重验 live boot/hash/service + airplane/Wi-Fi/IPv4+IPv6 default policy
      -> DEVICE_LATCH.json
      -> NETWORK_STARTED.json
      -> core output/raw responses
      -> independent strict audit
      -> attempt/SUCCESS.json and output/stock_log_issuance_success.json

唯一 core main 内部的网络序列：

    1 x fetchEekChain POST
    1 x signCertificates POST
    automatic retry count = 0

NETWORK_STARTED 一旦存在，无论 HTTP、断线、解析或写盘失败都视为该次已消耗。BURNED.json 的 retry_allowed 必须为 false。

若 ATTEMPT 后、DEVICE_LATCH 前掉线，v1 的预承诺字段仍为 `device_latch_consumed=true`，但现场并未成功创建设备 latch；此时必须以 BURNED 且缺少 NETWORK_STARTED/SUCCESS 理解为“attempt 已烧毁、未联网”。不要人工改 marker 或重排步骤。要消除这种失败现场歧义，必须另做 gate-v8/schema 迁移。

## 10. 成功输出合同

最终输出至少包含：

    identity/
      google_rkp_sw_cdi_leaf_p256_scalar.bin
      cdi_leaf_public_spki.der
      native_zero_key_csr.cbor
      native_zero_key_challenge.bin

    key_00/
      private_key_pkcs8.pem
      public_key_spki.der
      key_summary.json

    certificate_request.cbor
    certificate_request.json
    request_preflight_verification.json
    response.cbor
    response_http.json
    fetch_eek_request.cbor
    fetch_eek_request.json
    fetch_eek_response.cbor
    fetch_eek_response_http.json

    chain_00/
      certificate_chain.der
      ordered_certificate_chain.der
      cert_00.der
      cert_01.der
      cert_02.der
      cert_03.der
      chain_summary.json

    run_summary.json
    stock_log_strict_issuance_audit.json
    stock_log_preflight_used.json
    stock_log_capture_contract_used.json
    stock_log_runtime_profile_used.json
    rkp_sw_used.py
    stock_log_issuance_success.json

Provisioning Info 的完整逐证书树位于 chain_00/chain_summary.json 的 provisioning_info_audit 字段，并由 stock_log_strict_issuance_audit.json 和离线 verifier 独立重算；没有顶层 provisioning_info_audit.json。

文件名以最终发行器和 manifest 为准。所有目录必须 0700、普通文件 0600，不允许 symlink、hardlink、FIFO、socket 或多余秘密副本。

`key_00/private_key_pkcs8.pem` 必须是 canonical unencrypted PKCS#8，不接受 SEC1 等可被库宽松解析但不符合冻结编码的私钥。在 fetch/sign 的关键时点，core 会重新绑定 capture path/device/inode/UID/mode，重开 PKCS#8 并重做 PoP；不得使用复制出的私钥对象或手工替换文件继续运行。

SUCCESS 硬门：

    one software P-256 key                         true
    software private -> saved SPKI                true
    software SPKI != CDI identity SPKI            true
    software SPKI -> request sole key             true
    canonical PKCS#8 reopened + fresh PoP          true
    capture UID/0700/path/dev/inode/PID bindings  true
    source DICE/UDS/DeviceInfo exact match         true
    saved fetchEek challenge -> request/sign URL  byte-exact
    HTTP fetch/sign success                       true
    one returned chain / four certificates        true
    DER exact consumption                         true
    issuer/subject and all signatures             true
    pinned Google root                            true
    leaf SPKI -> software private                 true
    Provisioning Info leaf parseable              true
    full-chain exact NOT_APPROVED hits            zero
    ctf_no_not_approved                           true
    identity scalar -> identity SPKI              true
    identity SPKI -> source CDI leaf              true

android_schema_current_strict 是布尔报告字段，不在 SUCCESS_REQUIRED_TRUE 中。

### 10.1 离线最终验包

不要使用旧 package_verify_k70e_portable.py。用 stock 专用 verifier，并把 capture 目录和外部可信 profile 同时传入：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/verify_k70e_stock_log_submission.py \
      --submission-dir $HOST_ROOT/PRIVATE/SUBMISSION_DIR \
      --capture-dir $HOST_ROOT/PRIVATE/CAPTURE_DIR \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --output-report $HOST_ROOT/NEW/OUTSIDE_BOTH_INPUTS/verification.json

verifier 必须离线、只读，重算完整关系，检查 capture 下唯一 attempt 目录和 ATTEMPT/LIVE_STOCK_PREFLIGHT/DEVICE_STATE_DIR_PREPARED/DEVICE_LATCH/NETWORK_STARTED/SUCCESS，拒绝 BURNED、第二 attempt 或 marker hash 不一致。可选 output report 必须是两个输入树之外的新文件。

边界：这些本地 marker、HTTP metadata 和内部 hash 可以证明交付树内部一致、没有被验收器发现第二 attempt，但它们不是 Google 签名的交易回执，不能单独从密码学上证明“本次 fresh 网络交换”或真实 exactly-once dispatch。Google 证书签名证明链本身真实；若赛事还要求防重放 freshness，必须由赛事方提供 nonce、可信时间或服务端签名 receipt。

对外提交目录可以只包含三件套和自包含审计，但内部完整证据必须同时保留 capture、attempt 和 submission 三棵树；没有 attempt 证据时只能验证密码学包，不能证明一次性状态。

## 11. NOT_APPROVED 或服务端风险分支

### 11.1 返回 NOT_APPROVED

如果 exact approved-baseline live gates 全部通过，却仍返回 NOT_APPROVED：

1. raw response、HTTP metadata、request、私钥和整条链全部保留；
2. 发行器必须非零退出；
3. 不写 SUCCESS；
4. attempt 写 BURNED，retry_allowed=false；
5. 不再次 keygen，不再次 POST，不换 challenge 试探；
6. 该 attempt 到此结束，但根因调查必须继续；
7. 对照 clean native control 离线比较 DeviceInfo、五层 measurement/security、五层完整 payload、URL、fetch body 和 EEK；
8. 只有找到并修正具体偏差、新门全部通过后，才允许建立不同的 controlled attempt。

已知的两张异常证书是 HTTP 200 且无 429/quota/abuse，不能归类为简单次数风控。

### 11.2 HTTP 429、quota 或明确 abuse 状态

暂停外部请求。不要把网络代理、UA、challenge 或请求计数当作规避风控的变量；离线取证和代码审计仍可继续。

### 11.3 HTTP 200 且无 NOT_APPROVED

仍不能只看该字段。必须完成私钥、请求、证书和根链的全部关系门，最后再写 SUCCESS。

## 12. 另一台 K70E 的移植规则

另一台手机不能直接使用本机 profile。必须新建目标命名空间，并重新取得：

- 新 serial、fingerprint、slot、boot ID；
- 目标自己的 stock TA、TEE、lk/preloader 备份，以及与指纹对应的 known-good Magisk init_boot；
- 目标自己的 stock zero-key 或 one-key approved baseline CSR/challenge；
- 目标自己的 UDS 和五层 DICE；
- 目标自己的 known-approved Google leaf，且其 Provisioning Info 无 NOT_APPROVED；
- 新 run ID、新 capture 目录、新 issuance latch；
- 新 CDI_Leaf scalar、新软件私钥、新 Google 链。

目标 TA/TEE 与参考不同时必须 PORT_REQUIRED，不能把参考偏移或哈希塞进 profile。更重要的是：即使 TA/TEE 字节相同，也必须证明该设备自己的 signed DeviceInfo 和五层 DICE 是已获认可的 stock baseline。没有已认可基线时，只能证明结构正确，不能保证 Google 不返回 NOT_APPROVED。

stock TA 日志调用点若同固件字节相同，可复用解析语义；若 TA 不同，必须重新定位：

- SignWithDeviceKey；
- hwbcc_sign_key；
- get_attest_cdi；
- P256KeypairFromCDI；
- 成功后的 scalar 指针；
- dump_to_hex 调用；
- 两行日志语法。

只有静态闭合和同轮 SPKI 关系都成立，才允许创建目标版本的捕获器 allowlist。

## 13. 恢复和防砖边界

本 stock 日志路线本身不刷写、不重启。若 live hash 不匹配，捕获器会在 Binder 之前停止。恢复环境时：

- 当前参考机的最终恢复合同以文档 58 为准：官方 CN304 `super`/`preloader_a` 加该目标批准 preflash 的六个 full raw 输入；
- 每个写入目标先用 by-name、size、SHA 和 slot 只读确认；
- 固定顺序只允许 `super`、`vbmeta_system_a`、`vbmeta_vendor_a`、`vendor_boot_a`、`dtbo_a`、完整 raw `gz_a`、`lk_a`、最后的官方 `preloader_a`；
- whole `super` 是唯一跨槽例外；禁止显式 B/AB，且禁止写 TEE、boot、顶层 `vbmeta_a`、`init_boot_a`；
- 不 relock；
- 不触碰 seccfg、proinfo、persist、nvram、nvdata、efuse、RPMB、userdata；
- preloader 写入风险高，只有目标映射和 BROM 恢复已验证时才操作；
- 当前 by-name preloader_raw_a 与实际启动 LU 映射仍有平台歧义，因此最终授权仍以同轮 signed DICE 为准，不能只凭磁盘路径哈希。
- 在已启动的同一 boot 里把 TEE/TA 恢复为 stock、把 init_boot 恢复到 pinned known-good Magisk 锚，不会倒转已完成的 DICE 测量，也不会卸载 tee-supplicant namespace 里已加载的 TA。必须先让全部 early-chain 锚回到 approved-baseline 组合，然后新启动并重新捕获。
- 恢复任何失败都停留 Fastboot，不自动重试、回滚或重启；成功后的 reboot 是独立阶段。fresh boot 还必须由独立验证器全量通过并写 `POSTBOOT_VERIFIED.json`，该 marker 本身不授权联网。

用户允许刷机不等于所有分区都应写。这里的最小原则是：只为恢复 approved-baseline 启动测量而写，且一次只处理已确认目标。

## 14. 机密和证据边界

- CDI_Leaf scalar 和软件 PKCS#8 私钥不得打印、复制进聊天、截图、剪贴板、Git 或公共网盘；
- 命令行只传文件路径，不传 scalar literal；
- 禁止 set -x；
- 私有 capture/key 目录必须当前 UID 所有且精确 0700，文件精确 0600；不允许 symlink/hardlink/special file；
- 文档记录 hash、size、SPKI 关系和状态，不记录秘密字节；
- 旧失败包继续作为 negative fixture，不覆盖、不重签、不修改 manifest；
- 新输出只能是新目录，禁止 merge 多轮证据。

## 15. 当前剩余工作

截至本文冻结：

    K70E physical USB present               yes
    Pixel physically coexists               no
    stable native K70E ADB                   yes
    current HLOS/AVB approved                no; b9b1d867… rejected
    stable native ADB one-device session    yes; 21/21 native backend
    CN304 approved-environment restore      no; inputs/tool verified, attended run pending
    POSTBOOT_VERIFIED                       no
    live approved-baseline hashes verified no
    stock zero-key CSR triggered           no
    Binder zero-key one-shot consumed       no
    CDI_Leaf scalar captured               no
    offline issuance preflight             no
    Google new attempt                     no
    Google one-shot consumed                no
    new leaf without NOT_APPROVED           no
    final three-part submission             no

所以当前完成的是实现、静态闭合、根因定位和恢复/验收工具冻结，不是真机签发验收。稳定单 K70E native ADB 已通过；下一步是在用户当前交互明确在场后执行文档 58 的固定八步 CN304 恢复、独立 reboot，并以 `POSTBOOT_VERIFIED.json` 闭合批准环境。只有随后完成 approved-baseline fresh-boot 捕获、唯一受控签发并得到新链 `ctf_no_not_approved=true`，才能声称题目真机结果已解决。

## 16. 证据优先级

发生冲突时按下列顺序：

1. 新现场原始文件、hash、signed CSR/DICE、Google raw response；
2. capture_evidence_contract 和 strict issuance audit 的独立重算；
3. 文档 58、最终 recovery manifest 与 `POSTBOOT_VERIFIED.json`；
4. 文档 52–57；
5. README 唯一入口和当前 Skill；
6. 文档 45–51 的历史关系证据；
7. 文档 00–44 的研究过程。

任何自然语言 PASS 都不能覆盖 raw Provisioning Info 中的 NOT_APPROVED。


---

## 原始记录段 5 / Source section 5: 55_K70E_CTF_NOT_APPROVED与stock路线踩坑记录_20260906.md

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

## 原始记录段 6 / Source section 6: 65_K70E_CTF_clean_DeviceInfo_APPROVED完整流水线记录_20260906.md

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


---

## 原始记录段 7 / Source section 7: 67_K70E_CTF_DeviceInfo_NOT_APPROVED最终踩坑与故障树_20260906.md

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

## 原始记录段 8 / Source section 8: 68_K70E_CTF_NOT_APPROVED根因定位与APPROVED签发报告_20260906.md

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


---

## 原始记录段 9 / Source section 9: 69_K70E_CTF_Skill_v3更新与AI接手说明_20260906.md

# K70E CTF Skill v3 更新与 AI 接手说明

> Skill 名：`k70e-rkp-ctf`  
> 更新原因：2026-09-06 20:00 的 Google `PASS_CLEAN_HYBRID` 实验（程序原始状态 `PASS_CLEAN`）推翻了“modified DICE 必然 NOT、只能先恢复 stock”的旧核心结论。  
> 2026-09-07 增量：正式冻结提交候选与 `verify_hybrid_submission.py` 已完成，路径和验收锚点见文档 71。  
> 同步范围：安装版与工作区导出版同步更新。

---

## 1. Skill 位置

安装版：

```text
<CODEX_HOME>/skills/k70e-rkp-ctf
```

工作区导出版：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/05_Skill/k70e-rkp-ctf
```

两份应逐文件相同。

## 2. v2 过时的五个核心点

### 2.1 过时：项目尚无新私钥和 Google chain

新事实：成功 run 中已保存 `google-rkp-sw` 新生成 P-256 私钥和对应 Google 四证书链。

### 2.2 过时：modified DICE 会必然导致 NOT

新事实：exact modified five-layer DICE + clean DeviceInfo 获 `APPROVED`。

### 2.3 过时：只能先恢复 stock 再发行

新事实：已有 host-only hybrid 发行成功。stock 恢复只是 fully-stock fresh provenance 或修机支线的前置。

### 2.4 过时：必须再提取更底层 seed

新事实：当前 final leaf scalar 匹配 modified DICE leaf，已成功签 outer request 并获 Google APPROVED。

### 2.5 过时：Google one-shot 尚未消耗

新事实：hybrid clean-DeviceInfo one-shot 已消耗且成功，全局 claim 为 `CONSUMED_NO_RETRY`。strict-stock 路线自己的标记范围不能与它混淆。

## 3. v3 当前真相

```text
Google issuance evidence class   PASS_CLEAN_HYBRID
raw FINAL_RESULT.status           PASS_CLEAN
certificate chain               1 x 4
Provisioning Info               APPROVED
NOT_APPROVED hits               0
software private key            SAVED
private=request=leaf            TRUE
identity scalar=modified leaf   TRUE
modified DICE signatures        5/5 TRUE
source profile                  MODIFIED DICE + HISTORICAL CLEAN DEVICEINFO
semantic classification         RESEARCH_ONLY_HYBRID
organizer acceptance            PENDING / NOT RECORDED
phone recovery                  SEPARATE, STILL UNRESOLVED
```

## 4. 新的模式分流

### 4.1 审计/提交现有成功候选

优先读：

```text
references/hybrid-clean-deviceinfo-pass.md
工作区文档 65–70
```

只读操作；不碰手机，不访问 Google，不重跑 runner。

### 4.2 要求 fresh fully-stock same-run provenance

走 strict-stock 分支：

```text
references/cn304-recovery.md
references/stock-mitee-log-route.md
references/evidence-contract.md 的 strict-stock 部分
```

该分支仍需要解决手机双 AVB mismatch、恢复官方成对 boot images、新 `POSTBOOT_VERIFIED.json`、stock log 和新一次性授权。

### 4.3 另一台 K70E

必须作为新 target/port：

- 自己的 serial/UDS/DICE/final leaf scalar；
- scalar-to-leaf SPKI 门；
- 目标的 approved DeviceInfo/profile；
- 新 software key 和 Google chain；
- 独立 one-shot 账本。

不得复制参考机私钥、scalar、UDS 或证书冒充新机。

### 4.4 修手机

这是与现有成功候选分离的恢复任务。文档 59–64 的双 AVB mismatch/Fastboot/BROM 证据仍有效，不得因证书成功就认为手机已修好。

## 5. 证据合同必须分层

### 5.1 通用 Google/密码学关系

- identity scalar 合法且派生 SPKI 匹配实际 DICE leaf；
- DICE 签名链和 outer 签名有效；
- registered UDS 准确；
- software private SPKI = request sole key = Google leaf SPKI；
- software key != identity key；
- 唯一四证书 Google 链，签名、root self-signature 和 pin 通过；
- 全链 PI 无解析错误和 `NOT_APPROVED`。

### 5.2 本次 hybrid 固定关系

- exact 2026-09-05 modified registered UDS/five-layer DICE；
- current identity leaf SPKI `64c672...ba4ad2`；
- exact DeviceInfo from the 2026-08-29 same-handset historical clean-chain request；
- clean DeviceInfo canonical SHA `19f9f9...8fd921`；
- 新 software SPKI `1e5ec6...84bc67`；
- `research_only_semantically_hybrid=true`；
- global claim 已消耗，不可重跑。

### 5.3 strict-stock 额外来源关系

- same-run stock DeviceInfo+DICE；
- freshly captured stock leaf scalar；
- corrected recovery/readback/postboot 证据；
- live same-boot 与手机离线门；
- stock-log 专用 verifier。

第 5.3 是更严格的 provenance 要求，不能再宣称是 Google 返回 APPROVED 的普遍必要条件。

## 6. 核心因果口径

允许：

> 本次 exact modified five-layer DICE 在使用取自同机历史 clean-chain 请求的 DeviceInfo 时获得 Google APPROVED，因此这套 modified DICE 差异不是 `NOT_APPROVED` 的充分原因，且 clean tuple 对该次请求足以获批。在设备控制的 signed approval profile 内，首要嫌疑收窄到 DeviceInfo 的 `vb_state`、`bootloader_state`、`vbmeta_digest` 三项或一致性规则，其中回显的 clean vbmeta digest 是最强线索。三项同时变化，新 challenge/software key/request_id/时间/服务端状态也未固定，不能声称严格因果隔离。

禁止：

- “Google 完全不看 DICE”；
- “已严格证明只有 vbmeta_digest 一个字段负责”；
- “所有 K70E 都可直接复制 acaa digest”；
- “赛事方已经接收”；
- “手机已经修好”。

## 7. 秘密和账本规则

- 不打印、粘贴、截图、base64 或公开提交 identity scalar/软件私钥；
- 可报告路径、size、file SHA、SPKI SHA、关系布尔值；
- 本次 global claim 和 NETWORK_STARTED/SUCCESS 证据不得删除或重置；
- 本次成功已达到核心技术目标，不再为逐字段试探消耗签发；
- 离线验收不操作手机也不联网。

## 8. 下一位 AI 的强制阅读顺序

1. 顶层 `README.md`。
2. 文档 65：本次成功流水线。
3. 文档 66：私钥/证书位置和离线验收。
4. 文档 67：最终踩坑与故障树。
5. 文档 68：根因和影响报告。
6. 本文档 69：Skill 与接手边界。
7. 文档 70：证据哈希。
8. 只有在需要修手机或 strict-stock recapture 时才阅读文档 59–64 和 recovery/stock-log reference。

## 9. 现有成功证据锥点

```text
runner sha                116a47dd00421896e9526c1816a441fc30c521335436678707e613b2fdc89767
request sha               f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303
identity SPKI             64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
software/leaf SPKI        1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
software private file sha 58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
leaf DER sha              b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180
ordered chain sha         423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
Google root DER sha       6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
clean DeviceInfo CBOR sha 19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921
independent audit sha     473cac82fa8282bbc9f755aba53d7d1d132f9160273fbaefd8a16a7a3e1e4b0c
```

## 10. Skill 验收用例

### 用例 A：“给我现在的私钥和证书位置”

应直接给成功 run 中的 PKCS#8 DER 和 ordered chain DER/PEM 路径，附 size/hash，不打印私钥。

### 用例 B：“是不是 DICE 污染导致 NOT？”

应回答：这套 exact modified DICE 已随 clean DeviceInfo 获 APPROVED，因此不是充分原因；在设备控制的 signed profile 内三项/一致性是首要嫌疑，但每次必变变量和服务端状态未固定，不能写成绝对根因，也不能泛化到所有 DICE。

### 用例 C：“再跑一次看看是哪个字段”

应说明现有 one-shot 已消耗且核心目标已达成，不删 marker、不重放；如确有新的赛事必要性，必须建立独立新授权和实验设计。

### 用例 D：“另一台 K70E 直接用这套私钥行不行？”

应拒绝身份复制，并转到 target-specific onboarding：新 UDS/DICE/leaf scalar、新 software key/chain、新 one-shot。

### 用例 E：“证书成功是不是说明手机已经修好？”

应明确回答不是；本次没碰手机，恢复状态必须从独立现场证据确认。

## 11. 终态描述

Skill v3 应使用下列精确语句：

> 参考 K70E 已有一份主机端一次性 `PASS_CLEAN_HYBRID` 候选（程序原始状态 `PASS_CLEAN`）：当前 modified 五层 DICE 和其 final leaf scalar 保持原样，搭配取自同机历史 clean-chain 请求的 DeviceInfo，为一把新 `google-rkp-sw` P-256 软件私钥取得了有效 Google 四证书链；leaf Provisioning Info 明确为 `APPROVED`，全链无 `NOT_APPROVED`。该 run 为 semantic hybrid，Google/密码学/PI 审计已通过，赛事方对这份新包的最终回执尚未记录。这一次性请求已消耗，后续默认只做离线验收与交付。


---

## 原始记录段 10 / Source section 10: 70_K70E_CTF_clean_DeviceInfo_APPROVED证据SHA256_20260906.txt

# K70E clean-DeviceInfo APPROVED evidence SHA-256
# Immutable run evidence section (lines until the next heading) is relative to:
# 03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/
# This list intentionally does not contain secret bytes; hashes of secret files are permitted audit metadata.

89a9bd0507307c709c819d1a7e6fc53552745520207dfa7ec78004ae29f0b650  ATTEMPT.json
8135d8674e20f5c3ebb0b265f2a31e46af2b4c70c3a8833e7b0d83e0cbaff36f  FINAL_RESULT.json
a835e153f98be7c03751bbe4e20e31448c576555676685b569ab32cfefb91e0b  INPUT_AUDIT.json
9e92b7c7e9a5a4b1f41b3ebfde144e8f50fbc089494861b6f854dc2a17970b9f  REQUEST_AUDIT.json
7152637f112863076a970829f7b80b9d3c56c8622dd93509df6fc68f56bdaf90  RUN_STARTED.json
54d69f9ea17cb1020ad889bdd44e7a378b5f749946406f4ebfc36165d2b27839  SUCCESS.json
f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303  certificate_request.cbor
b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180  chain_00/cert_00.der
c14b3197ebc5fbfd3afad79ac5d51a6d207a5d3551bfd303eb8670398393051e  chain_00/cert_00.pem
12642d51c5a0f2900625517363d78758bbf905a4609bc1463cf8589bcedb97fd  chain_00/cert_01.der
f7ad96a8537c997b6bbc9db5dfb7c54e9dedfba50b20b8047c72faebbd68810d  chain_00/cert_01.pem
187521be8eec99791aa793ab339172a67f05b1ec1d1259adbe6d5fe7d7f5d43b  chain_00/cert_02.der
7ef6098c4ea6b4765f9fdf21ad4cab26f0ae690b9c22657254103d22bcafa662  chain_00/cert_02.pem
6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0  chain_00/cert_03.der
979d0f7fba6c2e28cc05a5d67e8f21f705b90379291cbc80291eb224cc11586b  chain_00/cert_03.pem
423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20  chain_00/certificate_chain.der
358b5269c517a29fc2cc0731375a14deadd038336fc029b96ff3c9be9928a9e6  chain_00/chain_summary.json
b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180  chain_00/ordered_cert_00.der
c14b3197ebc5fbfd3afad79ac5d51a6d207a5d3551bfd303eb8670398393051e  chain_00/ordered_cert_00.pem
12642d51c5a0f2900625517363d78758bbf905a4609bc1463cf8589bcedb97fd  chain_00/ordered_cert_01.der
f7ad96a8537c997b6bbc9db5dfb7c54e9dedfba50b20b8047c72faebbd68810d  chain_00/ordered_cert_01.pem
187521be8eec99791aa793ab339172a67f05b1ec1d1259adbe6d5fe7d7f5d43b  chain_00/ordered_cert_02.der
7ef6098c4ea6b4765f9fdf21ad4cab26f0ae690b9c22657254103d22bcafa662  chain_00/ordered_cert_02.pem
6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0  chain_00/ordered_cert_03.der
979d0f7fba6c2e28cc05a5d67e8f21f705b90379291cbc80291eb224cc11586b  chain_00/ordered_cert_03.pem
423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20  chain_00/ordered_certificate_chain.der
c63a4e76d3af5cc6f857ca6bbf102f5a63d2755aab3a088ba39a5e7045defc34  chain_00/ordered_certificate_chain.pem
5b2944cc636574445c275e1817bb307897b8e0c51bac0e8a16cd1e580634ff08  chain_00/ordered_untrusted_intermediates.pem
70451453a549999e66ec652d77c770e7f8edeab15dd53cd78a543c7d25e39219  challenge.bin
843cddbba747228feb1f3ccaf319f6cf1d660d5824380f7413815e9270994336  clean_device_info.json
4868e30ca3d3307cf874c18de18a91725d7584d6a701b44fe04a73dc1315ed9a  fetch_eek_NETWORK_STARTED.json
fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2  fetch_eek_request.cbor
1b1beb4de1dac45e476a5291c23e1d487954bcfd5211dd25eded6e0bfea1e6cb  fetch_eek_request.json
b4eb4e924d406be2355e5ba14c3ab5b47c8a85473b21c6dc1e63cce3fd44d250  fetch_eek_response.raw
c6c0214f6ee7617976303e3703c33515e9a5a65893773c405dfade5bc7c4332e  fetch_eek_response_http.json
c6f57e75d1ae3cfbdd7c5d248c00fc8c51e6067c1c7f0b754d415b5b62c83c36  key_00/key_summary.json
58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8  key_00/private_key_pkcs8.der
1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67  key_00/public_key_spki.der
98d63b9641a0ce4a49f4714bb0d1263a3effb467497aaf65b3977638dac84493  sign_certificates_NETWORK_STARTED.json
f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303  sign_certificates_request.cbor
d035856e66720ba25fe09bd7987d632e757a9842ca9eb1671331a37926a12359  sign_certificates_request.json
9cc11011bb67258487a7a3cc3b23bcb36f996839c6770e169c6adec2891cb939  sign_certificates_response.raw
bd30cf2495c2b02981c2ddf80ea24a90a1c71b6f525f7338a0b84acd32a8c705  sign_certificates_response_http.json
842b5124721d07b84291c8e95406801f0bf88bb7ba0066ee740a42ceaa1d21ea  verified_modified_dice.cbor
c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0  verified_uds_certs.cbor

# External input/tool/audit anchors below are relative to PROJECT:
# <PROJECT_ROOT>/<DEVICE_WORKSPACE>/
116a47dd00421896e9526c1816a441fc30c521335436678707e613b2fdc89767  02_脚本与补丁/run_k70e_modified_dice_clean_deviceinfo_once.py
724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  02_脚本与补丁/k70e_portable_profile.py
c8f7eb8d20474a549aa73a301a8ca1780586853c057e9b5421307057f8566b47  03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/native_trigger_csr.cbor
ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c  03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2  03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/identity/cdi_leaf_public_spki.der
f03011311dca791fccca64f1f78323ba113197f56ac368fbdeeb97162c3ccf56  03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/certificate_request.cbor
473cac82fa8282bbc9f755aba53d7d1d132f9160273fbaefd8a16a7a3e1e4b0c  03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_INDEPENDENT_AUDIT.json
dc808ae4668a5470a891b300697907b65778e5c82f060d7bdeea881ad8a38f58  05_Skill/k70e-rkp-ctf/scripts/audit_provisioning_info.py
e9c7cf433d4d313779ff4b8b8291845a9c3c2d7f29cad00d88fc63a5c76a1149  ../.k70e_google_rkp_hybrid_clean_di_ledger/MODIFIED_DICE_CLEAN_DEVICEINFO_ONCE.CLAIM.json
619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  ../third_party/google-rkp-sw/rkp_sw.py

# 2026-09-07 frozen hybrid submission and verifier anchors:
40c5fb66de0db42187900382e2523ca34ca01d2a8ae70c01edafd78e1b0aa40c  00_文档/71_K70E_CTF_PASS_CLEAN_HYBRID正式提交包与校验器_20260907.md
b1c946f4e78c99319aa0373be2cef08b1c8b5f06382f9a455e1b394a2c328934  02_脚本与补丁/verify_k70e_hybrid_submission.py
b1c946f4e78c99319aa0373be2cef08b1c8b5f06382f9a455e1b394a2c328934  05_Skill/k70e-rkp-ctf/scripts/verify_hybrid_submission.py
cea16a1d15a61e2546f3245da2a4dc283b6543d3177c6bc7c140dc48abde6505  03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL/SHA256SUMS.txt
b1c946f4e78c99319aa0373be2cef08b1c8b5f06382f9a455e1b394a2c328934  03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL/99_verifier/verify_k70e_hybrid_submission.py
9e2cb8fb517dc60a6a3085240e64e90160a0516543d608def45d4472e9b31bd7  03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL_VERIFICATION.json


---

## 原始记录段 11 / Source section 11: 71_K70E_CTF_20260906_RKP证书离线验收与Pixel部署记录.md

# K70E CTF：RKP 证书离线验收与 Pixel 部署记录

日期：2026-09-06  
项目：Redmi K70E / duchamp CTF 靶机研究

## 1. 本次输入材料

本次检查针对以下一次性签发产物：

- PKCS#8 DER 私钥：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/key_00/private_key_pkcs8.der`
- 四证书链 DER：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.der`
- 四证书链 PEM：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.pem`
- 叶证书 DER：
  `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_cert_00.der`

私钥文件权限为 `0600`。文档不记录私钥内容、标量、PEM 私钥文本或任何可恢复私钥的材料。

## 2. 文件摘要

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `private_key_pkcs8.der` | 138 B | `58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8` |
| `ordered_certificate_chain.der` | 2486 B | `423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20` |
| `ordered_certificate_chain.pem` | 3593 B | `c63a4e76d3af5cc6f857ca6bbf102f5a63d2755aab3a088ba39a5e7045defc34` |
| `ordered_cert_00.der` | 565 B | `b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180` |

## 3. 离线验收结果

### 私钥与叶证书关系

- 私钥派生公钥 SPKI SHA-256：
  `1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67`
- 叶证书公钥 SPKI SHA-256：
  `1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67`
- 结论：匹配。

### 证书链

- 证书数量：4
- 叶证书：`CN=df5d0b538f137beaf18aa9ab7252043a, O=TEE`
- 叶证书签发者：`CN=Droid CA3, O=Google LLC`
- 链路顺序：叶证书 -> Droid CA3 -> Droid CA2 -> Key Attestation CA1
- 所有证书字节均被严格消费，无尾部数据
- 子证书签名链验证：通过
- 根证书自签名验证：通过
- 根证书 SHA-256：
  `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`
- 结论：四证书链结构和签名关系正常，根与项目固定的 Google Key Attestation CA1 锚点一致。

### 叶证书有效期

- 生效：2026-09-04 12:00:30 UTC
- 到期：2026-09-16 14:47:51 UTC

## 4. Provisioning Info 扩展解析

目标 OID：`1.3.6.1.4.1.11129.2.1.30`

叶证书 CBOR 解码结果为：

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

检查结果：

- 叶证书扩展存在
- CBOR 单项解析成功
- 无尾随字节
- 原始 CBOR 长度：91 B
- 原始 CBOR SHA-256：
  `8a28b6caee0213767426c60bacb6e9fae9ad064fbe24d18449583fea2041dab7`
- 链中 `NOT_APPROVED` 命中数：0
- 解析错误数：0
- 非叶证书未携带该扩展，符合本次链审计结果

## 5. 结论

这组产物通过了离线材料验收：

1. 私钥与叶证书公钥匹配。
2. 四证书链完整，签名和根锚点验证通过。
3. Provisioning Info 可解析，叶状态为 `APPROVED`，没有 `NOT_APPROVED`。
4. 因此，当前证书文件、私钥编码、证书链顺序和 CBOR 扩展不是明显的格式错误来源。

该结果对应原始流水线的 `FINAL_RESULT.status=PASS_CLEAN`，但语义标签仍为 `PASS_CLEAN_HYBRID` / `research_only_semantically_hybrid`：它是研究用的混合来源候选，不能等同于赛事方已接受，也不能等同于全量 stock 同次运行证明。

## 6. Pixel 部署状态

本次没有连接、刷写、重启或修改 Pixel，也没有将私钥和证书写入或替换真实设备的 Trickystore。原因是这会改变真实设备对外呈现的硬件认证状态，超出本记录的离线 CTF 材料验收范围。

后续安全测试应使用 Android Emulator、本地模拟 verifier 或专用隔离靶机，并保留原始证书、哈希和验收日志作为只读 fixture。

## 7. 证据来源

- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/FINAL_RESULT.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/REQUEST_AUDIT.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/chain_summary.json`
- `03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/chain_00/ordered_certificate_chain.der`
