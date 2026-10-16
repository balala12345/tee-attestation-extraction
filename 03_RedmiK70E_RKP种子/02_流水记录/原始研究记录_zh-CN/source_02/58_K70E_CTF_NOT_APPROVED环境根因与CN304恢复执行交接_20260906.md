# K70E CTF `NOT_APPROVED` 环境根因与 CN304 恢复执行交接

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 因果覆盖：**本文的 CN304 恢复事实仅作历史，旧八步合同已被实机双 AVB mismatch 推翻。更重要的是，exact modified DICE + clean DeviceInfo 已获 Google `APPROVED`，所以“必须先恢复 stock 才能解决 NOT”已过时。见文档 65–70。

> **2026-09-06 18:05 最高优先级撤销说明：** 本文是恢复前计划，已被文档 59–63 覆盖。本文所述八步恢复已实际执行并重启；step 4 的 `501ec32c…` 经逐字节复核是 OrangeFox vendor_boot，不是官方 CN304，且被保留的 `9d5d12a7…` 是 Magisk init_boot。二者均不匹配 stock `vbmeta_a`，已出现 `the system has been destroyed`。当前恢复/验收程序及三个旧 SHA 清单不得再作为执行授权；暂停期间不得操作手机。

> 日期：2026-09-06（Asia/Taipei）  
> 目标：Redmi K70E / duchamp / `<DEVICE_SERIAL>`  
> 历史状态（已失效）：恢复已经执行并重启；旧计划造成双 AVB mismatch。本文只用于审计计划为何失败，不得执行其中命令。approved-stock 专用 one-shot 尚未开始，generic/default 负实验已有网络 marker，仍无新的 clean chain。  
> 权威性：本文被文档 59–63、更新后的 Skill 和暂停 manifest 覆盖；旧 manifests 只作漂移证据。

---

## 1. 已经排除简单尝试次数风控

现有 27 张不同 DER 的 Provisioning Info 证书中，25 张干净，2 张含 `NOT_APPROVED`，0 张解析失败。12 张干净证书与 2 张失败证书同样是键 1 计数 32。两个失败请求均为 HTTP 200，没有 429、`Retry-After`、`quota` 或 `abuse`。

同一 modified 环境中，真机 Binder 和 host google-rkp-sw 返回了逐字节相同的拒绝扩展：

```text
{1:32, 3:"Xiaomi", 5:{1:"NOT_APPROVED"}}
```

因此当前证据分类是：

```text
simple attempt/count risk       EXCLUDED BY OBSERVED CONTROL
host framing as primary cause   EXCLUDED BY NATIVE CONTROL
environment/request divergence  PROVEN PRIMARY ROOT-CAUSE FAMILY
```

只有未来出现明确 429/`quota`/`abuse` 才暂停外部请求。`NOT_APPROVED` 烧毁的是当前 ATTEMPT，不是整个调查。

## 2. 真机拒绝环境已复现

Pixel `<DEVICE_SERIAL>` 已不在场；IORegistry 和 native ADB 只看到目标 K70E，Fastboot 为空。连续稳定性检查已通过。当前真机 HLOS 哨兵为：

```text
ro.boot.vbmeta.size                 13120
ro.boot.vbmeta.digest               b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744
ro.build.host                       <BUILD_HOST>
ro.crypto.state                     unsupported
ro.control_privapp_permissions      <empty>
ro.miui.build.region                gb
ro.product.locale                   en-GB
```

批准基线必须是：

```text
ro.boot.vbmeta.size                 13184
ro.boot.vbmeta.digest               acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9
ro.build.host                       <BUILD_HOST>
ro.crypto.state                     encrypted
ro.control_privapp_permissions      enforce
ro.miui.build.region                cn
ro.product.locale                   zh-CN
```

HLOS 属性不能替代 signed DeviceInfo/DICE，也不是正向认可权威；它们在当前冻结工具中仅作为“已知坏环境的负向排除门”。

最新 `--live-check-only` 没有写设备、没有调 Binder、没有联网；它在一次性边界前因空 `control_privapp_permissions` 严格 `SAFE_ABORT`。运行后：

```text
zero_key_invocation = 0
ATTEMPT            = 0
DEVICE_LATCH       = 0
NETWORK_STARTED    = 0
BURNED             = 0
SUCCESS            = 0
```

## 3. AVB 重建证明是启动环境，不是随机服务端标签

离线精确重建得到：当前顶层/boot 与社区 system/vendor child VBMeta 组合的最终 digest 正好是 `b9b1d867…9744`；原批准 child VBMeta 组合正好是 `acaa9258…b6e9`。批准与失败 signed DeviceInfo 不同，DICE 第 1/2/4 层 measurement/security 不同，五层完整 payload 全部不同。

结论：不应再修改 Google 请求格式或用更多请求试探；必须先恢复批准启动链/HLOS 组合，然后 fresh boot 重新采集。

## 4. 恢复前备份已闭合

当前拒绝环境的 11 个 A 槽 raw 已只读备份到：

```text
01_设备输入/duchamp_拒绝环境刷前只读备份_20260906_125645/
```

11/11 长度和 SHA-256 已核验。该目录是失败环境回退证据，不是批准恢复源。

当前仍正确、必须保留的 A 槽锚：

| 分区 | SHA-256 |
|---|---|
| `vbmeta_a` | `c38281042cd2581421c4589ee2ccaf349e929d1e6a1390b915133c3bb2291ce0` |
| `boot_a` | `8a7f406b56e6db22a910eef5370e9f2cbcf08a3e7e5be8fff6fbbe19a42058b8` |
| `tee_a` | `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d` |
| `init_boot_a` | `9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4` |

不得再刷 TEE；已有实证说明 patched TEE 会改变服务器可见 DICE 并返回 `NOT_APPROVED`。

## 5. 官方 CN304 恢复输入已验档

位置：

```text
../刷机资源_只读下载_20260831/duchamp_CN304_official_verified_20260906/
```

上游整包：

```text
length  9,219,698,464
MD5     e6fa23dfda27bbf653545d1ccc8e6343
gzip -t PASS
tar full traversal PASS / 63 members
anti_version.txt = "1\n"
```

官方 `super.img`：

```text
size           9,094,580,440
SHA-256        aac250546e07dda942610c112038f61d1d3982980ae92c3efa790879c03f7290
expanded size  9,663,676,416
```

官方 `vendor_a` 中 stock KeyMint TA 是 1,401,936 字节，SHA-256 `facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`，与批准 TA 精确一致。完整 A 槽 9 个动态分区 size/hash 在 `SUPER_A_PARTITIONS_VERIFIED.json`。

`SUPER_METADATA_ALL.json` 的 B size 存在工具解析器错位，不可作权威值；实际包内 `*_b` 都是 `num_extents=0,size=0`。A 槽 9 项是单 linear extent，不受此 bug 影响。

## 6. 唯一允许的恢复集合

| 顺序 | Fastboot 目标 | 源 | 长度 | SHA-256 |
|---:|---|---|---:|---|
| 1 | `super` | 官方 `super.img` | 9,094,580,440 | `aac250546e07dda942610c112038f61d1d3982980ae92c3efa790879c03f7290` |
| 2 | `vbmeta_system_a` | 目标 preflash raw | 8,388,608 | `b3fa87e82361a8f6efc0a3b170ae9fe75111681e64e184405bd36d0c426503ee` |
| 3 | `vbmeta_vendor_a` | 目标 preflash raw | 8,388,608 | `ec0f5244b94798dae89875d91afea7e0651064dc1dcfdd5f4e5738158dbbbe5e` |
| 4 | `vendor_boot_a` | 目标 preflash raw | 67,108,864 | `501ec32cb585c60c4db9245266c16469eb42b31f7b4fb37b8f8f6d1c7d45d9c9` |
| 5 | `dtbo_a` | 目标 preflash raw | 8,388,608 | `6def7656d2a130bff752754647d37d2003416f2277d4c8cce79c954fadd83336` |
| 6 | `gz_a` | 目标 preflash 32 MiB raw | 33,554,432 | `21ebe0bbc10e0ddd6632b989840ef1adab29ae3e4da09133880d47a6fbf5a177` |
| 7 | `lk_a` | 目标 preflash raw | 16,777,216 | `9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35` |
| 8 | `preloader_a` | 官方 payload | 746,772 | `d6edfdaa9a1ace48013c9ce6336b504e0b5adcd997e2c54fd6deb8ad4c05e9d1` |

官方短 `gz.img` 与目标 raw 前缀完全一致，raw 余部全零。恢复使用目标 32 MiB raw，以直接写满批准整分区哈希，不依赖 Fastboot 对短文件的尾部语义。

## 7. 恢复边界与 whole-super 例外

`super` 是无槽物理容器，官方 LP 元数据涵盖 A/B 命名空间。因此 whole `super` 是唯一明确授权的跨槽例外，不得声称 B 动态内容 bitwise 保留。

除这个例外外：

- 禁止任何显式 `_b`、`_ab` 或 B boot-chain 写入；
- 禁止 `tee*`、`boot*`、顶层 `vbmeta_a`、`init_boot*`；
- 禁止 erase/format/wipe/set_active/lock/unlock/`oem cdms`/fastbootd/`flash_all*`；
- 第一轮禁止擦 `metadata` 或 `userdata`；
- 每个命令必须用绝对 Fastboot 路径和 `-s <DEVICE_SERIAL>`，不经 shell；
- `super` 第一，`preloader_a` 只能在前七步全部成功后最后执行；
- 任何失败/超时/掉线/不可解析输出都不执行下一步，不自动重试、不自动回滚、不重启，保留在 Fastboot。

历史实证 Fastboot 关键预期：

```text
serialno               <DEVICE_SERIAL>
product                duchamp
current-slot           a
anti                   1
is-userspace           no
max-download-size      0x8000000
slot-count             2
snapshot-update-status none
slot-unbootable:a      no
partition-size:super   0x240000000
has-slot:super         no
```

当前 Android ROM 没有 `/system/bin/bootctl`、`/vendor/bin/bootctl` 或 snapshotctl；`update_engine_client` 也不支持 `--status`。不得把“命令不存在”当成 `none`。ADB 阶段仅记录 `ro.virtual_ab.enabled=true`和“非权威”；写入前必须由 fresh Fastboot `getvar snapshot-update-status` 精确返回 `none`，空值/unknown 均停止。

## 8. 两阶段防呆执行

恢复器使用主机耐久 marker，不运行官方 `flash_all*`：

```text
restore_k70e_cn304_approved_environment.py
SHA-256  3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9
size     109,993
tests    35/35 PASS
```

1. ADB audit/preflight：只读检查物理目标、唯一 ADB、空 Fastboot、离线路由、电量、当前拒绝环境 raw 和四个保留锚，重验所有源文件后 exclusive 写 `PREPARED.json`。
2. 用户手动进入 Fastboot。
3. Fastboot execute：fresh IORegistry/transport/getvar/partition-size/has-slot 全部通过，从真实 TTY 输入 serial、nonce 和固定范围短语，全局 ledger 一次性 claim，再按八步固定写入。
4. 八步都成功后写 `FLASH_COMPLETE.json`，默认仍停 Fastboot。
5. 独立复核后才允许唯一 reboot；成功开机后做 ADB 只读 post-boot 验证。

恢复/重启/采集/Google one-shot 都必须在同一次当前交互中收到用户明确说“我现在人在 K70E 旁边，可以开始恢复”。旧消息、heartbeat 或脚本 `--attended` 参数本身都不算新的现场授权。

## 9. post-boot 批准门

重启后必须在任何 Binder/RKP/Google 之前验证：

- 唯一物理 K70E，唯一 online ADB，Fastboot 空；
- boot complete、slot A、Magisk root；
- 恢复的 7 个 raw A 分区和 `preloader_raw_a` 必须等于本文批准哈希；
- `vbmeta_a/boot_a/tee_a/init_boot_a` 必须仍等于四个保留锚；
- B 独立 boot-chain raw 必须与恢复前记录一致；不声称 B 动态内容不变；
- `SUPER_A_PARTITIONS_VERIFIED.json` 中 9 个 A 逻辑分区 size/SHA-256 全部匹配；
- stock KeyMint TA 为 `facdfe3d…3f32`；
- HLOS 哨兵为 `13184/acaa9258…/pangu/encrypted/enforce/cn/zh-CN`；
- `--live-check-only` 完整通过；
- 全盘一次性 marker 盘点仍为 0。

9 个 A 逻辑分区总读取量约 9.12 GB，须串行、给足超时。不得只凭属性就写 `POSTBOOT_VERIFIED`。

冻结的独立验证器为：

```text
verify_k70e_cn304_approved_postboot.py
SHA-256  c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add
size     99,185
tests    24/24 PASS
```

它硬钉上述最终恢复器身份和保存的恢复账本，逐项验证 `PREPARED`、global claim、8 组 STARTED/OK/raw Fastboot 输出、`FLASH_COMPLETE`、独立 reboot、fresh boot ID、物理/ADB/Fastboot inventory、离线路由、A/B raw、9 个 A 逻辑分区、stock TA/services 与 HLOS 哨兵。只有全部通过才以独占、持久方式写主机侧 `POSTBOOT_VERIFIED.json`；该 marker 明确不表示 Binder、RKP 或 Google 网络已授权。真实运行会串行读取超过 9.1 GB，目前只完成 host-only mocks，尚未实机生成此 marker。

如果除 `ro.crypto.state` 外全部恢复为批准值，但 crypto 仍为 `unsupported`，状态必须是“启动链已恢复，加密状态阻塞”。不得自动擦数据，不得进入 RKP。只有在再次盘点 marker 为 0 后，获得独立的数据毁灭确认，才可以同时重建 `metadata` 和 `userdata`；禁止只擦一个。

## 10. 恢复后唯一 CTF 流水线

只有 post-boot 全部通过后，才允许：

```text
capture_k70e_stock_cdi_log_once.py --attended --execute-zero-key-once
  -> rkp_sw_stock_log_once.py --preflight-only
  -> rkp_sw_stock_log_once.py --attended --execute-google-once
  -> verify_k70e_stock_log_submission.py (offline)
```

最终必须同时得到：

1. 目标 K70E 的 google-rkp-sw CDI_Leaf 身份数据；
2. 该轮新产生、耐久保存的 canonical P-256 PKCS#8 软件私钥；
3. 叶公钥与该私钥相等的 Google 证书链；
4. 全链 raw Provisioning Info 精确 `NOT_APPROVED` 命中数为 0；
5. strict audit、`SUCCESS`和独立 stock verifier 全部 PASS。

在这五条实际成立前，本题仍未完成。

## 11. 当前主机发布状态

```text
core rkp_sw.py          619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822 / 193161
profile helper          724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57 / 134026
stock collector         732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c / 75305
collector test          67e38a25a96c026595ca6a3157c3bc4a5639c6cf969609b461348b7d3bfdfd2d / 50002
stock issuer wrapper    99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3 / 121031
wrapper test            d2a6bc8fe54eef5b36fc8bf15e4ece71b82061d9eaec6eb979939094cf399793 / 99075
stock verifier          f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357 / 120223
runtime profile file    5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81 / 17803
runtime internal hash   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
offline regression      23+13+12+31+10+10+42+37 = 178/178 PASS
restore tool            3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9 / 109993
restore test            15bb1201dcb4180b37ff3f776393aca98a4b9f6b33748f83f1c508741054adc7 / 43802 / 35/35 PASS
postboot verifier       c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add / 99185
postboot test           c13433501cdb3870852e2494e5055b556a11b565e9ad19d58bf3e04e9a7c476b / 42736 / 24/24 PASS
```

Android `ip route` 在当前 ROM 会给合法 dummy0 行加 ASCII 尾空格。修复只在完整 transport framing 通过后对单条 route 做 trim/token 语义解析，没有放宽 dummy0/table-1002 grammar。最新 wrapper 主测试 42/42 通过，另有 39 个非法 frame、4 个键值边界空白和 2 个 stripped dummy route 的独立补充矩阵通过。

三组测试应分开表述：stock 工具链 `178/178`、恢复器 `35/35`、post-boot 验证器 `24/24`，合计 237 项但权限边界不同。`SHA256SUMS_PORTABLE.txt` 必须包含四个新增恢复/验收程序；`SHA256SUMS_RECOVERY_CN304.txt` 必须绑定八个生产输入、官方 super 元数据和四个程序；全部文档/Skill 完成后最后重建 `SHA256SUMS_HANDOFF.txt`。任何一个 manifest 未通过都不得声称交接闭合。
