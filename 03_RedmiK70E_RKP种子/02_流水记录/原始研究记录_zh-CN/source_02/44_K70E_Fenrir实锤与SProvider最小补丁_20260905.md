# K70E Fenrir 实锤与 SProvider 最小补丁

> **2026-09-06 适用性更正：** 本文仍能证明 Fenrir/SProvider 技术事实，但该路线改变 Google 可见的 DICE 第 1/2/4 层，所得真机 Binder 和 host `google-rkp-sw` 证书都含赛事不接受的 `NOT_APPROVED`。不得把本文路线当作合格签发方案；见文档 52。本文第 10 节原有“stock 日志没有 CDI_Leaf scalar”结论也已被原厂 TA 精确调用图推翻；当前唯一主路线是文档 52–57 的原厂 stock MiTEE 日志路线。

日期：2026-09-05  
设备：Redmi K70E / `duchamp` / 当前槽 `_a`

## 结论

当前启动链已经在运行官方 duchamp Fenrir LK，并且 Fenrir 对 TEE 子镜像的认证旁路确实生效。属性层显示的 `green`、`flash.locked=1` 是该启动链的伪装结果，不能再据此阻断 CTF 工作，也不需要小米账号的正式解锁授权。

旧 `tee_a_v4_patched.img` 的启动失败不是“Fenrir 无法放行修改 TEE”的证据。该文件在重建时丢失了 LZ4 frame 后面的证书和 `spmc_dtb` 条目，本身就是结构损坏镜像。

新的最小方案已经完成主机侧构建和两轮离线校验：

1. 修改后的 KeyMint TA 更新 body SHA-256 和 header SHA-256，使两个摘要门都自洽；
2. 只修改 BootFS `bin/svchost`/SProvider 的 RSA 结果门一条 4 字节指令；
3. RSA 验证函数仍执行，只有失败结果被忽略；后续 body/header digest 验证完全保留并强制执行；
4. TEE 镜像大小、69 个 LZ4 block descriptor、所有 block 偏移、frame 结束位置和 frame 后全部字节保持原样。

截至本文记录时，候选文件尚未写入手机；手机的 `tee_a` 仍是原厂哈希。

## 1. 当前 Fenrir 运行时证据

设备只读复核：

```text
slot=_a
ro.boot.verifiedbootstate=green
ro.boot.flash.locked=1

lk_a whole SHA-256:
428f49b5e3898e5504ea7e6c640c55190df75842fe3169e0f877f1f4da1249c0

lk_a first 3,395,824 bytes SHA-256:
615d437f33fb9addea9b9bd56d8fbd5a8d17bc35b13546815a673248a8e0bf19

tee_a SHA-256:
18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

`lk_a` 的有效前缀哈希与官方 duchamp Fenrir LK 完全一致。全分区哈希不同只是因为 16 MiB 分区尾部填充。

当前 `/dev/block/by-name/expdb` 的启动记录对 TEE 给出：

```text
tee image name found
mkimg hdr detected (3106816)
img_auth_required = 0
[SEC] tee cert parsing pass.
Load 'tee_a' partition to 0x0xffff0000bffffdc0 (3106816 bytes in 3 ms)
[DICE] BL2_EXT [tee] DICE flow #2 success in 25 ms. (pkc: 0, ekc: 0)
```

这组证据直接推翻 `42_K70E_项目交接与踩坑记录_20260903.md` 中“`sbcen_unlock=2 -> img_auth_required=1 forever`、Fenrir 在 K70E 不可用”的旧结论。后续不得再用账号授权、`green/locked` 属性或该旧结论阻塞 CTF。

## 2. 旧 v4 启动循环的真实原因

原厂与旧 v4 的 BootFS LZ4 frame：

| 项目 | 原厂 | 旧 v4 |
|---|---:|---:|
| frame start | `0x1c6188` | `0x1c6188` |
| frame end | `0x3e076c` | `0x3e0573` |
| frame length | `0x21a5e4` | `0x21a3eb` |
| block count | 69 | 69 |
| last non-zero byte | `0x3e2c85` | `0x3e0569` |

TEE 顶层 `tee` 条目声明的下一条目固定从 `0x3e0930` 开始。原厂从这里依次包含：

```text
cert1     @ 0x3e0930
cert2     @ 0x3e1200
spmc_dtb  @ 0x3e17e0  (name bytes at 0x3e17e8)
cert1     @ 0x3e1de0
cert2     @ 0x3e26b0
```

旧 v4 在其 frame 结束后全部为零，五个条目全部丢失。因此旧 v4 启动循环最合理且可逐字节证明的原因是镜像尾部被构造器截断，而不是 OEM/Fenrir 验签拒绝。

旧 v4、旧 `build_patched_tee.py` 和任何会全量重压、移动顶层条目或丢弃 frame 后字节的产物不得再刷。

## 3. 正确的 REE TA 加载门

`/vendor/mitee/ta` 的 normal-world provider 路径由 BootFS `bin/svchost` 内的 SProvider 处理：

```text
secure VMO map                  0x33f7c..0x33f98
REE 分块复制到 private VMO      0x34274..0x342a4
signed header parser            BL @ 0x343c0
RSA verifier                    BL @ 0x343f8 -> 0x33bd8
RSA result gate                 0x343fc
body/header digest verifier     BL @ 0x34430 -> 0x338f8
digest result gate              0x34438
去掉 0x150 外层头并返回 VMO      0x34464..0x34474
```

SProvider 返回的是已经去掉签名头的 VMO；`ta-mgr` 后续直接把同一 VMO 交给 ELF/launchpad，不会再对 provider VMO 重新做外层签名验证。因此只补 `bin/ta-mgr` 对这个 bind 场景无效。

采用的唯一 TEE 逻辑补丁：

```text
bin/svchost ELF offset: 0x343fc
BootFS offset:           0x0e93fc
LZ4 block:               14, local 0x93fc

stock:   80 01 00 34    cbz w0, 0x3442c
patched: 0c 00 00 14    b   0x3442c
```

随后 `0x34430/0x34438` 的 digest verifier 和 gate 均保持原字节，所以修改 TA 必须仍然满足 body 和 header 两个 SHA-256 门。

## 4. 最终 TA 候选

生成器：

`02_脚本与补丁/finalize_k70e_scalar_ta_selfconsistent_hostonly.py`

输出：

`../out/k70e_scalar_rkp_selfconsistent_hostonly/dba51a17-0563-11e7-93b16fa7b0071a51.scalar_rkp_selfconsistent_hostonly.ta`

```text
size:                   1,401,936 (0x156450)
SHA-256:                6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0
body SHA-256:           050444d5832bed9bc4b15f81572c58b5c100badabdeabcc8eecb357bd5a38481
header SHA-256:         c036d19cd39126b4dbc16623915268604380ba9d6d8185eb86f7e4343cff05b3
unchanged signature SHA-256:
                        9c5a833d13a682b1be44a0dd547b15ebd3a7d27d8161a7ce3724fe3c331e6b08
```

从上一版 `e42656...` 到本版只改外层 `0x30..0x4f` 32 字节 header digest；签名和整个 ELF 完全不变。最终检查矩阵：magic、image size、body SHA、header SHA、UUID、anti-rollback version 101 全部通过；RSA-PSS 按预期失败。

TA 逻辑仍是已审计的 RKP-only/no-BSS 单 hook：只在 `GenerateRkpKey` 成功完成 KeyBlob/MacedPublicKey 后、私钥清理前，把同一次调用的 P-256 标量以 32 字节大端写入返回 blob；普通 GenerateKey 路径不触发；不使用全局/BSS scratch。

## 5. 最终 TEE 候选

生成器：

`02_脚本与补丁/build_k70e_sprovider_rsa_bypass_exactframe_hostonly.py`

输出：

`../out/k70e_sprovider_rsa_bypass_exactframe_hostonly/tee_a_sprovider_rsa_bypass_exactframe.img`

```text
size:        5,242,880 (0x500000)
SHA-256:     3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
stock SHA:   18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

结构门禁：

```text
BFSB:              0x1c6168，头部逐字节不变
LZ4 frame:         0x1c6188..0x3e076c，长度 0x21a5e4 不变
content size:      0x44c000
block count:       69
target block:      #14
descriptor offset: 0x23525b
payload offset:    0x23525f
payload size:      38,783，和原厂完全相同
spmc_dtb name:     0x3e17e8，尾段逐字节不变
```

补丁后的 block 14 用 liblz4 HC4 先得到 38,740 字节。构造器再把一个 47 字节 match 缩短为合法最小 4 字节，并把其余 43 字节等价转成下一条 literal，得到合法且解压结果相同的 38,783 字节 block。因此无需改 descriptor、无需移动后续 block、无需借用 ELF 空洞，也无需在 frame 尾部加兼容性未知的 padding。

独立解压差异只有：

```text
BootFS 0x0e93fc: 80 -> 0c
BootFS 0x0e93fd: 01 -> 00
BootFS 0x0e93ff: 34 -> 14
```

`0x0e93fe` 原来和现在都是 `00`，所以一条 4 字节指令在逐字节 diff 中只有三个字节不同。所有非目标压缩块、所有 descriptor、frame 后全部字节均与原厂相同。

机器校验报告：

- `../out/k70e_scalar_rkp_selfconsistent_hostonly/verify.json`
- `../out/k70e_sprovider_rsa_bypass_exactframe_hostonly/verify.json`

## 6. 最终 early-bind / 自动回退构件

实际设计不再使用普通 Magisk `post-fs-data` 模块。该触发点晚于 vendor
`tee-supplicant.rc` 的 `on fs`，无法保证首次 TA 加载前可见。最终方案是在当前已验证
Magisk `init_boot_a` 的 `overlay.d` 中注入同步 root `on fs` action。

构建器：

`02_脚本与补丁/build_k70e_scalar_final_earlybind_initboot_hostonly.py`

最终输出：

`../out/k70e_scalar_final_earlybind_initboot_hostonly/init_boot_a_scalar_final_earlybind_one_shot.img`

```text
size:              8,388,608 (0x800000)
SHA-256:           4d83cd26f02c585dce733f81d05faf38ec5c8f247f89fbaa9fcf46b70d2b4d85
source SHA-256:    9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
embedded TA:       6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0
```

原 37 条 newc 记录和 3 个 device node 逐字节保留，只在 `TRAILER!!!` 前增加
rc、early-bind helper、TEE 恢复 helper 和 TA 四条记录。AOSP `avbtool`
独立验证 footer、algorithm-NONE vbmeta 和 `init_boot` SHA descriptor 通过。

early-bind 在消耗任何授权标记前依次强制：

1. 设备是 `duchamp`，ARM/ALLOW 双文件及精确 token 存在，且 latch 不存在；
2. 活动槽是 `_a`；
3. `/dev/block/by-name/tee_a` 大小为 `0x500000`；
4. 其哈希正好是候选 `3990a8...`；
5. 内置 TA 哈希正好是 `6abe6d...`。

成功后会记录 `preconsume_tee_hash`、`preconsume_tee_size`，才把 ARM/ALLOW
移入一次性 latch，然后在 `/dev` tmpfs 中创建并 relabel 源文件，只做一次
bind。early-bind 本身没有 `dd`/flash/reboot/服务控制，对分区只有
`blockdev` 和 `sha256sum` 只读访问。

`sys.boot_completed=1` 后，第二个 helper 只在“当前磁盘 TEE 是 `3990a8...`、
恢复源大小/哈希是精确 stock、块设备大小精确”全部成立时，把磁盘
`tee_a` 恢复为 `182277...`，不主动重启。本次已加载的 secure world 仍在内存中，
足以完成一次 CTF keygen；下一次启动则回到 stock TEE。

关键回退不变式：若候选 TEE 在 init 前失败，外部只恢复 stock `tee_a`，
下一次启动就会在 TEE 哈希门、且在消耗 ARM 前 fail-closed。因此不必同时
恢复 `init_boot_a` 才能避免把 RSA-invalid TA 绑到 stock TEE。

## 7. 当前部署边界

截至本文最后更新，手机仍为健康实验基线（stock TEE + 已知可启动的 Magisk `init_boot`，不是纯原厂 init_boot）：

```text
boot_completed=1
battery=100
slot=_a
tee_a=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
init_boot_a=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
global TA=tee-supplicant namespace TA=facdfe3d...a3f32
```

stock TEE 已预置为
`/data/local/tmp/k70e_rkp_scalar_final_recovery/tee_a.stock.img`，大小 `0x500000`、
哈希 `182277...`、模式 `0444`。新 ARM/ALLOW/latch 均不存在。

发现一个虽然模块已 disable、但仍会独立执行的旧 v6 hook：

`/data/adb/post-fs-data.d/00_k70e_v6_bind.sh`

它会在后续阶段把 tee-supplicant namespace 目标覆盖为旧 `c33c...` TA。已按原
SHA-256 `de9fd5fa...3559a` 可恢复地移动到：

`/data/local/tmp/k70e_legacy_hook_quarantine_20260905/00_k70e_v6_bind.sh.de9fd5fa.disabled`

文件保留、模式 `0600`，未重启。`k70e_v6_diag` 模块本体仍在且有
`disable`；当前已无可执行旧 K70E hook，无旧 armed marker。

由于用户不在设备旁，尚未刷入新 `init_boot_a` 或 `tee_a`。这不是解锁/账号
阻断：是候选 TEE 可能在 init/ADB 之前失败，而 Fastboot/BROM/USB 枚举均不能由软件
保证的物理恢复边界。在“避免变砖”前提下，应等人和恢复环境在场再执行。

## 8. 最终验收工具

纯主机整体预检：

`02_脚本与补丁/preflight_k70e_scalar_final_deployment_hostonly.py`

它对 TA/TEE/init_boot/stock 恢复件/BROM tee-only XML 钉死大小和哈希，独立重算
init_boot 的 newc/LZ4/AVB 容器，验证 shell 语法、TEE 门与 ARM 消耗顺序。当前结果：
`READY_FOR_ATTENDED_DYNAMIC_VALIDATION`。

纯只读设备阶段预检：

`02_脚本与补丁/preflight_k70e_scalar_final_device_readonly.py`

当前 `--phase stock` 实机结果 PASS，证据为
`../out/k70e_scalar_final_device_preflight_stock_20260905.json`。

最终一次性提取/提交器：

`02_脚本与补丁/capture_k70e_rkp_scalar_and_provision_once.py`

它在 keygen 前强制检查：精确 final `init_boot_a`、early-bind 成功日志及 latch、
pre-consume TEE 哈希/大小、tee-supplicant namespace TA=`6abe...`、磁盘 TEE 已自动回到
stock、旧 K70E hook/模块不活跃。只接受严格 32-byte big-endian scalar，检查
`1 <= d < n` 且推导 X/Y 与同次 MacedPublicKey 完全一致；所有私钥文件 `0600`，
不打印私密。独立 CSR 验证通过后才联网提交，最后要求单一链、leaf SPKI
匹配、链签名和根自签全通过。

host-only 五项 scalar/坐标自测全通过。在当前 stock 手机上还做了一次负向门
测试：它在识别 tee-supplicant 仍看到 stock TA `facdfe...` 后立即 `SAFE_ABORT`，
没有 keygen、没有网络提交、没有远程目录或分区修改。

另外已把构件内的 exact early-bind helper 在当前 stock TEE 上做了一次有界负向实测：
临时放入哈希精确的内置 TA 和 ARM/ALLOW，执行 helper 后得到
`tee_hash_gate_fail=182277...`，ARM/ALLOW 原样保留、latch 未创建、目标 TA 仍为
`facdfe...`、TEE/init_boot 哈希均未变。证据日志已保存到
`../out/k70e_scalar_final_deployment_preflight_hostonly/live_stock_tee_gate_20260905.log`。
测试创建的 ARM、ALLOW、临时 TA/脚本和设备上的测试日志已精确删除；随后再次
运行 `--phase stock` PASS，证据为
`../out/k70e_scalar_final_device_preflight_stock_after_gate_test_20260905.json`。

## 9. 有人在场时的唯一部署顺序

1. 保持 stock `tee_a`、不放 ARM/ALLOW，只刷最终 `init_boot_a=4d83...`，先启动一次；
2. 运行设备预检 `--phase candidate-unarmed`，验证 overlay 解析、内置文件、root/服务和 stock TEE/TA；
3. 确认 BROM/fastboot 物理恢复可用后，最后才创建新 ARM/ALLOW，运行 `--phase armed-before-tee`；
4. 只写 `tee_a=3990...`，启动且只做一次实验；
5. ADB 恢复后，不要错把磁盘 `tee_a=stock` 当成“补丁未运行”：这是 boot-complete 自动回退的预期结果。以 `preconsume_tee_hash=3990...`、`BIND_OK`、latch、namespace TA=`6abe...`和 `restore_final=182277...` 为证据；
6. 运行一次性提取/提交器；任何门失败都立即停止；
7. 在最终正常重启前恢复 `init_boot_a=9d5d...`，复核两个分区都是已知可启动哈希。

如果候选 TEE 在 init 前失败，只恢复 stock `tee_a`即可让持久 final init_boot
在预消耗哈希门 fail-closed。仍不得触碰 `preloader/gz/seccfg/proinfo/persist/nvram/nvdata/efuse/RPMB/userdata`，不得 relock。

## 10. 2026-09-06 更正：原厂日志路线可以提取 CDI_Leaf scalar

本节旧版把 `dump_to_hex` 调用图覆盖不全，错误地得出了“stock 日志没有目标 scalar”的
结论。精确 stock KeyMint TA 的活动 CSRv2 设备签名路径实际还包含：

```text
generateCertificateRequestV2(keysToSign=[])
  -> MiteeRemoteProvisioningContext::SignWithDeviceKey  0x0be710
  -> hwbcc wrapper                                       0x0c2e18
  -> tee_sign_key                                        0x0dd9b0
  -> hwbcc_sign_key                                      0x0dd438
  -> get_attest_cdi                                      0x0dcd10
  -> P256KeypairFromCDI                                  0x0db330
  -> success x26                                         0x0dd934
  -> dump_to_hex("private_key", x26, 32)                 0x0dd954
```

这里的 32 字节是活动 `CDI_Leaf` P-256 私钥标量。原厂 TA 会在 MiTEE memlog 中输出
两条相邻的固定语法行；新的解析器不靠标签猜测，而是把所有候选逐个派生 SPKI，只接受
与**同一次 zero-key AuthenticatedRequest 最终 DICE leaf**完全一致的唯一候选。

因此，当前方案不需要 patched TA、patched TEE、Fenrir 或 SProvider 绕过。必须使用文档
52–57 和下列专用入口：

```text
02_脚本与补丁/capture_k70e_stock_cdi_log_once.py
02_脚本与补丁/extract_k70e_cdi_leaf_from_mitee_log.py
02_脚本与补丁/rkp_sw_stock_log_once.py
```

KAK、被拒绝的 KDF 中间候选和 RKP 每把待签 key 的 scalar 仍然不是 CDI_Leaf；旧版对这些
非目标值的排除仍有效。被作废的只是“活动 stock CSRv2 路径不存在 CDI_Leaf dump”这一句。

## 11. 2026-09-05 现场执行与旧验证器验收：REJECTED_NOT_APPROVED

> 本节保存的是事故发生时的执行记录。其密码学关系曾由旧验证器判为 PASS，但 Google
> leaf 的原始 Provisioning Info 含 `{5:{1:"NOT_APPROVED"}}`，赛事方已明确拒绝。不得提交，
> 不得从本节恢复“最终赛事验收 PASS”结论。

旧 `6abe...` TA 只导出 native RKP 每把密钥 scalar，不符合最终题目口径。现场执行改用最终 CDI_Leaf 身份捕获构件：

```text
TA:
  7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
init_boot one-shot:
  5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517
TEE exact-frame gate:
  3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
stock TEE recovery:
  18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

这次没有“解决 TEE 签名”：TA 的 OEM RSA 仍无效；成功依赖前文已审计的 SProvider RSA 结果最小旁路，且 body/header digest 继续严格生效。

动态证据：

```text
preconsume_tee_hash=3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
preconsume_tee_size=5242880
target_hash=7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
BIND_OK
restore_final=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

捕获器 `capture_k70e_google_rkp_sw_identity_once.py` 得到 32-byte big-endian CDI_Leaf P-256 scalar；其派生 SPKI 与紧邻 zero-key native CSR 的最终 leaf 均为：

`64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2`

随后 `google-rkp-sw` 使用该身份、同轮完整 proper DICE 链、同轮 canonical green/locked DeviceInfo 生成一把新 P-256 私钥并向 Google 提交：fetch HTTP 200、sign HTTP 200、返回一条四证书链。叶证书公钥与软件私钥公钥逐字节一致；链签名、根自签、DER 全消费全部通过。

最终交付：

`03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244/`

其中：

- `01_identity/`：`google-rkp-sw` 身份标量、同轮 native AuthenticatedRequest、5 段 DICE/DeviceInfo 证据；
- `02_generated_key/private_key_pkcs8.pem`：同次软件运行生成的私钥；
- `03_certificate_chain/ordered_certificate_chain.pem`：Google 返回的对应四证书链；
- `FINAL_VERIFICATION.json`、`SHA256SUMS.txt`：综合验收与全目录清单。

现场收尾已完成：`tee_a=182277...`、`init_boot_a=9d5d12...`、namespace TA=`facdfe...`、`boot_completed=1`、`vendor.teefs_state=ready`。最终成果已完成，不要再重复刷写或重新签发。
