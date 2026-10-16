# K70E 活动 `GenerateRkpKey`/`A7B88` 路径与 Fenrir 门禁

日期：2026-08-29（Asia/Taipei）  
设备：Redmi K70E / `duchamp` / `<DEVICE_SERIAL>`  
范围：原厂 Mitee KeyMint TA 的离线静态审计，以及 Fenrir 的只读必要性判断。

## 结论先行

本轮没有刷写分区、没有替换 TA、没有重启设备。设备最后复核仍为：

```text
adb get-state=device
sys.boot_completed=1
ro.bootmode=normal
ro.boot.slot_suffix=_a
ro.boot.verifiedbootstate=green
ro.boot.flash.locked=1
ro.boot.vbmeta.device_state=locked
getenforce=Enforcing
```

静态证据已经把当前活动的 RKP 密钥生成/校验链与旧的 `P256KeypairFromCDI` 辅助链分开。当前活动链能够把 KeyMint 生成的对象序列化为 opaque handle、`MacedPublicKey` 和 CSR 所需数据，但在可审计的返回边界没有发现主机可读的 32 字节私钥 scalar 或 `CDI_Leaf` seed。

因此：

1. 现有 `03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/` 中的 Google 证书链是真实 HTTP 200 产物；
2. 同目录的 275 字节 `private_key_blob_opaque.bin` 仍是 TEE/KeyMint opaque handle，不是 PKCS#8/raw 私钥；
3. 赛事要求的“同一公钥对应的主机私钥 + Google 证书”目前仍未完成；
4. Fenrir 不是完成 RKP 私钥交付的必要条件，当前也不应为了这个目标刷写 LK。

## 活动调用链静态证据

分析输入为原厂 TA ELF（与设备 `/vendor/mitee/ta/dba51a17-0563-11e7-93b16fa7b0071a51.ta` 对应），原厂 TA SHA-256：

```text
facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
```

### 1. 活动入口

在活动命令处理函数中，`0xc94d8` 直接调用 `GenerateRkpKey`：

```text
0xc94d8:  bl 0x61960
```

调用前设置了三个关键参数：

```text
x0 = [x24]       厂商/KeyMint 上下文对象
x1 = x20 + x28   调用方输出结构
x2 = x20 - 0x150c 结果对象/状态结构
x3 = 1           活动模式参数
```

`0x61960` 保存 `x0/x1/x2` 后，通过 `x0` 对象的 vtable `+0xb8` 方法取得内部密钥/证书对象。该方法返回的对象继续留在 TA 内部；没有直接把私钥字节写入 Binder 输出缓冲区。

### 2. `GenerateRkpKey` 中的两个 32 字节缓冲区

> **2026-08-30 静态复核更正：** 本节早期把 `0xa7b88` 误读为 `memcmp` 比较器。该结论已被新文档 [`22_K70E_活动GenerateRkpKey_私钥生成路径静态闭合_20260830.md`](22_K70E_活动GenerateRkpKey_私钥生成路径静态闭合_20260830.md) supersede；`0xa7b88` 实际对应 `GetEcdsa256KeyFromCert` 的公钥 X/Y 提取路径。

在 `0x61cd8` 附近，函数分配并清零两个独立的 32 字节缓冲区，然后以长度 `0x20` 调用 `0xa7b88`：

```text
0x61cd8:  bl 0x6e9b4       分配 0x20 字节（缓冲区 A）
0x61d10:  bl 0x6e9b4       分配 0x20 字节（缓冲区 B）
0x61d3c:  ldur x0, [x23,#-0xe8]  内部证书/密钥对象
0x61d48:  sub  x2, x8, x1         A 长度 = 0x20
0x61d58:  sub  x4, x8, x3         B 长度 = 0x20
0x61d5c:  bl   0xa7b88
```

TA 中紧邻该调用点的日志字符串为：

```text
GenerateRkpKey GetEcdsa256KeyFromCert
```

`0xa7b88` 的可见语义是：

- 校验 `x2 == 0x20`、`x4 == 0x20`；
- 从 `x0` 指向的内部证书/密钥对象取得两个 EC 大整数；
- 通过 `0x1157d0` 和 `0xee560` 将两个坐标各序列化为 32 字节输出；
- 通过对象方法继续完成状态/证书一致性处理。

紧邻调用点的日志是 `GenerateRkpKey GetEcdsa256KeyFromCert`，所以这条路径是公钥 X/Y 取得，不是私钥 scalar 或 `CDI_Leaf` seed。成功分支随后进入 `0x61f48` 及后续对象/向量序列化，产生的是 KeyMint 句柄、公钥/证书相关数据和 CSR 所需结构。

### 3. 与旧 `P256KeypairFromCDI` 路径的隔离

TA 中仍存在旧的字符串和包装路径：

```text
P256KeypairFromSeed       -> 0xd9f88（旧生成/日志包装）
P256KeypairFromCDI        -> 0xda938（旧包装）
旧包装                     -> 0xda520（P-256 primitive）
```

`0xda520` 的直接调用返回地址只有 `0xd89f8` 与 `0xdad10`。而活动 CSRv3/`GenerateCsr` 入口区（`0x626c8` 一带）直接调用的是 `0x925c8`、`0x94d08`、`0x63498`、`0x635a8`、`0x91a40` 等函数/函数表，没有到旧 `0xda520` 的直接 `BL`。此前针对 `0xda520` 的诊断 TA 未得到 `CDI_Leaf` 匹配值，与这条调用图一致：它没有覆盖活动 CSRv3 的实际结果对象。

旧诊断补丁的另一个版本在结果 hook 中使用了未重新设置条件码的 `b.eq`；这属于不安全的控制流假设。即使改成真实的 `cbz`，也只能修正空指针保护，不能证明它会命中活动 CSRv3，更不能把任意 32 字节窗口变成 IDC。

## Fenrir 必要性与风险门禁

Fenrir 的作用是修改 LK/启动链中的安全、锁状态或 AVB 行为；它不是 RKP 私钥导出器，也不提供 `google-rkp-sw` 所需的 32 字节 `CDI_Leaf` seed。当前只完成了保存的原版 `lk_a.img` 的内存 dry-run：

```text
sec_get_vfy_policy              6 hits
force_green_state               1 hit
bypass_security_control         2 hits
bypass_lock_control             2 hits
bypass_cmd_erase_lock_control   1 hit
bypass_cmd_flash_control        0 hit
spoof_get_sboot_state            3 hits
spoof_lock_state                 2 hits
spoof_custom_lock_state          1 hit
avb_allow_verification_error     1 hit
DRY_RUN_OK                       True
DRY_RUN_NO_OUTPUT                True
```

当前原版 `lk_a.img` SHA-256 为：

```text
9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35
```

仓库旧 `duchamp.bin` 与本机 LK 不是同一镜像；本机还缺少 `bypass_cmd_flash_control` 模式。历史上错误重组/截断 LK 曾导致卡 Logo、黑屏和只能进 Recovery，随后才用原始 `lk_a` 恢复。因此当前门禁为：

- 不把上游旧 `duchamp.bin` 直接刷入本机；
- 不为 RKP 身份提取再次修改或刷写 LK；
- 不在没有完整分区备份、长度校验、BROM 回退和可用授权链时运行 `flash.sh`；
- Fenrir 只保留静态版本差分用途，不能作为本次私钥/证书交付的前置步骤。

结论是 **当前没有使用 Fenrir 的必要性**。使用它会增加启动链变砖风险，却不会越过 TEE 私钥不可导出的边界。

## 当前交付物与缺口

已保存的原生 Google 产物：


- 证书链：`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/ordered_certificate_chain.pem`
- opaque 句柄：`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/private_key_blob_opaque.bin`（275 字节）

叶证书有效期为 `2026-08-27 08:40:55 UTC` 至 `2026-09-09 04:41:24 UTC`，时长 `12 天 20:00:29`；provisioning-information 给出的 `certificates_issued_last_30_days_approx` 为 `8`。这些数据已在 `K70E_google_rkp_raw_native_submit_20260829_081925/REPORT.md` 审计。

缺口只有一个核心事实：工作区没有与该叶证书公钥逐把匹配、可在主机上读取的私钥文件，也没有可供 `google-rkp-sw.resolve_seed()` 接受的 K70E 专用 32 字节 `CDI_Leaf` seed。外来 Samsung keybox、Nothing/xaga 材料和 `ctf_artifacts` 仅能作为对照/本地测试，不能冒充本机交付物。

在赛事方提供 K70E 专用可导出 seed、规定的 RKP 测试签发沙箱，或明确接受本地 CTF 根签发之前，不能诚实地把当前半成品写成“私钥 + Google 证书已交付”。
