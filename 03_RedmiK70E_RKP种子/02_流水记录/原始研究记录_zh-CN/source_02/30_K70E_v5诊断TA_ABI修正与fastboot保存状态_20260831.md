# K70E v5 诊断 TA ABI 修正与当前 fastboot 保存状态

日期：2026-08-31（Asia/Taipei）  
设备：Redmi K70E / `duchamp` / `<DEVICE_SERIAL>`

## 结论

当前没有在设备上执行刷写、重启、分区写入或联网提交。用户反馈设备卡在 logo 后已进入 fastboot；但本轮只读询问显示 `fastboot devices` 为空、ADB 仍在线，`sys.boot_completed=1` 、 Verified Boot=`green`、两个服务为 `running`，且 TEE 命名空间实际哈希为旧版 `97b7…`。这与界面状态不一致，因此不能把设备视为可安全部署。工作区仍**没有**赛事要求的同一把 K70E 私钥 + Google 证书最终三件套。

设备 metadata 的只读复核还显示：仍有旧版 `v4.ta.armed`、模块自身的 TA 文件仍为 stock 哈希 `facd…`，本次没有把 v5 文件推入设备。因此不存在“v5 已刷入但未成功”的隐性状态；当前 `97b7…` 来自旧的命名空间 bind 证据。

静态复核发现，之前的两个“组合版”之间还存在一个必须修正的 AArch64 ABI 问题：诊断 cave 在调用 `memcpy` 后错误地继续使用 caller-saved 寄存器。已生成只在主机保存的 v5 修正版，修正后才能作为下一次设备验证的唯一候选。

## 为什么 `97b7…` 不能用

`97b7b012…`（旧称 v4）只把 `0x62320` 首返回向量跳到结果 cave；它没有把 `0xa32b8` 的 `EvpKeyToKeyMaterial` 返回值挂到私钥捕获 cave。因此该版本即使加载成功，也只能返回原始 275 字节 KeyMint opaque handle，不可能出现 `K70DER1` 诊断记录。对应的 RX 映射修正版 `700e9c95…` 只是给同一 result-only 版本补上可执行段映射，仍然没有私钥 hook。

之前基于这两个版本得到的目录：

`03_提取结果/K70E_private_der_google_provision_20260831_115017/`、`_115743/`、`_120952/`

都只有 `private_blob=275` 和 119 字节 `MacedPublicKey`，且 `network_submitted=false`；这些是有效的失败证据，不是私钥产物。

## `3d7f…` 组合版的第二次静态复核

`3d7f6f60…` 首次把两个必要 hook 组合起来：

```text
0xa32b8 -> 0x141400   // a79d0 返回后的 KeymasterBlob(data,length)
0x62320 -> 0x141500   // 必经的首返回向量
```

但进一步按 AArch64 调用约定检查发现：

* 私钥 cave 在 `BL 0x140dc0`（`memcpy` PLT）后直接使用 `x10` 写 magic；`x10` 属于 caller-saved `x0..x17`，不能假定保留。
* 结果 cave 在同一 `memcpy` 后直接回到 `0x62324`；stock 后续 `0x6232c` 仍使用 `x8` 比较，而 `x8` 也属于 caller-saved。
* 旧脚本的 magic 数值按小端写入后不是字面量 `K70DER1\0`。虽然采集器与旧数值自洽，但会让原始记录的标记字节与文档语义不一致。

这三点都属于主机静态可证明的补丁错误，不应通过重复重启或刷写“碰运气”验证。

## v5 修正版

修复脚本：

`02_脚本与补丁/repair_k70e_combined_private_der_v5.py`

输出（只写主机工作区，未部署）：

`02_脚本与补丁/duchamp_Mitee_活动私钥DER诊断TA_v5_combined_mapped_20260831/dba51a17-0563-11e7-93b16fa7b0071a51.active_private_der_diag_v5_combined_mapped.ta`

SHA-256：

```text
88d4b3eecddce9be45d1e73c833a9340e154cb10a2b9c2a1844f3615213679a3
```

v5 的静态不变量：

1. 仍从 stock K70E TA 的已映射 `3d7f…` 组合版派生，RX `PT_LOAD` 仍为 `0x5f000..0x142000`；不改变生成、opaque handle、CSR 或安全存储逻辑。
2. `0xa32b8` cave 先保存 `w0`，清空 magic/长度；只有 `a79d0` 返回状态为 0 且 `(data,length)` 非空时才复制，复制后重新计算 scratch 的 `x10`，再写字面量 `K70DER1\0`。
3. `0x62320` cave 保留 stock 的 `stp x26,x28,[x25,#0x20]`；`memcpy` 返回后重新从 `[x29,#-0x70]` 装载 `x8`，再回到 stock `0x62324`。
4. 诊断记录仍为 0x100 字节：magic `0x00..0x07`、小端长度 `0x08..0x0f`、DER `0x10..` 最多 0xf0 字节。
5. 外层 TA ELF hash 已重新计算，输出的 `PT_LOAD`/hook/cave 均通过主机反汇编核对；`repair_metadata.json` 记录每项静态门禁。

采集器与监视器现只接受 v5 SHA-256 `88d4…`；旧的 `97b7…`、`700e…` 和 `3d7f…` 都会在设备端门禁前拒绝。该改动尚未触碰设备文件。

为后续的一次性验证另行准备了命名空间 bind 辅助脚本 [`early_bind_tee_ns_v5_20260831.sh`](../02_脚本与补丁/early_bind_tee_ns_v5_20260831.sh)，只能在用户在场、设备稳定且明确准备一次验证时手动运用。本脚本不包含自动重启或刷写。

## 设备恢复后的唯一安全门禁

设备稳定回到系统且用户在场前，不执行任何 bind、服务重启或 keygen。后续若明确开始一次验证，顺序固定为：

```text
tee-supplicant 命名空间 TA 哈希 == 88d4…
    -> 单次 GenerateRkpKey
    -> 记录 magic/DER 可解析为未加密 P-256
    -> DER 公钥 X/Y == 同次 MacedPublicKey
    -> 原生 CSRv3 独立验证 PASS
    -> Google signCertificates HTTP 200 且叶公钥匹配
```

任一条件失败，立即停止，不联网、不把 275 字节 opaque blob 改名为私钥，也不把历史 K70E 证书链与新 key 拼接。成功时才会在新的结果目录保存 `key_00/private_key_der.bin`、`key_00/private_key_pkcs8.pem`（0600）和 `chain_00/ordered_certificate_chain.pem`。

## 当前已有证书只能作参考

现有原生 K70E 证书链仍位于：

`03_提取结果/K70E_google_rkp_raw_native_submit_20260829_081925/chain_00/ordered_certificate_chain.pem`

它证明 Google HTTP 200、叶证书有效期 `2026-08-27 08:40:55Z` 至 `2026-09-09 04:41:24Z`（12 天 20:00:29），证书扩展报告滚动近 30 天近似值 `8`。同目录的 275 字节文件仍是 opaque handle，未发现与该叶公钥匹配的主机私钥，因此这条链不能作为本次赛事的私钥+证书交付物。

## 两次可回滚动态验证：确认 TEE 缓存边界

2026-08-31 在设备当前 ADB 在线、不刷分区的前提下，对 `tee-supplicant` 命名空间做了两次完全可回滚的 v5 叠加 bind：

1. v5 文件推入 `/data/local/tmp`，TEE 命名空间哈希确认为 `88d4…`；执行一次 keygen 后只返回 `private_blob=275`，诊断 magic 不存在；未联网。
2. 重启 `vendor.keymint-mitee` 服务（未停 `tee-supplicant`）后重复 v5 bind 和 keygen，仍然是 `private_blob=275`；两个服务均恢复 `running`。

两个证据目录都记录 `network_submitted=false`：

`03_提取结果/K70E_private_der_google_provision_v5_20260831_attempt01/`  
`03_提取结果/K70E_private_der_google_provision_v5_20260831_attempt02/`

每次验证后均卸载 v5 bind、删除临时文件，TEE 路径恢复到 `97b7…`，两个服务保持 `running`。这证明已运行的 `tee-supplicant` 内部仍缓存旧 TA 实例；单独叠加文件 bind 或重启 KeyMint HAL 不会重新加载 v5。要进入 v5 真正执行路径，必须在设备可恢复、用户在场时重建 `tee-supplicant` 生命周期；本轮不停该服务，也不重启整机。
