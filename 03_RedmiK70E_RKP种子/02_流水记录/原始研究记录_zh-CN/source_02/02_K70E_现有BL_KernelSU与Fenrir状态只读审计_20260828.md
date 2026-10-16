# K70E 现有 BL、KernelSU 与 Fenrir 状态只读审计

日期：2026-08-28

设备：Redmi K70E（`duchamp`）

序列号：`<DEVICE_SERIAL>`

## 结论

当前 `lk_a` **不是 Fenrir 补丁镜像**。当前可观测方案是：

1. Fastboot 层已解锁（先前只读 `getvar` 返回 `unlocked: yes` / `secure: no`）。
2. Android 用户空间由 KernelSU 3.2.5 和 Play Integrity/Hide 类模块修改属性，因此 `getprop` 显示 `ro.boot.verifiedbootstate=green` 和 `ro.boot.vbmeta.device_state=locked`。
3. Android 层的 `locked/green` 不能证明 Mitee TA 证书校验或启动链验证已绕过。
4. K70E BCC seed 诊断模块在首次排练中过早写入 `disable`，所以没有实际 overlay `/vendor/mitee/ta/...`。本次启动使用的仍是原厂 TA。

## 关键证据

### 启动链备份

- `lk_a.img` SHA-256：`9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35`
- LK 版本字符：`fb02623c6_202606171151`
- 当前 slot：`_a`

### Fenrir duchamp 模式扫描

使用 Fenrir 自带的 duchamp `PatchStage` 与 `liblk` 3.2.0 解包当前 `lk_a.img`，结果如下：

| 补丁阶段 | 原始模式 | 补丁模式 |
|---|---:|---:|
| `sec_get_vfy_policy` | `lk=2, bl2_ext=2, aee=2` | 0 |
| `force_green_state` | `lk=1` | 0 |
| `bypass_security_control` | `lk=1, aee=1` | 0 |
| `bypass_lock_control` | `lk=1, aee=1` | 0 |
| `bypass_cmd_erase_lock_control` | `lk=1` | 0 |
| `spoof_sboot_state` | `lk=1, bl2_ext=1, aee=1` | 0 |
| `spoof_lock_state` | `lk=1, aee=1` | 0 |
| `spoof_custom_lock_state` | `lk=1` | 0 |
| `avb_allow_verification_error` | `lk=1` | 0 |

`bypass_cmd_flash_control` 的上游固定模式在当前新 LK 中原始/补丁均为 0，说明该函数版本已变，不影响其余八项对“当前未打 Fenrir 补丁”的判断。

### TA 可见文件

- 当前 `/vendor/mitee/ta/dba51a17-0563-11e7-93b16fa7b0071a51.ta` SHA-256：`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`
- KernelSU 模块中待测诊断 TA SHA-256：`7a7f263468024412891a944e0c5d2b7741d4d2ab789f57ed26901adb5ac03e92`
- 当前 `/vendor` 可见哈希是原厂值，没有命中诊断 TA。

## 保存的现场

目录：

`03_提取结果/K70E_KernelSU与TA加载方案现状采集_20260828/`

内容包括：

- 设备上当时的 `k70e_bcc_seed_diag` 模块完整快照；
- PID 1 mountinfo、`/proc/mounts` 和 kernel cmdline；
- 当前用户空间可见的 KeyMint TA 原始字节；
- 模块内诊断 TA 原始字节。

## 下一步门禁

1. 先仅将模块自禁用时机从 `post-fs-data` 移到 `service` 阶段，保证 overlay 已建立后再预置下一启动回退。
2. 诊断启动后先核对 `/vendor` 可见 TA 哈希，再核对 KeyMint/RKP Binder 是否在线。
3. 如 Mitee 拒绝修改 TA，立即重启回原厂 TA，并将拒绝日志作为“仅 KernelSU overlay 不足”的证据。
4. 只有第 3 步确认后，才评估针对当前 LK 版本的最小 Fenrir 路径；绝不直接刷入上游旧 `duchamp.bin`。

## 2026-08-29 状态同步

此前损坏的 `lk_a` 已用原始备份安全恢复，恢复证据见 `../02_脚本与补丁/duchamp_BROM_原LK恢复_20260828/恢复证据_20260829_085747.md`。恢复写入没有改变 BL 锁状态，也没有证明 Fenrir 可用。

Fenrir 下一步仍必须先执行 `PatchStage`/`liblk` 静态干运行和原始镜像哈希核对；没有新的完整备份、长度校验和回退路径，不得生成或刷写补丁 LK。

2026-08-29 静态复现已完成但仍为 dry-run：本机原版 LK 的 `sec_get_vfy_policy`、`force_green_state`、安全/锁状态、sboot、custom lock 和 AVB 模式均可匹配；`bypass_cmd_flash_control` 未匹配，说明与仓库样本存在版本差异。没有生成补丁文件，也没有设备侧写入。完整输出、仓库 commit 和 RKP 只读状态见 `06_K70E_Fenrir静态复现与RKP只读续验_20260829.md`。
