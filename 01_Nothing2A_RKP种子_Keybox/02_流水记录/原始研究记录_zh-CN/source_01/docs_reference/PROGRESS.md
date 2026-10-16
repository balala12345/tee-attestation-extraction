# 有效行为记录（已验证的正确路径）

> **状态：✅ 已完成 —— KeyMint 认证 keybox 明文已提取并密码学验证通过**
> 交付物：`result/keybox_plaintext.bin`（8716B 明文，含 EC+RSA 两套认证私钥+证书链）、`result/attest_ec_privkey.hex`

> 只记录经实证有效的步骤与结论。目标：提取设备 **KeyMint 认证 keybox（keystore attestation 私钥+证书链）**。
> 设备：Nothing Phone (2a) A142 / Pacman / MT6886 / NOS U2.5-240114-2323 / Trustonic Kinibi (t-base 510a)

---

## 一、漏洞利用（已实锤成功）

1. **漏洞**：seccfg=unlock 时 Preloader 跳过 bl2_ext 校验 → EL3 控制（fenrir）
2. **解锁**：`fastboot flashing unlock`，屏幕 5 秒倒计时时**按一下「音量下」**即确认
3. **补丁 lk（最小化）**：只打 `sec_get_vfy_policy`（pattern `00 01 00 b4 fd 7b bf a9` → `00 00 80 52 c0 03 5f d6`，MatchMode.ALL 3 处命中）
   - 基底：`firmware/u25-candidates/.../U2.6-firmware/lk.img`（U2.6-240828，nothing_archive）
   - 构建：`fenrir/injector` 下 `../.venv/bin/python inject.py pacman ../bin/pacman.bin -o pacman-fenrir-minimal.bin --config ../minimal.json`
   - 产物：`pacman-fenrir-minimal.bin`（仅 21 字节差异）
   - **刷 lk_a 成功启动** = Preloader 接受修改的 bl2_ext = 漏洞实锤
   - 当前 `lk_a` 即此补丁版（保留完好）

## 二、t-base 签名旁路（已实锤成功）

- 目的：让 t-base 加载修改过的 trustlet（绕过 MCLF 签名校验）
- 基底：**U2.5-231207 原厂 tee.img**（nothing_archive，SHA256 `8c2ef73a...`）
  - ⚠️ 关键教训：tee 必须与系统大版本配套。U2.6 tee 刷到 U2.5 系统 → 无法启动（内嵌驱动不配套）。U2.5-231207 tee 在 U2.5-240114 系统上启动正常。
- 补丁点（t-base 载荷 file 0x5C500 起，运行基址 0x1D000000）：
  - **只打补丁 A**：`tee.img` file `0xBE978` `ff032ed1`→`00008052`、`0xBE97C` `e203022a`→`c0035fd6`（verifySignature 恒返回 0）
  - **不要打补丁 B**（0xBEDD8 白名单跳转）——会导致无法启动（已踩坑）
  - 产物：`tee-patched-A-only.img`（仅 7 字节差异）
- **刷 tee_a 成功启动，TEE 服务正常**（init.svc.tee-1-1 running），签名旁路生效

## 三、Root（已实锤成功）

- boot 套件：`firmware/U2.5-240301-boot/`（内核 `5.15.104-android13-8-00001-gac1072c849eb-ab10753874` 与设备 240114 **逐字符一致**）
- Magisk v30.7 APK 修补 `init_boot.img`（U2.5-240301）→ `magisk_patched.img`
- `fastboot flash init_boot_a magisk_patched.img` → `su -c id` 返回 `uid=0(root)` ✓

## 四、当前设备状态快照

```
lk_a      = fenrir 补丁版（启动链不校验）
tee_a     = 补丁版（t-base 签名验证恒过，只打补丁A）
init_boot_a = Magisk 补丁（root）
系统      = U2.5-240114 正常启动
TEE/DRM   = 服务正常
BL        = 解锁（orange state）
```

## 五、关键资源/文件位置

- fenrir 源码+venv：`fenrir/`；最小补丁配置 `fenrir/minimal.json`
- mtkclient+venv312：`mtkclient/`（已修 mfusepy OSError 兼容；MT6886 需签名 DA，见下）
- 固件：`firmware/u25-candidates/Pacman_U2.5-231207-0042/`（含 tee/lk/gz 等 22 镜像）、`firmware/U2.5-240301-boot/`、`firmware/U2.6-*/`
- 救砖包：`firmware/pacman_flashtool.7z`（5.4GB 下载中，含签名 DA + U2.5 全镜像，用于救援/备份）
- Magisk：`Magisk-v30.7.apk`
- trustlet 集合：`tas/`（NOS3.0 dump）+ `tas/device_u25/`（设备 U2.5 精确版，root 后拉的）
- persist 提取：`persist_dump/`（attest_keybox.so 8716B=加密认证keybox、attestation_ids.so、DRM_KBF_BIN）

## 六、已验证的 TEE/TA 结构

- tee.img = BL31 + **t-base (Kinibi) 内核**；gz.img = GenieZone（与本目标无关）
- Trustonic trustlet/driver 在 `/vendor/app/mcRegistry/`（MCLF 格式，magic "MCLF"，UUID 在 0x18）
- KeyMint HAL：`android.hardware.security.keymint@2.0-service.trustonic`（Trustonic 实现）
- **认证 keybox**：`/mnt/vendor/persist/attest_keybox.so`（加密存储，需 KeyMint TA 解）
- Trustonic 安全存储（SFS）：`/mnt/vendor/persist/mcRegistry/Store_1.tf`（3.8MB 加密）
- MCLF 加载签名验证在 t-base 内核（tee.img），已被补丁A绕过

## 七、最终结果（已完成）

- **目标 TA = KeyMint trustlet `07060000-0000-0000-0000-00000000004d.tlbin`（teeKeymint v2.0）**
- **RKP 结论**：TA 支持 RKP（rkp_bcc_km / EEK 标记），实际提取走**工厂 attest_keybox.so 解密**路径 → 本机认证 keybox 为工厂烧录
- 提取方法：root 客户端（keymint_tee_client/kmtee_probe）mcOpenTrustlet 打开该 TA → mcMap 送入 persist/attest_keybox.so（加密）→ TA 用设备 KEK 解包 → 补丁 TA 把明文写回 → 读回
- **结果**：`result/keybox_plaintext.bin` 8716B 明文，含 EC P-256 认证私钥 + 完整 X.509 证书链（另含 RSA 套）
- **验证**：私钥→公钥推导与叶证书公钥逐字节一致（纯 Python secp256r1 验证）
