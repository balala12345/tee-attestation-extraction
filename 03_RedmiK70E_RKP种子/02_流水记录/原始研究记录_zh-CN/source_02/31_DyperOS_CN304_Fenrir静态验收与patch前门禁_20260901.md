# DyperOS CN304 / Fenrir（duchamp）静态验收与 patch 前门禁

日期：2026-09-01（Asia/Taipei）  
目标：Redmi K70E / POCO X6 Pro 5G，代号 `duchamp`，MT6897。  
范围：本文件只整理本地包、已有逆向证据和下一次验证的判定门槛；本轮不刷写、不重启、不改分区。

## 结论先行

用户提供的包已在本地完整验档，文件哈希与给出的 DyperOS CN304 包一致。静态上，它不是普通 CN304 官方包，而是带工程 Preloader、Fenrir LK、Global 3.0.6 AVB 指纹的定制混合包。包内 `lk.bin` 与公开的 duchamp Fenrir LK 哈希相同，说明它**很可能已经包含 Fenrir 启动链改造**；但这只是镜像来源证据，不是设备已经执行或安全世界已经接受该改造的证据。

特别注意：目标是 `duchamp`/K70E，不是 `xaga`/Redmi 11T Pro。xaga 的案例只能用于方法对照，不能把其 LK、TEE、TA 或身份材料混用到 K70E。

用户称该包已经刷入设备；工作区的静态资料无法证明当前设备实际上正在运行包内镜像。设备侧必须另做只读哈希、slot 和启动日志核对，不能用“能开机/卡 logo”代替证明。

赛事最终交付仍然只有在同一把 K70E RKP key 的以下对象同时成立时才算完成：

1. 主机可读取的未加密 P-256 私钥（raw scalar、DER/PKCS#8 或受控 PEM）；
2. 用同一公钥生成的 CSRv3 和原始请求/响应；
3. Google `signCertificates` HTTP 200 返回的完整证书链；
4. 私钥公钥、CSR 中的 `MacedPublicKey`、证书叶公钥逐字节匹配。

已有的 275 字节 KeyMint opaque handle、CSR 签名成功、或历史证书链都不能单独作为私钥交付物。

## 1. 包的不可变基线

| 项目 | 值 |
|---|---|
| 本地包 | [`刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate.zip`](../../刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate.zip) |
| 公开来源 | DyperOS Telegram 帖（[worstdosmod](https://t.me/s/worstdosmod)） |
| 下载对象 | [Pixeldrain NxG7Xy3S](https://pixeldrain.com/u/NxG7Xy3S) |
| 文件大小 | 5,002,153,549 bytes（约 4.66 GiB） |
| SHA-256 | `4ac1fcb60ad845177308a56ded891203c33d4a4e852c112b2dc8714e541a244e` |
| ZIP 完整性 | `unzip -tqq passed` |
| `pre-device` | `duchamp` |
| 包 metadata | `Redmi/duchamp/duchamp:16/BP2A.250605.031.A3/16OS3.1.260617.194228688.MTPECN.S:user/release-keys` |
| 安全补丁级别 | `2026-06-01` |

对应的只读哈希和脚本审计见 [`community_tengeos_CN304_fenrir_candidate_hashes.txt`](../../刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate_hashes.txt) 与 [`verify_fenrir_candidate_readonly.sh`](../../刷机资源_只读下载_20260831/verify_fenrir_candidate_readonly.sh)。校验脚本未调用 ADB/Fastboot，也未写设备。

## 2. Fenrir/启动链静态证据

### 2.1 镜像哈希与版本关系

| 镜像 | 大小 | SHA-256 | 静态判断 |
|---|---:|---|---|
| `images/preloader_duchamp.bin` | 768,316 | `f68f4a691e2e3a09bd7fed6a8973edcae5dfe3d7205c4605b69f22e24e5ec82f` | 与公开工程 Preloader（SHA-1 `c8c0116c47cacaa7cb7cafa3fbff3ee30507e171`）字节一致 |
| `images/lk.bin` | 3,395,824 | `615d437f33fb9addea9b9bd56d8fbd5a8d17bc35b13546815a673248a8e0bf19` | 与公开 duchamp Fenrir LK SHA-1 `690f3871a613545d40a78ce6f0e237252761bcde` 一致；不同于 stock Global 3.0.6 LK `5fc164…` |
| `images/tee.img` | 4,074,640 | `7fb6de60e9f1247ed0d536e4b3c9bace8efa871573c9dca71c4a75fe613cf8c8` | 与当前 stock `tee_a.img`（`182277…`）不同，必须视为未知定制 TEE |
| `images/boot.img` | 67,108,864 | `e8d4603379ed10e94e066976c1a663b748917b93fc688065a9dc9fa97a3e29b6` | 与当前 stock `boot_a.img`（`8a7f…`）不同 |

`vbmeta.img`、`vbmeta_system.img`、`vbmeta_vendor.img` 均为 `Flags: 0`、`SHA256_RSA2048`，嵌入公钥指纹为 `b2a02f1e56e366d727a1a8e089762fe0b91bbc84`；其字符串包含 Global `OS3.0.6.0.WNLMIXM` 的 `duchamp_global`、`missi` 等指纹。因此该包应分类为“CN 标签 + Global306 元数据 + 工程/Fenrir 启动链”的混合定制包。

### 2.2 LK 分区差分

对候选 `lk.bin` 与本地 stock Fenrir 样本做 `lk-dump` 后，`lk_main_dtb` 和 `lk_dtbo` 相同，而 `lk`、`bl2_ext`、`aee` 三个分区不同。这与“社区包重新封装/修改启动链”的判断相符。

候选分区哈希：

```text
lk.bin       d33273d0b74929f2f6445709656065a090a21fa50341e100d79c8994045d3e80
bl2_ext.bin  80de3106f4a9448248636a14f2427668409ce8137d8c9472e82773fcb21d3d85
aee.bin      3136c1e55d5f056d453dbf2d1905ffa345fbf424435636d5d3e77765022cdd9d
```

对候选 LK 扫描原始 stock patch needle 的 10 项命中均为 0。这只表示它不像未修改的 stock 输入，和“候选已经改过”一致；它不证明 Preloader 已加载 `bl2_ext`，也不证明 patch 在真机上执行。

### 2.3 真正的 Fenrir 运行时证据

下一次动态验证只接受下面这条证据链：

```text
Preloader -> bl2_ext
  -> expdb/串口日志明确出现 img_auth_required = 0
  -> LK/AVB 放行日志与实际 boot 成功
  -> 设备侧运行的 LK/Preloader 哈希等于已验档候选
```

历史 `[AVB] img_auth_required = 0` 只能说明 LK/AVB 阶段，不能替代 Preloader→`bl2_ext` 的 `[PART]` 行。若只看到 `[PART] img_auth_required = 1`、卡 logo、或没有日志，判定为 Fenrir 门禁未证实，不继续向 TA 写入。

## 3. 包内脚本的风险边界

未执行包内任何安装器。静态读取显示：

- Linux/macOS fastboot 安装器各约 84 次 flash，涉及 `preloader_a/b`、LK、TEE、vbmeta、boot、`super.img.0..53` 等；升级变体仍会擦除 `expdb` 并重启。
- format-data 变体另含 metadata、userdata、expdb、frp 擦除。
- Recovery `updater-script` 直接写入低层 A/B 镜像和全部 super chunks。
- Recovery 使用 `preloader_raw_a/b`，fastboot 脚本使用 `preloader_a/b`；与设备当前 by-name 命名不一致。
- 包没有可独立核验的官方 `anti_version.txt`/scatter/完整签名链，不能从 ZIP 推断 anti-rollback 兼容性。

因此该包只能作为静态研究和已获授权的单次验证候选，不能再次盲目运行一键安装器，也不能只刷 LK 或 Preloader 后“碰运气”判断成败。当前已保留的 stock 启动链备份位于 [`设备备份_只读_20260831_preflash`](../../设备备份_只读_20260831_preflash/) 和 [`duchamp_当前启动链只读备份_20260828`](../01_设备输入/duchamp_当前启动链只读备份_20260828/)。

## 4. K70E RKP 私钥/证书验收门禁

Fenrir 只解决“让指定镜像/诊断 TA 有机会运行”的启动链问题，不自动提供 RKP 身份。RKP 目标必须继续沿 K70E 的活动调用链验证：

```text
GenerateRkpKey 0xc94d8
  -> GenerateKey 0x61960 / 0x610e8
  -> EcKeyFactory::GenerateKey 0xa2fd0
  -> EC_KEY_generate_key 0x116c28       # 生成 P-256 scalar + 公钥
  -> EvpKeyToKeyMaterial 0xa79d0
  -> 0xa32b8 返回点                     # x25 = KeymasterBlob(data,length)
  -> CreateKeyBlob / opaque handle
```

只有 `0xa79d0` 返回后的 `x25` 数据在诊断记录中能解析为未加密 P-256 DER/PKCS#8，且与**同一次** `MacedPublicKey` 的 X/Y 逐字节相等，才允许进入后续步骤：

1. 用该私钥独立验证 CSRv3（外层签名、DICE 条目、challenge/Maced 绑定）；
2. 用 `google-rkp-sw`/等价主机实现生成提交材料；
3. 保存 `private_key_der.bin`、`private_key_pkcs8.pem`（权限 0600）、原始 CSR、原始 HTTP 请求/响应和 `ordered_certificate_chain.pem`；
4. 检查 Google 返回 HTTP 200，且证书叶 SPKI 与私钥公钥相同；
5. 解析叶证书 `notBefore`/`notAfter` 和 provisioning-information OID，记录滚动近 30 天签发近似值。

以下对象一律不算核心身份或私钥：275 字节 opaque handle、119 字节 MacedPublicKey、EEK、CSR、MAC/签名、任意 32 字节窗口、FID/FF06。

## 5. 现有证据与缺口

已确认：

- K70E 原生 CSRv3 可由 Google 返回 HTTP 200；历史叶证书有效期为 `2026-08-27 08:40:55Z` 至 `2026-09-09 04:41:24Z`（12 天 20:00:29）。
- 该历史链的 provisioning-information 报告 `certificates_issued_last_30_days_approx=8`；这是服务端滚动近 30 天近似值，不是自然月精确总数。
- 历史返回的 275 字节 `private_key_blob_opaque.bin` 不是主机私钥，不能和证书链拼成交付物。
- v5 诊断 TA（SHA-256 `88d4b3eecddce9be45d1e73c833a9340e154cb10a2b9c2a1844f3615213679a3`）已完成 ABI/映射静态修正，但尚未形成“真机加载 + DER + 同把公钥匹配”的闭环。

尚未确认：

- 当前设备实际运行的 Preloader/LK/TEE 是否等于本包候选；
- Preloader→`bl2_ext` 是否真实出现 `img_auth_required=0`；
- v5 TA 是否在 `tee-supplicant` 的真实 mount namespace 被加载；
- 是否已经得到主机可读 P-256 私钥；
- 是否已经用该私钥取得一条新的、叶公钥匹配的 Google 证书链。

## 6. 设备可操作后的单次验证顺序

只在设备稳定、可恢复、用户明确开始动态验证时执行：

1. 只读确认 `product=duchamp`、slot、Bootloader 状态、anti-rollback、当前启动镜像哈希和 `tee-supplicant`/KeyMint 服务状态；保存新一份日志。
2. 只读确认可回滚备份可读，且恢复入口（Recovery/Fastboot/BROM）可用；不运行包内一键脚本。
3. 先验证候选 Preloader/LK 的来源和设备实际哈希，再收集启动链日志；没有 `[PART] img_auth_required=0` 就停止。
4. 在正确的 `tee-supplicant` mount namespace、正确的 `post-fs-data` 时序加载 v5 TA；只做一次 GenerateRkpKey，并把全部 stdout/stderr、TA 哈希和 bootreason 归档。
5. 依次执行 DER/P-256、同把 Maced X/Y、CSR 独立验证、Google HTTP 200/叶公钥四道门禁；任何一道失败立即回滚 TA bind/模块，保留失败证据，不把半成品命名为私钥。
6. 只有四道门禁全通过，才把私钥、CSR、证书链和有效期/签发近似值写入新的结果目录，并生成 SHA-256 清单。

## 7. 当前可直接使用的资料入口

- 包哈希与脚本静态审计：[`community_tengeos_CN304_fenrir_candidate_hashes.txt`](../../刷机资源_只读下载_20260831/community_tengeos_CN304_fenrir_candidate_hashes.txt)
- 只读验档脚本：[`verify_fenrir_candidate_readonly.sh`](../../刷机资源_只读下载_20260831/verify_fenrir_candidate_readonly.sh)
- 全链路与最终门禁：[`27_K70E_纯静态全链路复盘与诊断补丁边界_20260831.md`](27_K70E_纯静态全链路复盘与诊断补丁边界_20260831.md)
- TA 缓存/命名空间/冷启动边界：[`28_K70E_活动TA缓存与Marker冷启动结论_20260831.md`](28_K70E_活动TA缓存与Marker冷启动结论_20260831.md)
- v5 ABI 修正与保存状态：[`30_K70E_v5诊断TA_ABI修正与fastboot保存状态_20260831.md`](30_K70E_v5诊断TA_ABI修正与fastboot保存状态_20260831.md)
- 原生 Google 签发结果（历史参考，不含主机私钥）：[`16_K70E_google-rkp-sw原生CSR签发结果_证书私钥保存边界_20260829.md`](16_K70E_google-rkp-sw原生CSR签发结果_证书私钥保存边界_20260829.md)

## 8. 2026-09-01 现场只读前置结果

在设备保持正常启动、没有执行重启或写入的情况下，主机只读核对得到：

```text
serial                 <DEVICE_SERIAL>
product                duchamp
build                  OS3.0.304.0.WNLCNXM
slot                   _a
ro.boot.mode           normal
ro.boot.verifiedbootstate green
ro.boot.vbmeta.device_state locked
ro.boot.flash.locked   1
ro.boot.bootreason     reboot
sys.boot_completed     1
tee-supplicant         running (PID 598)
vendor.keymint-mitee   running (PID 635)
adb shell              uid=2000 (非 root)
su                    不存在/不可访问
ro.debuggable          0
```

`adb root` 返回 `adbd cannot run as root in production builds`。项目的一次性采集器因此在 root 门禁处安全退出：

```text
SAFE_ABORT: root shell is unavailable; refusing to load diagnostics
```

本次前置记录保存在 [`K70E_private_der_google_provision_20260901_preflight/run_summary.json`](../03_提取结果/K70E_private_der_google_provision_20260901_preflight/run_summary.json)，其中 `network_submitted=false`、`flash_or_bootloader_modified=false`。这组实时证据表明当前启动环境仍是原厂 CN304/锁定/非 root 状态；它不能被描述为 Fenrir 已在本次启动中生效。

设备公开的 `cmd remote_provisioning dump/certify` 仍能读取组件信息和已有证书链，但该接口不输出私钥；调用它不能替代 TA 私钥出口验证。

**最新状态标签：**本地 DyperOS 包已验档；Fenrir 候选静态证据已整理；当前设备实时 Fenrir/root 门禁未通过；没有向 Google 提交新的请求；K70E 私钥 + 同钥证书最终交付仍未完成。只有在设备实际进入可验证的 Fenrir/root 启动环境后，才继续第 6 节的单次动态验证。
