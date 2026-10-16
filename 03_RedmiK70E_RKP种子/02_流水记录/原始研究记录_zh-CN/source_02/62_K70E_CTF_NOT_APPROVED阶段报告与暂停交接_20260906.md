# K70E CTF `NOT_APPROVED` 阶段报告与暂停交接

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 阶段结束覆盖：**本文的“暂停/无合格三件套”状态已过时。host-only one-shot 已产生新软件私钥和 Google `APPROVED` 四证书链；终态报告见文档 68。本文的恢复现场证据仍保留。

> 日期：2026-09-06（Asia/Taipei）  
> 目标设备：Redmi K70E / `duchamp` / `<DEVICE_SERIAL>`  
> 暂停性质：用户主动要求暂停、收拢并固化记录  
> 赛事状态：**未完成**  
> 设备状态：已完成 CN304 八步恢复写入和一次重启，随后出现 `the system has been destroyed`；后续从唯一 serial Fastboot 执行 `reboot recovery` 返回 OK，但暂停前 Fastboot/ADB 枚举均为空，屏幕未被再次确认，因此当前物理模式为 UNKNOWN  
> 严格禁止：本文不包含 CDI 标量、软件私钥或完整 MiTEE 日志字节

---

## 0. 暂停时一页结论

1. `NOT_APPROVED` 不是已解决问题；现有拒绝包仍不可提交。
2. 简单尝试次数/证书计数风控已被现有样本对照排除；环境/请求身份差异是已证明的主要根因簇。
3. CN304 八步恢复写入已完成，但恢复设计同时留下两个错误 AVB 输入：第 4 步写入的 `vendor_boot_a=501ec3…d9c9` 实为 OrangeFox/TWRP，未写的 `init_boot_a=9d5d12…2fab4` 是 Magisk 修改镜像。恢复 stock LK 后，顶层 `vbmeta_a` 同时拒绝两者，因此显示 destroyed。
4. 官方 CN304 `vendor_boot_a=63531c…17ef` 和 `init_boot_a=8367dd…3c93` 都已通过顶层 `vbmeta_a=c3828104…1ce0` 的各自 descriptor 离线校验。已尝试的仅是单写官方 `init_boot_a`，stock Fastboot 在分区介质 I/O 之前的 lock-control gate 返回 `No support by lock control`，该命令未改变分区；即使它单独写成，OrangeFox `vendor_boot_a` 仍会保留第二个 AVB mismatch。
5. BROM 真实入口已到达，但唯一一次在线签名返回“MTK V6 卡密已耗尽”；未进 DA，未读写分区。
6. 当前不存在 `POSTBOOT_VERIFIED.json`，也没有任何可替代它的正向证据。
7. approved-stock 的 stock-log zero-key 捕获与 Google one-shot **都尚未消费**。
8. 与之分开，`true K70E CDI + pristine upstream generic/default` 试验已生成并保存一把软件 P-256 私钥，两个网络阶段都已写 `NETWORK_STARTED`，`fetchEekChain` HTTP 200，`signCertificates` HTTP 444 `Device not registered.`。该试验已消费、禁止重放，也不是 approved-stock 试验。
9. HTTP 444 试验没有返回证书，因此无法得出“无 `NOT_APPROVED`”结论；它只是 generic/default 请求的负样本。
10. 项目的完成标准仍然是：本机身份数据 + 同一 approved-stock 流水线中由 `google-rkp-sw` 生成的新私钥 + 与该私钥绑定的 Google 证书链 + 全链 `NOT_APPROVED=0` + 严格验收 PASS。

## 1. 目标与不可缩减的交付物

最终三件套必须来自同一台 K70E 和同一受控流水线：

1. 本机 `google-rkp-sw` 身份数据：目标自有 CDI_Leaf P-256 标量和同轮 zero-key `AuthenticatedRequest`/挑战。
2. 由受控 `google-rkp-sw` one-shot 新产生、原子持久保存的 canonical unencrypted P-256 PKCS#8 软件私钥。
3. Google 为该软件公钥返回的唯一证书链。

最终关系必须同时成立：

```text
CDI scalar -> same-run DICE leaf SPKI
saved PKCS#8 SPKI == sole KeysToSign COSE key == Google leaf SPKI
saved PKCS#8 SPKI != CDI identity SPKI
four-certificate chain signatures/root/path == PASS
full-chain raw Provisioning Info NOT_APPROVED hits == 0
strict audit == PASS
SUCCESS == present and bound
offline stock verifier == PASS
```

任何老 key/新 cert、新 key/老 cert、别的手机身份、generic/default 负样本或仅离线自洽的组合都不是答案。

## 2. 已证实

### 2.1 简单次数/计数风控已排除

全部可用历史 Provisioning Info 样本的统计是：

| 项目 | 结果 |
|---|---:|
| 不同 DER 证书 | 27 |
| 无 `NOT_APPROVED` | 25 |
| 含 `NOT_APPROVED` | 2 |
| 解析失败 | 0 |
| 计数 32 但干净 | 12 |
| 计数 32 且拒绝 | 2 |

两个含 `NOT_APPROVED` 的请求均为 HTTP 200，没有 HTTP 429、`Retry-After`、`quota` 或 `abuse` 信号。所以现有证据排除“只要计数到 32 就风控”和“只因尝试次数多才出现 `NOT_APPROVED`”。

### 2.2 环境/测量差异是主根因簇

干净 native 对照：

```text
request SHA-256        f03011311dca791fccca64f1f78323ba113197f56ac368fbdeeb97162c3ccf56
DeviceInfo SHA-256     19f9f9b0…
CDI leaf SPKI          0684d469…
Provisioning Info      {1:8, 3:"Xiaomi"}
```

两个拒绝请求共享：

```text
DeviceInfo SHA-256     82e42dd8…
CDI leaf SPKI          64c67208…
Provisioning Info      {1:32, 3:"Xiaomi", 5:{1:"NOT_APPROVED"}}
```

干净与拒绝 signed DeviceInfo 的已知差异只落在：

```text
orange / unlocked / acaa9258…
green  / locked   / b9b1d867…
```

DICE 的第 1、2、4 层 measurement/security 同时变化，五层完整 payload 也不同。在同一 modified 环境中，真机 Binder 和 host software 请求获得逐字节相同的拒绝扩展，因此 host framing 不是主因。

### 2.3 拒绝证书不能后处理为合格证书

Provisioning Info 位于 Google 签名的 TBSCertificate 中。删字段、重编 CBOR、换扩展或拼旧链都会破坏证书签名或 key 绑定。唯一有效修复是从被服务端认可的环境重新产生一次新请求。

### 2.4 CN304 恢复写入已真实完成

权威证据目录：

```text
03_提取结果/K70E_CN304_APPROVED_RESTORE_20260906_live5/
03_提取结果/K70E_CN304_APPROVED_RESUME_20260906_live5_step2/
.k70e_cn304_restore_execution_ledger/
```

关键事实：

- `super` 输出有 68 个完整 sparse chunk，原恢复器因精确的 AVB footer warning 出现 parser false negative。
- 独立续执行工具验证原始 stdout/stderr、程序控制流、chunk 数和 fresh Fastboot gate 后，将 step 1 裁定为已完成，**没有重刷 `super`**。
- step 2–8 均完成，`FLASH_COMPLETE.json` 记录 `completed_steps=[1..8]`、`last_target=preloader_a`、`automatic_retry=false`。
- `RECOVERY_COMPLETE.json` 和 `REBOOTED.json` 证明已单次重启，且 marker 明确写着 `postboot_verified=false` 与 `rkp_authorized=false`。

因此文档 58 的“尚未执行恢复”已过时，不得继续引用。

### 2.5 destroyed 的双重 AVB 直接因果已闭合

恢复器保留的旧 `init_boot_a` 是：

```text
size      8,388,608
SHA-256   9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
role      known-good historical Magisk init_boot
```

官方 CN304 `init_boot.img` 是：

```text
size      8,388,608
SHA-256   8367dddeb8629def57d702eb26d92219654cca4d952e1d5ad0557cae47583c93
role      stock image matching the signed top-level vbmeta descriptor
```

第 4 步实际写入的 `vendor_boot_a` 是：

```text
size      67,108,864
SHA-256   501ec32cb585c60c4db9245266c16469eb42b31f7b4fb37b8f8f6d1c7d45d9c9
role      OrangeFox/TWRP, not stock
```

官方 CN304 `vendor_boot.img` 是：

```text
size      67,108,864
SHA-256   63531c1f25db3b5676c0fcb3fb241f8795e24846841d7f065462019ef77517ef
role      stock image matching the signed top-level vbmeta descriptor
```

顶层 `vbmeta_a` 为：

```text
size      8,388,608
SHA-256   c38281042cd2581421c4589ee2ccaf349e929d1e6a1390b915133c3bb2291ce0
```

离线重算证明，该 `vbmeta_a` 的 `init_boot` descriptor 只与官方 `8367dd…3c93` 相符，`vendor_boot` descriptor 只与官方 `63531c…17ef` 相符。原厂 LK 恢复后开始严格执行两个绑定，OrangeFox `501ec3…d9c9` 和 Magisk `9d5d12…2fab4` 都不匹配，与屏幕所见 destroyed 一致。所以后续的 locked-stock 救机单元必须是官方 `vendor_boot_a + init_boot_a` 配对，不再是单 `init_boot_a`。

### 2.6 stock Fastboot 直写路线已被当前锁控拒绝

事件专用单分区程序的 fresh gate 记录：

```text
serialno                 <DEVICE_SERIAL>
product                  duchamp
current-slot             a
secure                   yes
unlocked                 no
is-userspace             no
has-slot:init_boot       yes
partition-size:init_boot_a 800000（Fastboot 原文；按十六进制为 8 MiB）
```

唯一一次写入输出：

```text
Sending 'init_boot_a' (8192 KB)                    OKAY
Writing 'init_boot_a'                              FAILED (remote: 'No support by lock control')
fastboot: error: Command failed
```

对应证据目录：

```text
03_提取结果/K70E_CN304_INIT_BOOT_RECOVERY_20260906_live1/
```

该目录已存在 `FLASH_STARTED.json` 和 `PARTIAL_OR_UNKNOWN.json`，不得删 marker、换目录重放或把 Sending OKAY 当成分区写成功。Sending OKAY 只把 8 MiB 传入 Fastboot 缓冲区；Writing 在分区介质 I/O 之前的 lock-control gate 被拒绝，因此该命令未改变 `init_boot_a`。`PARTIAL_OR_UNKNOWN.json` 仍是已发生的耐久事件 marker，必须保留作为审计痕迹，不因事后已定位 pre-media-I/O 拒绝就删除或改名。

### 2.7 BROM 入口可到达，但当前授权通道已耗尽

本次 Windows/SP Flash Tool 现场事实：

- Windows 识别到 `MediaTek USB Port (COM4)` / PID `0003`，因此是真实 BROM，不是 Preloader 冒充。
- `Auth.exe` 显示新的 80-byte challenge BLOB。
- 仅点击一次“在线签名 F2”，返回：`MTK V6 卡密已耗尽`。
- 没有第二次点击，没有重连后重试。
- 签名响应为空，SP Flash Tool 未进入 DA，因此无分区读、写、擦除或重启。
- 本次 XML 只设计两项 READ-FLASH：LU2 `seccfg` 与 `expdb`；未执行。
- Windows 证据快照保存在 `D:\duchamp_recovery\BROM_AUTH_EXHAUSTED_20260906_1755`，之后已精确停止 `SPFlashToolV6.exe` 和 `Auth.exe`。

现有 `.kami` 不得继续尝试。新 BROM 会话会产生新 challenge，旧响应不可复用。

### 2.8 generic/default 网络试验已消费并返回 HTTP 444

独立负样本目录：

```text
03_提取结果/K70E_google_rkp_sw_vanilla_true_CDI_generic_default_20260906_172657/
.k70e_google_rkp_sw_vanilla_default_ledger/TRUE_CDI_GENERIC_DEFAULT_ONCE.CLAIM.json
```

可公开审计元数据：

| 项目 | 值 |
|---|---|
| ledger status | `CONSUMED_NO_RETRY` |
| mode | `true_K70E_CDI_plus_pristine_upstream_generic_defaults` |
| upstream commit | `8a74e55e6e900c04c84e12380e467cefa1a27cc5` |
| DeviceInfo | `generic/default/default:13/...`, green/locked |
| DICE | pristine-upstream degenerate, 2 entries, `UDS == CDI_Leaf` |
| KeysToSign | 1 把新 P-256 software key |
| private key | 已在网络前保存，私密材料未打印 |
| fetch marker | `fetch_eek_NETWORK_STARTED.json` 存在 |
| fetch response | HTTP 200 |
| sign marker | `sign_certificates_NETWORK_STARTED.json` 存在 |
| sign response | HTTP 444，62 bytes，`Device not registered.` |
| certificate count | 0 |
| final marker | `FAILED.json` / `FAILED_OR_REJECTED` |

该试验证明 generic/default 请求到达 Google 并被明确归类为未注册；它不能证明 approved-stock 身份未注册，也不能证明证书中无 `NOT_APPROVED`，因为根本没有证书返回。

### 2.9 approved-stock one-shot 未消费

暂停时没有 stock-log 产线的：

```text
zero-key DISPATCHING_NO_RETRY
stock capture contract
host ATTEMPT.json
device issuance latch
stock NETWORK_STARTED.json
BURNED.json
SUCCESS.json
```

恢复前最后一次 live gate 在 Binder 和任何 stock ATTEMPT 之前 `SAFE_ABORT`；恢复后设备未通过 postboot，所以 stock 路线也没有起跑。

**generic/default 的消费账本和 approved-stock 账本必须永久分开。** 前者已烧毁，后者仍保留一次受控机会。

## 3. 已排除

| 假设/路线 | 判定 | 证据边界 |
|---|---|---|
| 只是尝试次数多 | 已排除为现有样本的简单主因 | 12 个 count-32 干净对照；拒绝样本无 429/quota/abuse |
| host framing 是主因 | 已排除 | modified 真机 Binder 与 host 拒绝扩展逐字节一致 |
| 请求到 HTTP 200 就是 PASS | 已排除 | 两个 HTTP 200 证书仍含 `NOT_APPROVED` |
| 删掉证书里的字段 | 已排除 | 会破坏 Google TBSCertificate 签名 |
| 继续修 TEE/上 patched TA 做正式签发 | 已排除 | 已改变 DICE 并实际产生 `NOT_APPROVED` |
| 恢复磁盘后不重启就能倒转 DICE | 已排除 | DICE 已在当次 boot 构建，必须 fresh boot |
| 当前 locked stock Fastboot 可直写 `init_boot_a` | 已排除 | lock-control gate 在介质 I/O 前精确拒绝；分区未改变 |
| Sending OKAY 等于分区已写 | 已排除 | Writing 明确 FAILED |
| 现有 BROM 卡密仍可重试 | 已排除 | 单次签名明确报卡密已耗尽 |
| generic/default 444 是合格三件套 | 已排除 | 没有证书链，且不是 approved DeviceInfo/DICE |
| 离线回归 PASS 等于赛事完成 | 已排除 | 离线工程验证不产生 Google chain |

## 4. 未证实

以下事项必须保持 UNKNOWN，不得凭经验补结论：

1. Fastboot 拒绝后缺少一份独立 raw readback 作为额外交叉证据。事件本身已证明 lock-control gate 在分区介质 I/O 前拒绝、该命令未改变分区；`PARTIAL_OR_UNKNOWN` marker 仍作为已发生事件的审计痕迹保留。
2. 暂停瞬间的物理模式与主机 transport。唯一 serial Fastboot 曾返回 `reboot recovery OKAY`，之后 Fastboot/ADB 抽样均为空，手机屏幕没有新权威记录。
3. stock Mi-Recovery、OrangeFox、destroyed、Android 或黑屏中的哪一个实际落地。`reboot recovery OKAY` 只证明 bootloader 接受了命令。
4. Mi-Recovery `Connect with MIAssistant` 能否接受这一 CN304 恢复包。完整 recovery OTA 下载未完成，`.part` 文件不可使用。
5. 当前 standard `seccfg` 和 Xiaomi custom/RPMB 锁状态的最新成对实值。BROM 读取没有进入 DA。
6. 官方 `vendor_boot_a + init_boot_a` 成对恢复后设备能否完整启动；当前只有离线 AVB 配对证据。
7. 官方 pair 启动后如何在不破坏 approved DICE 的前提下取得 stock MiTEE 日志所需 root。当前 restore/postboot/capture/issuer/profile 仍错误钉死 OrangeFox `501ec3…` 和 Magisk `9d5d12…`。
8. 新鲜 approved-stock 捕获是否与已认可基线的 signed DeviceInfo、五层 measurement/security 和五层完整 payload 相同。尚未采集。
9. approved-stock one-shot 返回的证书是否为干净链。尚未请求，不可承诺。
10. generic/default HTTP 444 不能外推为 approved-stock 身份的注册状态。

## 5. 当前设备状态

### 5.1 已确定的时序

```text
CN304 step 1 super: 68/68 sparse chunks complete
  -> parser false negative independently resolved, no retry
  -> steps 2..8 complete, last target preloader_a
  -> one verified reboot
  -> screen: Xiaomi logo then "the system has been destroyed"
  -> Fastboot read-only gate: locked/secure/slot A
  -> one official init_boot_a flash attempt
  -> Sending OKAY, Writing rejected by lock control
  -> true BROM COM4 entered
  -> one online auth attempt: card exhausted
  -> no DA, no partition I/O
  -> SPFT/Auth stopped
  -> unique serial Fastboot observed
  -> serial-bound reboot recovery returned OKAY
  -> subsequent Fastboot/ADB samples both empty
  -> actual Recovery/screen state remains UNKNOWN
  -> user requests pause
```

### 5.2 安全判定

- BootROM、Preloader 和 Fastboot 均已有存活证据，不是“硬砖已证实”。但暂停时物理模式为 UNKNOWN，不能因 Fastboot/ADB 为空就宣称 Recovery 已启动。
- Android 正常启动当前不成立。
- ADB、root、TEE service、stock TA、HLOS 哨兵和 logical partition 都未做 postboot 实机验证。
- `POSTBOOT_VERIFIED.json` **不存在**。
- 所以 Binder zero-key、software keygen 和 approved-stock Google 网络请求全部仍不授权。

## 6. 证据缺口

| 缺口 | 所需最小证据 | 获得前禁止 |
|---|---|---|
| 当前 transport | 唯一物理设备 + 唯一 `<DEVICE_SERIAL>` Fastboot/ADB 记录 | 任何写入、重启到未知目标 |
| 当前 `init_boot_a` raw | 全长 readback + size/SHA-256 | 宣称已恢复或已保留 |
| 当前锁状态 | 同一 BROM 会话的 `seccfg` + `expdb` readback，加上 custom/RPMB 状态能力 | 写 `seccfg`、解锁/重锁推测 |
| stock/recovery 实际模式 | 用户屏幕原文 + fresh USB inventory；已有 `reboot recovery OKAY` 不足以判定 | 擦数据/盲刷/假定 Recovery 已起 |
| 完整 recovery OTA | 完整 size + 官方 hash/MD5 + 压缩包遍历 | 使用 `.part` |
| postboot 认可 | 独立验证器写入的 `POSTBOOT_VERIFIED.json` | Binder/RKP/Google |
| approved DICE 身份 | 同 boot stock zero-key capture 通过 contract | 发行预检 |
| Google 三件套 | 唯一 approved-stock ATTEMPT 的 raw request/response/key/chain 和 strict audit | 报告解题完成 |
| Windows BROM 现场证据 | 将 `BROM_AUTH_EXHAUSTED_20260906_1755` 完整复制回主工作区并建 hash manifest | 丢弃 Windows 目录或重用 challenge |

## 7. 恢复阻塞与可行分支

### 7.1 阻塞 A：stock Fastboot 写权限

当前 Fastboot 自报 `unlocked=no` 且 `secure=yes`，对精确官方 `init_boot_a` 的 Writing 返回 lock-control 拒绝。不再执行裸 `oem unlock`：历史已证明它可显示 OKAY 但不建立可信的双域解锁状态。

### 7.2 阻塞 B：BROM SLA 授权

当前工具可生成 challenge，但卡密已耗尽，未有可用的新响应。需要以下其一：

- 合法的新 challenge-specific 签名额度/响应；
- 官方售后/服务模式授权；
- 经独立验证、明确支持 MT6897 `0x1203` 且能在 DA1 之前跨过 SLA 的方法。

泛用 mtkclient HeapBait 位于 DA1 之后，不能当作现有 pre-DA1 SLA 的已验证解法。

### 7.3 分支 C：先识别已发出 recovery reboot 后的真实落点

暂停前已经在唯一 `<DEVICE_SERIAL>` 上执行一次 serial-bound `reboot recovery`，命令返回 OKAY，但实际画面未记录。恢复工作时：

1. 不先按键或重发命令，先由现场人记录屏幕原文，再只读枚举 USB/ADB/Fastboot；
2. 如进 stock Mi-Recovery，先记录菜单，不选 wipe，只研究 `Connect with MIAssistant` 的可逆入口；
3. 如显示 OrangeFox，先只读鉴别它的 ADB/root/块设备能力，不手点 Install/Format/Flash；
4. 如返 destroyed/Fastboot/黑屏，保留结果，不循环重试；
5. 只有 fresh 唯一 Fastboot 重新出现且上述已消费命令无法解释当前落点时，才按文档 60 的无写诊断合同决定是否再做一次，不默认重发。

不得把 Fastboot/ADB 抽样为空推导为“Mi-Recovery 已起”；当前仍是 UNKNOWN。

### 7.4 分支 D：BROM 授权后的最小工作

如将来获得新授权，顺序必须是：

1. 使用已钉 hash 的 DA/Auth/只读 XML；
2. 在同一会话只读 `seccfg` 与 `expdb`，两者都完整 readback 并校验；
3. 先分类 standard seccfg 和 Xiaomi custom/RPMB 锁状态，不凭单一镜像猜解锁；
4. 如锁状态不需写，就不写 `seccfg`；
5. 在可证明的映射、目标和回读能力下，把同固件官方 `vendor_boot_a=63531c…17ef` 和 `init_boot_a=8367dd…3c93` 当作一个不可拆的 locked-stock 恢复对；
6. 两项分别写后立即精确 readback，两者都等于官方 hash 才独立重启。

默认禁止 TEE、B 槽、RPMB、efuse、userdata、relock 与广泛擦除。

## 8. 一次性账本状态

| 路线 | 状态 | 是否可重放 | 备注 |
|---|---|---:|---|
| historical rejected 2026-09-05 bundle | `REJECTED_NOT_APPROVED` | 否 | 仅作负 fixture |
| generic/default true-CDI experiment | `CONSUMED_NO_RETRY`, HTTP 444 | 否 | 已生成私钥，无证书 |
| CN304 eight-step restore claim | 已消费并完成 | 否 | step 1 未重刷，steps 2–8 完成 |
| CN304 reboot claim | 已单次消费 | 否 | 重启后 destroyed |
| official init_boot-only Fastboot repair | `PARTIAL_OR_UNKNOWN` marker 已落盘；pre-media-I/O reject 已定位 | 否 | lock-control gate 未改变分区；且语义上缺 official vendor_boot |
| serial-bound `reboot recovery` | 命令已执行一次并返回 OK | 不默认重发 | 实际 Recovery/屏幕落点 UNKNOWN |
| stock zero-key capture | 未消费 | 仅在全部门通过后一次 | 当前未授权 |
| approved-stock Google issuance | 未消费 | 仅在全部门通过后一次 | 当前未授权 |

### 8.1 旧三 manifests 已隔离

下列旧 manifests 不再具有执行授权：

```text
SHA256SUMS_RECOVERY_CN304.txt
SHA256SUMS_PORTABLE.txt
SHA256SUMS_HANDOFF.txt
```

它们既有恢复器/postboot verifier/Skill 等字节漂移，又把 OrangeFox `vendor_boot_a=501ec3…` 和 Magisk `init_boot_a=9d5d12…` 错当成当前批准锚。旧三清单必须保留作为事故/漂移证据，不得通过就地改 hash 复活。只有 paired restorer、postboot、collector、issuer、profile、测试和 Skill 全部完成语义迁移后，才能创建新版本/新名称的 replacement manifests。

## 9. 完成条件

项目只有在以下各项都有当前强证据时才能标记完成：

1. 当前双重 AVB mismatch 被一个经审计的配对方案闭合，设备恢复为可稳定启动、唯一 ADB 目标，且 fresh boot 可区分于历史 boot。
2. 独立 postboot verifier 完整读取 raw A/B boot-chain、9 个 A 逻辑分区、stock TA/TEE/services/HLOS，并以独占持久方式生成 `POSTBOOT_VERIFIED.json`。
3. 旧三 manifests 继续隔离；新 versioned replacement manifests 与实际脚本/语义一致，相关回归在当前字节上重跑 PASS。
4. 同一 fresh approved boot 中仅运行一次 stock zero-key 捕获：0 KeysToSign、5 层 DICE、outer signature、challenge、signed DeviceInfo 和同机 CDI_Leaf 标量关系全部 PASS。
5. signed DeviceInfo、5 层 measurement/security 和 5 层完整 payload 逐项等于已认可基线。
6. stock issuer `--preflight-only` 报告 `network_issuance_allowed=true` 且 `network_access=false`。
7. 在同一 boot 、手机仍离线、用户当下在场的前提下，只消费一次 approved-stock Google one-shot。OrangeFox/Magisk/Fenrir/patched TEE/TA 可用于经审计的临时救援或取证，但绝不能作为最终 accepted issuance 环境。
8. `google-rkp-sw` 生成的新 P-256 私钥已按 0600 持久保存，存储重读、SPKI 和 PoP 门都 PASS。
9. 请求唯一 key、私钥 SPKI 与 Google leaf SPKI 相同，且与 CDI identity SPKI 不同。
10. 四张证书精确消费、链签名有效、根是钉死 Google root、无重复/歧义。
11. 全链每个 Provisioning Info 原始扩展均严格解析，`ctf_no_not_approved=true`，精确命中数 0。
12. strict audit、`SUCCESS`、独立 stock verifier 全部绑定同一 capture/attempt/output 并 PASS。
13. 最终三件套、文档、Skill 和 versioned replacement manifests 重新冻结，无私密材料副本外泄；旧三 manifests 仍作为历史隔离证据。

## 10. 暂停与恢复工作逻辑

本次暂停不改写任何一次性语义。恢复工作时：

1. 先读文档 59–63，然后 58，最后 52–57；以当前文件字节和耐久 marker 为最终事实。
2. 不运行 Binder、不连 Google、不刷机，先做离线 marker/目录/manifest 盘点；旧 recovery/portable/handoff 三 manifests 保持隔离，不重写复活。
3. 把 generic/default 路线当成已消费负样本，不删 marker，不换目录重试。
4. 把 stock capture 和 approved-stock Google one-shot 当成尚未消费，但在 `POSTBOOT_VERIFIED.json` 出现之前绝不运行。
5. 用户重新明确说已在手机旁边后，才做 fresh 唯一设备 transport 盘点。
6. 不假设 Recovery 已启动；先记录屏幕原文和 fresh USB inventory。`reboot recovery` 已返回过一次 OK，不默认重发；不再重试已拒绝的 init_boot-only Fastboot flash。
7. 如转 BROM，必须有新授权才继续，先读后写；现有耗尽卡密不得再点。
8. 恢复可启动后也不立即跑 CTF；先把 restore/postboot/capture/issuer/profile 中的 OrangeFox `501ec3…` + Magisk `9d5d12…` 错误锚迁移为真实的恢复/root/批准合同，并重新验证 approved DICE。

## 11. 证据优先级与过时说明

后续 AI 的阅读顺序：

```text
当前字节 / 原始输出 / 耐久 marker
  > 文档 59–63（本次最新现场收拢）
  > 文档 58（恢复执行前设计）
  > 文档 52–57（NOT_APPROVED 根因与 stock-log 工程）
  > 文档 45–51（历史，其旧 PASS 已被否定）
```

明确过时点：

- 文档 58 的“尚未执行恢复”已被本文覆盖。
- 文档 58 固定的恢复器/postboot verifier 旧 hash 已漂移；旧 recovery/portable/handoff 三 manifests 已撤销执行权，不得盲信或就地复活。
- 文档 45–51 中任何“最终 PASS/已解题”措辞都已被 `NOT_APPROVED` 事故和本次现场证据覆盖。

## 12. 阶段报告结论

当前工程已经把“简单次数风控”排除，把拒绝定位到环境/测量差异，并完成 CN304 主恢复写入。但恢复集错把 OrangeFox `vendor_boot_a` 当成 stock，同时保留了 Magisk `init_boot_a`；两者都与 stock `vbmeta_a` 不匹配。当前 locked Fastboot 和耗尽的 BROM 授权又阻断了官方 `vendor_boot_a + init_boot_a` 配对恢复。

generic/default 已消费试验的 HTTP 444 证明该伪默认环境不可作为赛事答案；它没有消费 approved-stock one-shot。后续唯一正确方向是先恢复一个可证明的 approved stock boot，生成真实 `POSTBOOT_VERIFIED.json`，然后在同一 boot 中仅执行一次 stock capture 和一次 approved-stock Google 签发。

**在新链实际返回、私钥/请求/叶公钥关系闭合、全链 `NOT_APPROVED=0` 且三重验收 PASS 之前，任务仍是未完成。**
