# 行为记录（Action Log）— Fenrir 复现 & Keybox 提取

> 逐条记录本次任务的所有操作、命令、结果与决策依据。时间：2026-08-12 ~ 2026-08-13
> 设备：Nothing Phone (2a) A142 / Pacman / MT6886 / NOS U2.5-240114-2323

---

## 阶段 0：调研与选型（08-12）

1. 分析 fenrir 仓库（README/injector/payload 源码）：漏洞 = seccfg=unlock 时 Preloader 跳过 bl2_ext 校验（EL3）。
2. 核对 14 款支持设备的适配完整度：payload 头文件仅 pacman/tetris/lg8n/q25 齐全；补丁为字节模式匹配。
3. 读完 fenrir 全部 open/closed issue + 3 个 release：
   - 关键情报：**Nothing 在 NOS4 stable 已修复**；v2.0 release 用"beta preloader + 补丁 lk"绕开
   - issue #20：NOS3.2-250904 + v1.0 → bootloop（版本需匹配）
   - issue #28：刷 fenrir 后锁状态被伪装 → fastboot 刷写被拒（"No support by lock control"）
   - issue #15：MT6897 补丁 pattern 不匹配（SoC 必须精确）
4. 决策：选定 Nothing Phone 2a (A142/Pacman)——作者开发机、唯一有官方预编译 release、官方固件可下。
5. 制定现场采购核验清单（型号/SoC/OEM解锁/fastboot/USB/锁类）。

## 阶段 1：采购现场验机（08-12，商场）

通过 adb 实测（设备：序列号 <DEVICE_SERIAL>）：
```
ro.product.device = Pacman ✓
ro.product.model  = A142 ✓
ro.hardware       = mt6886 ✓
ro.build.display.id = U2.5-240114-2323（NOS 2.5, 2024-01 出厂版）
ro.build.fingerprint = Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys
sys.oem_unlock_allowed = 0（初始）→ 用户手动开启后 = 1 ✓
ro.boot.flash.locked = 1（原装 locked，正常）
无 Google 账号/演示模式/企业锁 ✓
fastboot getvar product = k6886v1_64（MT6886 板级名，与 Pacman 吻合）
current-slot: a
unlocked: no
```
判定：全部通过，购买。

## 阶段 2：环境搭建（08-12）

1. fastboot/adb 已有（v37）。
2. 网络抖动多次后，tarball 方式下载 fenrir（main）与 mtkclient 到工作目录。
3. fenrir：`.venv` 装 liblk（master 分支 tarball，pip 直装 git 失败因网络）→ `inject.py` 列出 14 设备，验证可用。
4. mtkclient：系统 Python3.9 语法不兼容（`X | None`）→ brew 装 python3.12 → 建 `.venv312`；装 pyusb/pyserial/pycryptodome*/colorama/capstone/mfusepy；mfusepy 缺 libfuse 抛 OSError（非 ImportError 捕获不到）→ patch 两处 except 为 `except (ImportError, OSError)`（`mtkdafs.py`、`mtk_da_handler.py`）→ CLI 正常。
5. brew 装 libusb（pyusb 后端）、sevenzip。

## 阶段 3：解锁 Bootloader（08-12）

过程曲折，关键记录：
1. `adb reboot bootloader` → fastboot 在线。
2. `fastboot flashing unlock` → 返回 OKAY 但 `unlocked: no`（假象）。
3. 多次尝试发现规律：命令发出后**手机屏幕弹 5 秒倒计时确认界面**，超时自动取消（两次 OKAY 均为整 5.167s）。
4. `fastboot oem unlock` → unknown command（LK fastboot 无此命令）。
5. **成功姿势**：发命令后屏幕一变，**立刻按「音量下」一下**即确认解锁（不需要电源键）。返回 `Start unlock flow`，`unlocked: yes` ✓
6. 设备自动 wipe 重启。用户后续重进向导、重开 USB 调试（ wiped 后调试授权失效）。

## 阶段 4：mtkclient 能力与救援通道评估（08-12/13）

1. 设备进下载模式测试（关机+音量上下按住+插线）：
   - **BROM 模式**（按音量键）：`Cmd 0xC8 blocked: True`，dump 需 auth；kamakiri payload 发送时 USB 权限错误（macOS 端问题）
   - **Preloader 常规模式**（不按键插线）：`Mem read/write auth: False`、`Cmd 0xC8 blocked: False`——内存读写开放
2. DA 上传失败：`DAA_SIG_VERIFY_FAILED (0x7024)`——通用 DA 未签名；目标配置 SBC=True/DAA=True/SLA=False。
3. mtkclient 对 MT6886 的 brom_config 大部分被注释 = 半成品支持。
4. 结论：**当前无法用 mtkclient 读写闪存**；救援需签名 DA。
5. 找到救援资源：`mistrmochov/nothing-pacman-hardbrick`（含 Nothing 官方 Flash Tool，硬砖可救，Windows）→ 开始下载 5.4GB 救砖包（MediaFire）。

## 阶段 5：固件获取（08-13，慢网环境）

1. 用户出差网速差，停掉 5.4GB 包（已下 1.2GB，文件保留可续传）。
2. 改从 nothing_archive 获取 **Pacman_U2.6-240828-1906**（存档最老版本）：
   - `image-firmware.7z`（50MB）→ 含 lk.img / tee.img / gz.img / preloader_raw.img 等 22 个镜像
   - `image-boot.7z`（34MB）→ boot/init_boot/dtbo/vendor_boot/vbmeta
3. 用 OTA payload.bin Range 下载法解析出真实分区名基列表（tee/gz/lk/preloader_raw 等）。
4. fastboot 探测法实测：**tee 分区名 = `tee_a`/`tee_b`**（不存在的名字直接报 "partition does not exist"，安全）。

## 阶段 6：TEE 架构侦察（08-13）

1. tee.img/gz.img 均为 MTK 头（magic 0x58881688）：
   - tee.img = ATF(BL31) + **t-base (Kinibi) 内核**，版本 `t-base-MTK-A64O-Android-510a-V017-20230522`
   - gz.img = GenieZone（与 keybox 无关）
2. trustlet 来源：`RandomPush/nothing_pacman_dump`（NOS3.0 构建 dump）的 `vendor/app/mcRegistry/`：
   - `e97c270ea5c44c58bcd3384a2fa2539e.tabin`（451KB）= **Widevine 主 TA**（MCLF v5，含 OEMCrypto_InitKeybox/drMdw_QueryKeybox 字符串）
   - `40188311faf3...` = Widevine DRMDR 驱动；`5020170115e0...` = DRM_HDCP_Common 驱动（含 "wv keybox length" 校验）；`abcd270e...` = keybox 包装 TA
3. 尝试 `adb pull /vendor/app/mcRegistry` → Permission denied（需 root，记下后续补）。

## 阶段 7：双路逆向（08-13，两个子代理并行）

**A. Widevine trustlet 导出补丁**（完整报告在会话记录）：
- MCLF 解析：text VA 0x1000=file 0x80；file=VA-0xF80
- keybox 链：TCI cmd 0x1b → 分发器 0x2368 → InitKeybox 0x11f40 → keybox 明文指针 `[sp+0x48]`（0x11f98）
- TCI 全局指针 `[0x70af0]`，大小 0x8000；方案：拷贝 keybox 到 TCI+0x1000
- 补丁：file 0x11020 改 `bl 0x57050`（代码洞 0x30 字节拷贝例程，capstone 验证编码）
- keybox 有效长度 ~0x1b9 字节（keybox v3）

**B. t-base 签名验证补丁**：
- tee.img 切分：6 组件；t-base 载荷 file 0x5C500–0xEC6C0，运行基址 0x1D000000
- 补丁 A：file 0xBE978/0xBE97C → `mov w0,#0; ret`（verifySignature 恒过）
- 补丁 B：file 0xBEDD8 → `b 0x6A92C`（白名单拒绝点改跳转）
- 确认无镜像自检等第二层防护

## 阶段 8：刷机与故障（08-13）

1. **第 1 刷**（兼容性验证）：`fastboot flash lk_a U2.6原版lk.img` → 启动正常 ✓（证明 U2.6 lk 兼容 U2.5 机器）
2. **第 2 刷**（漏洞验证）：`fastboot flash lk_a pacman-fenrir-minimal.bin` → **启动正常 ✓ = Preloader 接受修改过的 bl2_ext = 漏洞实锤**
3. **第 3 刷**（t-base 补丁）：tee-patched.img（A+B 补丁，U2.6 基底）刷 tee_a + tee_b → **"Can't load Android system"（Try again / Factory data reset）**
4. 回刷 U2.6 原版 tee 到 tee_a/tee_b → **仍进 recovery**；factory reset 无效
5. 诊断结论：**U2.6 tee 与 U2.5 系统不配套**（vendor 内 trustlet/KeyMint 与 TEE 内核版本不匹配导致 userdata 无法挂载）；教训：未备份 U2.5 tee 就双槽覆盖

### 故障期间的模式/按键记录（本机实测怪癖）
- recovery 的 adbd 半残：shell/exec 全崩（SELinux context 错），`adb root` 拒绝（production）；`adb reboot-bootloader` 能触发重启但回到 recovery
- VolUp+Power 长按 → orange state 底部显示 "recovery mode" → 进 recovery
- VolDown+Power 长按 → 用户观测为黑屏+间歇震动（判断为强制重启循环，电源长按覆盖）
- 解锁后插 USB 会自动上电，干扰"关机后按键"时序
- **最终有效**：fastbootd 路径（用户借助其他 AI 完成进入）

## 阶段 9：当前进行中（08-13）

- 续传救砖包 `pacman_flashtool.7z`（~2.2MB/s，后台 curl -C -）
- 到达后计划：
  1. 7z 解压 → 取签名 DA + U2.5 时期全分区镜像
  2. mtkclient `--loader` 指定 DA → BROM/preloader 连设备 → 刷回 U2.5 tee（必要时连 lk 一起）→ 恢复启动
  3. 用 DA dump 全分区做完整备份（含 U2.5 原版 tee/lk/boot）
  4. U2.5 tee 上只打补丁 A（不碰 B）→ 小步验证
  5. Magisk root → 替换 trustlet → 客户端发 TCI 0x1b → 读 TCI+0x1000 → keybox

## 失误清单（诚实记录）

1. 刷 tee 前未备份设备原版 U2.5 tee，且双槽（a+b）同时覆盖 → 失去回退基线
2. 低估了 fastboot 按键在解锁后设备上的时序怪异度，多轮按键指导无效，浪费用户时间
3. 初期报价/判断凭印象（Pova 4 Pro 价格、"社区 keybox 案例多"表述）被用户纠正，应以实证为准
4. tee 补丁一次打 A+B 两个，违反"小步验证"原则，应只打 A 逐步测试

## 阶段 9.5：单变量恢复成功（08-13，用户主导）

- 借助第三方 AI 定位进入 fastboot 的可行路径（fastbootd），**仅回刷 tee_a ← U2.5 原厂 tee.img**
- 结果：系统正常启动，TEE/DRM 服务运行正常（init.svc.tee-1-1 / drm64 = running）
- 保留状态：lk_a = fenrir 补丁版（CTF 成果完好）、BL 仍解锁、boot/vbmeta 未动
- tee_b 仍为 U2.6 原版（无影响，活动槽为 a）
- **诊断坐实**：之前无法启动的根因是 U2.6 tee ↔ U2.5 系统不匹配，非补丁问题
- 后续教训固化：任何分区操作前先备份；单变量测试；补丁 A/B 分开验证

## 阶段 10：tee 签名补丁成功（08-13）

- 用 U2.5-231207-0042 原厂 tee.img（nothing_archive 公开包，SHA256 8c2ef73a...）做基底
- 实证：U2.5-231207 与 U2.6 的 tee.img 在补丁点字节一致、t-base 版本相同（510a-V017）；U2.6 启动失败的根因是其内嵌驱动与 U2.5 系统不配套，非补丁问题
- 构建 tee-patched-A-only.img（**只打补丁 A**：0xBE978/0xBE97C → `mov w0,#0; ret`，共 7 字节差异）
- 刷 tee_a → **系统正常启动，TEE 服务运行正常** → t-base 签名旁路生效，补丁 B（白名单跳转）确认为上次故障元凶
- 同时确认：U2.5-240301-2206 boot.img 内核版本与设备（240114）**逐字符一致**（5.15.104-android13-8-00001-gac1072c849eb-ab10753874）→ 用其 init_boot 做 Magisk 材料
- Magisk v30.7 APK 已下载（11MB）

## 阶段 11：目标纠正（08-13）

- **用户纠正目标**：要提取的是 **keystore 认证 keybox（KeyMint attestation 私钥+证书链）**，不是 Widevine keybox
- 待确认设备是否 RKP（远程密钥置备）
- 之前对 Widevine trustlet 的逆向（patched/patched2/patched3 方案）属方向性偏差，但方法论与基础设施（签名旁路、root、触发 app、客户端）全部可复用到 KeyMint TA

### 期间完成的其他有效动作
- 构建出 MediaDrm 触发 APK（wvtrig.apk，app_process 路线失败改用 aapt2/d8/apksigner 全流程，调通）
- 实测：原版 trustlet 下 Widevine L1 初始化成功（证明 TEE+签名旁路下 trustlet 正常工作）
- patched2（钩 callDriver 门）导致 L1 初始化失败——stub 上下文假设不成立，已在文档记录，待修

## 阶段 12：锁定正确目标 TA（08-13，离线）

- 排除：`05060000...tabin`（10MB）= 汇顶指纹 TA（含 "GxGetDarkPatternInfo_Shenzhen"）
- **锁定 KeyMint trustlet = `0706000000000000000000000000004d.tlbin`（281KB，设备 U2.5 精确版）**
  - 铁证字符串："KEYMINT"、"Keymint TA"、"teeKeymint-package-2.0.0-20220420"、"decrypt_keybox"、"verify_keybox"、"Decrypting keybox is success!"、"Verify Keybox Signature..."
- **RKP 判定**：含 `rkp_bcc_km`（RKP Boot Cert Chain）+ "USING EEK ROOT KEY FROM VTS" → **TA 支持 RKP**。同时 persist 里有工厂 attest_keybox.so → 工厂烧录+RKP 双支持。是否实际启用 RKP 需运行时确认（看认证密钥数量）
- 流程推断：NWd keymint 服务读 persist/attest_keybox.so → 送 TA → decrypt_keybox 解密 → 认证私钥明文落 TA 内存；密钥认证（attestation）为**离线操作**（keystore generateKeyPair+attestation challenge 即可触发）
- 提取路径（纠正后）：patch KeyMint TA 的 keybox 解密点 → 导出明文到 TCI → 离线触发 attestation 读取

## 阶段 13：🎉 keybox 提取成功（08-13）

- 并行执行线产出客户端 `keymint_tee_client/kmtee_probe`（mcOpenTrustlet+mcMap+mcNotify 协议打通）+ 补丁 TA `patched_ta/07060000...4d.dumpkeybox.tlbin`
- 运行日志 `gptdoc/kmtee_patched_run_20260813_175411.txt`：全程 rc=0
- **产出 `keymint_tee_client/out_patched/attest_keybox_buf_after.bin` = 解密的认证 keybox 明文**
- **密码学验证**：从明文提取 EC P-256 私钥 `8e2d2645...ce45`，纯 Python secp256r1 基点乘推导公钥，与 keybox 内叶证书公钥**逐字节一致** → keybox 完整有效
- 证书链：leaf(title=TEE, SN 325d90cd...) → TEE 中间(SN aa3d661e...) → root(SN f92009e853b6b045, 2022-2042)，含 EC+RSA 两套
- 交付物固化：`result/keybox_plaintext.bin`（8716B 明文）+ `result/attest_ec_privkey.hex`
- **RKP 结论**：TA 含 rkp_bcc_km/EEK 标记（支持 RKP），实际以工厂 attest_keybox.so 解密路径提取成功 → 本机认证 keybox 走工厂烧录

## 阶段 14：RKP 情况调查（08-13，离线+只读）

**设备 RKP 已启用**，证据链：
- `android.hardware.security.keymint.IRemotelyProvisionedComponent/default` HAL 在线
- `remote_provisioning` 系统服务在线；`remote_provisioning.hostname=remoteprovisioning.googleapis.com`
- `dumpsys remote_provisioning`：hwVersion=2, rpcAuthorName=Trustonic, uniqueId="Trustonic keymint", supportedEekCurve=2, supportedNumKeysInCsr=4

**RKP 数据是什么**：设备远程置备的密钥认证材料——EEK（端点加密密钥）链 + 批量认证密钥对（EC P-256 / RSA-2048 私钥 + Google 服务器签发的证书链）+ BCC（Boot Certificate Chain）。

**存放位置**：Trustonic SFS `/mnt/vendor/persist/mcRegistry/Store_1.tf`（3.8MB，SFS4 格式，全盘加密，11613 个非零数据块=大量密钥对象；rkp/eek/bcc 字样为密文内随机片段非明文目录）。persist 分区，**恢复出厂不擦除**。
另注：TA 内有 "[WARNING] USING EEK ROOT KEY FROM VTS" 测试告警字符串（EEK 根路径相关）。

**能否提取**：能，路径与工厂 keybox 相同（签名旁路 tee + root + patch KeyMint TA）。但比工厂 keybox 工作量大：
- 工厂 keybox：单对象、走 persist 文件路径 → 已完成
- RKP 密钥：一批对象、存 SFS、需 TA 内枚举+逐个解包导出 → 需在 KeyMint TA 里逆向 RKP 密钥的存储/枚举/unwrap 逻辑，估计额外 2-4 天

## 阶段 15：RKP 池调查 + 枚举工具就绪（08-14）

**实测结论（本地认证触发，不联网）：**
- 现场生成 attestation：完整 5 证书链，根到谷歌 `Key Attestation CA1`
- 池子链型：`O=TEE/CN=9663bbe... ← Droid CA3 ← Droid CA2 ← Key Attestation CA1`（谷歌 RKP 专用 CA），与工厂 keybox（根 f92009e853b6b045）是**不同链** → 证明在线用的是 RKP 置备密钥
- **有效期**：RKP 认证密钥证(cert1) **Aug 11–25 2026 ≈ 14 天**（短期轮换实锤）；Droid CA3 ~2月；CA2 ~3年；CA1根 10年
- 连续 6 次认证同一把密钥（CN=9663bbe）→ TA 复用当前密钥，非每次换新；该密钥是 8/11（锁定时期）置备的
- 叶证书 rootOfTrust：**verifiedBootState=2(Unverified/orange), deviceLocked=false**（如实反映当前解锁态）——注意 ro.boot 属性显示 green 是模块涂的，attestation 才是 TEE 真实状态

**枚举工具（已建成，待跑）：**
- `tas/device_u25/km.enum.patch.tlbin`：KeyMint TA 枚举补丁，自定义 cmd 0x50707，dump EC表/RSA表/标签记录阵（BSS 运行时表，非 SFS）
- `keymint_tee_client/kmtee_enum`：NDK 编译的客户端（mcOpenTrustlet 直读补丁 TA）
- 分析确认：该 TA 无 SFS 客户端，密钥在 BSS 三表（EC≤9/RSA≤9/记录≤100），由安装命令灌入
- **待办**：设备在线后跑 enum——若空表，需先 KMTEE_INSTALL_KEYBOX 或用系统已灌的实例；澄清 RKP 池具体把数与内容
- **当前阻塞**：设备离线

## 阶段 16：RKP 池枚举尝试与并行线成果核对（08-14）

**关键发现**：存在另一套**已验证稳定**的提取方案（gptdoc/QUICK_REPRO.md + WORKLOG.md）：
- 补丁 `patched_ta/...dumpkeybox.tlbin`：钩 keybox parse 点（0x1df3c/0x1e4d4），非每命令钩子 → **不崩**
- 客户端 `kmtee_probe`：用 `mcOpenTrustlet` 从 /data/local/tmp 加载补丁 TA（**不 bind-mount /vendor**，所以不干扰系统服务）
- 成果：`extracted_keybox/` 已含 EC+RSA 两套私钥+证书链，三级验证全过（私钥公钥匹配/链验证/签名验签）

**我的 enum patch 失败教训**：
- km.enum.patch.tlbin 钩 cmd 循环 0x12C58（每命令都过）→ bind-mount 后服务启动即 SIGSEGV crash 循环 → 已 unmount 恢复
- 对比：稳定方案钩的是"只在 keybox 安装时才命中"的 parse 点，而我的钩在全局循环 → 暴露面大、易崩
- 原则：patch 钩点要选低频路径，别钩全局循环

**RKP 数据定位**：
- keymint 服务仅读 persist/attest_keybox.so + attestation_ids.so，无独立 RKP 密钥文件
- RKP 密钥存于 Trustonic SFS：Store_0.tf（/data，会 wipe）+ Store_1.tf（persist，不 wipe），全加密
- 当前活跃 RKP 认证密钥：CN=9663bbe...，EC P-256，证书 Aug11-25 2026（14天），Droid CA3→Key Attestation CA1 链

**矛盾点待解**：并行文档称"RKP 无可用 key，回退工厂链"，但我实测在线认证用了 RKP/Droid CA 链 → 说明设备后来（联网后）置备到了 RKP 密钥。
