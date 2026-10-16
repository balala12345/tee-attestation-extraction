# K70E CTF stock 日志路线 Skill 制作与交接

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 Skill v3 覆盖：**当前 Skill 必须支持已成功 hybrid 候选的离线审计/交付，stock-log 只作为 fully-stock provenance 和新 target 支线。见文档 69 和 `references/hybrid-clean-deviceinfo-pass.md`。

> **2026-09-06 18:05 Skill v2 覆盖：** 本文旧 Skill 状态已失效；先读文档 59–63 与已更新 `05_Skill/k70e-rkp-ctf/`。旧恢复/验收程序及旧 manifests 已隔离为非执行权威。

> Skill 名称：k70e-rkp-ctf  
> 安装版：<CODEX_HOME>/skills/k70e-rkp-ctf  
> 工作区导出版：05_Skill/k70e-rkp-ctf  
> 要求：两份逐文件相同，quick_validate PASS
> 历史执行说明（已失效）：当前 Skill 必须先读文档 59–63，再把文档 58 当历史事故证据；不得假设 ADB 在线，不得运行旧恢复/postboot 程序。旧八步已执行并失败，当前仍无 clean chain。

---

## 1. Skill 的职责

这个 Skill 只处理 Redmi K70E / duchamp 的 google-rkp-sw CTF：

- 审计旧 NOT_APPROVED 包；
- 用 clean/failed 对照区分环境问题和显式服务端风险；
- 审计/执行 stock MiTEE 日志 CDI_Leaf 捕获；
- 消费 stock_mitee_log_v1；
- 运行 proper-DICE 软件签发；
- 审核三件套；
- 在另一台 K70E 上做目标绑定的 port；
- 处理失败关闭、恢复和交接。

它不用于泛化 Android RKP 问答，也不把旧 patched TEE 流程继续当默认方案。

## 2. 当前默认结论

Skill 必须先告诉任何 AI：

    old 20260905_2244 bundle = REJECTED_NOT_APPROVED
    modified Fenrir/patched TEE route = historical only
    primary route = stock MiTEE log
    simple attempt/count rate limit = excluded by observed local evidence
    current toolchain = V5 stock-log-only; core gate = v7
    current final submission = not yet generated

次数风控结论来自 27 张唯一 Provisioning Info 证书中 12 张 clean count=32 与 2 张 bad count=32 的共存，且两个 bad fetch/sign 均为 HTTP 200，无 429/`Retry-After`/quota/abuse；这是观测排除，不是猜测。不能把文档 45–51 的 PASS 当作当前事实。

## 3. Skill 目录结构

    k70e-rkp-ctf/
      SKILL.md
      agents/
        openai.yaml
      references/
        workspace-map.md
        evidence-contract.md
        device-runbook.md
        portable-new-target.md
        stock-mitee-log-route.md
      scripts/
        audit_provisioning_info.py
        strict_dice_reaudit.py
        verify_submission.py

其中 stock-mitee-log-route.md 是当前主运行手册。旧 portable-new-target.md 只保留历史 patched 路线和移植研究；它不能覆盖新手册。

## 4. SKILL.md 必须写明的硬门

### 4.1 Provisioning Info

- 全链扫描，并递归进入复合 CBOR map key；
- leaf 扩展必须存在且可解析；
- raw CBOR 必须 canonical；
- 任何精确 NOT_APPROVED 都失败；
- 任何显式 `cbor2.CBORTag` 都 fail-closed，包括内嵌 encoded CBOR 的 tag 24；
- tag 258 的 set/frozenset、tag 35 的 `re.Pattern` 等自动语义对象都 fail-closed；
- Android strict 只报告；
- 不允许删除或重签证书。

### 4.2 stock approval

- profile schema v4；
- approved baseline；
- exact signed DeviceInfo；
- 五层 DICE measurement/security claims；
- 五层完整 same-handset DICE payload raw hashes；
- target-own UDS/CDI；
- 软件 SPKI 必须与 CDI identity SPKI 不同；
- live stock TA/TEE/LK/preloader + pinned known-good Magisk init_boot；
- scalar-to-same-run-leaf SPKI；
- network_issuance_allowed=true。

### 4.3 一次性

- zero-key capture 每输出一次；
- preflight exclusive；
- host attempt 一次；
- device issuance latch 一次；
- NETWORK_STARTED 后永不重放该 attempt；
- dispatch ticket/authorization 绑定 creator PID，fork 后不得沿用；
- ATTEMPT schema v1 的 host marker 是对未来 `DEVICE_LATCH.json` 和设备 latch 关系的预承诺；ADB/latch 失败必须 `BURNED`、无 `NETWORK_STARTED`、无 POST，不能单凭 future hash 通过 SUCCESS；
- 不得局部改成“先设备 latch，后 host ATTEMPT”；要改跨 host/device 提交语义必须同步升级 schema/core/wrapper/verifier/fixture/manifest 为 gate-v8，当前冻结仍是 gate-v7；
- zero-key invocation marker 只对当前 capture 目录 fail-closed；换目录重放的防止依赖全量盘点和交接纪律，不得声称是跨目录全局 latch；
- NOT_APPROVED 烧毁该 attempt，但无显式风控信号时必须继续离线差分；
- 显式 429/quota/abuse 或网络结果未知才暂停外部请求。

### 4.4 秘密

- 不显示 identity scalar；
- 不显示软件 PKCS#8；
- 不把私钥放 argv；
- 只报告 hash、SPKI 和关系；
- 软件私钥只使用 canonical PKCS#8/PEM，持久化后必须 nofollow 重开、hash/dev/inode/SPKI 复核和 PoP；
- 私有目录 0700、文件 0600，文件/key 目录/run 目录/父目录做所需 `fsync`；
- capture 目录要求当前 UID、exact mode 0700，并绑定 path/dev/inode；在 fetch/submit 网络边界前后重验。

### 4.5 手机离线与路由查询

- 飞行模式必须为 1，Wi-Fi 必须为 0/null；
- AOSP netd 的严格 `default dev dummy0 table 1002`、无 `via` 路由是丢包黑洞，不是外网；
- 仅允许当前 token grammar 锁定的 IPv4/IPv6 dummy sink；缺/错/重复 dev/table、`via/nexthop/nhid/encap`和未知尾缀均 fail-closed；
- `forwarding_default_route_count` 必须为 0，`ignored_dummy_sink_default_route_count` 独立记录；
- IPv4/IPv6 route query 必须分别成功，并以 `ipv4_route_query_succeeded=true` / `ipv6_route_query_succeeded=true` 进入证据；查询非零不得以空输出通过；
- collector 基线和 final-dispatch 两阶段都必须以严格全局 `adb devices -l` inventory 作为该阶段第一个设备操作，通过前不运行 serial-scoped shell；
- collector 第二轮 inventory 如果漂移，之后必须是零设备 shell、零 Binder、零 invocation marker；已 staged 的远端临时目录清理延期，host `remote_cleanup.json` 耐久记录精确路径、`removed=false` 和原因；
- online wrapper 的 live preflight 和 latch 阶段也分别先做严格全局 inventory；它在 host `ATTEMPT` 前记录 `LIVE_STOCK_PREFLIGHT.json`，并在 `reserve_device_latch()` 真正创建 latch 前按同语义再检一次；
- ADB inventory 必须恰好为标准 header + 一条 pinned serial/`device` 记录，非 ASCII、控制字符、换行异常、第二/重复记录、非 `device` 状态和畸形/重复 detail token 都必须 fail-closed；
- `pidof tee-supplicant` 必须恰好为一个 ASCII 十进制 PID；空或多 PID 不得进入 namespace TA/latch 门；
- `--attended` 必须在 build preflight、输出创建和任何 one-shot 副作用之前验证。

## 5. 触发后的阅读顺序

Skill 应按任务最小加载：

### 审计旧包

1. SKILL.md；
2. references/evidence-contract.md；
3. scripts/audit_provisioning_info.py；
4. 文档 52。

不访问设备、不触网。

### 操作参考 K70E

1. 文档 52；
2. 文档 53；
3. 文档 54；
4. references/stock-mitee-log-route.md；
5. capture/parser/wrapper 的 --help；
6. manifest。

### 另一台 K70E

1. 文档 53 第 12 节；
2. references/stock-mitee-log-route.md 的 port 章节；
3. references/portable-new-target.md 仅作为旧研究背景；
4. 目标自己的 stock artifacts 和 approved baseline。

## 6. Skill 不应自动做的事

- 不自动连接 Google；
- 不自动刷机；
- 不因为结构 PASS 就联网；
- 不复用参考 identity；
- 不修改 allowlist 让目标通过；
- 不清理 attempt/latch；
- 不把日志候选直接当 scalar；
- 不调用旧 rkp_sw_portable.py 消费 stock contract；
- 不调用 `rkp_sw_portable.py` 的直接联网分支；该分支已永久禁用，portable 只作 stock wrapper 的受限库和离线工具；
- 不运行已隔离的 TA/OEMCrypto probe 或 in-process injector；
- 不用旧 package verifier 验 stock contract；
- 不把失败解释为“再试一次”。
- 不在 Pixel 或其他 Android 设备仍物理连接时启动现场流程；`--one-device` 不能取代物理断开。
- 不用 `adb --one-device` 后的单设备视图代替 IORegistry/外部 USB 端口 inventory；`--one-device` 会隐藏没有被该 daemon 接管的其他物理设备。
- 不在第二轮 inventory 漂移后用远端清理为名发送任何 shell；只能保存 host evidence，之后重新确认物理层和 ADB 视图中的唯一目标，再手工清理记录的精确路径；清理绝不授权 Binder 重跑。
- 不在旧 ADB daemon/libusb 约 4 分钟卡顿后盲目重跑 one-shot；先判定是否已跨过一次性 marker。

只有用户明确要求设备操作且所有 live gate 通过时，才执行动态阶段。

## 7. 参考命令

### 7.1 验旧失败包

    /usr/bin/python3 \
      <CODEX_HOME>/skills/k70e-rkp-ctf/scripts/verify_submission.py \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244

预期是 FAIL，并命中 5/1。

### 7.2 stock capture

现场前置：先从 IORegistry/外部 USB 端口 inventory 核对物理层，Pixel（`<DEVICE_SERIAL>`）必须物理拔掉，手机开发者选项开启 **Stay awake**。只使用 profile 锁定的官方 ADB；本次现场观测到旧 daemon/libusb 路径可约 4 分钟后才超时，所以必须在 Binder 前建立单设备 server：

    ADB=<HOST_SDK>/platform-tools/adb
    SERIAL="<TARGET_SERIAL>"
    "$ADB" kill-server
    ADB_LIBUSB=0 "$ADB" --one-device "$SERIAL" start-server
    ADB_LIBUSB=0 "$ADB" devices -l

`devices -l` 必须只有该 serial 且状态为 `device`；`offline`、`unauthorized`、第二设备或约 4 分钟超时都在 Binder 前停止。但 `--one-device` 可以屏蔽其他物理 transport，所以必须在 server 前和 one-shot 紧前重做 IORegistry/外部端口盘点，不得因 `--one-device` 而留着 Pixel。最新状态是 Pixel 已移除、唯一 K70E ADB 已稳定，但当前仍为拒绝环境；下列命令仍只是交接模板，CN304 恢复/post-boot 门通过前不得执行 one-shot。

如果 staging 已完成但 final-dispatch 第二轮 inventory 漂移，立即以失败返回；不得再发设备 shell 做自动清理。保留 `remote_cleanup.json` 后，只能在 Pixel/其他设备已物理移除、IORegistry/外部端口与严格 ADB inventory 再次同意“唯一 K70E”后，对记录的精确远端路径手工清理。

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/capture_k70e_stock_cdi_log_once.py \
      --serial <DEVICE_SERIAL> \
      --profile $HOST_ROOT/CURRENT/TARGET_PROFILE.json \
      --output-dir $HOST_ROOT/NEW/PRIVATE/CAPTURE_DIR \
      --attended \
      --execute-zero-key-once

### 7.3 发行预检

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile $HOST_ROOT/CURRENT/TARGET_PROFILE.json \
      --capture-dir $HOST_ROOT/PRIVATE/CAPTURE_DIR \
      --serial TARGET_SERIAL \
      --preflight-only

### 7.4 唯一 Google 运行

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile $HOST_ROOT/CURRENT/TARGET_PROFILE.json \
      --capture-dir $HOST_ROOT/PRIVATE/CAPTURE_DIR \
      --serial TARGET_SERIAL \
      --preflight-report $HOST_ROOT/PRIVATE/CAPTURE_DIR/stock_log_provision_preflight.json \
      --output-dir $HOST_ROOT/NEW/PRIVATE/SUBMISSION_DIR \
      --attended \
      --execute-google-once

## 8. 另一台 K70E 的 Skill 行为

Skill 必须把新设备视为 port：

1. 从目标设备采集 public metadata 和 target-owned stock backups；
2. 取得目标自己的 approved baseline CSR/challenge；
3. 新建 profile，不复制参考 UDS/CDI；
4. TA/TEE 不同则 PORT_REQUIRED；
5. 即使 TA/TEE 相同，当前 capture/consumer 仍硬编码参考机 lk_a 与 preloader_raw_a 整分区锚；新机这两项不同必须做 collector port 和重新测试，不能改常量硬过；
6. 重新静态验证 stock TA 日志调用点；
7. 固定新 zero-key client/parser/profile/core allowlist；
   可执行 zero-key 载荷的唯一活动路径为 `<PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload`；
8. host-only 全回归；
9. 才能运行 zero-key；
10. 没有 target-approved baseline 时不允许声称网络结果可获认可。

## 9. 安装版和导出版同步

编辑顺序：

1. 先修改安装版；
2. 用 apply_patch 对导出版作同样修改；
3. 不用 cp 覆盖用户未知改动；
4. diff -rq 必须无输出；
5. quick_validate 两份都通过。

验证命令：

    /usr/bin/python3 \
      <CODEX_HOME>/skills/.system/skill-creator/scripts/quick_validate.py \
      <CODEX_HOME>/skills/k70e-rkp-ctf

    /usr/bin/python3 \
      <CODEX_HOME>/skills/.system/skill-creator/scripts/quick_validate.py \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/05_Skill/k70e-rkp-ctf

    diff -rq \
      <CODEX_HOME>/skills/k70e-rkp-ctf \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/05_Skill/k70e-rkp-ctf

## 10. Skill 验收用例

### 必须拒绝

- 旧 20260905_2244；
- leaf 缺 Provisioning Info；
- malformed CBOR；
- duplicate-key hidden NOT_APPROVED；
- true/int key collision；
- tuple、CBORTag、FrozenDict 复合 key hidden NOT_APPROVED；
- tag 24 内嵌 encoded CBOR，tag 258/tag 35 自动语义对象；
- modified DICE [F,F,T,F,T]；
- stock contract 交给 legacy consumer；
- capture scalar 与 CSR leaf 不匹配；
- output 已存在；
- attempt/latch 已存在；
- 缺少 `--attended`、或 `--preflight-only` 错误搭配 `--attended`；
- ADB inventory 包含第二/重复/非 device/非 ASCII/控制字符/换行或 detail-token 畸形记录；
- `tee-supplicant` PID 为空、多个或非 ASCII 十进制；
- IPv4/IPv6 route query 任一非零、marker 畸形或证据布尔非严格 true；
- `ccmni`/`rmnet`/`wlan`/其他 default，以及伪装成 dummy0 但 table/尾缀/字段不精确的路由；
- 非官方 URL；
- 两把软件 key 或两条 chain；
- 软件 SPKI 与 CDI identity SPKI 相同；
- SEC1/非 canonical PKCS#8、capture 非当前 UID/非 exact 0700、path/dev/inode 换位或 creator PID 不符；
- ATTEMPT v1 在 latch 前 ADB 失败后又企图继续到 device latch、network POST 或 SUCCESS；
- collector 第二轮 inventory 漂移后仍执行设备 shell/自动清理、写 invocation marker 或调用 Binder；
- Android strict=true 但含 NOT_APPROVED。

### 必须接受为“可继续”，但不自动联网

- 真实 approved historical leaf，CTF true / Android strict false；
- stock profile approval baseline eligible；
- zero-key capture关系全部 PASS；
- preflight-only network_access=false。

### 必须验证的顺序与失败状态

- collector 两阶段和 wrapper live/latch 的 inventory-before-shell 顺序回归 PASS；
- collector 第二轮 inventory 漂移时零后续 shell/Binder/marker，并在 host `remote_cleanup.json` 记录延期清理；
- ATTEMPT v1 在 latch 前 ADB 失败时只留 ATTEMPT+BURNED，无 device-latch/network/POST/SUCCESS；这是失败状态回归通过，不表示该 attempt 可继续。

### 只有现场才能验证

- 原厂日志是否在这次设备 boot 正常落盘；
- live whole-partition hashes；
- same-boot USB/ADB 稳定性和“仅 host 有网络”边界；
- Google 是否返回无 NOT_APPROVED 的新链。

截至最新冻结点，Pixel 已移除、唯一 K70E ADB 已稳定，但 live/AVB 只读证据确认当前是 `b9b1d867…` 拒绝环境；工作停在待执行的 CN304 恢复与 post-boot 验收。本轮 fresh-stock zero-key Binder 尚未调用，Google one-shot 也尚未执行。当前没有消耗真机 one-shot，也没有新的无 `NOT_APPROVED` 链。

## 11. 交接时必须说明

最终答复不能只说“Skill 已创建”，必须说明：

- 安装版路径；
- 导出版路径；
- quick_validate 结果；
- diff 结果；
- 主参考文档；
- 当前手机是否连接；
- 是否实际触网；
- 是否已产生新三件套；
- 若未产生，唯一现场下一步是什么。

## 12. 当前 Skill 的终态措辞

Skill 的 Terminal condition 应为：

    旧包已拒绝。当前主路线是原厂 stock MiTEE 日志提取 CDI_Leaf，
    然后使用专用一次性发行器取得一把软件 key 和 Google chain。
    只有 full-chain ctf_no_not_approved=true 才完成。
    如果 controlled attempt 被 NOT_APPROVED，保存证据并禁止重放该 attempt。
    无显式 429/quota/abuse 时，继续离线找根因；只有修正被证明的偏差并通过全部新门后，
    才允许一个不同的 controlled attempt。永不降低门。

这里的“不同 controlled attempt”只能来自已证明的环境修复和 fresh capture，不是因为“多试几次”。当前简单次数风控已被观测样本排除。

终态措辞还必须附带两个局限：zero-key marker 仅为目录级，跨目录不重放靠盘点和交接纪律；ATTEMPT v1 是 future-latch precommit，任何协议修订必须整体升级 gate-v8，不能先设备 latch 后 host marker。

这段措辞防止下一位 AI 回到“缺少 stock read primitive，因此只能继续 patch TEE”的旧死路。

## 13. 当前冻结锚

    toolchain id       k70e-portable-macos-host-20260906-v5 (stock-log-only; no V4 inheritance)
    core gate          v7
    core SHA-256       619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  size 193161
    profile helper     724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  size 134026
    portable library   0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c  size 76113; direct online disabled
    collector SHA-256  732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c  size 75305
    issuer SHA-256     99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3  size 121031
    verifier SHA-256   f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357  size 120223
    profile internal   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
    profile file       5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81  size 17803
    collector tests    67e38a25a96c026595ca6a3157c3bc4a5639c6cf969609b461348b7d3bfdfd2d  size 50002
    wrapper tests      d2a6bc8fe54eef5b36fc8bf15e4ece71b82061d9eaec6eb979939094cf399793  size 99075
    verifier tests     13a4e5383595753def31d1c301c01f119898558982936a224baa20193886e20e  size 67504
    regression         8 groups, 178/178 PASS (23+13+12+31+10+10+42+37)
    recovery tool      3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9  size 109993
    recovery tests     15bb1201dcb4180b37ff3f776393aca98a4b9f6b33748f83f1c508741054adc7  size 43802; 35/35 PASS
    postboot verifier  c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add  size 99185
    postboot tests     c13433501cdb3870852e2494e5055b556a11b565e9ad19d58bf3e04e9a7c476b  size 42736; 24/24 PASS

离线 verifier 只能证明交付树内部一致，不能密码学证明 fresh Google 交易或真实 exactly-once dispatch。拥有同 UID 恶意文件改写权或同 Python 解释器任意代码执行权的攻击者仍在当前安全边界外。若赛事要求防重放，需由赛事方提供 nonce/签名 receipt/外部不可变日志。

此冻结表是待完成真机终验的发行候选，不是已解决声明。恢复与 post-boot 工具虽已完成 35/35 + 24/24 host-only 回归，但尚未实机运行、`POSTBOOT_VERIFIED.json` 尚不存在。本轮现场也尚未执行 fresh-stock zero-key Binder 和 Google one-shot，所以尚未取得新 CDI_Leaf、新软件私钥和全链 raw Provisioning Info 零 `NOT_APPROVED` 的 Google 链。
