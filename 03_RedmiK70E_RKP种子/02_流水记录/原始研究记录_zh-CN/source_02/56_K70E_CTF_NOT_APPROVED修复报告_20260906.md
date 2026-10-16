# K70E CTF Provisioning Info NOT_APPROVED 修复报告

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 最终结果：**本文所述 stock 方案是历史严格路线；新差分实验已使用 exact modified DICE + clean DeviceInfo 取得 `APPROVED` 证书和对应新私钥。当前根因报告为文档 68。

> **2026-09-06 18:05 结论覆盖：** 本文“恢复方案已就绪”不再成立。旧计划已执行并造成双重 AVB mismatch；尚无 `POSTBOOT_VERIFIED.json` 或合格三件套。当前阶段报告见文档 62。

> 报告日期：2026-09-06  
> 设备：Redmi K70E / duchamp / <DEVICE_SERIAL>  
> 参考 serial：<DEVICE_SERIAL>  
> 历史结论（已失效）：检测器修复仍有效，但“恢复方案已实现、尚未刷写、以文档 58 执行”均已被后续事件撤销。当前没有可执行恢复程序、没有 `POSTBOOT_VERIFIED.json`、没有合格三件套；以文档 59–63 为准。

---

## 1. 执行摘要

赛事方拒绝了 2026-09-05 的提交，因为 Google 叶证书 Provisioning Information 中存在未被旧验证器识别的字段：

    {1: 32, 3: "Xiaomi", 5: {1: "NOT_APPROVED"}}

事故包含两个独立问题：

1. 验收缺陷：旧 google-rkp-sw 只读取已知键 1、3、4，静默丢弃键 5，导致把拒绝证书误报为 PASS。
2. 环境缺陷：提取 CDI_Leaf 的 patched TA/TEE/Fenrir 路线改变了 Google 可见的启动 DICE 测量。native Binder 与 host 软件请求都得到相同 NOT_APPROVED，证明问题不是单纯 host 拼包。

修复方案：

- 把 Provisioning Info 改成全链、无损、canonical、重复键安全的硬门；
- 把结构兼容、认可环境和联网许可分成三个 verdict；
- 用历史已获 Google 正常证书的 stock signed DeviceInfo 与五层 DICE 作为认可锚；
- 放弃 patched TEE 签发路线；
- 利用原厂 KeyMint TA 在 stock CSRv2 设备签名路径自带的 private_key 日志，提取 CDI_Leaf scalar；
- 以同轮 zero-key CSR 最终 DICE leaf SPKI 唯一确认 scalar；
- 使用专用两阶段一次性发行器，只在所有 approved-baseline 门通过后生成一把软件 key 并联系一次 Google；
- collector 和 wrapper 都以严格唯一 ADB inventory 作为每个设备阶段的首个操作，并把 `--attended` 授权前置到任何 preflight/副作用之前；
- NOT_APPROVED、网络不确定或解析失败都会烧毁并保留同一 attempt，禁止原样重放；这不停止离线差分和环境修复。只有明确 429、`quota` 或 `abuse` 才暂停新的外部请求。

## 2. 对“是不是尝试次数太多”的判断

### 2.1 简单次数/计数风控已经由现有样本排除

对 `03_提取结果` 中所有可找到的 DER 证书按证书 SHA-256 去重并扫描 Provisioning Info：

    unique ProvisioningInfo certificates   27
    clean                                   25
    NOT_APPROVED                             2
    parse error                              0
    clean count=32                          12
    clean count=8                           13

count=32 在 12 张干净证书上出现，因此它不能解释两张同为 count=32 的失败证书。两张失败证书对应的 fetch/sign 请求都是 HTTP 200；现有元数据没有 429、`Retry-After`、`quota` 或 `abuse`。native Binder 与 host 软件请求的拒绝扩展逐字节一致，而 stock approved 与 modified failed 的 signed DeviceInfo/DICE 有系统性差异。所以“简单尝试次数/计数风控”是由已观测样本排除，不是凭感觉猜测。

### 2.2 当前工程分类

    simple attempt/count rate limit     EXCLUDED BY CURRENT EVIDENCE
    host HTTP/framing as primary cause  EXCLUDED BY NATIVE CONTROL
    environment/request divergence      PRIMARY ROOT-CAUSE FAMILY
    new clean Google chain              NOT YET OBTAINED

这不是对 Google 未公开策略的官方解释；它是现有 27 张证书、HTTP 元数据和三个请求的离线差分结论。服务端仍可有其他未公开策略，但不能再用“尝试次数多”代替已经观察到的环境差异。

### 2.3 决策规则

- 不再用未改变的 modified 环境做盲试；
- 每个失败 ATTEMPT 都保留并烧毁，绝不原样重放；
- NOT_APPROVED 且已有 clean native control 时，继续离线比较 DeviceInfo、五层 DICE、启动链和请求语义；
- 只有找到并修复具体差异、approved-baseline early chain 后 fresh boot、重新采集且通过全部新门，才允许新的 controlled attempt；
- 只有明确 HTTP 429、`quota` 或 `abuse` 才暂停新的外部请求；暂停网络不等于停止只读、离线和恢复工作。

## 3. 事故根因分析

### 3.1 验证器根因

旧函数只返回少数字段：

    count
    manufacturer
    security_level

未知键 5 没有进入 summary，后续 validator 也不读 raw extension。最终产生：

    cryptographic relationship PASS
    organizer policy FAIL
    old local verdict PASS   <- 错误

### 3.2 环境根因

历史 approved 与失败请求的精确 DeviceInfo 差异：

    approved
      canonical SHA-256  19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921
      vb_state           orange
      bootloader_state   unlocked
      vbmeta_digest      acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9

    modified
      canonical SHA-256  82e42dd801204a814823be7f14a5912501dc5ffee4c0323c748e5618eaecd1ad
      vb_state           green
      bootloader_state   locked
      vbmeta_digest      b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744

measurement claims 与 security claims 的五层 match 都是：

    [false, false, true, false, true]

变化层对应：

    layer 1   preloader / early boot
    layer 2   BL2_EXT / Fenrir
    layer 4   TEE payload

完整 COSE_Sign1 payload 则五层全部不同。逐层 raw payload SHA-256 为：

    approved stock
      6d662c12275ea9a0adf35e94e8ba339c0e0a4cc4247cee30289dfc84360dc6ec
      229219105fcb22e2dce684fd424a1d379069e146ef2c75b777d8a08ad4c1de34
      08606b4a703df5252c5d0dc9d57294c0e7722a027b49bf930d303da587c1ff8b
      6b8586445c3c891a8be4026a8384e2a81fd897ac3b217ea9b3c7145ee138f90d
      e4f17a71c000068f62b506d16c0322967b9dd4e58b6cdda9e9e2831fbba72792

    modified native = modified host
      ff2572c3f3f1aec6a0495f555c100784cdf7ce5bf87457b359a7b81fc468607c
      8c16ea83be8fe7e89cef273b82dff14730655c38d67d7c91eb32a653f79d602b
      e4a61de8ee2140aafe17d4773d52bdf5ec6faae93971d21667cf6f20b4d0eec7
      0966b679d13f64dbb2b4b4084fb60fd52316812523f78d6be072cf79bc33a708
      850b48eb3502ad2bcc938b8c1da364dda857d80d7931b45f498aed3c83cf569e

第 3、5 层 measurement/security 子集相同而完整 payload 不同并不矛盾：前层改变会级联改变派生 subject key 和 issuer/subject。modified native 与 modified host 五层完全相同，进一步排除 host 重编码为主因。

### 3.3 协议控制量排除 URL/fetch/EEK/host framing

approved native、modified native、modified host 三次保存运行的共同量：

    fetch URL
      https://remoteprovisioning.googleapis.com/v1:fetchEekChain

    fetch body
      size      101
      SHA-256   fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2

    canonical EEK chains extracted from response
      size      613
      SHA-256   11dc72f46af10129d6a2584ebbd1c6e44ca2d26322f534606435808da42e9305

sign 请求也都发往同一官方 `v1:signCertificates` endpoint；完整 query 中的 fresh challenge/request_id 按协议应当不同。因此 URL、fetch body、EEK chain 和 host HTTP framing 不是当前主因。

### 3.4 post-restore 不能倒转当前 boot 的测量

失败证据树显示：`device_preflight.json` 中 `tee_a` 磁盘已为 stock `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d`，但 init_boot 磁盘仍为 candidate `4d83cd26f02c585dce733f81d05faf38ec5c8f247f89fbaa9fcf46b70d2b4d85`，tee-supplicant namespace TA 仍为 patched `6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0`。后续 `04_postrestore_stock_preflight.json` 虽再次看到 TEE/TA 磁盘回到 stock、init_boot 回到 pinned known-good Magisk 基线，也发生在本次 boot 已完成 early-chain DICE 派生、TA 已加载之后。

所以在同一 boot 中恢复磁盘、解除 bind 或替换文件，不会修改已经签进 AuthenticatedRequest 的 DICE/DeviceInfo。正确顺序必须是：approved-baseline early chain（原厂 preloader/LK/TEE/TA + pinned known-good Magisk init_boot）落稳并禁用 early replacement -> fresh boot -> 新 zero-key capture -> 五层完整 payload、measurement/security 和 signed DeviceInfo 全门验证 -> controlled attempt。

### 3.5 为什么不能后处理

Provisioning Info 位于 TBSCertificate。删除或改写扩展会使 Google 叶签名失效；本地重签也不再是 Google 链。唯一有效的修复是让 Google 在认可的原始请求上签出不含 NOT_APPROVED 的新证书。

## 4. 新身份提取方案

### 4.1 静态发现

原厂签名 TA 中：

    get_attest_cdi
      -> P256KeypairFromCDI
      -> success x26
      -> dump_to_hex("private_key", x26, 32)

该路径由 generateCertificateRequestV2 的设备签名触发。

### 4.2 动态触发

使用自审计 ARM64 Binder 客户端：

    keysToSign_count = 0
    challenge_length = 32
    transaction      = 4
    flags            = 0
    network          = none

它不会生成赛事软件 key，也不会联系 Google。

### 4.3 身份确认

从 bounded MiTEE log window 提取所有精确两行候选，对每个候选派生 P-256 SPKI。只接受与同轮 AuthenticatedRequest 最终 DICE leaf 公钥匹配的唯一候选。

这消除了按日志标签猜 key 的风险。

## 5. 环境认可方案

当前 profile schema v4 与不继承 V4 的 stock-log-only toolchain V5 共同固定：

- 已获认可的 signed DeviceInfo canonical hash；
- 五层 DICE measurement claim hash；
- 五层 DICE security claim hash；
- 五层完整 verified DICE payload raw hash（包含 issuer/subject/中间公钥）；
- 参考固件 TA/TEE；
- 当前设备 UDS 和 CDI leaf 由目标自己的 baseline 绑定；
- source init_boot、ADB 和 core 工具。

当前参考 profile：

    path
      03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json

    internal profile SHA-256
      809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3

    file SHA-256
      5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81
      size 17803

    toolchain
      k70e-portable-macos-host-20260906-v5
      stock-log-only; no V4 inheritance

    classification
      EXACT_REFERENCE_FAST_PATH

    approval baseline
      ELIGIBLE

现场还必须检查完整 early boot：

    lk_a             9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35
    preloader_raw_a  33ef65d9560e92990e5d6bbf7dc8e161e57346e7f9434082b59d31366a638d1f
    tee_a            18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
    KeyMint TA        facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
    known-good Magisk init_boot_a  9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4  # not factory-stock

HLOS ro.boot.* 只记录，不参与认可判定。

## 6. 代码修改清单

### 6.1 核心

    third_party/google-rkp-sw/rkp_sw.py

主要修改：

- Provisioning Info 全链无损审计；
- exact one CBOR item；
- deterministic canonical round-trip；
- 防重复键和 Python key collision；
- 递归精确文本扫描，包括 tuple/FrozenDict 复合 map key；
- 任何显式 `cbor2.CBORTag` 都 fail-closed，包括内嵌 encoded CBOR 的 tag 24；
- tag 258 自动转换的 set/frozenset、tag 35 自动转换的 `re.Pattern` 等语义对象都 fail-closed；
- raw extension 长度/hash/tree/hit path；
- leaf 缺失/畸形/命中均失败；
- ctf_no_not_approved 与 Android schema verdict 分离；
- 网络后原始响应先落盘；
- 失败不生成 SUCCESS；
- gate-v7 stock approval 无法由普通 CLI/API 绕过，且直接 core 入口也锁定精确 AuthenticatedRequest 和五层完整 payload；旧 gate-v4/v5/v6 都只保留为离线历史身份。

### 6.2 profile

    02_脚本与补丁/k70e_portable_profile.py

主要修改：

- schema v4；
- exact signed DeviceInfo；
- 五层 measurement/security claims；
- recognized approved baseline；
- structural、approval、network 三 verdict。
- 当前 V5 allowlist 只锁定 core、ADB、Python runtime、zero-key payload+源码、stock capture/extractor、portable 受限库以及 stock TA/TEE/source-init/device config；不包含 tx2 keygen、candidate TA/TEE/init_boot、restore/build/lz4。

### 6.3 stock 捕获

    02_脚本与补丁/rkp_binder_csr_v2_zero_key_client.cpp
    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload
    02_脚本与补丁/extract_k70e_cdi_leaf_from_mitee_log.py
    02_脚本与补丁/capture_k70e_stock_cdi_log_once.py

新的手机离线门不再用简单 `^default` 计数。AOSP netd 的严格 `dummy0/table 1002`、无 `via` default 是丢包 sink，不是外网；它单独计入 `ignored_dummy_sink_default_route_count`。真正的门是 `forwarding_default_route_count=0`，且 IPv4/IPv6 路由查询 RC 必须都是 0。缺/错/重复 table/dev、`via/nexthop/nhid/encap`、未知尾缀或任一查询失败都 fail-closed，防止“查询失败 -> 空输出 -> 误判离线”。

设备唯一性也改为严格合同：`adb devices -l` 只能包含标准 header 和一条 pinned-serial/`device` 记录；非 ASCII、控制字符、异常换行、多余空白、第二/重复记录、非 `device` 状态和畸形/重复 `key:value` token 全部拒绝。collector 先在基线阶段做 inventory，通过后才允许任何设备 shell；在最终 dispatch 阶段又以 inventory 作为该阶段首个设备操作，再做 shell、写 marker 和调用 Binder。

若第二轮 inventory 相对基线发生漂移，collector 必须在它之后做到零设备 shell、零 Binder、零 `zero_key_invocation.json` marker。因为清理本身也是设备 shell，已 staged 的远端临时目录不在漂移现场自动删除；host 必须将路径、`removed=false` 和延期原因耐久写入 `remote_cleanup.json`。仅在之后重新通过 IORegistry/外部 USB 端口盘点和严格 ADB inventory、再次确认唯一目标后，才能手工清理该精确路径；清理不能转化为 Binder 重跑授权。

collector 还要求 `pidof tee-supplicant` 恰好返回一个非空纯十进制 PID；空、多 PID 或任何非数字字符都不得进入 `nsenter` namespace TA 门。

### 6.4 专用发行

    02_脚本与补丁/rkp_sw_stock_log_once.py

主要职责：

- 只消费 stock_mitee_log_v1；
- 独立重算 capture 关系；
- preflight-only 零网络；
- live same-boot stock recheck；该阶段以严格唯一 ADB inventory 开始，在 inventory 通过前不做任何 serial-scoped shell；
- 在 host `ATTEMPT` 前检查并把飞行模式、Wi-Fi、双栈路由查询成功布尔、forwarding/dummy-sink 计数与路由 inventory hash 绑入 `LIVE_STOCK_PREFLIGHT.json`；
- `reserve_device_latch()` 先重做严格全局 ADB inventory，通过前不进入任何 latch 阶段 shell；随后用 `set -eu`、显式查询退出码和同语义严格 AWK 再做第二道手机离线门；
- live 和 latch 的 namespace TA 验证都要求 `tee-supplicant` 恰好一个 ASCII 十进制 PID；
- `--attended` 在 build preflight、输出验证和任何 one-shot 副作用之前验证；只允许与 `--execute-google-once` 配对；
- host/device 双一次性状态；
- NETWORK_STARTED 在 core 前耐久写；
- authorization 内恰好生成一把软件 P-256 key，以 canonical PKCS#8/PEM 耐久保存；
- 持久化后重开、校验 hash/dev/inode/SPKI、执行 PoP，并在 fetch/submit 网络边界前后重验；
- 软件 SPKI 必须与 CDI identity SPKI 不同；
- 恰好一条 Google chain；
- 独立验签、根、私钥关系、Provisioning Info；
- 输出中自含赛事三件套；
- Android strict 只报告；
- NOT_APPROVED 不写 SUCCESS。

## 7. 安全和完整性设计

### 7.1 文件输入

- O_NOFOLLOW；
- lstat/fstat identity；
- regular file；
- size limit；
- 读后 dev/ino/size/mtime/ctime 稳定性；
- 固定 SHA/size；
- 私有 snapshot。

### 7.2 设备

- 显式 USB serial；
- 只允许一台设备；
- duchamp、slot _a、fingerprint；
- root 和服务；
- boot ID；
- 分区全 hash；
- global/namespace TA；
- zero-key 前双重检查；
- issuance 前再次检查。
- 飞行模式必须为 1，Wi-Fi 必须为 0/null；IPv4/IPv6 route query 必须分别成功；
- 允许的只是严格 AOSP `dummy0/table 1002` 黑洞 grammar，任何 `ccmni`/`rmnet`/`wlan` 或其他 default 都拒绝。
- collector 的基线与 final-dispatch 两阶段、wrapper 的 live 与 latch 两阶段，都必须在该阶段任何设备 shell 前通过严格唯一 ADB inventory。
- `tee-supplicant` 必须恰好有一个 ASCII 十进制 PID；空或多 PID 均 fail-closed。

本次现场还暴露了 USB 运行级约束：旧 ADB daemon/libusb 路径可卡住约 4 分钟后才超时。现场必须先用 IORegistry/外部 USB 端口 inventory 确认物理层，物理拔掉 Pixel（`<DEVICE_SERIAL>`）及其他 Android 设备，再只用 profile 锁定的官方 ADB；清理旧 server 后用 `ADB_LIBUSB=0 adb --one-device <DEVICE_SERIAL> start-server` 限制 daemon。`--one-device` 会隐藏未被该 daemon 接管的其他物理设备，所以随后的 `adb devices -l` 单设备视图不能取代 IORegistry 和 Pixel 物理断开。手机开发者选项开启 **Stay awake**，并在任何 Binder/ATTEMPT 之前解决 unauthorized/offline/超时；一次性 marker 出现后不得因 USB 问题盲目重跑。最新状态是 Pixel 已移除、唯一 K70E native ADB 已稳定；但当前仍是拒绝环境，所以真机 one-shot 尚未授权、也未消耗。

### 7.3 一次性

    zero-key DISPATCHING_NO_RETRY
    host ATTEMPT
    device issuance latch
    NETWORK_STARTED
    BURNED or SUCCESS

任何网络不确定性都不能通过删除状态重试。

当前 ATTEMPT schema v1 使用 future-latch precommit：host `ATTEMPT.json` 先对稍后的 `DEVICE_LATCH.json` 内容/哈希与设备 latch 关系作预承诺，然后才在严格 ADB/stock/offline 再检后消耗设备 latch。这是已知的跨 host/device 提交局限，不是 SUCCESS 绕过：ADB/latch 失败必须留下 `ATTEMPT.json` + `BURNED.json`，不得出现 `NETWORK_STARTED.json` 或 POST；成功验收又必须要求实际 `DEVICE_LATCH.json` 与预承诺一致。

不能把顺序简单改成“先设备 latch，后 host ATTEMPT”，否则 host marker 失败时会留下无 host 证据的已消耗设备 latch。任何正确修订都必须使用新 schema，同步更新 core/wrapper/verifier/fixture/manifest，并整体迁移 gate-v8；当前执行面仍是 gate-v7。

zero-key 的 `zero_key_invocation.json` 只是 capture 目录级 marker，对同目录 fail-closed，却不会自动拦截换新目录的重放。跨目录不重放仍依赖全量 capture 盘点与交接纪律；若需强保证，必须增加设备端全局 latch、组织者 nonce/签名 receipt 或外部不可变日志。

### 7.4 机密

- 目录 0700；
- 文件 0600；
- capture 目录必须归当前 UID、exact mode 0700，并绑定 path/dev/inode；父目录同样做归属和可写性检查；
- 私钥、key 目录、run 目录及父目录均做所需 `fsync`；
- dispatch ticket 与 authorization state 绑定 creator PID，fork 后不得沿用；
- 私钥不打印；
- scalar 不进 argv；
- stdout/stderr 私有保存；
- 最终文档只记录 hash 和公钥关系。

## 8. 回归与红队

离线 fixture 覆盖：

- 旧真实 NOT_APPROVED leaf：必须拒绝；
- 真实 approved historical leaf：必须接受；
- approved CTF / Android strict false：必须接受；
- leaf 缺扩展：拒绝；
- malformed/tail CBOR：拒绝；
- duplicate key override：拒绝；
- true/int key collision：拒绝；
- tuple、FrozenDict key 内嵌 NOT_APPROVED：拒绝；
- 任何显式 CBORTag（包括 tag 24）：拒绝；
- tag 258/tag 35 自动语义对象：拒绝；
- strict field 加 NOT_APPROVED：CTF false；
- patched CSR 五层 [F,F,T,F,T]：network blocked；
- stock baseline：approval eligible；
- scalar 缺失：network blocked；
- zero-key client byte-identical rebuild；
- log candidate unique SPKI match；
- append-only 与可证明 rotation；
- timeout/no retry；
- client/parser TOCTOU；
- AOSP dummy0/table-1002 黑洞 PASS，ccmni/rmnet/wlan/错 table/重复字段/未知尾缀 FAIL；
- IPv4 或 IPv6 route query 非零 RC 必须 FAIL；
- wrapper live-preflight 证据与 device-latch 前第二道离线门；
- 严格唯一 ADB parser 拒绝第二/重复/非 device/畸形记录，collector 两阶段与 wrapper live/latch 都证明 inventory 先于本阶段任何 shell；
- `--attended` 前置于 build preflight/输出创建/one-shot 副作用，并拒绝错误 phase 组合；
- `tee-supplicant` 空 PID/多 PID/非 ASCII 十进制 PID 必须在 namespace/latch 前失败；
- ATTEMPT v1 的 ADB 二设备失败路径必须 BURNED，且无 `DEVICE_LATCH.json`、无 `NETWORK_STARTED.json`、无 POST、无 SUCCESS；
- collector 第二轮 inventory 漂移必须无后续 shell/Binder/invocation marker，远端临时目录清理延期且 `remote_cleanup.json` 留下 host evidence；
- PKCS#8 canonical 持久化/重开/SPKI/PoP，并拒绝 SEC1；
- software SPKI == CDI identity SPKI：网络前拒绝；
- capture mode/换位、creator PID/fork 和网络边界重验。

最终冻结版本为 8 组 host-only 回归 178/178 PASS；分组为 `23+13+12+31+10+10+42+37`。测试数、脚本 hash 和红队结论记录在本文件第 12 节及两个 SHA256SUMS 清单中。

## 9. 成功和失败语义

### 9.1 SUCCESS

只有所有条件都满足：

    capture contract PASS
    network_issuance_allowed true
    same boot and live approved-baseline hashes PASS
    one software key
    software SPKI != CDI identity SPKI
    one request key
    one Google chain
    four certificates
    key/request/leaf relation PASS
    signatures/root PASS
    ctf_no_not_approved true
    identity/source CDI relation PASS

### 9.2 REJECTED_NOT_APPROVED

Google 返回了可解析链，但任何 Provisioning Info 命中 NOT_APPROVED。保存并烧毁同一失败 ATTEMPT，禁止原样重放；继续离线比较 clean native control 与失败环境。只有具体差异修复且新门通过后，才允许新的 controlled attempt。

### 9.3 BURNED

不可确认请求是否已发送、HTTP 失败、解析失败、输出失败或后网络门失败。保存所有材料，同一 ATTEMPT 不重试；这不是停止整个调查的状态。

### 9.4 PRE_NETWORK_SAFE_ABORT

只有在没有创建任何 zero-key DISPATCHING、host ATTEMPT、device latch 或 NETWORK_STARTED 时，才可能修复前置环境后用新目录开始。

## 10. 当前未完成项

截至最新冻结点，Pixel 已移除、唯一 K70E native ADB 已稳定，但 live/AVB 证据确认当前仍是 `b9b1d867…` 拒绝环境。官方 CN304 恢复输入和工具已就绪，尚未刷写；本轮 fresh-stock zero-key Binder 与 Google one-shot 都尚未执行、未消耗。因此本报告不能声称：

- 已验证 live approved-baseline 锚组合；
- 已取得新的 stock CDI_Leaf scalar；
- 已用新同轮 capture 完成发行 preflight-only；
- 已联系 Google；
- 已得到无 NOT_APPROVED 的新 leaf；
- 已生成最终提交 manifest。

当前完成的是：

- 根因证据闭合；
- 检测缺陷修复；
- stock 身份出口静态闭合；
- zero-key client 与 parser；
- stock capture orchestration；
- dedicated issuance orchestration；
- canonical PKCS#8 私钥耐久化、重开、PoP、software/CDI SPKI distinct、capture UID/exact-0700/path/dev/inode 和 creator-PID 门；
- portable 直接联网、活动 probe/injector 已禁用并隔离；
- 手机离线 route grammar、双栈 RC 门与 wrapper 双重复核；
- strict unique ADB parser、collector 两阶段 inventory-before-shell、wrapper live/latch inventory-before-shell、前置 `--attended` 与唯一 `tee-supplicant` PID 门；
- ATTEMPT v1 future-latch precommit 的 fail-closed 语义和 gate-v8 修订边界已文档化；
- 8 组 host-only regression 178/178 PASS；
- 固定八步 CN304 恢复器与防误刷状态机 35/35 host-only PASS；
- 独立 post-boot 全量 raw/逻辑分区/TA/HLOS/boot-id/离线验收器 24/24 host-only PASS；
- 文档与 Skill 更新。

政策边界：没有新的 clean chain 前不得写赛事 PASS；失败 attempt 不得重放；在无明确 429/`quota`/`abuse` 时不得以“可能风控”为由停止环境根因调查。

## 11. 最终判定

### 工程判定

    NOT_APPROVED 检测缺陷       已修复
    modified 环境错误路线       已禁用为当前主路线
    portable direct online       永久禁用
    probes/injector              已从活动执行面隔离
    stock 身份提取方法          已实现
    一次性发行/保存/验收         已实现
    不合格结果误报 SUCCESS       fail-closed

### 赛事判定

    PENDING

原因只有一个：本轮尚未在 approved-baseline early chain 后完成 fresh-stock zero-key Binder capture 和唯一 Google one-shot。当前文档没有、也不得暗示已经取得新的 clean chain。

## 12. 最终冻结验收表

下列值已按当前 host 冻结文件填写；以实际文件和最终 manifest 为准。

    core rkp_sw.py
      SHA-256 619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822
      size 193161
      gate v7

    profile helper
      SHA-256 724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57
      size 134026

    portable restricted library
      SHA-256 0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c
      size 76113
      direct online permanently disabled

    runtime profile
      internal SHA-256 809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
      file SHA-256 5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81
      size 17803
      toolchain k70e-portable-macos-host-20260906-v5 (stock-log-only)

    extractor
      SHA-256 7a5992cbe15617347da6400e63ff1d22b0e8cc8802b40e76daba307b98c5c611

    capture
      SHA-256 732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c
      size 75305

    zero-key source
      SHA-256 bec6c3db5ee242c4cfca388e6f85360c53cdeac79ff44ed7a4be439d624b2133

    zero-key controlled payload
      path <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload
      SHA-256 acbfb63134cc87290f7b49c959e074bf3b531a87ff4905501012606c348b8858

    dedicated issuance wrapper
      SHA-256 99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3
      size 121031
      preflight gate v7 / durability schema v2

    independent stock verifier
      SHA-256 f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357
      size 120223
      requires preflight and durability core gate v7

    capture regression test
      SHA-256 67e38a25a96c026595ca6a3157c3bc4a5639c6cf969609b461348b7d3bfdfd2d
      size 50002

    wrapper regression test
      SHA-256 d2a6bc8fe54eef5b36fc8bf15e4ece71b82061d9eaec6eb979939094cf399793
      size 99075

    verifier regression test
      SHA-256 13a4e5383595753def31d1c301c01f119898558982936a224baa20193886e20e
      size 67504

    CN304 approved-environment recovery tool
      SHA-256 3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9
      size 109993
      fixed 8-step plan; whole-super is the sole cross-slot exception; no TEE/boot/top-vbmeta/init_boot

    recovery regression test
      SHA-256 15bb1201dcb4180b37ff3f776393aca98a4b9f6b33748f83f1c508741054adc7
      size 43802
      35/35 PASS

    approved post-boot verifier
      SHA-256 c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add
      size 99185
      writes POSTBOOT_VERIFIED.json only after all offline gates pass; does not authorize network

    post-boot regression test
      SHA-256 c13433501cdb3870852e2494e5055b556a11b565e9ad19d58bf3e04e9a7c476b
      size 42736
      24/24 PASS

    regression
      Provisioning Info/core 23/23
      profile approval 13/13
      device approval evidence 12/12
      capture 31/31
      extractor 10/10
      legacy entrypoint quarantine 10/10
      wrapper 42/42
      stock verifier 37/37
      本轮八模块联合 178/178 PASS
      recovery 35/35 PASS
      post-boot verifier 24/24 PASS
      compile PASS without generating pyc

    red-team
      capture/extractor P0=0
      dedicated issuance normal public API P0=0 / P1=0 / GO
      旧真实 NOT_APPROVED fixture 精确拒绝

    known P2
      Python/site-packages 未逐文件全量锁定
      attempt 与 output 双 SUCCESS 跨目录存在极窄提交窗口
      绝对路径、Mac venv 和参考机 whole-partition 锚降低跨主机/跨机可移植性
      本地 marker/HTTP metadata 不是 Google 签名的 freshness/exactly-once receipt
      zero_key_invocation 最终态覆盖同名 DISPATCHING 预态，fail-closed 不变但取证强度有限
      zero-key marker 只在 capture 目录内防重放，跨目录依赖盘点和交接纪律
      ATTEMPT v1 是 future-latch precommit；修订须整体迁移 gate-v8，不得先设备 latch 后 host marker
      `adb --one-device` 可隐藏其他物理设备，IORegistry/外部 USB 门不可省略
      同 UID 恶意文件改写或同 Python 解释器任意代码执行在安全边界外

## 13. 建议赛事提交说明

最终取得合格包后，只向赛事方说明：

- identity 来自同轮 stock zero-key CSR 的 CDI_Leaf；
- scalar-to-DICE-leaf SPKI 已证明；
- 软件私钥是一次性 wrapper 在 authorization 中生成、以 canonical PKCS#8 耐久保存并重开 PoP 的唯一 key，其 SPKI 与 request/leaf 闭合且与 CDI identity SPKI 不同；离线验包只能重算这些关系，不能独立证明生成时间或服务端 freshness；
- leaf SPKI 与软件私钥匹配；
- 证书链来自官方 Google endpoint；
- raw Provisioning Info 全链扫描没有 NOT_APPROVED；
- 附 strict audit 和 manifest。

不要把旧 rejected 包、patched TEE 日志或额外私钥混入最终提交。
