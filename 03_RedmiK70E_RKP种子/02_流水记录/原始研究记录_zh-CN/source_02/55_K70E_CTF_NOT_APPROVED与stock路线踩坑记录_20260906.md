# K70E CTF NOT_APPROVED 与 stock 路线踩坑记录

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 增量覆盖：**本文的旧工程/恢复坑仍有价值，但凡把 modified DICE 当成 `NOT_APPROVED` 充分原因、把 stock 当成唯一必须路线的表述已过时。最新因果坑和故障树见文档 67。

> **2026-09-06 18:05 新增覆盖：** 本文旧恢复边界已被实机推翻；完整新增坑见文档 61，当前暂停与证据链见文档 59、62。尤其禁止把 `501ec32c…` 当 stock vendor_boot 或把 `9d5d12a7…` 当 approved factory init_boot。

> 目标：让下一位 AI 不再重复 2026-08-28 至 2026-09-06 的错误  
> 原则：每个坑都写“错误想法、证据、正确处理、当前 ATTEMPT 如何处置、调查是否继续”；ATTEMPT 停止不等于项目停止
> 历史快照（已失效）：下述“ADB 稳定、尚未刷写、以文档 58 为准”已被后续实机事件推翻。当前先读文档 59–63；旧八步不可重跑，设备模式 UNKNOWN，旧三份 manifests 不具执行权威。

---

## 1. 把密码学闭环误当赛事 PASS

错误想法：

    私钥匹配 leaf，证书链验签通过，所以提交一定合格。

事实：

旧 20260905_2244 包的私钥、公钥、CSR 和四级 Google 链全部闭合，但 leaf 的 Google Provisioning Info 含 NOT_APPROVED。赛事方明确拒绝。

正确处理：

- 链验签与 Provisioning Info 是两个独立门；
- 全链逐张扫描 OID 1.3.6.1.4.1.11129.2.1.30；
- 对 raw CBOR 做 exact-one-item、canonical、重复键安全解析；
- 任何精确文本 NOT_APPROVED 都失败；
- 缺 leaf 扩展或畸形扩展也失败；
- 只有 ctf_no_not_approved=true 才可 SUCCESS。

本次结果处置：

    NOT_APPROVED hit count > 0 -> 当前结果 REJECTED，当前 ATTEMPT 不得重放；继续离线根因调查

## 2. 只读取已知 Provisioning Info 键

错误想法：

    Android 文档只定义键 1、3、4，未知键可以忽略。

事实：

旧代码只投影 1、3、4，恰好丢掉赛事方拒绝的键 5。

正确处理：

- 保留所有键、值和类型；
- 扫描 map key、map value、array、tag；
- 原始 CBOR hash 和 JSON-safe tree 都落盘；
- 不把“公开 schema 未定义”解释为“没有意义”。

## 3. Python dict 掩盖重复 CBOR key

错误想法：

    cbor2.loads 后在 dict 中没看到 NOT_APPROVED，就说明没有。

事实：

恶意或非规范 CBOR 可以用重复键、true 与整数 1 的 Python 等值碰撞覆盖前值。

正确处理：

- raw bytes 必须等于确定性 canonical 重编码；
- 拒绝尾随 item；
- 拒绝重复/碰撞键；
- parse_error 必须 fail-closed。

## 4. 认为计数 32 就是次数风控

错误想法：

    Provisioning Info 键 1 等于 32，所以尝试太多被封。

反证：

- 对工作区 DER 证书按证书 SHA-256 去重后，共有 27 张带 Provisioning Info 的不同证书：25 张干净、2 张含 NOT_APPROVED、0 张解析失败；
- 25 张干净证书中有 12 张同样为 `{1:32,3:"Xiaomi"}`，另有 13 张为 count=8；
- 两个失败请求都是 HTTP 200，不是 429；现有元数据没有 `quota` 或 `abuse`；
- Google 公开说明中该计数是近似获发量，不是公开的拒绝码。

正确结论：

在现有样本内，简单尝试次数/键 1 计数风控已经排除。环境/请求语义差异是当前必须继续追查的主因。

正确处置：

- NOT_APPROVED：烧毁并保存同一失败 ATTEMPT，禁止原样重放；继续离线差分、启动链恢复和门禁修复；
- 新 controlled attempt：只有找到具体差异、修复后 fresh boot、重新采集且通过全部新门才允许；
- 429、明确 `quota` 或 `abuse`：暂停外部请求，但仍可继续只读和离线调查；
- 绝不能把“同一 ATTEMPT 不重试”写成“整个 CTF 调查停止”。

## 5. 认为 host 模拟请求不被认可

错误想法：

    google-rkp-sw 是 host 拼包，换成真机 Binder 就会正常。

事实：

同一 modified 环境的真机 Binder 请求和 host 请求得到完全相同的 NOT_APPROVED raw CBOR。

协议对照还显示：approved native、modified native、modified host 三次运行使用相同官方 fetch URL；fetch body 均为 101 字节，SHA-256 都是：

    fdcfa6bd6cf6b0fd8fbf53a260e6c80c621face28b51c586d39c8bf244799fc2

三份 response 中 canonical EEK chains 均为 613 字节，SHA-256 都是：

    11dc72f46af10129d6a2584ebbd1c6e44ca2d26322f534606435808da42e9305

signCertificates endpoint 相同；查询串中的 fresh challenge/request_id 按设计不同。modified native 与 modified host 的五层 DICE raw payload 又完全相同。因此 URL、fetch body、EEK chain 和 host framing 都不是现有证据支持的主因。

正确处理：

先修服务器可见的 signed DICE/DeviceInfo 测量，而不是继续微调 host 请求编码。

## 6. 用 HLOS ro.boot.* 代表 TEE 签名状态

错误想法：

    adb getprop 显示 green/locked，因此 signed DeviceInfo 也一定 green/locked。

事实：

参考机历史已获认可 stock 请求的 signed DeviceInfo 是 orange/unlocked；HLOS 属性可被启动链伪装。相反，modified 失败请求的 TA 签名 DeviceInfo 才是 green/locked。

精确对照：

    approved
      DeviceInfo canonical SHA-256  19f9f9b0a96254da4c45aa0e85a3a8ca8de2496738aebc3dc88fcc4be88fd921
      vb_state / bootloader_state    orange / unlocked
      vbmeta_digest                  acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9

    modified
      DeviceInfo canonical SHA-256  82e42dd801204a814823be7f14a5912501dc5ffee4c0323c748e5618eaecd1ad
      vb_state / bootloader_state    green / locked
      vbmeta_digest                  b9b1d86756902fe9cdaf5eb666e5d83025052b1b41138f58f81ce50dc3a49744

正确处理：

- HLOS 属性只记录；
- approval gate 以 AuthenticatedRequest 内 signed DeviceInfo 为准；
- 所有字段逐类型比较；
- 五层 DICE claim 同时比较。

## 7. patched TEE 路线虽然能取 key，但污染测量

错误想法：

    只要能绕过 TA 签名并提取 scalar，就完成了题目。

事实：

Fenrir/SProvider/patched TEE 路线改变 DICE 第 1、2、4 层，Google 以 HTTP 200 返回 NOT_APPROVED。

measurement claims 和 security claims 的逐层匹配向量都是：

    [false, false, true, false, true]

不要把这误读为“第 3、5 层完整 payload 相同”。五层完整 COSE_Sign1 payload 全部不同，因为前层变化还会级联改变派生 subject key 和 issuer/subject。approved 与 modified 的 raw payload SHA-256 分别为：

    approved
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

正确处理：

- patched TA、TEE、Fenrir 只保留历史研究；
- 不再用 3990a8...、7ea594...、5b7405... 做合格签发；
- 主路线改为 stock TA 自带 MiTEE 日志。

## 8. 误以为 stock TA 不会输出 CDI_Leaf

错误想法：

    dump_to_hex 调用图只有 KAK、失败候选和 UUID，所以日志路线已死。

事实：

旧静态分析漏掉了活动 CSRv2 SignWithDeviceKey 链：

    get_attest_cdi -> P256KeypairFromCDI -> x26 -> dump_to_hex

正确处理：

- zero-key CSRv2 触发设备身份签名；
- 捕获精确 private_key(15)/private_key(31) 两行；
- 只接受与同轮最终 DICE leaf SPKI 匹配的唯一候选。

## 9. 把日志中任何 private_key 当目标

错误想法：

    grep private_key，取第一组 32 字节。

事实：

同一日志可能有 MIKEYMINT KAK、KDF 中间候选或别的调用者。

正确处理：

- 不手工 grep 作为最终证据；
- 用冻结 parser；
- 对每个候选派生 P-256 SPKI；
- 与同轮 CSR 最终 DICE leaf 匹配；
- 唯一匹配才 PASS。

## 10. 混淆四种 key

必须区分：

1. raw CDI：KDF 输入，不是最终 P-256 scalar；
2. CDI_Leaf P-256 scalar：设备身份，赛事第 1 项核心；
3. native GenerateRkpKey scalar：真机每把待签 key，不是 google-rkp-sw 软件私钥；
4. google-rkp-sw 新软件 P-256 key：赛事第 2 项，leaf 必须绑定它。

KeyBlob、MacedPublicKey、SPKI、COSE_Key、签名、KAK 都不能代替私钥。

## 11. 用旧身份或别的 K70E 材料拼包

错误想法：

    同型号手机的 UDS、CDI leaf 或私钥可以复用。

事实：

UDS 和 CDI 链是设备身份；另一台 K70E 是新目标。

正确处理：

- 新 serial；
- 新 profile；
- 新 stock baseline；
- 新 scalar；
- 新软件 key；
- 新 Google response；
- 关系验收而不是固定 hash 验收。

## 12. 把 EXACT_REFERENCE_FAST_PATH 当联网许可

错误想法：

    TA/TEE hash 与参考相同，所以可以直接 POST。

事实：

EXACT_REFERENCE 只说明二进制兼容；不能证明目标设备自己的 UDS、signed DeviceInfo、五层 DICE 和 Google 风险状态已认可。

正确处理：

    structural_and_portability PASS
    approval_environment ELIGIBLE
    network_issuance_allowed true

三个结论必须分开。

## 13. 没有已认可基线却承诺不会 NOT_APPROVED

错误想法：

    全 stock 就一定得到认可。

事实：

Google 策略不可完全从公开代码推导。当前基线来自同一参考机历史已获认可证书；另一台设备若没有这种证据，只能证明结构正确。

正确表述：

代码保证坏结果不会被写成 SUCCESS；不能预言服务端一定签发合格证书。

## 14. 忽略 lk/preloader，只检查 TA/TEE

错误想法：

    NOT_APPROVED 只与 patched TEE 有关。

事实：

DICE 第 1、2 层也变化。preloader 和 Fenrir BL2_EXT 都可见。

参考机 stock 门：

    lk_a
      size 16777216
      SHA-256 9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35

    preloader_raw_a
      size 4190208
      SHA-256 33ef65d9560e92990e5d6bbf7dc8e161e57346e7f9434082b59d31366a638d1f

正确处理：

捕获前和 point-of-no-return 前都检查完整 early-boot 分区；发行前再检查。

## 15. OTA payload hash 与整分区 hash 混用

错误想法：

    OTA 中 lk/preloader 文件 hash 应等于整分区 hash。

事实：

- OTA lk size 3395584，与保存的 16 MiB lk_a 不是同一字节范围；
- OTA preloader size 749568，只等于保存 preloader 分区前缀；
- 整分区包含容器、尾部或其他区域。

正确处理：

明确记录比较范围、size 和来源。不要因为前缀相同就伪造整分区结论。

## 16. preloader by-name 与实际启动 LU 的歧义

坑：

MTK UFS 的 preloader A/B 或 LU 映射可能与简单 by-name 理解不同。

正确处理：

- 把 by-name 全分区 hash 作为前置锚；
- 不把它当唯一授权；
- 同轮 signed DICE 五层匹配才是最终证据；
- 未确认映射前不要随意写 preloader；
- 恢复必须先验证 BROM 能力和目标自己的备份。

## 17. 为了“更 stock”盲目刷官方包

错误想法：

    全量线刷最省事。

风险：

- 覆盖 userdata；
- 改写身份/持久分区；
- relock；
- 触碰 RPMB/efuse/校准；
- 失去现有 root 或恢复路径；
- 刷错 preloader 变砖。

正确处理：

stock 日志路线本身零刷写。只有 live exact gate 不符时，才针对已确认的必要分区恢复目标自己的已知原版，并逐项验证。

## 18. 账号“无解锁权限”被误当技术阻塞

事实：

设备过去能 fastboot、root 和运行所需环境；账号 UI 授权与题目证据不是同一个概念。

正确处理：

不争论账号状态，以实际能力、live hash、root 和 signed DICE 为准。也不要因为用户说“已解锁”就跳过防砖检查。

## 19. Wi-Fi 打不开就反复重启

风险：

stock zero-key capture 与 issuance 要求同一 boot ID。为了网络重启会使捕获失效。

正确处理：

- 捕获阶段手机离线；
- 捕获成功、preflight PASS 后，用已经验证的电脑共享网络；
- 不重启、不刷写；
- 在线 wrapper 再次验证同一 boot。

## 20. 捕获前就让手机联网

风险：

无法证明 zero-key 阶段没有后台 RKPD 或其他网络活动。

正确处理：

捕获器要求手机飞行模式、Wi-Fi off、零可转发默认路由。AOSP netd 无条件配置的严格 `dummy0/table 1002`、无 `via` 默认项是黑洞 sink，单独记录而不当作外网；任何 `ccmni`/`rmnet`/`wlan`、其他 table、重复字段或未知尾缀仍 fail-closed。preflight 完成后只需 host 电脑保持互联网；手机继续离线。

## 21. 把 zero-key CSR 当一次 Google keygen

事实：

zero-key 调用的 KeysToSign 数量为 0，只生成身份 AuthenticatedRequest 并触发设备签名日志；它不创建赛事软件 key，不联系 Google。

正确处理：

zero-key 捕获和 online one-key issuance 使用不同一次性状态。

## 22. 重复运行 zero-key client

风险：

日志窗口会混入多个候选，破坏同轮唯一性；不能再证明标量来自哪次 CSR。

正确处理：

- 新输出目录；
- 调用前写 DISPATCHING_NO_RETRY；
- 每个输出最多一次；
- 超时或状态未知也不自动重试；
- 保存完整 baseline/post 日志。

## 23. 日志轮转用“看起来像”来拼

错误想法：

    last_mitee.log 加 current mitee.log 大概就是增量。

正确处理：

只有 post last_mitee.log 逐字节以前一份 baseline current 为前缀时，才能重建跨轮转增量。任何不确定性输出 PARSER_REQUIRED，禁止重触发。

## 24. parser 路径可替换或解释器漂移

风险：

私钥 parser、profile helper 或 Python 环境如果从可写路径无锚导入，可能改变安全语义。

正确处理：

- 固定 canonical venv interpreter；
- 固定实体 realpath、size、SHA；
- O_NOFOLLOW；
- lstat 与 fstat 对比；
- 读后检查 dev、ino、size、mtime、ctime；
- 私有 snapshot；
- consumer 独立重算 scalar、CSR、DICE 和 profile，不盲信 collector summary。

发布时 manifest 必须固定最终脚本和运行时依赖。

## 25. client 验证后被替换

风险：

校验源 client 后再从原路径 push，存在 TOCTOU。

正确处理：

- 先冻结到私有 snapshot；
- 校验 snapshot；
- 从 snapshot push；
- 本地和远端多次 hash；
- 固定 size 和 SHA。

## 26. 把旧 portable capture contract 塞给新 consumer

事实：

旧 patched-TA 路线有 restore、ARM/ALLOW、Binder-keygen latch 等不同合同。stock 日志路线没有这些字段。

正确处理：

- capture_method 必须 stock_mitee_log_v1；
- schema 必须 k70e-rkp-ctf-stock-mitee-log-capture-contract-v1；
- 只用 rkp_sw_stock_log_once.py；
- 不伪造 legacy 字段去通过 rkp_sw_portable.py。

## 27. preflight 报告覆盖或重复生成

风险：

使在线 attempt 无法证明消费的是哪次离线检查。

正确处理：

- preflight report 使用 exclusive create；
- 必须是 capture 目录直属 JSON；
- 在线阶段重算 semantic report 并逐类型比较；
- 不覆盖，不 symlink。

## 28. 在 live preflight 之前就烧 host attempt

风险：

瞬时 ADB 断线或 state_dir 尚未建立，会在零网络请求时永久消耗 attempt。

正确设计：

- 所有纯只读、可重复的 live approved-baseline 检查应尽量在 reservation 前完成；
- device state_dir 缺失时，在 reservation 前安全、幂等创建并核验；
- 真正不可重试边界前才创建 host ATTEMPT；
- 设备 latch 和 NETWORK_STARTED 仍必须在 core 调用前耐久写入。

如果最终工具版本明确选择更早烧 attempt，也必须文档化；人工不得通过删除 attempt 绕过。

## 29. 用错误的 core response 文件名

风险：

wrapper 期待 sign_certificates_response.cbor，而核心实际保存 response.cbor，会导致 Google 已成功返回后独立审计找不到文件、永久烧毁。

该问题已在当前 wrapper SHA-256 `99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3`（size 121031）中修复，并加入真实输出文件名回归。

正确处理：

- wrapper 与 allowlisted core 的输出合同必须做真实 fixture 回归；
- 严格审计读取 core 实际文件名；
- 单测必须构造一套成功输出树，走到 SUCCESS；
- 不只测试失败分支。

## 30. 把 android_schema_current_strict 设成硬门

错误想法：

    当前 Android 文档要求键 4="TEE"，没有键 4 就失败。

事实：

历史已获认可真实 Google leaf 为 {1:8,3:"Xiaomi"}，没有键 4。

正确处理：

    ctf_no_not_approved              硬门
    android_schema_current_strict    报告

测试必须覆盖 CTF true / Android false 的成功样本。

## 31. 只检查叶证书

风险：

NOT_APPROVED 或畸形扩展也可能出现在链中其他证书。

正确处理：

全链逐张扫描；leaf 必须有可解析扩展；其他出现的扩展也必须可解析且无命中。

## 32. 收到 HTTP 200 就写 SUCCESS

错误想法：

    200 代表 Google 接受。

事实：

两次 NOT_APPROVED 都是 200。

正确顺序：

    raw response durable save
      -> parse
      -> one chain
      -> four certs
      -> signatures/root
      -> private/request/leaf relation
      -> Provisioning Info audit
      -> SUCCESS

## 33. 解析失败前没保存 raw response

风险：

一旦 parser 报错，服务端唯一证据丢失，又不能重试。

正确处理：

fetch/sign 的 body 与 HTTP metadata 都先耐久保存，再解析。

## 34. Ctrl-C 或超时后重跑

风险：

无法知道 request 是否已到 Google。

正确处理：

只要 NETWORK_STARTED 已写，或者网络调用状态未知，就视为消耗；保留 output 和 attempt，禁止重试。

## 35. 手工删除 device issuance latch

风险：

破坏“一次性”证据，无法向赛事方证明没有挑结果。

正确处理：

设备 latch、host attempt、NETWORK_STARTED、BURNED、SUCCESS 都不可删除、覆盖或重建。

## 36. 输出树里留下额外秘密副本

风险：

临时 scalar、parser staging、stdout 或旧 key 混入提交。

正确处理：

- 最终目录只保留合同列出的身份、单一软件 key、单一链和审计；
- attempt 内临时 scalar 在 finally 删除；
- package 前拒绝 symlink/hardlink/special file；
- manifest 最后生成；
- 不把原始 MiTEE 全日志放入对外提交目录。

## 37. 文档版本优先级错误

危险文档：

- 44 第 9/11 节保存 patched 路线历史；
- 45–51 正文大量旧 PASS；
- 46 有可复制的 patched TEE 命令；
- 50 是旧 portable 六入口移植方案。

正确阅读顺序：

    README
      -> 52 事故复盘
      -> 53 完整流水线
      -> 54 傻瓜教程
      -> 55 本文
      -> 56 报告
      -> 57 Skill

早期文档只作证据，不作当前命令源。

## 38. 为了“保证”而降低门

错误做法：

- 把 NOT_APPROVED 从 audit 里忽略；
- 把 known-approved baseline 改成当前失败身份；
- 把五层匹配改为任意三层；
- 把 HLOS green/locked 当相等；
- 改 server URL；
- 接受本地签名证书；
- 手工创建 SUCCESS。

正确保证：

程序保证任何不合格结果不能成为 SUCCESS。服务端最终决定能否签出无 NOT_APPROVED 的链。

## 39. 不要把“阶段停止词”误成“调查停止词”

以下文本表示当前阶段、当前输出目录或当前 ATTEMPT 必须 fail-closed，不能原样继续或重放：

    SAFE_ABORT
    PARSER_REQUIRED
    REJECTED_NOT_APPROVED
    ProvisioningInfoRejected
    NOT_APPROVED
    BURNED
    hash mismatch
    PORT_REQUIRED
    network_issuance_allowed=false
    approval_environment=INELIGIBLE
    DISPATCHING_NO_RETRY with unknown outcome

看到这些词后的正确动作是：保存证据，停止当前危险动作或同一 ATTEMPT，继续离线定位具体差异；修复后必须用 fresh boot、新捕获和全部新门建立新的 controlled attempt，不能删除 marker 或盲目重放。

只有以下明确服务端节流/滥用信号要求暂停新的外部请求：

    HTTP 429
    explicit quota error
    explicit abuse error

即使暂停外部请求，也不等于停止只读证据审计、离线差分、代码修复和 stock 环境恢复。

## 40. 最终五问

提交前必须能回答：

1. 身份 scalar 是否由同轮 stock CSR 最终 DICE leaf SPKI 证明？
2. 软件私钥是否由本轮 google-rkp-sw 新生成且匹配 leaf？
3. 是否只有一个 key、一个 request、一个 Google chain？
4. 全链 raw Provisioning Info 是否零个 NOT_APPROVED 命中？
5. SUCCESS 是否由独立重算写出，而不是人工声明？

任一回答不是明确“是”，就不是最终提交。

## 41. 只检查“直接字符串 map key”

风险：

CBOR map key 可以是可 hash 的复合对象。旧 gate-v4 虽然递归扫描 value，但对 key 只检查 `isinstance(key, str)`，因此如下 canonical CBOR 可漏报：

    {("NOT_APPROVED",): 7}
    {CBORTag(42, "NOT_APPROVED"): 7}
    {FrozenDict({"nested": "NOT_APPROVED"}): 7}

正确处理：

- 对每个 map key 本身递归，再对 value 递归；
- path 显式标记 `<key:...>`；
- tuple、CBORTag、FrozenDict 三种证书 fixture 都必须 `ctf=false / hit=1`；
- 旧 gate-v4 工具链保留为历史离线身份，禁止联网；gate-v5 虽修复复合 map key，但直接 core 未锁定五层完整身份 payload，也只作历史离线身份。gate-v6 同样只保留为升级轨迹；当前唯一联网门为 gate-v7、stock-log-only toolchain V5。

## 42. 把本地 marker 当成服务端 freshness 证明

事实：

ATTEMPT、NETWORK_STARTED、HTTP JSON 和 SUCCESS 都是本地状态。独立 verifier 能检查它们的 hash、时序、唯一性和与包内请求/证书的关系，但不能把本地文件变成 Google 签名的“本次网络交易回执”。持有旧链及对应私钥的人理论上可以离线重建一套内部自洽 marker。

正确表述：

- Google 证书签名证明链的真实性和 key 关系；
- 本地 marker 是可审计操作证据，不是不可伪造的 fresh/exactly-once 证明；
- 若赛事方要求密码学防重放，需要赛事 nonce、服务端签名 receipt 或不可变外部日志；
- 报告不得把离线 verifier 夸大为这种外部证明。

## 43. zero-key 最终状态覆盖 DISPATCHING 预状态

当前 capture 先 exclusive 创建 `zero_key_invocation.json` 的 `DISPATCHING_NO_RETRY`，调用结束后会用同名文件原子替换为最终结果。因此：

- 若调用中崩溃，DISPATCHING 留存并且 fail-closed；
- 若调用完成，目录中只保留最终状态，不保留独立的预状态文件；
- 这不会开放重试，也不改变单调用的程序逻辑，但会降低“同时保留 pre/post 两份不可变证据”的取证强度；
- 报告必须把它列为 P2 局限，不得声称有两份独立不可变 marker。

如果赛事后续要求更强取证，新版 schema 应使用两个 exclusive 文件（例如 `ZERO_KEY_DISPATCHING.json` 和 `ZERO_KEY_RESULT.json`），版本化合同并全量重测，不能在已有 capture 上补造。

## 44. 在同一 boot 中恢复磁盘 stock，不会倒转已经完成的 DICE

错误想法：

    先用 patched TEE/init_boot/TA 开机和取 key，签发前把磁盘恢复 stock，就等价于 stock 请求。

事实：

- `device_preflight.json` 已看到 `tee_a` 磁盘为 stock `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d`，但 init_boot 磁盘仍是 candidate `4d83cd26f02c585dce733f81d05faf38ec5c8f247f89fbaa9fcf46b70d2b4d85`，tee-supplicant namespace 中 TA 仍是 patched `6abe6de177a898afcab1ab2cbf62a3e878b6f5c31a1d134234e4aa8c27a2b8e0`；
- 后续 `04_postrestore_stock_preflight.json` 虽看到 TEE/TA 磁盘回到 stock、init_boot 回到 pinned known-good Magisk 锚，但这发生在当前 boot 的 early-chain DICE 已派生、TA 已加载之后；
- 同轮 AuthenticatedRequest 已把 modified DeviceInfo/DICE 签死，后来改磁盘内容不能修改已生成请求；
- 结果正是 modified native Binder 请求 HTTP 200 + NOT_APPROVED。

正确处理：

1. 先把目标设备的原厂 `lk_a`/实际启动 preloader/TEE/TA、pinned known-good Magisk init_boot 和 early-bind 状态全部恢复到 approved-baseline 组合；
2. 确认下次 early boot 不会再替换或 bind patched 组件；
3. 执行 fresh boot；
4. 在这个新 boot 中重新采集 zero-key AuthenticatedRequest；
5. 要求五层完整 payload、measurement/security claims、signed DeviceInfo 和 live hashes 全部通过 approved baseline 门；
6. 之后才允许新的 controlled Google attempt。

“磁盘当前符合认可锚”只是必要条件，不是“本次 boot 的 signed DICE 已符合 approved baseline”的充分条件。特别注意：参考锚 `init_boot_a=9d5d12…` 是 known-good Magisk，不是 factory-stock。

## 45. 把一次性 ATTEMPT 烧毁误写成整个项目停止

错误想法：

    NOT_APPROVED 或 BURNED 后，为了避免风控，所有工作都必须停止。

事实：

同一请求/同一 marker 不可重放是取证和 one-shot 约束；它不证明服务端在按次数风控。本项目已有 12 张 clean count-32 证书，两坏请求均 HTTP 200 且无 429/quota/abuse。

正确处理：

- 保留并烧毁失败 ATTEMPT；
- 不用相同环境盲试；
- 继续离线比较 clean native control 与失败路径；
- 找到具体差异并修复，fresh boot 后通过新门；
- 再创建全新的 controlled attempt；
- 只有明确 429/quota/abuse 才暂停外部请求。

在尚未取得新的 `ctf_no_not_approved=true` Google 链之前，只能写“根因修复待现场验证”，绝不能写“已经解决”或“已有合格新链”。

## 46. 只升级 core gate，发行/验收合同仍停在旧版

冻结后独立审计曾发现：核心、portable loader 和 capability 都已要求 gate-v6，但专用发行器仍在 preflight 中写死 `core_rkp_gate_version=5`，验收器也把这个旧值当作合法值；合成 fixture 进一步将错误固化为回归期望。manifest 全 PASS 只能证明“错误被一致冻结”，不能证明语义正确。

这是 gate-v5 到 v6 时发现的历史错误。随后对 CBOR 语义对象和持久化边界的复查又将当前门升到 v7。当前必须整体满足：

- 发行器从 `portable.REQUIRED_RKP_ISSUANCE_GATE_VERSION` 取值，并硬要求严格整数 `7`；
- preflight 写入 `core_rkp_gate_version=7`；
- durability 合同使用无版本误导的 `installed_after_allowlisted_core_load=true`，并另存 `core_gate_version=7`；
- 独立 verifier 同时要求 preflight 和 durability 的 v7；
- 当前 profile 的 toolchain 必须是 `k70e-portable-macos-host-20260906-v5`，且 V5 是 stock-log-only，不继承 V4 的 patched/candidate 执行面；
- fixture 与回归断言同步，并明确禁止旧 `installed_after_allowlisted_gate_v5_load` 字段。

通用教训：每次升级 gate，必须同时全局扫描代码、报告 schema、verifier、fixture、文档和 manifest；不能只看核心常量或测试总数。

## 47. 把 `cbor2.loads()` 的返回值当作只有 dict/list/string/bytes

`cbor2` 会对部分 tag 自动转成 Python 语义对象。已复现的两个绕过是：

    tag 258 -> set / frozenset
    tag 35  -> re.Pattern

如果递归器只认 `dict/list/tuple/CBORTag`，然后对未知对象做 `str(value)`，就可能漏掉容器里的精确 `NOT_APPROVED`，或把对象的非稳定字符串表示当成安全语义。

gate-v7 的处理原则：

- Provisioning Info 只接受明确允许的原始类型；
- tag 258 产生的 `set/frozenset`、tag 35 产生的 `re.Pattern` 等所有自动解码语义对象全部 fail-closed；
- 所有显式 `cbor2.CBORTag` 也全部 fail-closed，不因 tag 号看似无害而放行；
- 不使用 fallback stringification 作为安全扫描；
- 测试必须包含 tag 258 和 tag 35。

## 48. 以为通用 `CBORTag` 只是一层可递归包装

tag 24 的 value 可以是“另一段已编码 CBOR”的 bytes，例如内部再藏 `{1:"NOT_APPROVED"}`。外层 canonical round-trip 完全正常，如果扫描器只看 tag value 的 bytes 本身，仍然会漏报。其他 tag 也可引入自动语义转换。

当前规则是更小的可信语法：Provisioning Info 中任何显式 `cbor2.CBORTag` 都拒绝，不尝试猜测其业务语义。tag 24（内嵌 encoded CBOR）和普通 tag 42 都必须有独立负向 fixture；这与 tag 258/tag 35 自动转换后语义对象的拒绝门同时生效。

## 49. 只禁用 CLI，却保留裸的 keybox 构造 API

`cmd_keybox` 返回 SAFE_ABORT 不等于所有导出路径都关闭。旧 `build_keybox_xml()` 可直接接收私钥和任意证书链，既不扫 Provisioning Info，也不验证 leaf SPKI 与私钥。已实测它能对现有 `NOT_APPROVED` 链生成 XML。

对本 CTF 发行 core，裸 builder 不属于必需功能，应 fail-closed 退役。若未来真需导出，必须使用只能由“全链签名 + 可信根 + leaf/private-key + raw PI”最终审计产生的一次性能力，不得恢复纯函数入口。

## 50. 源码已修，但旧 `.pyc` 仍是可执行在线旁路

Python 可以显式加载与当前 `.py` 不一致的 bytecode。本轮真实发现：

- `third_party/google-rkp-sw/__pycache__/rkp_sw.cpython-314.pyc` 仍嵌入旧 arm/fetch/submit/cmd_provision；
- 旧 tx2 采集器也有残留 pyc；
- 删除/改写 `.py` 不会自动清除这些文件。

当前发行前必须扫描项目树和 core 树的非 venv `*.pyc`/`__pycache__`，全部删除；测试使用 `PYTHONDONTWRITEBYTECODE=1`，并用回归断言没有过期 core bytecode。

## 51. 把“请求里的 KTS 公钥等于干净 leaf”当成服务器评估了该 DICE 请求的证明

离线派生设备 evidence 存在 mix-and-match 攻击：攻击者可将借来的 clean leaf 公钥填入另一份由目标 CDI_Leaf 签名的 request KeysToSign，再配上借来的 clean chain。DICE 签名、leaf/KTS 公钥、Google 链可各自成立，但这些关系不证明 Google 曾对该 DICE 请求做出 clean 决定。

所以：

- 自动派生 evidence 默认仅用于诊断；
- 它不得通过“自己包含的 digest”自我授权联网；
- 只有被 core 代码中独立审阅的“完整 evidence canonical hash + 全安全 expectations”投影 allowlist 明确收录后，才能作为新设备权威基线；
- 当前 allowlist 为空，参考机使用内置已审批 evidence。

## 52. 让调用者提供 profile helper，再在 core 里 `exec`

即使 helper 旁边有“调用者自报 SHA-256”，也不会变成权威。恶意 helper 可在任何授权校验之前执行顶层副作用，并伪造 `load_profile()` 结果。同样，将认可常量保存为运行时 module globals，会被同解释器调用者重绑。

gate-v7 的正确边界：

- gate factory 创建时把内置参考 evidence hash、curated derived set 和 reference expectations 复制进闭包；
- core 自己严格解析 profile/evidence JSON、校验 exact keys、typed value 和 profile self-hash；
- helper snapshot 只是取证材料，不导入、不执行、不决定授权；
- ticket 封存 canonical expectation bytes，authorization 再深快照，不读取可变 globals。

## 53. 只验证 wrapper 的 ATTEMPT/NETWORK 文件，没有绑定 core dispatch claim 和真机 latch

新 core 会在 attempt 目录 exclusive 创建 `CORE_DISPATCH_CLAIM.json`；stock wrapper 另有 `DEVICE_LATCH.json`、profile/evidence/helper 快照。若独立 verifier 的 exact file set 忘记这些文件，真实成功运行反而必定失败；若 core 不绑定它们，又可以绕过 wrapper 自造 host marker。

每次 dispatch 合同升级必须同时修改：

1. wrapper 写入的 exact key set、path 和 SHA；
2. core arm 的参数、重读、跨文件关系和 bound-files 快照；
3. stock verifier 的 ATTEMPT_ALLOWED_FILES/NETWORK exact schema；
4. 合成 fixture；
5. 真实 wrapper→core 集成测试，不能把 arm mock 成空 lambda 后就声称通过。

注意：本地 JSON 和真机目录 latch 仍然不是 Google 签名 receipt，也不能抵抗拥有同 UID/同解释器代码执行权的攻击者。它们的作用是可审计的 fail-closed 操作约束。

## 54. 把“私钥 PEM 写成功”当成“签发后一定可交付”

仅对临时文件 `fsync` 再 `rename`，若不 `fsync` 父目录，崩溃后文件名仍可能丢失。仅用内存私钥生成 KeysToSign，不在 fetch EEK 前重读 PEM，则磁盘换位、损坏或不可解析只会在 Google 消耗签发后才暴露。

正确的 point-of-no-return 顺序是：

1. authorization 内部生成唯一 P-256 私钥；
2. 以 canonical PKCS#8/PEM、mode 0600 持久化唯一私钥及 SPKI/summary，`fsync` 文件、key 目录、run 目录和父目录；SEC1 或任何非 canonical 私钥编码拒绝；
3. `O_NOFOLLOW` 重读 PEM，核对 dev/inode/size/hash；
4. 重新解析为 exact P-256 private key，SPKI 等于已存公钥和 KeysToSign；
5. 对随机 nonce 签名并用公钥验签，证明真正持有私钥；
6. 将 path/hash/dev/inode/SPKI 封存进 authorization state，并要求 capture 及父目录归当前 UID、capture exact mode 0700、path/dev/inode 稳定；
7. 然后才 fetch EEK；
8. fetch 和 signCertificates 的网络边界前后都重验 capture、PKCS#8、SPKI、PoP 和精确 request bytes；
9. dispatch ticket 与 authorization state 绑定 creator PID，constructor 期间或此后 fork 出的子进程不得复用能力。

duck object 只实现 `.public_key()` 不能作为私钥证明。这个门必须在网络前，不能只交给最终验包器。

## 55. “复制进归档”不等于“已从活动执行面退役”

旧 tx2、任意 KeysToSign tx4、patched 采集器、旧 online core 和诊断 APK 即使已打包，只要原路径还有脚本/二进制/APK/pyc，后续 AI 仍可误运行。

当前隔离合同：

- 原始 18 个目标成员保存在 `06_历史危险能力隔离/legacy_online_capabilities_20260906.tar.xz`；
- archive SHA-256 为 `6cb0f03628b4140a8860ad6d6c89e09a83ae50d565f8e6051dcb22c1cfc24842`，权限 0600，不含 `._*` AppleDouble；
- 每个成员必须符合 `ORIGINAL_SHA256SUMS.txt`；
- 旧 Python/shell 原路径仅留 rc=78 无副作用 tombstone；
- tx2 ELF、任意 tx4 ELF 和两个 APK 已移出活动树；
- 必需的 zero-key tx4 仅保留为 `<PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload`，mode 0600，SHA-256 `acbfb63134cc87290f7b49c959e074bf3b531a87ff4905501012606c348b8858`；
- 旧拒绝包中的两个 proof `.py` 从文件树删除，验证器只按固定 archive/member hash 读其惰性字节，严禁执行。

## 56. 把 Python 模块内的“不可绕过”写成敌对代码安全边界

同一 Python 解释器内的恶意代码可重绑 module globals、替换公开函数、修改 `__globals__`。闭包、WeakKeyDictionary 和 exact-type check 能阻断普通误用和不带代码执行权的 API 绕过，但不能在 CPython 中建立真正隔离边界。

因此威胁模型必须如实写：

- 受信 wrapper、core、profile/evidence 快照在一个无任意插件的本地进程中执行；
- 调用者不在 arm 与网络之间获得任意 Python 代码执行；
- 拥有同 UID 文件改写或同解释器代码执行权的攻击者在安全边界外；
- 若要防这类攻击，必须用单用途隔离进程、最小 IPC、只读代码映像和 OS 权限边界，不能再加一个 Python boolean。

报告可以写“直接 CLI/普通 API 误用 fail-closed”，不能写“同解释器敌对代码无法绕过”。

## 57. 看到 NOT_APPROVED 就猜“尝试次数过多”

本项目的全量本地样本是 125 张 DER、27 个唯一 Provisioning Info：25
个 clean、2 个含 `NOT_APPROVED`，且零解析错误。关键反证是同一
count-32 集合里同时有 12 个 clean 和 2 个 bad；两个 bad 的 fetch/sign
都是 HTTP 200，无 `429`/`Retry-After`/quota/abuse。

与此同时，bad 请求的 signed DeviceInfo 从 orange/unlocked 偏离到与
approved 基线不同，五层完整 DICE payload 全部不同；modified native 与
host google-rkp-sw 在同一身份、DeviceInfo、测量和五层 payload 上一致，
排除了“host 模拟天生不被接受”。因此当前根因排序是 modified
boot/DICE 环境远高于次数风控。未见明确节流信号时，不得用“可能风控”
停止环境修复。

## 58. 新软件私钥和 CDI 身份钥可以相同

CTF 交付的“一次成功产生物私钥”必须是本轮 google-rkp-sw 新生成的
KeysToSign 私钥，不是 CDI_Leaf 身份私钥的另一份拷贝。

gate-v7 现在在首次 fetch 前强制：

- 持久化后重读的软件 SPKI 与封存 CDI identity SPKI 必须不同；
- fetch、build、request verify 和 submit 每次重读私钥都重复 distinct 断言；
- capture 目录必须由当前 UID 拥有、mode 0700，且 path/dev/inode 在私钥持久化前后不变；
- dispatch ticket 和 authorization 都绑定 creator PID，fork 后的子进程不能沿用父进程的一次性能力。

## 59. 文件名里有 readonly/probe 就当成无副作用

本轮复查找到三个反例：

- `k70e_rkp_ta_readonly_probe` 允许环境变量选择任意 TA UUID/命令；
- `oemcrypto_csr_probe` 真正调用 OEMCrypto CSR；
- `k70e_rkp_inprocess_readonly_injector` 使用 ptrace/process_vm_writev、改寄存器并选命令。

三个活动 ARM64 二进制均已删除，同名 C 只留 rc=78 tombstone。
原始字节可从两个 mode-0600 归档恢复：

- `legacy_active_probes_20260906.tar.xz` = `c21aa52edaacfb4e0dad13194577cb49a909b6b4fa23d8b5c1d47cb63f0bcd04`；
- `legacy_inprocess_injector_20260906.tar.xz` = `56e33646a11a9ea1ba75c073a4ac57b5181fe3255a416f92961d73ece3895c5b`。

以后判断“只读”必须看实际 syscall/API/命令 allowlist，不能看文件名或注释。
这些 probe/injector 与旧联网能力一样，已从活动执行面禁用并隔离，不存在“临时备用”例外。

## 60. 保留旧 portable 联网 CLI 作为“备用”

旧 portable 路线可以在 patched TA/TEE/init_boot 捕获物上继续走 Google，这正是
本次环境偏离的重复入口。当前规则：

- `rkp_sw_portable.py` 仅保留离线 preflight、resume-finalize 和供 stock wrapper 使用的库函数；
- 它的直接联网分支永久 SAFE_ABORT，不得恢复；
- 唯一受支持的新签发入口是 `rkp_sw_stock_log_once.py`；
- current toolchain/profile 是不继承 V4 的 stock-log-only V5，只能绑定 stock-log 所需文件，不得再把 tx2 keygen、candidate TA/TEE、patched init_boot 或 restore builder 列为当前信任集。

## 61. 离线门全 PASS 就宣布 NOT_APPROVED 已经解决

离线工作可以证明旧结果是环境偏离、新管线不会在已知偏离上联网、不合格链无法发布；它不能代替 Google 对 fresh stock boot 的新决定。
截至最新冻结点，Pixel 已移除且唯一 K70E ADB 已稳定；工作停在已实证的 `b9b1d867…` 拒绝环境和待执行 CN304 恢复。本轮 fresh-stock zero-key Binder 与 Google one-shot 都未消耗。因此尚未取得新的无 `NOT_APPROVED` 证书链，不得把“离线 178/178 PASS”写成“真机终验已解决”。

最终“已解决”的唯一验收是 K70E 回到精确 approved-baseline 组合后，在
fresh boot 中新捕获五层 stock request，执行一次 controlled attempt，并产生：

1. 同轮 CDI_Leaf 身份数据；
2. 同轮新软件私钥；
3. 与该私钥 SPKI 匹配、Google 签名可验、全链 raw Provisioning Info 零 `NOT_APPROVED` 的唯一证书链。

## 62. 把 `dummy0/table 1002` 黑洞路由当成手机外网

错误做法：

    ip route 输出里只要有以 default 开头的行，就判定手机可上外网。

事实：

AOSP netd 会无条件安装 `default dev dummy0 table 1002` 类型的直连 sink。它没有 `via`，是丢包黑洞，不是可转发的外网通道。旧的 `^default` 计数会把参考机正常离线状态误报成 FAIL。

正确处理：

- 只忽略当前代码严格 token grammar 认可的、无 `via` 且 `dev=dummy0/table=1002` 的 IPv4/IPv6 sink；
- `forwarding_default_route_count` 必须严格为 `0`；
- `ignored_dummy_sink_default_route_count` 单独记录，不得与可转发路由混数；
- 缺 table、错 table、重复 `dev/table`、`via/nexthop/nhid/encap`、未知尾缀和跨 IPv4/IPv6 语法全部 fail-closed。

不能为了消除误报而宽泛放行所有 `dummy0` 或所有无 `via` 路由。

## 63. 路由查询失败被空输出掩盖

错误做法：

    ip -4/-6 route 查询失败，但 shell 最后的 echo 返回 0；
    parser 看到空路由后误判“零 default，所以离线”。

正确处理：

- IPv4/IPv6 路由查询分开边界和分开记录 RC；
- `ipv4_route_query_succeeded` 和 `ipv6_route_query_succeeded` 必须都为严格布尔 `true`；
- 任一 RC 非 0、marker 重复/错位、查询结果无法解析，都必须在 Binder/ATTEMPT/设备 latch 前 SAFE_ABORT；
- 不得把“空 stdout”当成“查询成功且无路由”。

## 64. 只在早期检查手机离线，到 latch 时不复核

风险：

手机在 live preflight 后到 host `ATTEMPT`/设备 latch 之间可能恢复 Wi-Fi、移动数据或反向共享，从而与 host 的唯一 Google 运行并发。

当前专用 wrapper 有两道手机离线门：

1. 在 host `ATTEMPT` 之前的 live preflight 先用严格唯一 ADB inventory 解析器验证全局 transport，通过后才允许任何 serial-scoped shell；随后检查飞行模式、Wi-Fi、IPv4/IPv6 查询 RC 和严格 default-route grammar，结果绑入 `LIVE_STOCK_PREFLIGHT.json`；
2. `reserve_device_latch()` 也先独立重做全局 ADB inventory，在该阶段任何设备 shell 和 latch 创建之前拒绝第二记录、重复记录、非 `device` 状态或畸形行；通过后才使用 `set -eu`、显式查询失败退出和同语义严格 AWK 再做手机离线门。

两道都允许严格 AOSP dummy sink，但任何可转发 default 都拒绝。第二道失败必须阻止 latch 消耗，不得用 AWK 反向退出码把解释器错误当成通过。

## 65. ADB 旧 daemon/libusb 卡顿、多设备和休眠被当成可重试小问题

本次现场已观测到：旧 ADB daemon/libusb 路径可卡住约 4 分钟后才超时。这不是 K70E 身份或 Google 风控证据，也不能在一次性边界后盲目重跑。

现场正确顺序：

1. 先用 IORegistry/外部 USB 端口 inventory 确认物理层，再拔掉 Pixel（历史 serial `<DEVICE_SERIAL>`）和其他 Android 设备；`adb --one-device` 会把其他物理设备隐藏在 daemon 视图之外，所以它不能取代外部物理 inventory 和断开；
2. 只使用 profile 锁定的官方 platform-tools ADB，清理旧 server 后以 `ADB_LIBUSB=0 adb --one-device <DEVICE_SERIAL> start-server` 启动；
3. 再确认 `adb devices -l` 只有目标 serial，不接受 offline/unauthorized/第二设备；
4. 操作员在手机开发者选项开启 **Stay awake**，USB 供电期间保持屏幕/授权上下文稳定；
5. 在任何 Binder point-of-no-return 之前处理 ADB 问题。一旦已有 `DISPATCHING_NO_RETRY`、`ATTEMPT`、device latch 或 `NETWORK_STARTED`，就不能把 USB 超时当成“再试一次”的理由。

截至最新冻结，Pixel 已不在场，唯一 K70E ADB 已稳定；但因当前仍是拒绝环境，本轮尚未执行 fresh-stock zero-key Binder 或 Google one-shot，没有消耗真机 one-shot。

## 66. 用宽松文本处理 `adb devices -l`

错误做法是只搜索目标 serial，或在多行输出中取第一个 `device`。这会放过第二设备、同 serial 重复行、`offline`/`unauthorized`、控制字符、非 ASCII、异常 CR 换行、多余头尾空白和重复/畸形 detail token。

当前 collector 和 wrapper 各自内置严格唯一 parser：输出必须恰好是标准 header 加一条记录，记录必须是 pinned serial、状态严格为 `device`，每个后续 token 必须是唯一且合法的 `key:value`。任何偏离都在首个设备 shell 之前 SAFE_ABORT。

## 67. inventory 在 shell 之后才做

serial-scoped `adb -s $SERIAL shell` 不能替代全局 transport inventory；如果先做 shell，另一设备已在场的事实会被绕过。

当前顺序是：

1. collector 基线阶段：全局 inventory 必须是该阶段第一个设备操作，通过后才允许 stock/offline/log shell；
2. collector 最终 dispatch 阶段：再次全局 inventory，通过后才允许本阶段的任何 shell，然后才写 `DISPATCHING_NO_RETRY` 并唯一调用 Binder；如果第二轮 inventory 相对基线漂移，必须做到零后续 shell、零 Binder、零 invocation marker；
3. wrapper live preflight：全局 inventory 先于所有 live shell；
4. wrapper latch 阶段：在 host `ATTEMPT` 已耗用后重做全局 inventory，通过后才运行原子的 stock/offline/latch shell。

collector 在第二轮 inventory 失败时也不得用“清理”为名对设备再发 shell。已分发的远端临时目录保留，host 在 `remote_cleanup.json` 记录 `removed=false`、远端路径和“final exclusive ADB inventory failed”原因。只能在之后重新从 IORegistry/外部 USB 端口和严格 ADB inventory 确认唯一目标后手工清理；清理不授权 Binder 重跑。

## 68. `--attended` 在预检后才验证

`--attended` 是人在机旁的现场授权，不是普通配置字段。如果到 build preflight、创建输出目录或任何 one-shot 副作用后才发现未提供它，就会把未授权的调用带进现场逻辑。

当前两个 CLI 都在任何 preflight/输出创建/设备操作之前验证：collector 必须同时指定 `--attended --execute-zero-key-once`；wrapper 只有 `--execute-google-once` 可以与 `--attended` 配对，实际发行缺少它立即 SAFE_ABORT，`--preflight-only --attended` 也拒绝。

## 69. `pidof tee-supplicant` 多 PID 被当成一个 PID

`pidof` 可以返回空、一个 PID 或空格分隔的多个 PID。把整串直接交给 `nsenter -t` 不能证明命名空间唯一，而且 shell/解析差异可以让验证变得含糊。

collector、wrapper live preflight 和 latch 前原子 shell 现在都要求返回值恰好是一个非空 ASCII 十进制 PID；空值、空格、多 PID、符号或其他字符全部在 namespace TA 验证/latch 之前拒绝。

## 70. ATTEMPT v1 的 future-latch 预承诺被误写成 SUCCESS 绕过

当前 `k70e-rkp-ctf-stock-log-issuance-attempt-v1` 会先耗用 host `ATTEMPT.json`，其中预承诺稍后将创建的 `DEVICE_LATCH.json` 路径、内容哈希和设备 latch 关系，然后才重做 ADB/stock/offline 门并消耗设备 latch。这是 v1 的 future-latch precommit 语义局限，不是 SUCCESS 绕过：

- 如果 latch 前 ADB inventory 失败，当前 attempt 必须写 `BURNED.json`，不存在 `DEVICE_LATCH.json`、`NETWORK_STARTED.json` 或 POST；
- SUCCESS verifier 必须看到实际 `DEVICE_LATCH.json`，且它必须与 `ATTEMPT.json` 的预承诺逐字节关系一致；只有 future hash 不能成为 SUCCESS；
- 不能用“先在设备上创建 latch，再在 host 写 ATTEMPT”来表面修复；一旦 host marker 创建失败，会留下已消耗的设备 latch 而没有 host attempt 证据；
- 如要改变这个跨 host/device 提交协议，必须设计新 schema，同步更新 core/wrapper/verifier/fixture/manifest，并整体迁移到 gate-v8。当前冻结执行面仍是 gate-v7，不允许在 v7 内静默改序。

## 71. 把 `adb --one-device` 当成物理唯一性证据

`--one-device SERIAL` 限制的是新 ADB daemon 接管的 transport；它会让其他已物理插入的 Android 设备不出现在随后的 `adb devices -l` 视图中。因此“严格 ADB parser 只看到 K70E”只能证明 daemon 视图唯一，不能证明 USB 物理层唯一。

现场必须在启动 `--one-device` server 前和 one-shot 紧前使用 IORegistry/外部 USB 端口 inventory，确认 Pixel 和其他 Android 设备已物理移除。当前 Pixel 已移除且 ADB 已稳定，但这不覆盖拒绝环境门；在 CN304 恢复/post-boot 全门通过前，真机 one-shot 仍不授权、也未消耗。

## 72. 把 zero-key marker 当成跨目录全局 latch

`zero_key_invocation.json` 及其 `DISPATCHING_NO_RETRY`/最终态只属于当前 capture 目录。它能阻止同一目录原地重跑，但不能在新目录中自动发现历史 dispatch，也不是设备签名的 exactly-once receipt。

所以跨目录不重放仍依赖操作纪律：执行前盘点所有私有 capture 目录/交接记录，一旦任何目录出现 dispatch 或不确定结果就视为已消耗，禁止换目录重跑。如需强跨目录防重放，需要设备端全局 latch、组织者 nonce/签名 receipt 或外部不可变日志，不能在文档中将目录级 marker 夸大为这些保证。

## 73. `PREPARED.json` 只验主键，把持久证据当作装饰字段

旧恢复器只复核 target、工具/源哈希和少数 snapshot 字段。已实证将 `network_used: false` 改为整数 `0`、将 `forbidden.network: true` 改为整数 `1`、将 SHA/nonce 字符串改成 64 位十进制整数，甚至增加未知顶层字段，都会进入八步 mock flash。

当前 `prepared-v2` 在 execute 和 reboot 共用同一 exact validator：

- 顶层、target、ADB audit、transport、offline、snapshot、battery、raw baseline、B 链、legacy、forbidden、source、plan 的键集必须完全相等；
- JSON `bool`/`int`/`float`/字符串不允许 Python 弱类型相等或 `str(...)` 强制转换；
- 未知、缺失、多余、重复键、非 canonical JSON、时间/UUID/boot-session 或 nested identity 偏移均在 global claim 和首个 flash 之前拒绝。

## 74. 只看 `FLASH_COMPLETE` 摘要就重启

旧 reboot 路径只看步数/status，已实证篡改 `completed_steps`、STARTED/OK 的 step 类型、裁剪 claim reference，或删掉 `execution_claim_sha256`/`automatic_retry`/`completed_epoch` 仍会发出 mock reboot。

当前唯一 reboot 前必须完整重放：global claim 和 exact local ref、post-claim full gate、8 组 STARTED/OK、每步 raw stdout/stderr 哈希及独立重解析、full/critical Fastboot gate 及哈希、时间顺序、claim 绑定的 exact `FLASH_COMPLETE`。目录必须恰好只有预期文件；任何 PARTIAL、额外或缺项都在 TTY 和 `fastboot reboot` 之前停止。

## 75. 用“看起来像 OKAY”的宽松 Fastboot 文本解析

最终审计找到三类真问题：

- pinned `super.img` 明确是 Android sparse，但旧 parser 接受 raw `Sending 'super'`；现在 step 1 必须是从 `1/N` 到 `N/N` 的连续 sparse 序列，后 7 步必须 raw；
- `getvar` 和 reboot 旧实现只计数，倒序 `Finished` 仍可通过；现在顺序必须分别是 assignment→Finished 和 Rebooting→Finished；
- Fastboot status 用 `OKAY [%7.3fs]`，Finished 用 `%.3fs`。任意空格既会错收不可能 frame，也会错拒合法 `[100.001s]`。当前分开两套 grammar，拒绝错误 padding、前导零、非 3 位小数、错 target、`NOT_OKAY`、未知行和倒序。

仅保留两条已观测、逐字节固定的 macOS `e0005000` IOKit cleanup warning，input/output 各最多一次。Fastboot 报告的 KB 数只作语法证据，端到端正确性仍由 pinned binary/source、exact argv 和 post-boot 全分区 SHA-256 闭环。

## 76. 长哈希后查过离线，但 transport 盘点后留了窗口

只在 9.1 GB 哈希后复核 offline 还不够；后续 IORegistry/ADB/Fastboot transport inventory 期间仍可发生网络状态变化。当前 post-boot 顺序是：初始 offline→长哈希后 offline→boot-id→transport inventory→第三次 offline→terminal boot-id。三份 offline 证据必须 typed-equal，最后 boot-id 覆盖第三次查询窗口，然后才能原子写 host marker。

## 77. 2026-09-06 当前唯一冻结快照

以下是当前执行面，不得从上文历史升级记录回退：

    toolchain          k70e-portable-macos-host-20260906-v5 (stock-log-only)
    core gate          v7
    core               619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  193161
    profile helper     724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  134026
    portable library   0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c   76113
    stock collector    732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c   75305
    stock wrapper      99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3  121031
    verifier           f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357  120223
    profile internal   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
    profile file       5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81   17803
    collector tests    67e38a25a96c026595ca6a3157c3bc4a5639c6cf969609b461348b7d3bfdfd2d   50002
    wrapper tests      d2a6bc8fe54eef5b36fc8bf15e4ece71b82061d9eaec6eb979939094cf399793   99075
    verifier tests     13a4e5383595753def31d1c301c01f119898558982936a224baa20193886e20e   67504
    host-only tests    8 groups, 178/178 PASS (23+13+12+31+10+10+42+37)
    recovery tool      3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9   109993
    recovery tests     15bb1201dcb4180b37ff3f776393aca98a4b9f6b33748f83f1c508741054adc7   43802; 35/35 PASS
    postboot verifier  c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add   99185
    postboot tests     c13433501cdb3870852e2494e5055b556a11b565e9ad19d58bf3e04e9a7c476b   42736; 24/24 PASS

`portable library` 的 hash 仅表示 stock wrapper 调用的受限库代码，不表示允许直接 portable 联网；该入口已永久禁用。上述门可防普通 CLI/API 误用和已覆盖的文件换位，但拥有同 UID 恶意改写权或同一 Python 解释器任意代码执行权的攻击者仍在安全边界外。

这个冻结快照是“可继续现场终验的发行候选”，不是赛事 PASS。当前 core 仍为 gate-v7；ATTEMPT v1 若修订必须整体迁移 gate-v8，不得在此冻结身份上局部改序。Pixel 已移除且唯一 K70E ADB 已稳定，但当前仍是 `b9b1d867…` 拒绝环境。必须先按文档 58 恢复并由独立工具写出 `POSTBOOT_VERIFIED.json`，再执行新 stock zero-key capture 和一次 controlled attempt，并得到全链 raw Provisioning Info 零 `NOT_APPROVED` 才能终验。恢复固定八步不含 TEE/boot/顶层 vbmeta/init_boot；whole `super` 是唯一跨槽例外，任何失败停 Fastboot且不自动重试。
