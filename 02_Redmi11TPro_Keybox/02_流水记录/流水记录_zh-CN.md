# Redmi 11T Pro：全量研究流水账（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 本文件保留从基线采集、失败样本、临时提权、TA/TEE 静态修改、引导链部署、实机成功提取、解析验收到回滚的原始顺序和每个失败分支。

---

## 原始记录段 1 / Source section 1: 02_Keybox全流程流水账.md

# Keybox 全流程流水账

## 1. 任务定义

目标是在仅操作序列号 `<DEVICE_SERIAL>` 的 xaga CTF 设备的前提下，读出 KeyMint/TEE 内部 Keybox，并证明所得不是随机字节，而是含 EC 和 RSA 私钥及可验证证书链的结构化数据。

## 2. 基线阶段

1. 采集设备型号、MIUI 版本、Android 版本、内核、槽位和分区映射。
2. 采集并保存原厂 `lk_a`/`lk_b`、`tee_a`/`tee_b`、TA 集合和 TEE 客户端库。
3. 使用原厂引导链调用同一 Keybox 客户端，得到失败基线：`03_提取结果/原厂Keybox调用失败基线_20260826_2121/`。
4. 这个对照排除了“客户端本来就能读”的可能。

## 3. 临时提权路线

实机使用 `bad_io_uring` 竞态 ELF，然后通过 preload 代码利用泄漏的 `anon_pipe_buf_ops` 内核地址归一化到 `init_task`。精确符号：

- `anon_pipe_buf_ops = 0xffffffc012353ba8`
- `init_task = 0xffffffc0129dbe40`
- 差值 `0x688298`

这个阶段的实际难点不只是 UID 0，还包括 Linux capability 和 SELinux 域。

### 保留的失败路线

1. **正向遍历失败**：遍历 task 的假设与实机链表布局不符，样本为 `libxaga_正向遍历失败样本_9684f278.so`。
2. **尾链未命中**：候选 task 选择错误，样本为 `libxaga_尾链未命中失败样本_39fde7aa.so`。
3. **UID 0 但无 capability**：`id` 显示 root 不代表能 `mount`/`dd`，样本为 `libxaga_uid0但无能力集失败样本_98136f44.so`。
4. **kernel 域拒绝 exec**：直接使用错误 SELinux 域会造成执行限制，样本为 `libxaga_命中任务但kernel域拒绝exec样本_ba7cff8e.so`。
5. **SELinux 前置校验过严**：脚本把已经 Permissive 的状态当成失败，样本为 `libxaga_selinux校验过严失败样本_704d9bc1.so`。

最终路线在保持 shell 可执行的同时得到 root、必要 capability 和 Permissive，正式日志保存在 `04_日志/正式提权采集_20260826_204626/`。

## 4. TEE 和 Keybox TA 分析

1. 识别 Keybox TA UUID：`d91f322ad5a441d5955110eda3272fc0`。
2. 定位只读命令 `0x64`。
3. 发现命令号和 `paramTypes=0x662` 都是独立门禁，不需要修改。
4. 失败原因是 TA 还检查 `caller_mode==1`。
5. 在明文 ELF `0x40109c` 把 `ccmp w7,#1,#0,eq` 改为 NOP，只取消调用者模式限制。
6. 编辑后 TA 原签名失效，单独 bind mount 补丁 TA 不足以加载。
7. 在 TEE 内 `uTsecManager` `0x40f218` 将“验签错误则分支离开”改为 NOP，使其继续原有 AES-CTR 解包流程。
8. 重压缩 L4Re 模块，更新 stored/unpacked 大小和 MD5，并做二次解压回读。

## 5. 引导链部署

1. 实机只读备份 `lk_a`/`lk_b` 和 `tee_a`/`tee_b`。
2. 用精确 xaga LK 生成 Fenrir 补丁，取消 bl2_ext 对后续镜像的安全策略限制。
3. 把 Fenrir LK 封装为 8 MiB `lk_b` 完整分区镜像。
4. 把补丁 TEE 封装为 5 MiB `tee_b` 完整分区镜像。
5. 部署前确认 a/b 均是原厂，备份 b 槽，然后只写 b 槽。
6. 写入后完整回读，并再次确认 a 槽未变。
7. 实机成功记录时间为 2026-08-26 21:36，保存于 `03_提取结果/引导链部署记录_20260826_2136/`。

## 6. 实机提取

2026-08-26 21:39:22 CST：

1. root 会话标识：`uid=0(root)`，SELinux `Permissive`。
2. 原厂 TA SHA256：`0fafcb88...e52f`。
3. 停止 `vendor.keymint-beanpod`。
4. bind mount 补丁 TA，可见 TA SHA256 变为 `97e1c1b3...b2f5`。
5. TEE context 初始化成功：`0x00000000`。
6. session 打开成功：`0x00000000`，origin `0x00000004`。
7. `InvokeCommand(0x64)` 成功：`0x00000000`。
8. TA 内部状态：`0x00000000`。
9. 返回载荷 8578 字节，描述区 168 字节。
10. 结果目录中 `提取错误日志.txt` 为空，客户端返回码为 0。

## 7. 解析与验收

1. 描述区 magic `0x12345678`。
2. 载荷 SHA256 `fc7d68b66302469e5baad6761a692302ade54c4c161613b2b8f88c452a8df498`。
3. 描述区 MD5 和载荷 MD5 都为 `635c04aa3590d2cbe7ce3dfa79c3e3c7`。
4. 条目 1 是 EC，私钥 DER 121 字节，3 张证书。
5. 条目 2 是 RSA，私钥 DER 1769 字节，3 张证书。
6. 两个私钥导出公钥均与对应叶证书公钥逐字节相同。
7. 两条证书链均通过 OpenSSL 验证。

## 8. 为什么不能省略某一步

- 只有 root，没有 capability：不能稳定写分区或 bind mount。
- 只补 Keybox TA：签名失效，`uTsecManager` 拒绝加载。
- 只补 TEE：原 Keybox TA 仍拒绝非预期 caller mode。
- 只改 `caller_mode`而保留命令号/参数类型门：才能把行为限定为原有只读命令 `0x64`。
- 只看到一段二进制：不能证明是有效 Keybox；必须同时完成描述区 MD5、私钥/叶证书公钥匹配和证书链验证。


---

## 原始记录段 2 / Source section 2: 03_Keybox漏洞原理报告.md

# Keybox 漏洞原理报告

## 1. 系统模型

xaga 的 Keybox 不是 Android 文件系统中一个普通 XML。读取路径横跨：

1. Android/Linux 客户端。
2. TEE 客户端库 `libTEECommon_64.so`。
3. MediaTek TEE/GenieZone 通信通道。
4. `uTsecManager` 安全管理模块。
5. UUID `d91f322ad5a441d5955110eda3272fc0` 的 Keybox TA。
6. TA 内已存在的 Keybox 读取命令 `0x64`。

因此不能用“找文件然后 `cat`”的思路理解。

## 2. 引导链突破原理

Fenrir 针对 MediaTek 引导链的逻辑缺陷：当 seccfg 设为 unlocked 时，Preloader 对 `bl2_ext` 的验证可被跳过，而 `bl2_ext` 又负责验证 TEE、GZ、LK 等后续组件。如果修改 `bl2_ext` 的 `sec_get_vfy_policy()` 路径，就能使后续修改镜像被加载。

本项目对 xaga 使用精确 LK 图像中的指令特征做静态补丁，不依赖泛化函数地址。这一层的作用是让补丁 TEE 能启动，它本身不直接返回 Keybox。

## 3. TA 容器、加密与验签

xaga TA 由两部分组成：

- 前半部分是 AES-CTR 加密的 ELF 载荷。
- 尾部包含被 `uTsecManager` 内嵌 RSA 公钥保护的对称材料及签名/封装信息。

构建器从精确 `uTsecManager` 中解出 RSA 参数，定位 TA trailer，解封 AES-128 key/IV，解密 ELF，修改 4 字节指令，再用原 key/IV 重加密。

由于不拥有原 TA 签名私钥，修改后的 TA 签名必然不匹配。所以还需要在 `uTsecManager` 中让验签非零结果不再跳到错误路径，但保留后续容器解析和 AES-CTR 解密。

## 4. Keybox TA 调用者门

Keybox TA 已经实现了读取命令 `0x64`，但命令分发路径上存在多层检查：

1. command ID 必须是 `0x64`。
2. TEE paramTypes 必须是 `0x662`。
3. caller mode 必须是 TA 预期的特殊模式 `1`。

Linux 上普通 TEE 客户端能满足前两项，但不满足第三项。补丁在明文 ELF 偏移 `0x109c`、虚拟地址 `0x40109c`：

- 原指令：`e0 08 41 7a` (`ccmp w7, #1, #0, eq`)
- 补丁：`1f 20 03 d5` (`nop`)

该补丁不修改命令 ID 和参数类型检查，也没有修改 Keybox 写入命令。这是“只读提取补丁”的安全边界。

## 5. `uTsecManager` 补丁

在精确原始 `uTsecManager` 文件偏移 `0xf218`、虚拟地址 `0x40f218`：

- 原指令：`20 22 00 35` (`cbnz w0, verification_error`)
- 补丁：`1f 20 03 d5` (`nop`)

它的语义是忽略 `verify_ta` 的非零返回，但不跳过 TA 文件格式解析、对称材料解封和 AES-CTR 解密。

`uTsecManager` 位于 TEE 的 L4Re bootstrap 模块表中，存储形式为 gzip。重构时需保留 gzip filename/mtime，更新 descriptor 中的 stored size、unpacked size、stored MD5 和 unpacked MD5，且不能超过固定模块槽容量。

## 6. 运行时覆盖原理

补丁引导链启动后，Linux root 会话：

1. 停止 `vendor.keymint-beanpod`，避免原 TA 会话继续占用。
2. 使用 bind mount 把 `/data/local/tmp` 的补丁 TA 覆盖到 `/vendor/thh/ta/d91f...ta`。
3. 不改写只读 vendor 分区内的原文件。
4. 用精确实机 `libTEECommon_64.so` 打开 TA session。
5. 调用 `0x64`，保存 168 字节 descriptor 和 8578 字节 payload。

bind mount 是临时的，重启后原 vendor TA 路径自动恢复。

## 7. Keybox 载荷格式

描述区长 168 字节，前 152 字节按小端解析为 38 个 `uint32_t`，末尾 16 字节是 payload MD5。关键字段：

- word 0：magic `0x12345678`。
- word 1：实机值 `0xaf015838`，语义未完全确定，不作推测。
- word 2：payload 长度 8578。
- word 3..7：保留且必须为 0。
- 后续两组每组 15 个 word，描述私钥偏移/大小、证书数量、最多 4 张证书的偏移/大小和保留字段。

payload 内每个私钥和证书之前都有 4 字节长度前缀。解析器同时检查 descriptor 和 payload 前缀，避免只信任一处偏移。

## 8. 为什么结果可信

成功不是以“出现了 PEM 文件”定义，而是以多重不变式定义：

1. descriptor magic、长度、保留字段和 MD5 全部正确。
2. 每个条目的长度前缀与 descriptor 一致。
3. OpenSSL 能严格解析两个私钥 DER。
4. 私钥导出的公钥 SPKI 与对应叶证书的 SPKI 逐字节相同。
5. 叶证书能通过对应中间证书和根证书验证。

这些条件同时成立的情况下，随机或错位二进制几乎不可能伪装为该结果。


---

## 原始记录段 3 / Source section 3: 04_Keybox结果与验证报告.md

# Keybox 结果与验证报告

## 1. 结论

Keybox 第一阶段已在序列号 `<DEVICE_SERIAL>` 的 Redmi Note 11T Pro / xaga 实机上成功。读取命令、TA 状态和客户端返回码均为 0，得到 8578 字节载荷和 168 字节描述区。

主结果：`03_提取结果/Keybox实机成功提取_20260826_2139/`

## 2. 调用结果

```text
InitializeContext=0x00000000
OpenSession=0x00000000 origin=0x00000004
InvokeCommand=0x00000000 origin=0x00000004
TA status=0x00000000 payload=8578 descriptor=168 saved=yes
```

设备端流程日志中还有：

- `client_rc=0`
- `XAGA_KEYBOX_EXTRACTION_VERIFIED`
- 原厂 TA 覆盖前 SHA256 `0fafcb88...e52f`
- bind mount 后 SHA256 `97e1c1b3...b2f5`
- `提取错误日志.txt` 为 0 字节

## 3. 载荷完整性

- payload 长度：8578
- payload SHA256：`fc7d68b66302469e5baad6761a692302ade54c4c161613b2b8f88c452a8df498`
- payload MD5：`635c04aa3590d2cbe7ce3dfa79c3e3c7`
- descriptor MD5：`635c04aa3590d2cbe7ce3dfa79c3e3c7`
- descriptor magic：`0x12345678`
- MD5 匹配：是

## 4. EC 条目

- 私钥 DER 大小：121 字节
- 私钥 DER SHA256：`88ab172c180aaee97097a980fff4111ae343282e488e3fb0d3260bdf94bb4dc1`
- 私钥导出 SPKI SHA256：`e5eb3f8b35531f5e413226beebc9a8af0684b85a0244f2fba760b4b4e0f51f28`
- 叶证书 SPKI SHA256：同上
- 私钥与叶证书匹配：是
- 证书数：3
- OpenSSL 链验证：`OK`

EC 叶证书：

- Subject：`title=TEE/serialNumber=bd99e81eca9b2bb7ab0b801f66f12743`
- Issuer：`title=TEE/serialNumber=d8bfe951c840a04d5170b5ade06d3a54`
- Not Before：2022-01-25 23:33:27 GMT
- Not After：2032-01-23 23:33:27 GMT

## 5. RSA 条目

- 私钥 DER 大小：1769 字节
- 私钥 DER SHA256：`330ae41f468bdd67068ae557d85c6eb4377829066a700c571559a4945c6fa394`
- 私钥导出 SPKI SHA256：`ef8a561334b0a56e2589078f6c497577a43d4a672b1fbb4895fd8bee8b2cbd3f`
- 叶证书 SPKI SHA256：同上
- 私钥与叶证书匹配：是
- 证书数：3
- OpenSSL 链验证：`OK`

RSA 叶证书：

- Subject：`title=TEE/serialNumber=bd99e81eca9b2bb7ab0b801f66f12743`
- Issuer：`title=TEE/serialNumber=d8bfe951c840a04d5170b5ade06d3a54`
- Not Before：2022-01-25 23:33:26 GMT
- Not After：2032-01-23 23:33:26 GMT

## 6. 根证书

EC 和 RSA 链最终使用同一根证书：

- Subject/Issuer：`serialNumber=f92009e853b6b045`
- 自签名：是
- Not Before：2021-11-17 23:10:42 GMT
- Not After：2036-11-13 23:10:42 GMT
- DER SHA256：`ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a`

## 7. 有效期解读

对 Keybox 的实际使用上限应首先看叶证书，而不是根证书。本次 EC/RSA 叶证书都到 2032-01-23 到期；根证书到 2036-11-13。因此这不是“只有十几天”的 RKP 短期证书，而是一套更长期的设备 Keybox 凭据。

## 8. 证据路径

- 原始二进制：`...客户端输出/keybox_原始载荷.bin`
- 描述区：`...客户端输出/keybox_描述区.bin`
- 总清单：`...解析验证结果/解析与验证总清单.json`
- EC 结果：`...解析验证结果/条目1_EC/`
- RSA 结果：`...解析验证结果/条目2_RSA/`
- 现场日志：`...提取流程日志.txt`、`...调用前_logcat.txt`、`...调用后_logcat.txt`、`...调用前_dmesg.txt`、`...调用后_dmesg.txt`

## 9. 最终判定

本阶段不是“看起来提取到了”，而是已完成以下闭环：原厂失败对照 -> 最小只读补丁 -> 实机命令成功 -> 完整性检查 -> 两种私钥可解析 -> 私钥/叶证书公钥匹配 -> 两条证书链通过。


---

## 原始记录段 4 / Source section 4: 05_Keybox恢复与安全边界.md

# Keybox 恢复与安全边界

## 1. 版本边界

所有补丁都锁定到 xaga `V13.0.5.0.SLOMIXM` 的精确二进制。以下任一变化都需重新采集和反汇编：

- OTA 升级或降级。
- 内核 build 改变。
- `lk`/`tee`/Keybox TA/`uTsecManager` 哈希改变。
- 分区布局或活动槽改变。
- 使用另一台同型号设备。

同型号不等于同二进制。构建器和部署脚本拒绝哈希不匹配是必要安全措施。

## 2. 槽位边界

- 实验只写 `_b` 槽。
- `lk_a` 和 `tee_a` 始终保持原厂。
- 写 b 槽之前要同时验证 a/b 都是预期原厂哈希。
- 写入后要再验证 a 槽未变。
- 如果设备自动切槽，不要盲目重复写入，先读 `ro.boot.slot_suffix`。

## 3. 回滚材料

两组可用备份：

1. `01_设备输入/实机LK双槽只读备份_20260826_2126/`
2. `03_提取结果/引导链部署记录_20260826_2136/lk_b_写前完整备份.img`、`tee_b_写前完整备份.img`

回滚脚本：`02_脚本与补丁/设备端_回滚_Keybox引导链.sh`。

回滚后必须检查整个分区 SHA256，不要以“可以开机”代替一致性验证。

## 4. 运行时 TA 覆盖的恢复

Keybox TA 使用 bind mount 覆盖，未改写 vendor 文件。重启会自动清除该 mount。不重启时可在 root 会话内对精确路径 `umount`，然后重启 `vendor.keymint-beanpod`。

## 5. 私钥安全

- `私钥_*.bin` 和 `私钥_*.pem` 是敏感长期凭据。
- 不要上传公开仓库、聊天附件或第三方网盘。
- 不要在普通日志中打印 PEM 内容。
- 需要对比时优先使用 SHA256 或公钥 SPKI，不复制私钥。
- 备份应加密，并记录访问者和用途。

## 6. 禁止事项

1. 不要对不同序列号设备执行脚本。
2. 不要删除脚本中的哈希和分区大小检查。
3. 不要把失败样本 `.so` 当成最终 preload。
4. 不要同时修改 a/b 两个槽。
5. 不要把补丁 Keybox TA 永久写进 vendor 文件系统。
6. 不要宣称补丁“通杀所有 xaga 版本”。
7. 不要仅凭客户端返回码就宣称成功，必须完成私钥公钥匹配和证书链验证。
