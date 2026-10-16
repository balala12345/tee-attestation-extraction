# Redmi 11T Pro：Keybox 原理与补丁边界（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里保留 TEE 调用链、Fenrir 引导链、TA 加密/验签、caller mode 门、uTsecManager 旁路、载荷格式和多重验证不变式。

---

## 原始记录段 1 / Source section 1: 03_Keybox漏洞原理报告.md

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

## 原始记录段 2 / Source section 2: 05_Keybox恢复与安全边界.md

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
