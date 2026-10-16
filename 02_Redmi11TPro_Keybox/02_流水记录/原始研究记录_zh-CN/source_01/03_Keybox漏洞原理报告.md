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
