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
