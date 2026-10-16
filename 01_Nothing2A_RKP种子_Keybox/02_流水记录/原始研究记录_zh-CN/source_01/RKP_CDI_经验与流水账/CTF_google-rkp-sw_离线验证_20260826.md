# CTF `google-rkp-sw` 离线验证记录（2026-08-26）

## 结论

- 已在授权 CTF 手机 Nothing A142 / Pacman 上调用 KeyMint TA 内部
  `rkp_bcc_km` KDF，并导出稳定的 32 字节设备级派生材料。
- 两次以上独立 KeyMint 会话结果一致；最终 KDF 返回值为 `0`，输出非零。
- 已使用 `google-rkp-sw` 的 Ed25519 路径离线派生身份、生成
  AuthenticatedRequest v1 / CSR payload v3，并通过仓库自带 `verify` 验证。
- 已用仓库的 `build_keybox_xml()` 生成本地 CTF CA 签发的 keybox，完成私钥—叶证书
  公钥匹配和证书链签名验证。
- 未向 Google 生产 `signCertificates` 接口提交。本记录不能作为 Google 生产签发成功的
  证据。

## 目标与环境

- ADB serial：`<DEVICE_SERIAL>`
- Brand / model / device：Nothing / A142 / Pacman
- Build fingerprint：
  `Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`
- KeyMint TA UUID：`0706000000000000000000000000004d`
- 原始 TA SHA-256：
  `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`
- 最终补丁 TA SHA-256：
  `cb7a9ca7d7a05afc98e62fe34bfbbc9471fb53ac34f1f8ea8cf711be6c04bf65`

## 提取方式

最终补丁在已验证稳定的生产 RKP keygen 成功路径挂钩，随后：

1. 在 TA 栈上调用内部 KDF `0x22770`；
2. 参数使用生产 CSR 路径相同的标签 `rkp_bcc_km`、长度 10、输出长度 32、模式 1；
3. KDF 完成后才把 32 字节结果复制到 direct-output 共享缓冲 `+0x400`；
4. 把 KDF 返回码写入 `+0x420`，把指针完整性标记 `0x1234` 写入 `+0x424`；
5. 恢复原 keygen 清理路径，不修改声明的 `private_len`。

最终运行目录：

`04_结果/outputs/ctf_bcc_kdf_keygenleak_20260826_14_final`

验证结果：

- KDF status：`0x0`
- pointer marker：`0x1234`
- 派生材料 SHA-256：
  `e0e2617b3156d12a0b7108b71340484c3e4ae965ae686d7360c8032f2d82a7c3`
- 与此前独立会话结果一致：是
- KeyMint 服务运行状态恢复：是

## `google-rkp-sw` 验证

仓库固定版本：

`8a74e55e6e900c04c84e12380e467cefa1a27cc5`

本地修改：

- 增加 `--seed-file`，避免把长期材料放进进程参数；
- `info` 不再显示种子内容；
- 配置中的 `version` 按整数解析；
- `ctf_artifacts/` 整体加入 `.gitignore`。

离线 CSR：

- AuthenticatedRequest version：1
- CSR payload version：3
- certificate type：`keymint`
- DICE curve：Ed25519
- KeysToSign：1 个 P-256 公钥
- CSR 长度：725 字节
- CSR SHA-256：
  `759e4846f43a514dc3e1ed599d0e4c7b4ce8d72bbd938cbe9fdb6e821dd8a44e`
- 外层 CDI 签名：有效
- 退化 DICE entry 自签名：有效
- 仓库 `verify`：`Signature: VALID`

### 已实际执行到哪一步

不是只运行了 `info`。本次已经实际执行以下链路：

1. 把 TA 导出的 32 字节材料作为 `google-rkp-sw` 的 Ed25519 seed；
2. 用仓库的 `DeviceKeys` 派生 CDI/DICE 签名公钥；
3. 生成一把临时 P-256 待签密钥；
4. 构造 AuthenticatedRequest v1 / CSR payload v3；
5. 验证外层 SignedData 签名；
6. 验证退化 DICE entry 自签名；
7. 使用仓库自带 `rkp_sw.py verify` 重新解析并验证 CSR，结果为 `VALID`；
8. 使用仓库的 `build_keybox_xml()` 和本地 CTF CA 生成测试 keybox；
9. 验证 keybox 私钥与叶证书公钥匹配、叶证书签名有效。

因此已经证明：这 32 字节材料可以被该仓库作为软件侧身份密钥使用，并可以完成全部本地
密码学流程。尚未证明的是 Google 生产 RKP 服务是否认可仓库构造的 DICE 链和本机资料。

### 32 字节是否就是全部“身份”

32 字节不是普通的设备编号或可猜测 metadata，而是 256 bit 高熵私密种子。它在安全意义上
类似一把私钥的根材料：数据很短，但穷举不可行；真正的风险来自被提取后可以无损复制。

RKP 请求的完整身份还包括：

- 由种子派生的公开密钥和签名；
- UDS certificates（若平台提供）；
- 完整 DICE/BCC 证书链；
- DeviceInfo 和固件/启动状态测量；
- 服务端实时 challenge；
- 本次请求签发的 P-256 公钥。

其中只有私钥/CDI seed 必须保密；证书链、公开密钥、DeviceInfo 等大部分材料本来就是可公开
传输的。因此在特定实现上，“一份 32 字节私密材料 + 可复制的公开链和设备资料”确实可能
足以在软件中完成新的 challenge 签名，这也是永久设备身份材料泄露的严重性。

但不能仅凭 32 字节就断言一定能冒充成功：

- 服务端必须已经信任或登记与该种子对应的 UDS/CDI 公钥；
- 提交的 DICE 链必须与服务端认可的根和签名关系一致；
- DeviceInfo、协议版本、证书类型和服务端策略必须匹配；
- 非退化 DICE 链仍需要原设备公开链，叶 seed 不能伪造上游 UDS/bootloader 的签名；
- challenge 防止直接重放旧 CSR，但持有叶私钥者可以签新 challenge；
- 服务端仍可按设备状态、版本、撤销名单和异常行为拒绝签发。

本机已知成功的历史路径是 Android 13/DeviceInfo v2 风格的旧 RKP 请求，而
`google-rkp-sw` 当前实现构造的是 CSR payload v3。离线签名有效不等于服务端会接受这次
跨协议构造。

### 测试结论分级

| 项目 | 结果 |
|---|---|
| TA 内部 `rkp_bcc_km` KDF | 成功，返回 0 |
| 跨 KeyMint 会话稳定性 | 成功，结果一致 |
| `google-rkp-sw` Ed25519 身份派生 | 成功 |
| v3 CSR 构造与签名验证 | 成功，`VALID` |
| 本地 CTF keybox | 成功，链与私钥验证通过 |
| Google 生产证书签发 | 未执行、未证明 |

## “能否完全脱机”

不能把“协议客户端脱离 TEE”理解为“Google 证书可脱机签发”。

- 可脱机：从 CDI/派生材料生成 Ed25519 身份、DICE 链、待签 P-256 密钥、CSR、以及本地
  测试 CA 签发的 keybox。
- 不可脱机：获得 Google RKP 生产证书链。生产签发仍需服务器 challenge，并向
  `signCertificates` 提交 CSR，由服务端验证设备 DICE 身份和策略。
- 仓库走 CSR v3 时最终 AuthenticatedRequest 本身不包含旧协议的 ProtectedData；代码中仍
  构建的 EEK/ProtectedData 是未被最终 CSR 使用的冗余路径。AOSP v3 CDDL 的顶层结构是
  `[version, UdsCerts, DiceCertChain, SignedData]`。

## 产物与敏感性

所有 `ctf_artifacts` 文件权限均为 `0600`，且整个目录已被 Git 忽略。

- `ctf_seed.bin`：长期设备派生材料，敏感，不应分享或提交版本库。
- `ctf_attestation_ec_private.pem`：本次离线 CSR 对应的临时 P-256 私钥，敏感。
- `ctf_csr_v3.cbor`：离线 CSR。
- `ctf_offline_csr_summary.json`：不含私钥明文的验证摘要。
- `ctf_local_keybox.xml`：仅本地 CTF CA 签发，含私钥，敏感；不是 Google keybox。
- `ctf_local_keybox_summary.json`：本地证书链验证摘要。

## 边界说明

本次 direct TA 调用依赖当前 CTF 机的 ADB、`su`/Magisk 和可加载修改 trustlet 的实验环境，
不能据此推出普通锁定零售机“无需 root 即可提取”。市场聊天里所谓“正常解锁 BL 即可”或
“不解锁也可以”需要另一条 boot-chain/TEE 装载或漏洞证据，当前实验没有证明这些说法。
