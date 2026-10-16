# Redmi 11T Pro：详细 Keybox 复现教程（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里保留目标检查、输入哈希门禁、临时提权、引导链部署、只读调用、解析验证与回滚的完整步骤。序列号、主机绝对路径和个人标识已替换为变量。

---

## 原始记录段 1 / Source section 1: 01_Keybox傻瓜式复现教程.md

# Keybox 傻瓜式复现教程

## 1. 先读结论

本教程只适用于已授权的 Redmi Note 11T Pro / `xaga` CTF 设备，并且只对已实验的 `V13.0.5.0.SLOMIXM` 与精确内核有效。这不是通用固件，不要跳过哈希、槽位和序列号检查。

已完成的正式结果在：

`03_提取结果/Keybox实机成功提取_20260826_2139/`

## 2. 必须条件

1. 目标序列号必须是 `<DEVICE_SERIAL>`。
2. `ro.product.vendor.device` 必须是 `xaga`。
3. `ro.boot.slot_suffix` 必须是 `_b`。
4. `uname -r` 必须是 `5.10.66-android12-9-00001-g41ff3fa8fff9-ab8171928`。
5. 需要一次授权的临时 root 会话，且要有足够 capability 执行 `mount`/`dd`/`stop`。
6. 必须保留 a 槽原厂，只修改 b 槽。
7. 主机需要 `adb`、Python 3、OpenSSL、AArch64 反汇编工具。

## 3. 步骤一：确认只操作目标机

```bash
adb devices -l
adb -s <DEVICE_SERIAL> shell getprop ro.serialno
$SERIAL -s <DEVICE_SERIAL> shell getprop ro.product.vendor.device
adb -s <DEVICE_SERIAL> shell getprop ro.boot.slot_suffix
adb -s <DEVICE_SERIAL> shell uname -r
```

任何一项不匹配都立即停止。不要用不带 `-s` 的 ADB 命令。

## 4. 步骤二：检查输入与成品补丁

从项目根目录执行：

```bash
cd '<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_第一阶段_Keybox'
shasum -a 256 '02_脚本与补丁/只读Keybox补丁_20260826/'*
```

必须在 `补丁清单.json` 中看到：

- 原厂 TA SHA256 `0fafcb889813891dca764f36627691a839345105d8dcbb7fbdc82d9178f0e52f`
- 补丁 TA SHA256 `97e1c1b34d8da376df44f820fc32cdff6e9fac312a0d603d99116aebd572b2f5`
- 只改 Keybox TA `0x109c`：`e008417a` -> `1f2003d5`
- 只改 `uTsecManager` `0xf218`：`20220035` -> `1f2003d5`

如需从原始输入重建，使用：

```bash
python3 '02_脚本与补丁/构建_Keybox只读提取补丁.py' \
  --tee '<精确原厂tee.img>' \
  --secmanager '<从同tee.img解出的070_uTsecManager>' \
  --keybox-ta '01_设备输入/原厂TA全集_实机_20260826/ta/d91f322ad5a441d5955110eda3272fc0.ta' \
  --output-dir '<新输出目录>'
```

构建器自带精确 SHA256、原始指令、大小、AES-CTR 回读和 L4Re 模块 MD5 门禁。

## 5. 步骤三：得到完整引导镜像

实验已生成：

- `02_脚本与补丁/实机精确Fenrir_20260826/lk_b_实机精确_fenrir_完整8MiB.img`
- `02_脚本与补丁/实机精确Fenrir_20260826/tee_b_Keybox只读旁路_完整5MiB.img`

它们不是可以跨版本使用的通用固件。`lk_b` 用 Fenrir 取消后续镜像安全检查，`tee_b` 内含只忽略 TA 验签错误返回的 `uTsecManager` 补丁。

## 6. 步骤四：在临时 root 会话内部署 b 槽

将两个完整镜像和部署脚本放到设备：

```bash
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/实机精确Fenrir_20260826/lk_b_实机精确_fenrir_完整8MiB.img' /data/local/tmp/xaga_lk_b_fenrir_full.img
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/实机精确Fenrir_20260826/tee_b_Keybox只读旁路_完整5MiB.img' /data/local/tmp/xaga_tee_b_keybox_full.img
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/设备端_部署_Keybox只读引导链.sh' /data/local/tmp/
```

然后在已成功的 root + capability 会话内执行：

```sh
sh /data/local/tmp/设备端_部署_Keybox只读引导链.sh
```

成功标志是 `XAGA_STAGE1_DEPLOY_VERIFIED`。脚本会：

1. 检查序列号、产品、内核、槽位、分区大小和镜像哈希。
2. 检查 a/b 四个相关分区都是预期原厂哈希。
3. 备份 `lk_b` 和 `tee_b`。
4. 仅写 `lk_b` 和 `tee_b`。
5. 立即全分区回读 SHA256，并确认 a 槽没变。
6. 中途失败会自动回写备份。

## 7. 步骤五：重启到补丁引导链

退出临时 root 会话并正常重启。启动后再次确认：

```bash
adb -s <DEVICE_SERIAL> wait-for-device
adb -s <DEVICE_SERIAL> shell getprop ro.boot.slot_suffix
adb -s <DEVICE_SERIAL> shell getenforce
```

实验成功路线中，补丁 TEE 允许加载重加密但签名不再匹配的 Keybox TA。

## 8. 步骤六：上传只读 TA、客户端和库

```bash
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/只读Keybox补丁_20260826/d91f322ad5a441d5955110eda3272fc0_caller_gate_nop.ta' /data/local/tmp/d91f322ad5a441d5955110eda3272fc0_patched.ta
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/Keybox读取客户端/xaga_keybox_readonly' /data/local/tmp/xaga_keybox_readonly
adb -s <DEVICE_SERIAL> push '01_设备输入/TEE客户端库_实机_20260826/libTEECommon_64.so' /data/local/tmp/libTEECommon_xaga.so
adb -s <DEVICE_SERIAL> push '02_脚本与补丁/设备端_覆盖TA并提取Keybox.sh' /data/local/tmp/
adb -s <DEVICE_SERIAL> shell chmod 0755 /data/local/tmp/xaga_keybox_readonly /data/local/tmp/设备端_覆盖TA并提取Keybox.sh
```

## 9. 步骤七：提取

再开一次授权的 root + capability 会话，执行：

```sh
sh /data/local/tmp/设备端_覆盖TA并提取Keybox.sh
```

成功标志：

```text
InvokeCommand=0x00000000 origin=0x00000004
TA status=0x00000000 payload=8578 descriptor=168 saved=yes
XAGA_KEYBOX_EXTRACTION_VERIFIED
```

脚本会停止 `vendor.keymint-beanpod`，把补丁 TA bind mount 到原厂 TA 路径，然后只调用原有命令 `0x64`。不会放开写 Keybox 的命令 `0`/`0x65`/`0x66`。

拉回结果：

```bash
adb -s <DEVICE_SERIAL> pull /data/local/tmp/xaga_keybox_extraction_result '<新的本地结果目录>'
```

## 10. 步骤八：解析和密码学验证

```bash
python3 '02_脚本与补丁/解析并验证_Keybox.py' \
  '<结果>/客户端输出/keybox_原始载荷.bin' \
  '<结果>/客户端输出/keybox_描述区.bin' \
  '<结果>/解析验证结果'
```

验收必须同时满足：

- 描述区 magic 为 `0x12345678`。
- 描述区记录长度等于 8578。
- 描述区末尾 MD5 等于载荷 MD5。
- EC 私钥导出的 SPKI 与 EC 叶证书 SPKI 完全相同。
- RSA 私钥导出的 SPKI 与 RSA 叶证书 SPKI 完全相同。
- 两条叶 -> 中间 -> 根证书链都通过 `openssl verify`。

## 11. 回滚

使用 `02_脚本与补丁/设备端_回滚_Keybox引导链.sh`，并使用部署时的写前完整备份。回滚后必须对 `lk_b` 和 `tee_b` 做完整 SHA256 回读，不能只信任 `dd` 返回码。


---

## 原始记录段 2 / Source section 2: 04_Keybox结果与验证报告.md

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

## 原始记录段 3 / Source section 3: 05_Keybox恢复与安全边界.md

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
