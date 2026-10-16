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
