# Redmi K70E：详细 RKP/CDI seed 复现与验收教程（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里完整保留旧路线的失效门禁、stock MiTEE 日志路线、同轮 CDI leaf 身份捕获、`google-rkp-sw` 构造、Provisioning Info 检查、离线验收和恢复步骤。旧的 `NOT_APPROVED` 结果只用于复盘，不能当成通过结果。

---

## 原始记录段 1 / Source section 1: 46_K70E_CTF_傻瓜式复现教程_20260905.md

# K70E CTF 傻瓜式复现教程

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **后续覆盖（2026-09-06 20:00）：**本文的 patched-route 网络命令不得重跑，其旧证书包含 `NOT_APPROVED`。现有干净候选的只读验收/交付教程是文档 66，完整证据见 65–70。

> CURRENT ROUTE OVERRIDE：禁止执行本文任何 patched TA/TEE、Fastboot 或旧联网命令。请改用文档 54 的 stock MiTEE 日志傻瓜教程。

> **2026-09-06 失效更正：** 旧提交含赛事不接受的 `NOT_APPROVED`。第 2 节的 PASS 预期以及旧联网步骤不得执行。先读文档 52；只有 stock 测量认可门、现场 scalar 同叶门和 `network_issuance_allowed=true` 全部通过，才允许一次新签发。

> 目标：让没有参与前期逆向的人也能看懂、验证和在满足恢复条件时复现最终 `google-rkp-sw` 交付。  
> 最重要提醒：旧成品已因 `NOT_APPROVED` 被拒绝。默认只执行负向离线审计；不要为了验证而重复刷写或重新签发。

---

## 1. 先判断你要做哪一种操作

### A. 只想确认题目是否完成

只执行第 2 节。零刷写、零联网、零设备风险。

### B. 想看懂当时是怎么成功的

阅读第 3–14 节，不要复制执行命令。

### C. 必须新开一轮动态复现

不要继续照抄本文第 4–14 节的原机命令。另一台 K70E 必须改读 `50_K70E_CTF_跨设备复现与移植手册_20260905.md`，用其目标 profile 生成器、批次 builder、keygen 前严格 capture 入口、profile-driven `rkp_sw` 和关系型打包/验证器。只有 stock TA/TEE 字节级匹配的目标才会被自动分类为快速路径；其他版本会 fail-closed 为 `PORT_REQUIRED`。原机 `serial/UDS/token/latch/identity/private key/certs` 永不复用。

---

## 2. 最安全：验证现有最终提交包

工作区：

```bash
cd <PROJECT_ROOT>
```

提交包：

```bash
SUB='<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244'
```

### 2.1 运行最终离线验证器

```bash
cd "$SUB"
/usr/bin/python3 \
  <CODEX_HOME>/skills/k70e-rkp-ctf/scripts/verify_submission.py \
  "$PWD"
```

更正后的预期：退出码非 0，并看到旧包只在 Provisioning Info 门失败：

```json
{
  "status": "FAIL",
  "passed_checks": 51,
  "failed_checks": 1,
  "private_material_printed": false,
  "network_or_device_access": false
}
```

验证器不仅检查清单，还会拒绝额外文件、缺文件、symlink、错误目录/文件权限、非冻结 43 文件集合、错误 scalar/SPKI、PEM/DER 不一致、raw CBOR/DICE/request/response 语义和证书链错误。

如果出现 `FAIL`：停止。不要简单重建清单来“消掉红字”，那会给损坏内容重新背书；先从有明确来源的原始 identity/provision 目录恢复并重新做完整验证。只有内容是经过授权的已知变更、且整套固定参考也同步重新审计时，才允许生成新清单。

### 2.2 查看综合报告

```bash
jq . FINAL_VERIFICATION.json
```

必须看到：

```text
status=PASS
identity.same_run_native_leaf_match=true
google_rkp_sw_run.fetch_eek_http_status=200
google_rkp_sw_run.sign_certificates_http_status=200
google_rkp_sw_run.run_status=complete
generated_key.leaf_certificate_public_key_matches=true
certificate_chain.signature_links_valid=true
certificate_chain.root_self_signature_valid=true
```

### 2.3 独立检查私钥与叶证书公钥

在提交包目录内执行：

```bash
openssl pkey \
  -in 02_generated_key/private_key_pkcs8.pem \
  -pubout -outform DER 2>/dev/null | sha256sum

openssl x509 \
  -in 03_certificate_chain/ordered_cert_00.pem \
  -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | sha256sum
```

两行必须完全相同：

```text
a6397c1a8fd2c1e765e616c24b69c436224d429a3392c110e361fe2bcfcd481d
```

### 2.4 独立检查证书链

```bash
openssl verify \
  -attime 1788619355 \
  -CAfile 03_certificate_chain/ordered_cert_03.pem \
  -untrusted 03_certificate_chain/ordered_untrusted_intermediates.pem \
  03_certificate_chain/ordered_cert_00.pem
```

预期：

```text
03_certificate_chain/ordered_cert_00.pem: OK
```

`1788619355` 是本轮 `signCertificates` 捕获时刻 2026-09-05T14:42:35Z。使用当前时间会在短期叶证书过期后把“历史签发是否有效”错误判成失败；当前时刻有效性应另行检查，不能与历史闭环混为一谈。

### 2.5 确认三件套

```text
身份：01_identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
私钥：02_generated_key/private_key_pkcs8.pem
证书：03_certificate_chain/ordered_certificate_chain.pem
```

不要打印身份文件，不要 `xxd` 私钥，不要把它们发到公开聊天、GitHub 或网盘公共链接。

---

## 3. 从零复现前的硬性条件

以下任何一项不满足都停止：

- 设备确实是 Redmi K70E / `duchamp`。
- 设备在用户授权范围内。
- 人在手机旁，能按物理键进入 Fastboot。
- 有稳定 USB 数据线和供电，电量建议 60% 以上。
- 能识别唯一目标 serial；电脑上即使有其他 Android 设备也不会误刷。
- 当前活动槽是 `a`。
- Magisk root 可通过 `/debug_ramdisk/magisk su -c` 使用。
- 原厂 `tee_a` 恢复件大小和 SHA 完全正确。
- 已知良好 `init_boot_a` 恢复件大小和 SHA 完全正确。
- 所有 host-only 构建/审计门为 PASS。
- one-shot namespace/token/latch 是本轮新值，不与历史 COMMITTED 冲突。
- 最终 TA、init_boot 和 TEE 三个哈希彼此配套。

不要把“能进 Fastboot”理解成“可以任意刷”。本教程只涉及 `init_boot_a` 和 `tee_a`。

当前项目已经结题，原设备的这套 one-shot 也已消费。因此后文动态命令用于解释和审计成功顺序；在没有生成“新 serial/token/latch/hash/preflight 全部 PASS”的一套新批次前，禁止原样执行。仅想交付本题答案的人应停在第 2 节。

---

## 4. 固定变量和文件

```bash
set -euo pipefail
ROOT='<PROJECT_ROOT>'
SERIAL="<DEVICE_SERIAL>"

TA="$ROOT/out/k70e_cdi_leaf_identity_capture_hostonly/dba51a17-0563-11e7-93b16fa7b0071a51.cdi_leaf_identity_capture.ta"
TEE="$ROOT/out/k70e_sprovider_rsa_bypass_exactframe_hostonly/tee_a_sprovider_rsa_bypass_exactframe.img"
INIT="$ROOT/out/k70e_cdi_leaf_earlybind_initboot_hostonly/init_boot_a_cdi_leaf_identity_capture_one_shot.img"
STOCK_TEE="$ROOT/设备备份_只读_20260831_preflash/tee_a.bin"
GOOD_INIT="$ROOT/out/k70e_v6_prebind/init_boot_a_backup_20260901.img"

CAPTURE="$ROOT/<DEVICE_WORKSPACE>/02_脚本与补丁/capture_k70e_google_rkp_sw_identity_once.py"
KEYGEN="$ROOT/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_binder_keygen_client_arm64"
SUBMISSION="$ROOT/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244"
FROZEN_RKP="$SUBMISSION/04_proof/rkp_sw_used.py"
FROZEN_CONFIG="$SUBMISSION/04_proof/device_prop_k70e_duchamp.conf"
RKP_PYTHON="$ROOT/third_party/google-rkp-sw/.venv/bin/python"

fastboot_target_gate() {
  local listed product slot
  listed="$(fastboot -s "$SERIAL" devices | awk -v s="$SERIAL" '$1 == s {print $1; exit}')"
  test "$listed" = "$SERIAL"
  product="$(fastboot -s "$SERIAL" getvar product 2>&1 | awk -F': ' '$1 == "product" || $1 == "(bootloader) product" {print $2; exit}' | tr -d '\n')"
  slot="$(fastboot -s "$SERIAL" getvar current-slot 2>&1 | awk -F': ' '$1 == "current-slot" || $1 == "(bootloader) current-slot" {print $2; exit}' | tr -d '\n')"
  test "$product" = duchamp
  test "$slot" = a
}
```

后文所有写操作都在同一个启用了 `set -euo pipefail`、保留上述函数的终端中执行。`fastboot_target_gate` 任一检查失败会在写入前终止；不要删掉门函数只保留 `flash` 行。

成功批次哈希：

```text
TA=7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
TEE=3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
INIT=5b7405a136140f5f5eb77e22b1b58a5632a59fd0453298d9703dfaa44afe4517
STOCK_TEE=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
GOOD_INIT=9d5d12a72bd94d0b3ed4b5ea6b4408ab77e3f60886a6961675471c5f9052fab4
```

这些值只描述已经成功的历史批次。若重新生成任何构件，必须以新 verify.json 为准，不能一半用新文件、一半用旧哈希。

---

## 5. 主机预检

```bash
cd "$ROOT"
/usr/bin/python3 \
  '<DEVICE_WORKSPACE>/02_脚本与补丁/preflight_k70e_cdi_leaf_deployment_hostonly.py'
```

预期顶层：

```json
{"status":"PASS"}
```

它必须确认：TA digest、自洽 RSA 预期、TEE exact-frame、init_boot AVB/CPIO、early-bind fail-closed、自动恢复、capture/rkp_sw 编译全部通过。

不是 PASS 就停止，不刷任何东西。

---

## 6. 确认电脑没有选错手机

```bash
adb devices -l
```

历史现场同时有：

```text
<DEVICE_SERIAL>     Pixel 4 XL
<DEVICE_SERIAL>   duchamp
```

之后每一条命令必须带：

```text
adb -s "$SERIAL" ...
fastboot -s "$SERIAL" ...
```

先只读确认：

```bash
adb -s "$SERIAL" shell getprop ro.product.device
adb -s "$SERIAL" shell getprop sys.boot_completed
adb -s "$SERIAL" shell getprop ro.boot.slot_suffix
adb -s "$SERIAL" shell '/debug_ramdisk/magisk su -c "id"'
```

预期：

```text
duchamp
1
_a
uid=0(root) ... context=u:r:magisk:s0
```

任何不同都停止。

---

## 7. 核对当前分区与恢复件

```bash
adb -s "$SERIAL" shell \
  '/debug_ramdisk/magisk su -c "sha256sum /dev/block/by-name/tee_a /dev/block/by-name/init_boot_a"'
```

开始最终成功批次前必须是：

```text
tee_a=182277... stock
init_boot_a=9d5d12... known-good Magisk
```

把原厂 TEE 推到临时位置，先核哈希和大小，再由 root 原子移动到固定恢复路径：

```bash
adb -s "$SERIAL" push "$STOCK_TEE" \
  /data/local/tmp/k70e_cdi_leaf_tee_stock.stage.img
```

先读回 staging 文件：

```bash
adb -s "$SERIAL" shell \
  '/debug_ramdisk/magisk su -c "stat -c \"%s %a\" /data/local/tmp/k70e_cdi_leaf_tee_stock.stage.img; sha256sum /data/local/tmp/k70e_cdi_leaf_tee_stock.stage.img"'
```

必须先看到大小 `5242880` 和 SHA `1822778589...f21d`。只有完全一致才移动：

```bash
adb -s "$SERIAL" shell \
  '/debug_ramdisk/magisk su -c "set -e; mkdir -p /data/local/tmp/k70e_cdi_leaf_recovery; chmod 0700 /data/local/tmp/k70e_cdi_leaf_recovery; mv /data/local/tmp/k70e_cdi_leaf_tee_stock.stage.img /data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img; chmod 0444 /data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img; sync"'

adb -s "$SERIAL" shell \
  '/debug_ramdisk/magisk su -c "stat -c \"%s %a\" /data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img; sha256sum /data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img"'
```

最终恢复路径必须是：

```text
/data/local/tmp/k70e_cdi_leaf_recovery/tee_a.stock.img
size=5242880
mode=0444
sha256=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

不满足就停止。

---

## 8. 第一阶段：只刷 init_boot，绝不先刷 TEE

确认没有本轮 ARM/ALLOW/latch，然后：

```bash
adb -s "$SERIAL" reboot bootloader
fastboot_target_gate
fastboot -s "$SERIAL" flash init_boot_a "$INIT"
fastboot -s "$SERIAL" reboot
```

必须看到：

```text
product: duchamp
current-slot: a
Writing 'init_boot_a' OKAY
```

等待系统：

```bash
adb -s "$SERIAL" wait-for-device
adb -s "$SERIAL" shell getprop sys.boot_completed
```

只有 `1` 才继续。

本阶段验收：

```text
tee_a 仍是 stock 182277...
init_boot_a 是 candidate 5b7405...
embedded TA 是 7ea594...
tee-supplicant namespace 仍是 stock TA facdfe...
ARM/ALLOW/latch 不存在
root、KeyMint、RKP、teefs 正常
```

如果系统不能启动：只恢复 known-good `init_boot_a`；不要再刷 TEE。

---

## 9. 第二阶段：最后才创建 ALLOW 和 ARM

历史成功批次使用：

```text
state=/metadata/watchdog/k70e_cdi_leaf_identity
token=K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT
```

先确认：

- candidate init_boot 正常；
- 磁盘 TEE 仍是 stock；
- 固定恢复件正确；
- latch 不存在；
- 人仍在手机旁。

创建顺序必须是：

1. `ALLOW.tmp` 写精确 token；
2. chmod 0600；
3. 原子 rename 为 `ALLOW`；
4. 创建空 `ARM.tmp`；
5. chmod 0600；
6. 最后原子 rename 为 `ARM`；
7. `sync`。

成功批次最终：

```text
ALLOW size=39 mode=600
ARM size=0 mode=600
```

不要用 `echo` 引入额外换行；helper 要求 ALLOW 内容与 token 精确相等。

对应的可审计命令是：

```bash
adb -s "$SERIAL" shell \
  '/debug_ramdisk/magisk su -c "set -e; test ! -e /metadata/watchdog/k70e_cdi_leaf_identity/ARM; test ! -e /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW; test ! -e /metadata/watchdog/k70e_cdi_leaf_identity/once_7ea5948e; mkdir -p /metadata/watchdog/k70e_cdi_leaf_identity; chmod 0700 /metadata/watchdog/k70e_cdi_leaf_identity; printf %s K70E_CDI_LEAF_IDENTITY_7EA5948E_ONESHOT > /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW.tmp; chmod 0600 /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW.tmp; mv /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW.tmp /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW; : > /metadata/watchdog/k70e_cdi_leaf_identity/ARM.tmp; chmod 0600 /metadata/watchdog/k70e_cdi_leaf_identity/ARM.tmp; mv /metadata/watchdog/k70e_cdi_leaf_identity/ARM.tmp /metadata/watchdog/k70e_cdi_leaf_identity/ARM; sync; stat -c \"%n %s %a\" /metadata/watchdog/k70e_cdi_leaf_identity/ALLOW /metadata/watchdog/k70e_cdi_leaf_identity/ARM"'
```

输出必须是 ALLOW 39 bytes/mode 600、ARM 0 bytes/mode 600；任一不符都不刷 TEE。这个命令只描述已成功原批次；新轮次必须替换全部 namespace/token/latch 后再经审计。

---

## 10. 第三阶段：只刷 exact-frame tee_a

```bash
adb -s "$SERIAL" reboot bootloader
fastboot_target_gate
fastboot -s "$SERIAL" flash tee_a "$TEE"
fastboot -s "$SERIAL" reboot
```

必须看到 `product=duchamp`、`slot=a`、`Writing 'tee_a' OKAY`。

### 如果 ADB 能回来

等待 `boot_completed=1`，继续第 11 节。

### 如果 ADB 长时间不回来

不要继续发命令。人在设备旁时进入 Fastboot，只刷回精确 stock `tee_a`：

```bash
fastboot_target_gate
fastboot -s "$SERIAL" flash tee_a "$STOCK_TEE"
fastboot -s "$SERIAL" reboot
```

candidate init_boot 会在 stock TEE hash gate 上 fail-closed，并且不会消费 ARM；系统恢复后再分析日志。不要顺手刷其他分区。

---

## 11. 验证候选启动、bind 与自动回滚

查看：

```text
/metadata/watchdog/k70e_cdi_leaf_identity/earlybind.log
/metadata/watchdog/k70e_cdi_leaf_identity/tee_restore.log
```

必须有：

```text
preconsume_tee_hash=3990a801d6a52a77b5c3707ad396f601c4ed268820e0b971ae73aa55969043da
preconsume_tee_size=5242880
target_hash=7ea5948e5284d807139865a672f12920edc75b6ce7ddd6e6af780339dfddbb48
BIND_OK
restore_final=18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d
```

还必须确认：

```text
磁盘 tee_a=182277... stock
init_boot_a=5b7405... candidate
namespace TA=7ea594... candidate
COMMITTED marker=present
TEE_A_RESTORED_STOCK marker=present
```

获取 namespace PID 时优先使用：

```bash
adb -s "$SERIAL" shell pidof tee-supplicant
```

再由 root：

```text
nsenter -t <pid> -m -- sha256sum /vendor/mitee/ta/<UUID>.ta
```

注意：global `/vendor` 看到 stock TA 不代表私有 mount namespace 没有 bind；必须进入 tee-supplicant 的 mount namespace。

---

## 12. 一次性抓取 google-rkp-sw 身份

输出目录必须是新目录：

```bash
OUT='<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_identity_<新时间戳>'
```

运行：

```bash
test "$(sha256sum "$CAPTURE" | awk '{print $1}')" = \
  a5ad5158190a53e133b71b3f0eff8ed3a966acd3dfdd739014d4287e4679ce72
test "$(sha256sum "$KEYGEN" | awk '{print $1}')" = \
  79dc5f2bd523e5c35a77f34c46bbb345c22e7b79c245e2eee4b5bef0fbcb1cef
test "$(wc -c < "$KEYGEN" | tr -d ' ')" = 51280
/usr/bin/python3 "$CAPTURE" --output-dir "$OUT"
```

三个 `test` 任一失败都会因第 4 节的 `set -e` 在接触手机前停止。不能用工作树里“名字一样”的未钉死脚本替代；捕获器内部还会再次验证 Binder client 的大小和哈希。

脚本会自动：

1. 做严格设备门；
2. 生成随机 32-byte challenge；
3. 调 native zero-key CSR；
4. 做 native CSR 的基本 shape、逐段 ES256 签名、outer、challenge、KeysToSign=[] 和同轮 leaf 检查；
5. 紧接一次 Binder keygen；
6. 只接受 32-byte big-endian P-256 scalar；
7. 验 scalar SPKI 等于同轮 native leaf；
8. 以 0600 保存秘密；
9. 删除设备随机临时目录；
10. 不联网、不打印秘密。

这里必须区分两级验证：捕获脚本只负责“基本链签名 + outer + zero-key + same-run leaf”门；它不单独钉死固定 UDS、恰好五段 DICE、完整 claim profile 或 canonical DeviceInfo。第 13 节 `rkp_sw.py load_verified_dice_chain()` 才执行这些最终严格门。两级都通过才能提交，不能把第 12 节的轻量 PASS 夸大成完整 proper-DICE 审计。

预期顶层输出：

```text
status=PASS
identity_length=32
identity_public_spki_sha256 == same_run_native_cdi_leaf_spki_sha256
private_material_printed=false
network_submitted=false
```

失败就停止。不要重复 keygen 试图“撞到正确值”；先检查后台消费者、TA namespace、调用顺序和 leaf 是否同轮。

---

## 13. 用 google-rkp-sw 正式签发一把新密钥

设置：

```bash
ID_DIR='<第12节成功输出目录>'
PROV='<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_provision_<新时间戳>'
```

正式命令：

```bash
test "$(sha256sum "$FROZEN_RKP" | awk '{print $1}')" = \
  54e886ce80cfbdfa88e76cad075bad0e5ac949eb9ea5ec1246553bc673271401
test "$(sha256sum "$FROZEN_CONFIG" | awk '{print $1}')" = \
  b009a043e46c5e92fe6c107e5a4cc4865ce5f79f6ba83534ecafd4c9f73e31ea
test -x "$RKP_PYTHON"
PYTHONDONTWRITEBYTECODE=1 "$RKP_PYTHON" \
  "$FROZEN_RKP" provision \
  --seed-file "$ID_DIR/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin" \
  --curve p256 \
  --dice-chain-file "$ID_DIR/native_trigger_csr.cbor" \
  --config "$FROZEN_CONFIG" \
  --num-keys 1 \
  --output-dir "$PROV"
```

这里故意执行最终包中 SHA 锁定的 `rkp_sw_used.py` 和 config，不执行以后可能被修改的 live `third_party/google-rkp-sw/rkp_sw.py`。不要把 seed 改成 `--seed <hex>`；这会把秘密暴露到进程参数。不要使用旧 orange/unlocked DeviceInfo 手工覆盖同轮 source。

成功时依次看到：

```text
Fetching EEK ...
Challenge ...
Saved-request verification: OK
Submitting CSR ...
Response ...
Received 1 certificate chain(s)
Chain 0: 4 certs, key match=True
```

然后检查：

```bash
jq . "$PROV/run_summary.json"
jq . "$PROV/request_preflight_verification.json"
jq . "$PROV/chain_00/chain_summary.json"
jq . "$PROV/fetch_eek_response_http.json"
jq . "$PROV/response_http.json"
```

必须满足：

```text
run status=complete
fetch HTTP=200
sign HTTP=200
requested=1
received=1
preflight status=PASS
private/public match=true
DER fully consumed=true
chain links=true
root self-signature=true
```

如果是 HTTP 444：停止，不盲目重试。检查是不是 degenerate DICE、wrong UDS、不是 zero-key source、DeviceInfo 非 canonical、leaf/seed 不匹配。

---

## 14. 恢复手机

成功抓取身份后，软件签发只在主机进行。保存好所有证据后恢复 `init_boot_a`：

```bash
adb -s "$SERIAL" reboot bootloader
fastboot_target_gate
fastboot -s "$SERIAL" flash init_boot_a "$GOOD_INIT"
fastboot -s "$SERIAL" reboot
```

等待 `boot_completed=1`，确认：

```text
tee_a=182277... stock
init_boot_a=9d5d12... known-good
namespace TA=facdfe... stock
vendor.teefs_state=ready
root 正常
```

如果 `tee_a` 不是 stock，不要重启更多次；先调查自动恢复日志并只恢复精确 `tee_a`。

---

## 15. 最终提交怎么取

### 15.1 已被拒绝、只保留作证据的旧提交

不要重新拼包。唯一最终目录就是：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244
```

先执行第 2.1 节验证器；只有 `PASS / 51 / 0` 才从该目录取三件套：

```text
身份：<submission>/01_identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
私钥：<submission>/02_generated_key/private_key_pkcs8.pem
证书：<submission>/03_certificate_chain/ordered_certificate_chain.pem
```

同时附：

```text
FINAL_VERIFICATION.json
SHA256SUMS.txt
04_proof/ 中的请求、响应和验证报告
```

身份标量与私钥是秘密；如果比赛平台只要求哈希或特定封装，先确认格式，不要公开原始文件。

### 15.2 如果未来真的产生一个新批次

新包必须只绑定“一次成功 identity 抓取 + 紧随其后的一次成功 software provision”，禁止把不同时间、不同 seed 或不同请求的文件拼起来。源文件关系至少是：

```text
identity/  <- ID_DIR/identity/*、native_trigger_csr.cbor、
              native_trigger_challenge.bin 及同轮验证报告
key/       <- PROV/key_00/private_key_pkcs8.pem、public_key_spki.der、key_summary.json
chain/     <- PROV/chain_00/ordered_* 与 chain_summary.json
proof/     <- 同轮 request/response、HTTP capture、proper-DICE/preflight 报告、
              实际执行脚本和配置的冻结副本
```

打包时先建立新目录，目录权限固定为 `0700`、文件权限固定为 `0600`；先完成全部 raw 语义验证和证书验证，最后才写 `FINAL_VERIFICATION.json` 与不包含自身的 `SHA256SUMS.txt`。原机 Skill 验证器钉死的是 42 个清单项加清单自身、合计 43 个文件，不能拿它给新批次背书。另一台 K70E 必须按文档 50 使用 `package_verify_k70e_portable.py package` 和 `verify`，由通用验证器针对该轮数据重算关系、证书、原始请求/响应和最终清单；只有结果全 PASS 才能称为该目标的新最终成果。

---

## 16. 一页式停止条件

遇到以下任意情况立即停止：

- serial、product、slot 不符合；
- 多设备但命令没带 `-s`；
- host preflight 不是 PASS；
- 原厂恢复件大小/哈希不符；
- init_boot 未武装启动失败；
- TEE/TA/init 三件套哈希不配套；
- early-bind 没有 `BIND_OK`；
- 自动恢复没有 `restore_final=stock`；
- namespace TA 不是本轮 TA；
- native CSR 不是 zero-key；
- UDS、DICE、outer、challenge 任一验证失败；
- 导出不是 32 raw bytes；
- scalar 不在 P-256 范围；
- scalar SPKI 不等于同轮 leaf；
- source DeviceInfo 不是同轮签名值；
- request preflight 不是 PASS；
- HTTP 不是 200；
- 返回链数不是 1；
- 私钥公钥不等于叶证书公钥；
- DER 有尾随/截断/重复/断链；
- 设备恢复后分区哈希不符合。

不要“先继续看看”。该流程的安全性来自每一门都 fail-closed。

---

## 17. 2026-09-06 portable release：另一台 K70E 与窄恢复教程

前面第 3–14 节记录的是参考机历史操作，不应把其中的常量和镜像直接套到另一台 K70E。新目标的傻瓜式入口只有一个：先完整阅读文档 50，再按下列六个 wrapper 依次执行；每台机器都必须新建自己的 profile/run，不能手改旧捕获器常量“换机”。

```text
1. k70e_portable_profile.py
2. build_k70e_portable_batch.py
3. capture_k70e_identity_portable.py
4. confirm_k70e_portable_restore.py
5. rkp_sw_portable.py
6. package_verify_k70e_portable.py
```

先在项目根核验发布清单；任何一项失败都不要连接设备执行动态步骤：

```bash
cd <PROJECT_ROOT>/<DEVICE_WORKSPACE>
shasum -a 256 -c SHA256SUMS_PORTABLE.txt
```

profile `check` 必须 PASS。分类是 `PORT_REQUIRED` 时立即停止写入，去文档 50 做该固件的 TA/SProvider/boot 语义移植；不能把分类字段改成 Exact。分类是 `EXACT_REFERENCE_FAST_PATH` 时，也仍须使用新机自己的 serial、fingerprint、stock 备份、known-good init_boot、baseline CSR/challenge、runtime profile 和全新输出目录。

### 17.1 失败后先按这张表决策

| 现场状态 | 唯一允许动作 | 明确禁止 |
|---|---|---|
| live Binder latch 为 `ABSENT`，没有任何 host post-latch 证据，且 wrapper 明确分类 `PRE_KEYGEN_SAFE_ABORT` | 保留失败目录；修复前置问题后，在同一仍有效 profile/run 下换一个**全新 capture 输出叶**重新运行普通 capture | 复用/清空失败目录，伪造 ABSENT，忽略任何 post-latch 证据 |
| capture 的 Binder keygen latch 为 `CONSUMED` 或 `UNKNOWN`，或虽显示 `ABSENT` 但已有 host post-latch 证据 | 在**同一 capture 目录、同一 runtime profile、同一目标机**运行 `--resume-cleanup`，让持久 latch 解析真实状态 | 再运行普通 capture、直接调用 Binder client、手删 latch/远端目录/host duplicate |
| Google 已经成功返回并落盘恰好一把 key 和一条完整链，attempt 与 `NETWORK_STARTED.json` 均完整，但 SUCCESS 双副本或最后收尾中断 | 在**同一 provision 输出路径、同一 profile/capture/preflight/restore**运行 `--resume-finalize` | 再联网、再生成 key、换 output、移动目录、伪造/编辑 marker |
| issuance 已消费 attempt/network 边界后发生 HTTP/网络失败、响应或链不完整、证据不一致，或其他无法满足上述成功收尾前提的失败 | 保留失败现场，安全恢复后创建新 profile/run 和全新输出叶，从文档 50 对应门重新开始 | 用任一 resume 模式把失败“洗成成功”，删除 latch 后重试 |

换言之，`PRE_KEYGEN_SAFE_ABORT` 不是烧毁，因为 keygen 尚未发生；一旦状态不是可证明的 `ABSENT + 无 post-latch 证据`，就必须按已消费处理。旧文中“越过一次性边界后失败即烧毁”的原则仍然成立，但**不应误伤两个已经越过成功点、只缺幂等收尾的窄窗口**。resume 不是重试业务动作：capture resume 的 Binder keygen 调用数为 0；RKP resume 的设备访问、网络访问和新 key 数均为 0。

### 17.2 capture：只恢复 remote cleanup 与 canonical 收尾

只在 wrapper 或 `capture_recovery_status.json` 明确指示同一轮已消费 Binder latch、需要 cleanup recovery 时使用：

```bash
"$PY" "$S/capture_k70e_identity_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --output-dir "$CAPTURE_DIR" \
  --resume-cleanup
```

wrapper 会先核对固定 serial/product/fingerprint/root，再从设备 Binder latch 读取并核对 profile SHA、run ID、capture boot ID 和精确随机 staging path。它必须先找到或从该 staging path 拉回一个能通过同轮 CSR leaf/SPKI 验证的 32-byte scalar，并把 scalar、CSR、challenge、native verification、device preflight、summary 及父目录全部 fsync；只有这样才删除精确远端目录并证明不存在。随后它幂等创建/核对 canonical identity、公钥和 identity verification，再删除与 canonical byte-exact 相同的 host duplicate。

若设备断线、远端 scalar 尚未安全落到主机、latch 不匹配或删除无法确认，wrapper 会保留 UNCONFIRMED/recovery 证据并再次失败。此时只修复 ADB/root 连通性后重复同一条 `--resume-cleanup`；绝不能再 keygen，也不要手工 `rm -rf`。`capture_maced_public_key.bin` 只是可选传输佐证，不是 identity；它缺失不构成再次 keygen 的理由。

### 17.3 RKP：只完成已成功签发的本地 commit

只有本轮 official Google response、恰好一把新软件私钥、恰好一条可验证证书链和完整 run summary 已在同一 provision 目录耐久存在，且主机 attempt 目录内已有与本轮一致的 `attempt.json`、`NETWORK_STARTED.json` 时，才可运行：

```bash
"$PY" "$S/rkp_sw_portable.py" \
  --profile "$RUNTIME_PROFILE" \
  --capture-dir "$CAPTURE_DIR" \
  --output-dir "$PROVISION_DIR" \
  --preflight-report "$PREFLIGHT_REPORT" \
  --restore-report "$RESTORE_REPORT" \
  --resume-finalize
```

该模式不访问设备、不联网、不生成新 key。它从冻结文件重新执行严格 issuance/package 语义审计，验证 official URL、profile/run、restored boot、preflight、attempt、network、请求/响应、私钥/证书关系和当前 auditor/profile-helper 哈希，然后只创建或补齐 byte-identical 的 SUCCESS 权威副本与输出副本。

provision destination 在首次 attempt 时已绑定规范绝对路径，以及父目录的 filesystem device/inode。不要移动、重命名、复制到别处、换挂载点或用 symlink 替代原输出目录；这些操作会被拒绝。若缺 `NETWORK_STARTED.json`、Google response 未完整成功、输出只有一部分证书、已有 SUCCESS 被截断/修改，或任一 hash/关系不符，`--resume-finalize` 必须失败，该轮不能补写假成功。

### 17.4 打包与结果解释

最后使用 portable package/verify，不要拿参考机 51 项验证器验证新包。verify 二选一使用真正独立的信任锚：

```text
--trusted-profile <打包前保存、位于包外、非硬链接的 profile 副本>
--expected-profile-sha256 <通过独立渠道预先记录的 64 位 SHA-256>
```

2026-09-06 host golden profile 为 `2e39f1fabe0c660844296cbdf8542e666ce615f5df58a452db537f49b911d759`；同一测试包用上述两种锚均得到 `PASS / 469 / 0`。这是测试快照，不是固定计数合同。参考机冻结包仍是独立的 `PASS / 51 / 0`。截至该日，第二台实体 K70E 尚未走完整前向闭环，所以现场仍必须逐门验收，不能把 host golden 当成新机成功证明。


---

## 原始记录段 2 / Source section 2: 54_K70E_CTF_stock日志路线傻瓜教程_20260906.md

# K70E CTF stock MiTEE 日志路线傻瓜教程

> **现行阅读规则（2026-09-06 20:45）：**本文保留历史与设备恢复支线事实；下方任何“CURRENT/当前/最高权威/未完成/下一步”标签都只是其成文时快照，已由文档 65–70 与当前 Skill 重新分流。除非现行文档明确重新引用，否则不得据此操作手机、刷机、调用 Binder 或联网。

> **2026-09-06 20:00 路线重分类：**本教程只用于将来 fresh fully-stock recapture，不要为审计/交付现有成功 hybrid 包而执行。现有包的只读验收教程是文档 66。

> **2026-09-06 18:05 暂停覆盖：** 暂停期间禁止执行本文命令。先读文档 59–63；旧八步恢复已导致双重 AVB mismatch，必须先重做官方 vendor_boot/init_boot 成对恢复合同与独立验证器。

> 适用对象：第一次接手本工作区的人或 AI  
> 目标：不使用 patched TEE/Fenrir，取得 K70E stock CDI_Leaf 身份，并完成一把软件私钥及无 NOT_APPROVED 的 Google 证书链  
> 当前提醒：不要因为看到旧文档中的 PASS 就提交旧包；旧包已被赛事方拒绝  
> 历史快照（已失效）：不得再按文档 58 的旧恢复合同执行，也不得写“一次性 marker 全为零”。当前设备模式 UNKNOWN，旧八步已造成双 AVB mismatch；approved-stock 专用 one-shot 未开始，但 generic/default 负实验已有 fetch/sign `NETWORK_STARTED`。暂停解除后先按文档 59–63 重建 paired 恢复和 postboot 合同。

---

## 0. 先看这一句

只运行三个执行阶段，再用一个离线 verifier 验收，顺序不能换：

    1. capture_k70e_stock_cdi_log_once.py
    2. rkp_sw_stock_log_once.py --preflight-only
    3. rkp_sw_stock_log_once.py --attended --execute-google-once
    4. verify_k70e_stock_log_submission.py（离线、只读）

第 1 步不联网，第 2 步不联网，第 3 步才联系 Google 一次，第 4 步不联网也不访问手机。

如果任何一步显示 SAFE_ABORT、PARSER_REQUIRED、NOT_APPROVED、429、quota、BURNED 或 hash mismatch，立即结束当前执行，不要重放同一 attempt。保存证据后继续离线查根因；只有显式 429/quota/abuse 或网络结果未知才暂停外部请求。

## 1. 不要做的事

- 不要刷旧 candidate TEE 3990a8...；
- 不要部署旧 patched TA 7ea594...；
- 不要再跑文档 46 的 patched portable 六入口流程；
- 不要运行 `rkp_sw_portable.py` 的 direct-online 路径；该路径已永久禁用；
- 不要解包或重建已隔离的 TA/TEE/OEMCrypto probes 或 in-process injector；
- 不要提交 20260905_2244 旧包；
- 不要删 attempt、latch、DISPATCHING_NO_RETRY、BURNED 或 preflight 文件；
- 不要把 HLOS 的 green/locked 当成 signed DeviceInfo；
- 不要把 android_schema_current_strict=false 当成赛事失败；
- 不要把 scalar 粘到命令行或聊天；
- 不要用 Pixel 4 XL <DEVICE_SERIAL> 代替 K70E；
- 不要在 K70E 没连接时运行 capture。
- 不要把 178/178 离线 PASS 写成“已取得新 clean Google 链”。

## 2. 固定路径

项目根：

    <PROJECT_ROOT>

独立工作区：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>

Python：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python

ADB：

    <HOST_SDK>/platform-tools/adb

profile：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json

目标 serial：

    <DEVICE_SERIAL>

受控 zero-key 载荷（不要换回旧的活动根目录 ELF）：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload

### 2.1 当前冻结身份

    gate                       gate-v7
    toolchain                  k70e-portable-macos-host-20260906-v5 (stock-log-only)
    core rkp_sw.py             619e1f3fc41fd9f6afb8292a335229517140b1b164cc4c71cbfcee89cbe6a822  193161
    profile helper             724d9dc3a318f38ce6f81f80f4259acadf9a042d7c7af5a7f6183f699368be57  134026
    portable library           0c592938706989ff5447403e22f088b698739a37ec2b09d6fc3f6267d40a2c5c  76113
    stock log collector        732654cdea99b9d3f6f33242255caa46e517bcc4870f00af47002c995f849f8c  75305
    stock one-shot wrapper     99f8598577b8fa2f692cb6646d7a8d7ea83dce52e47f6499a81b3d3dbc796bb3  121031
    stock offline verifier     f3a26646547132ffa9cd1bfad1c20b0810222391ba39fc60416062c9107f9357  120223
    profile internal SHA-256   809a00199eebc8aaf61bb4ffec8bb12eae7d6762d183120b031eacbd3c4ec5b3
    profile file SHA-256       5172174e410c0c9730f0a07b2479f9f92b40414b5f6080f46912688f8f2d7b81  17803

`portable library` 的哈希仅用于 V5 固定的离线/库依赖；其 direct-online 分支固定 `SAFE_ABORT`，不是第二条在线路线。

## 3. 第一次开工：只做文件校验

进入工作区：

    cd <PROJECT_ROOT>/<DEVICE_WORKSPACE>

运行：

    shasum -a 256 -c SHA256SUMS_PORTABLE.txt
    shasum -a 256 -c SHA256SUMS_HANDOFF.txt

判断：

- 每行都是 OK：继续；
- 任一 FAILED 或文件缺失：停止，先定位工作区是否被改过；
- 不要为了通过而重写 hash 常量。

## 4. 确认连接的是正确手机

运行：

    <HOST_SDK>/platform-tools/adb devices -l

正确状态只允许看到目标：

    <DEVICE_SERIAL> ... product:duchamp ...

停止条件：

- 没有 K70E；
- 状态 unauthorized、offline；
- 同时连接两台或更多设备；
- 同一设备记录重复；
- inventory 不是规范 ASCII、换行/字段畸形或 detail key 重复；
- 只有 <DEVICE_SERIAL>；
- product 不是 duchamp。

先在手机上确认 USB 调试授权。不要用不带 -s 的其他 ADB 命令。

**这个 USB 阻塞已解决，但仍不能进入 capture**：Pixel 已移除，唯一 `<DEVICE_SERIAL> ... product:duchamp ... device` 的 native ADB 已稳定。新阻塞是 live 只读门确认当前是 `b9b1d867…` 拒绝环境。先按文档 58 恢复 CN304，独立 reboot 后通过 raw/HLOS/TA/9 个 A 逻辑分区和 `--live-check-only` 全门，才可进入第 5–8 节。当前未消耗 Binder zero-key 或 Google one-shot。

## 5. 在手机上准备离线捕获状态

人工操作：

1. 保持 USB 连接；
2. 开飞行模式；
3. 关 Wi-Fi；
4. 关移动数据；
5. 不重启；
6. 不插拔；
7. 保持屏幕可解锁；
8. 确保有人在旁边；
9. 确保电量足够。

不要先开启电脑共享网络。捕获阶段必须证明手机的 IPv4/IPv6 路由查询都成功，且零可转发 default 路由。

不要因为在飞行模式下看到 `default dev dummy0 table 1002 ...` 就手动删路由或删 dummy0。AOSP `netd` 会把这类直连 default 用作丢包 sink，它不能转发外网；参考源码见 `DummyNetwork.cpp` <https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/DummyNetwork.cpp#30> 和 `RouteController.cpp` <https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp#788>。捕获器只会忽略下面两种参考 K70E 精确形态：

```text
default dev dummy0 table 1002 proto static scope link
default dev dummy0 table 1002 proto static metric <十进制整数> pref medium
```

其他任何 default，包括未知尾缀、`via`、`nexthop`、`nhid`、`encap`、表号不对/缺失或字段重复，都会 `SAFE_ABORT`；IPv4/IPv6 任一查询失败或输出分隔结构畸形也会拒绝。捕获器在初始准备和 point-of-no-return 前各做一次这项检查，分别保存 `offline_gate_before.json` 和 `offline_gate_point_of_no_return.json`；证据区分 `forwarding_default_route_count=0`、已忽略 dummy sink count/hash 和完整 route inventory hash，兼容字段 `default_route_count` 仍必须为 0。

## 6. 校验 profile

运行：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/k70e_portable_profile.py \
      check \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json

必须看到：

    status: PASS
    classification: EXACT_REFERENCE_FAST_PATH
    approval_baseline_eligible: true

当前检查器会拒绝非 `k70e-rkp-ctf-target-profile-v4` 文件，同时必须看到 toolchain `k70e-portable-macos-host-20260906-v5`。这里的 schema-v4 和 toolchain V5 不矛盾：前者是 profile 文件格式，后者是当前 stock-log-only 执行白名单。任一不符就停止。

## 7. 创建一个全新的 capture 路径

只决定名字，不要手工 mkdir；脚本要求路径尚不存在。

示例：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_cdi_log_capture_20260906_230000

确认：

    test ! -e $HOST_ROOT/NEW/CAPTURE_DIR

退出码必须为 0。

## 8. 执行唯一 zero-key 捕获

复制以下命令，只替换最后的 CAPTURE_DIR：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/capture_k70e_stock_cdi_log_once.py \
      --serial <DEVICE_SERIAL> \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --output-dir $HOST_ROOT/NEW/CAPTURE_DIR \
      --attended \
      --execute-zero-key-once

这个命令会：

- 在初始和 point-of-no-return 两阶段，各自在任何设备 shell 前先检查 strict 唯一 `adb devices -l` inventory；
- 检查 stock 启动环境；
- 要求 `tee-supplicant` 恰好只有一个 ASCII 十进制 PID，才允许用 `nsenter` 检查 namespace TA；
- 只部署受控载荷 `02_脚本与补丁/受控载荷/rkp_binder_csr_v2_zero_key_client_arm64.payload`；
- 保存日志前快照；
- 调用一次 keysToSign=[] 的 CSR；
- 保存日志后快照；
- 从原厂 TA 日志中找 CDI_Leaf scalar；
- 用同轮 CSR 公钥关系确认 scalar；
- 不联系 Google。

如果第二阶段 inventory 因额外设备、offline/unauthorized 或畸形输出失败，脚本不会再发送 cleanup shell、Binder 调用或 `DISPATCHING_NO_RETRY` marker。此前已 staged 的远端临时目录会延期清理，并在 `remote_cleanup.json` 留下人工核对要求；此时不要为清理而绕过唯一设备门，只有重新确认 strict inventory 中唯一目标后才可手工清理。

### 8.1 正常成功

终端只应显示非秘密 summary，status 为 PASS。

只看状态和文件，不显示秘密内容：

    /usr/bin/stat -f '%Sp %z %N' $HOST_ROOT/NEW/CAPTURE_DIR/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
    /usr/bin/shasum -a 256 $HOST_ROOT/NEW/CAPTURE_DIR/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
    /usr/bin/shasum -a 256 $HOST_ROOT/NEW/CAPTURE_DIR/identity/cdi_leaf_public_spki.der

scalar 必须 32 字节、权限 600。不要用 xxd、hexdump、base64 或 strings。

### 8.2 SAFE_ABORT 在 DISPATCHING 前

如果明确还没有 zero_key_invocation.json 的 DISPATCHING_NO_RETRY：

- 原因通常是 hash、设备、网络、root 或服务门失败；
- 保留失败目录；
- 先修环境；
- 不删除失败目录；
- 修好后才用另一个新目录。

### 8.3 DISPATCHING 后失败

如果 zero_key_invocation.json 已存在且 state 是 DISPATCHING_NO_RETRY：

- 不重跑该目录；
- 不删 marker；
- 不立刻新建目录重试；
- 检查保存的 zero_key_client_stdout.txt、native CSR 和 logs；
- 交给熟悉 parser 的 AI 离线恢复。

### 8.4 PARSER_REQUIRED

这通常是日志轮转无法严格证明或 parser 输入不唯一。不要再次触发 CSR。保留：

    logs/baseline/
    logs/post/
    logs/delta/
    PARSER_HANDOFF.json
    native_zero_key_authenticated_request.cbor
    native_zero_key_challenge.bin

后续只离线解析。

## 9. 检查 capture 是否完整

不要用 jq 打印整个对象；只用 Python 读取非秘密状态：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python -c \
      'import json,sys; p=sys.argv[1]; d=json.load(open(p)); print(d.get("status"), d.get("capture_method"), d.get("network_submitted"))' \
      $HOST_ROOT/NEW/CAPTURE_DIR/capture_evidence_contract.json

预期：

    PASS stock_mitee_log_v1 False

再看关系状态：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python -c \
      'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("status"), d.get("network_issuance_allowed"), d.get("scalar_matches_same_run_leaf"))' \
      $HOST_ROOT/NEW/CAPTURE_DIR/identity_validation.json

预期：

    PASS True True

任一不同：停止。

## 10. 执行离线发行预检

保持手机同一 boot、仍不开 Wi-Fi。运行：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --capture-dir $HOST_ROOT/NEW/CAPTURE_DIR \
      --serial <DEVICE_SERIAL> \
      --preflight-only

成功后生成：

    $HOST_ROOT/NEW/CAPTURE_DIR/stock_log_provision_preflight.json

检查：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python -c \
      'import json,sys; d=json.load(open(sys.argv[1])); print(d["status"], d["network_issuance_allowed"], d["source_keys_to_sign_count"], d["dice_entry_count"], d["dice_signatures_verified"])' \
      $HOST_ROOT/NEW/CAPTURE_DIR/stock_log_provision_preflight.json

预期：

    PASS True 0 5 5

这个文件已存在时不要重复运行 preflight，也不要覆盖。报告还必须将 core 标识为 gate-v7，toolchain 标识为 `k70e-portable-macos-host-20260906-v5`；任何 gate-v6/V4 只能停在历史离线分析。

## 11. 在线前最后人工判断

问自己七个问题：

1. K70E 仍是 <DEVICE_SERIAL> 吗？
2. 手机从 capture 后没有重启吗？
3. 没有刷过任何分区吗？
4. capture 和 preflight 都 PASS 吗？
5. network_issuance_allowed 是 true 吗？
6. capture 目录里没有 .stock_log_google_attempt_* 吗？
7. 如果这次返回 NOT_APPROVED，我愿意保存证据、不重放该 attempt，并继续离线找出具体环境差异吗？

只有七个都是“是”才继续。

## 12. 只给电脑保留互联网，手机继续离线

Google 请求由电脑上的 google-rkp-sw 发出，手机不需要 Wi-Fi、移动数据或 USB 反向共享网络。手机继续保持飞行模式、Wi-Fi 关闭和零可转发 default 路由，避免后台 RKPD 干扰；第 5 节的 collector 两种精确 dummy0/table1002 黑洞 sink 可存在，不要手动删除。在线 wrapper 另外按 IPv4/IPv6 分族放行同一无 gateway 裸形态 `default dev dummy0 table 1002`：IPv4 的非裸形态必须是 scope-link，IPv6 的非裸形态必须是 decimal-metric/pref-medium；其他 default 全部拒绝。

网络准备规则：

- host 电脑可以访问官方 Google endpoint；
- 手机保持同一 USB serial 和同一 boot ID；
- 不开会改变 boot/DICE 的模块或镜像；
- 不登录小米解锁账号；
- 不需要重新刷机；
- 不运行试探性 curl 到签发 API；
- 不先跑另一个 RKP 请求验证网络。

发行器会在任何 host `ATTEMPT` 保留之前，完整验证 live approved-baseline hashes、同一 boot、飞行模式、Wi-Fi 和零可转发 default。保留 `ATTEMPT` 后，创建 device latch 前还会在单个 root shell 内原子重验 boot/分区/TA namespace/服务以及同一手机离线政策；第二门失败会烧毁已保留的 attempt，不得重试。
这个门严格证明的是飞行模式开启、Wi-Fi 关闭、IPv4/IPv6 查询成功且零可转发 `/0` default；不要把它扩大解读为所有 host-specific、VPN 或 fwmark 路径都已被独立排除。

两次 wrapper 手机检查各有自己的 strict ADB inventory：第一次在 ATTEMPT 前、任何 live shell 前执行；第二次紧贴 device-latch 单 root shell 之前执行。都只接受唯一 pinned serial 且状态为 `device` 的规范 ASCII 记录；额外/重复设备、`offline`、`unauthorized`、目标不符或畸形 inventory 全部拒绝。两次检查也都要求 `tee-supplicant` 为唯一 ASCII 十进制 PID。

## 13. 选择一个全新的最终输出路径

例如：

    <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_STOCK_20260906_233000

不要手工创建该目录。

确认：

    test ! -e $HOST_ROOT/NEW/SUBMISSION_DIR

## 14. 执行唯一 Google 运行

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/rkp_sw_stock_log_once.py \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --capture-dir $HOST_ROOT/NEW/CAPTURE_DIR \
      --serial <DEVICE_SERIAL> \
      --preflight-report $HOST_ROOT/NEW/CAPTURE_DIR/stock_log_provision_preflight.json \
      --output-dir $HOST_ROOT/NEW/SUBMISSION_DIR \
      --attended \
      --execute-google-once

`--attended` 是真实发行的硬门，并在 `build_preflight()` 之前检查；漏写时不会读取设备、构建/比较 preflight 或创建 ATTEMPT。`--preflight-only` 不得携带 `--attended`。

理解脚本的顺序（不要手工创建任何 marker）：

```text
strict unique ADB inventory
  -> 第一次 full live/offline gate（ATTEMPT 之前）
  -> 准备 device-state 目录
  -> ATTEMPT（v1 预承诺未来 DEVICE_LATCH consumed=true）
  -> 保存 LIVE_STOCK_PREFLIGHT + DEVICE_STATE_DIR_PREPARED 证据
  -> strict unique ADB inventory
  -> 第二次单 root-shell 原子 live/offline gate
  -> DEVICE_LATCH
  -> NETWORK_STARTED
  -> 唯一 core 调用 / strict audit / SUCCESS 或 BURNED
```

这里有一个容易误读的 v1 现场语义：`ATTEMPT.json` 会在真实 `DEVICE_LATCH.json` 创建前，先写 `device_latch_consumed=true` 以及未来成功 latch 的路径/哈希。这个 `true` 是“本 attempt 只能继续到这一个 latch”的预承诺，不表示写 ATTEMPT 的那一刻设备 latch 已经存在。若此后手机掉线或第二门失败，脚本写 `BURNED.json`，不会写 `NETWORK_STARTED.json` 或 `SUCCESS.json`，所以不会联系 Google，但单看 ATTEMPT 字段并不直观。不要为了“修顺序”手工交换两步；正确修订需要 writer、verifier、marker 哈希链和 attempt schema 一起做 **gate-v8/新 schema** 迁移。

不要：

- 加第二个 key；
- 改 URL；
- Ctrl-C 后重跑；
- 网络卡住时再执行一次；
- 删除 capture 下的 attempt 目录；
- 删除设备 issuance latch。

在任何 POST 前，core 会在授权内生成一把 P-256 软件 key，以 canonical unencrypted PKCS#8 耐久写入 0600 文件，对文件和目录 `fsync`，再从磁盘重开、重解析并对 fresh nonce 完成 proof-of-possession。capture/key 目录必须由当前 UID 所有且精确 0700，其 resolved path/device/inode/UID/mode 和 creator PID 在 fetch/sign 前会再次绑定。任一变化都应 `SAFE_ABORT`，不要手工“修文件”继续。

## 15. 判断在线结果

### 15.1 终端显示 SUCCESS

还要确认两个文件：

    $HOST_ROOT/NEW/SUBMISSION_DIR/stock_log_strict_issuance_audit.json
    $HOST_ROOT/NEW/SUBMISSION_DIR/stock_log_issuance_success.json

查看非秘密布尔值：

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python -c \
      'import json,sys; d=json.load(open(sys.argv[1])); ks=["software_private_public_match","software_request_one_key_verified","certificate_signatures_verified","leaf_matches_software_private_key","provisioning_info_ctf_no_not_approved","identity_scalar_derives_public_spki","identity_public_spki_matches_source_cdi_leaf"]; print(d.get("status"), [(k,d.get(k)) for k in ks], d.get("provisioning_info_android_schema_current_strict"))' \
      $HOST_ROOT/NEW/SUBMISSION_DIR/stock_log_strict_issuance_audit.json

每个硬门都必须 true。发行器在产生这份 strict audit 前已强制软件待签 key SPKI 与 CDI identity SPKI 不同，离线 verifier 会再独立比较；不得因为 strict audit 没有单列这个字段就跳过关系验证。最后一个 Android strict 只是报告，可以 false。

### 15.2 显示 ProvisioningInfo rejected 或 NOT_APPROVED

立即结束当前 attempt，不得重放。保存：

    response.cbor
    response_http.json
    chain_00/chain_summary.json
    certificate_request.cbor
    key_00/private_key_pkcs8.pem
    capture 下 .stock_log_google_attempt_*/BURNED.json

现有数据中 12 张 count-32 证书干净，两个坏请求都是 HTTP 200 且无 429/quota/abuse；因此不得直接归因为次数风控。对照 clean native control 离线比较 signed DeviceInfo、DICE measurement/security 和五层完整 payload。找到具体差异、修正并通过 schema-v4 + toolchain V5 + gate-v7 后，才能创建不同的 controlled attempt。

### 15.3 显示 HTTP 429、quota、abuse

保存证据并暂停外部请求，不重放，不换网络规避。离线审计可继续。

### 15.4 网络超时或进程中断

只要 ATTEMPT 或 NETWORK_STARTED 已存在，就当作已消耗。不得再次运行 execute-google-once。

## 16. 最终三件套在哪里

身份：

    SUBMISSION_DIR/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
    SUBMISSION_DIR/identity/cdi_leaf_public_spki.der
    SUBMISSION_DIR/identity/native_zero_key_csr.cbor
    SUBMISSION_DIR/identity/native_zero_key_challenge.bin

软件私钥：

    SUBMISSION_DIR/key_00/private_key_pkcs8.pem

Google 链：

    SUBMISSION_DIR/chain_00/ordered_certificate_chain.der
    SUBMISSION_DIR/chain_00/cert_00.der
    SUBMISSION_DIR/chain_00/cert_01.der
    SUBMISSION_DIR/chain_00/cert_02.der
    SUBMISSION_DIR/chain_00/cert_03.der

验收：

    SUBMISSION_DIR/stock_log_strict_issuance_audit.json
    SUBMISSION_DIR/stock_log_issuance_success.json
    SUBMISSION_DIR/chain_00/chain_summary.json

完整 Provisioning Info 审计在 chain_summary.json 的 provisioning_info_audit 字段中；strict audit 和离线 verifier 会重新计算，不能只信该保存字段。

## 17. 用 stock 专用 verifier 做最终离线验包

    <PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python \
      <PROJECT_ROOT>/<DEVICE_WORKSPACE>/02_脚本与补丁/verify_k70e_stock_log_submission.py \
      --submission-dir $HOST_ROOT/NEW/SUBMISSION_DIR \
      --capture-dir $HOST_ROOT/NEW/CAPTURE_DIR \
      --profile <PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_stock_mitee_log_runtime_profile_20260906.json \
      --output-report $HOST_ROOT/NEW/OUTSIDE_INPUTS/K70E_stock_submission_verification.json

必须 status=PASS、network_or_device_access=false。报告路径必须不存在，而且不能放在 capture 或 submission 里面。

verifier 会要求 capture 中只有一个成功 attempt，核对其 ATTEMPT、live approved-baseline state、device state、device latch、NETWORK_STARTED 和 SUCCESS；发现 BURNED、第二 attempt 或 hash 不一致就失败。它会对 `LIVE_STOCK_PREFLIGHT.phone_offline_gate` 做精确字段/类型验证：飞行模式为 true、Wi-Fi 关闭为 true、IPv4/IPv6 route query success 都为 true、`forwarding_default_route_count=0`、dummy sink count 为非负整数且 route inventory hash 合法。第二次原子门由成功 `DEVICE_LATCH` 合同及其跨 marker 承诺间接证明；它没有另存第二份 raw route inventory，也不是 Google freshness receipt。

Provisioning Info 解析也是 fail-closed：除了精确扫描 `NOT_APPROVED`，任意显式 `CBORTag`（包括 tag 24 encoded-CBOR）、tag 258 自动解码的 `set`/`frozenset`、tag 35 的 `re.Pattern` 和任何其他未允许 semantic object 都必须拒绝。不要把这些值转字符串或手工剔除后再验包。

注意：`PASS` 表示交付树内部关系自洽，不是 Google 签名的“fresh/exactly-once 交易回执”。若赛事方要求防重放证明，必须额外使用赛事 nonce、服务端签名 receipt 或外部不可变日志。

## 18. 另一台 K70E 怎么办

不能复制上面的 reference profile。新手机先停在离线阶段，做以下工作：

1. 新建私有目标目录；
2. 记录新 serial、fingerprint、slot；
3. 备份并 hash 新机 stock TA、TEE、lk、preloader，以及已启动验证的 Magisk init_boot；
4. 在未改造 stock 环境取得新机自己的 baseline CSR/challenge；
5. 找到同设备已获 Google 正常证书的基线，确认没有 NOT_APPROVED；
6. 用 k70e_portable_profile.py create 建 schema-v4 新 profile，锁定该机五层完整 DICE payload；
7. 要求 EXACT_REFERENCE_FAST_PATH 或完成目标固件的独立静态 port；
8. 把 stock capture 工具的 early-boot allowlist 改成目标自己的已认可锚；
9. 重新运行全部离线测试；
10. 才允许做这份教程的第 8 步。

没有已获认可基线时，只能说结构与密码学正确，不能声称 Google 一定不会标记 NOT_APPROVED。

## 19. 常见问题

### “OEM 解锁开着，但账号无内测授权，能不能做？”

能否 fastboot/刷写与账号 UI 授权不是本题验收门。当前 stock 日志路线甚至不需要刷写。以 live serial、root、partition hash 和 signed DICE 为准。

### “为什么不再刷 TEE？”

因为 patched TEE 改变服务器可见的 DICE 第 4 层，已经实证返回 NOT_APPROVED。原厂 TA 自己会在 CSRv2 签名路径打印目标 scalar。

### “Android strict=false 是不是还是不合格？”

不是。本赛事当前明确拒绝的是 NOT_APPROVED。历史认可 Google 证书只含键 1、3，也会让公开新 schema strict=false。

### “计数 32 是不是风控？”

不是当前证据里的简单风控条件。已有 12 张干净证书同样为 32，而两个异常请求均 HTTP 200。只有显式 429/quota/abuse 才暂停外部请求；普通 NOT_APPROVED 继续按环境/请求差异调查。

### “磁盘上已经恢复 stock，为什么还不行？”

因为同一次 boot 里已经完成的 DICE 测量不会被后续写盘倒转，tee-supplicant namespace 里已加载的 TA 也不会因磁盘文件恢复而自动替换。必须先让原厂 preloader/LK/TEE/TA 与固定的 known-good Magisk init_boot 回到 approved-baseline 组合，再 fresh boot 后捕获。

### “能不能把 NOT_APPROVED 从证书删掉？”

不能。删改会破坏 Google 对 TBSCertificate 的签名。

### “失败后换目录再来一次？”

只有明确在任何不可重试 marker 之前的纯前置失败，修复根因后才可新建目录。DISPATCHING、ATTEMPT、NETWORK_STARTED、BURNED 或状态未知都禁止重放同一运行。若是 NOT_APPROVED 且无显式风控信号，先继续离线定位；只有修复一个被证明的差异并通过新门后，才可建立独立 controlled attempt。

## 20. 当前停在哪里

截至本文冻结：

    K70E physical USB present                  yes
    Pixel physically coexists                  no
    stable native ADB one-device session       yes; native backend
    current approved HLOS/AVB environment      no; b9b1d867… rejected environment
    official CN304 restore inputs              verified; not yet flashed
    gate-v7 + V5 stock-log-only 实现        yes
    8 组离线回归                           178/178 PASS
    Binder zero-key one-shot consumed          no
    新 stock zero-key capture                    no
    新 software PKCS#8                           no
    Google one-shot consumed                   no
    新 Google chain without NOT_APPROVED         no
    最终三件套                                 no

回归分组映射是：Provisioning Info/core 23 + profile 13 + device evidence 12 + capture 31 + extractor 10 + legacy quarantine 10 + wrapper 42 + verifier 37 = 178。

因此现在可以声称“环境根因已定位、恢复输入与离线门禁已闭合”，不能声称“已在真机取得新的无 `NOT_APPROVED` 链”。下一步是在用户当前交互明确确认人在机旁后，严格按文档 58 执行 CN304 恢复、独立 reboot 和 post-boot 验收；全门通过后才从第 3 节继续。

冻结执行件：恢复器 `3a1c46399164adf99108b79cf9435fe8c992710a626e43b883f626663dbbe5e9 / 109,993 B`（35/35）；post-boot 验证器 `c76e4aeb3815401c12b128932843cef7067b6b11bfc823a69c0bec3dc3f07add / 99,185 B`（24/24）。`POSTBOOT_VERIFIED.json` 只表示批准环境离线验收通过，不授权联网；执行 zero-key 和 Google 时仍须各自的新鲜现场确认与现有一次性门。


---

## 原始记录段 3 / Source section 3: 66_K70E_CTF_clean_DeviceInfo_APPROVED傻瓜式验收与交付教程_20260906.md

# K70E CTF clean DeviceInfo `APPROVED` 傻瓜式验收与交付教程

> 用途：让下一位 AI 或人工操作者在不重放 Google 请求、不碰手机、不泄露私钥的前提下，找到、验证并交付本次三件套。  
> 结果：本地 Google/密码学/Provisioning Info 验收已通过；赛事方对本新包的最终回执尚未记录。
> 2026-09-07 更新：三件套已冻结成正式提交候选，直接使用文档 71 的目录和专用校验器，不再手工散拷文件。

---

## 0. 只记住四句话

1. 不要再运行联网脚本；这次 one-shot 已经成功且已消耗。
2. 题目要的软件私钥是 `key_00/private_key_pkcs8.der`，不是 K70E identity scalar。
3. 完整证书链优先交付 `ordered_certificate_chain.der`，同时可附 PEM 版方便查看。
4. 任何交付前必须再看 `chain_summary.json` 中 `ctf_no_not_approved=true`。

## 1. 成功目录

```text
RUN=<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot
```

不要对该目录里的证据文件做任何写入。目前它包含 45 个 0600 普通文件，所有目录为 0700。

## 2. 私钥在哪里

### 2.1 题目要的新软件私钥

```text
$RUN/key_00/private_key_pkcs8.der
```

完整绝对路径：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot/key_00/private_key_pkcs8.der
```

属性：

```text
format  canonical unencrypted PKCS#8 DER
curve   P-256 / secp256r1
mode    0600
size    138 bytes
sha256  58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
```

对应公钥：

```text
$RUN/key_00/public_key_spki.der
sha256 1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

### 2.2 K70E identity scalar（另一份秘密）

它用来签 outer request，不是本次新生成的软件 key：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/identity/google_rkp_sw_cdi_leaf_p256_scalar.bin
mode    0600
size    32 bytes
sha256  ac903105021c73ee239e83cabb1220bd1c65beca95f591df777e10a132f2f36c
```

对应 identity SPKI：

```text
.../identity/cdi_leaf_public_spki.der
sha256 64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

不要混淆：

```text
K70E identity SPKI  64c672...ba4ad2
software key SPKI   1e5ec6...84bc67
Google leaf SPKI    1e5ec6...84bc67
```

## 3. 证书在哪里

### 3.1 完整四证书链

DER：

```text
$RUN/chain_00/ordered_certificate_chain.der
size    2486 bytes
sha256  423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
```

PEM：

```text
$RUN/chain_00/ordered_certificate_chain.pem
size    3593 bytes
sha256  c63a4e76d3af5cc6f857ca6bbf102f5a63d2755aab3a088ba39a5e7045defc34
```

### 3.2 只要单张 leaf 时

DER：

```text
$RUN/chain_00/ordered_cert_00.der
size    565 bytes
sha256  b05b883c7777a4cd7449aff3b5faeadb9d5c706c13beefe966f6cf01790ab180
```

PEM：

```text
$RUN/chain_00/ordered_cert_00.pem
```

不建议只交 leaf；赛事验收应同时保留四张完整 Google 链。

## 4. 身份数据在哪里

本次用的 modified K70E 身份源请求：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_identity_20260905_2243/native_trigger_csr.cbor
size    2534 bytes
sha256  c8f7eb8d20474a549aa73a301a8ca1780586853c057e9b5421307057f8566b47
```

本次实际送给 Google 的新请求：

```text
$RUN/certificate_request.cbor
size    2611 bytes
sha256  f0c1208abd682702ea7de9fd19223d267c26ef8c2b7517f73b291b8750fc9303
```

本 run 中拆出的可复核身份组件：

```text
$RUN/verified_modified_dice.cbor  # [registered UDS, five DICE entries]
$RUN/verified_uds_certs.cbor      # 1-byte empty top-level UdsCerts map
$RUN/clean_device_info.json
$RUN/challenge.bin
```

`verified_uds_certs.cbor` 不是 registered UDS；它只是请求顶层空
`UdsCerts={}` 的持久证据。registered UDS 位于
`verified_modified_dice.cbor[0]`，其后才是五个 DICE entry。

只交一个 32-byte scalar 无法让审计者验证它与 DICE leaf 的关系。完整身份交付应包含源 CSR、实际请求、registered UDS + DICE、空顶层 UdsCerts、DeviceInfo 和关系审计，scalar 只通过私密渠道提供。

## 5. 最快只读验收

在终端中：

```bash
RUN='<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_oneshot'
jq . "$RUN/FINAL_RESULT.json"
jq . "$RUN/REQUEST_AUDIT.json"
jq . "$RUN/key_00/key_summary.json"
jq . "$RUN/chain_00/chain_summary.json"
```

应看到：

```text
FINAL_RESULT.status                         PASS_CLEAN
ctf_no_not_approved                        true
not_approved_hit_count                     0
provisioning_info_parse_error_count        0
certificate_chain_count                    1
certificate_count                          4
software_private_spki_equals_leaf_spki     true
root_matches_pinned_google_root            true
REQUEST_AUDIT.keys_to_sign_count           1
REQUEST_AUDIT.all_five_dice_signatures...  true
REQUEST_AUDIT.outer_leaf_signature...      true
```

## 6. 不读私钥内容的文件验收

```bash
stat -f '%Sp %Su:%Sg %z %N' "$RUN/key_00/private_key_pkcs8.der"
shasum -a 256 "$RUN/key_00/private_key_pkcs8.der"
shasum -a 256 "$RUN/chain_00/ordered_certificate_chain.der"
shasum -a 256 "$RUN/certificate_request.cbor"
```

不要执行：

```text
cat/xxd/hexdump/base64 private_key_pkcs8.der
cat/xxd/hexdump/base64 google_rkp_sw_cdi_leaf_p256_scalar.bin
set -x
```

对私钥的正确验收是派生公钥哈希和证明持有性，而不是把私钥打印出来。`key_summary.json` 明确记录 PoP；独立审计 JSON 记录 private-derived SPKI、请求 sole key 与 Google leaf SPKI 的三方关系。

## 7. 独立 Provisioning Info 验收

```bash
PY='<PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python'
AUDIT='<CODEX_HOME>/skills/k70e-rkp-ctf/scripts/audit_provisioning_info.py'
"$PY" "$AUDIT" "$RUN/chain_00/ordered_certificate_chain.der"
```

预期结果：

```text
PASS
certificates=4
ctf_no_not_approved=true
not_approved_hit_count=0
parse_error_count=0
```

解码必须包含：

```text
5/1 = "APPROVED"
5/2 = "acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"
```

## 8. 交付清单

最小私密交付：

```text
[identity]
google_rkp_sw_cdi_leaf_p256_scalar.bin
native_trigger_csr.cbor

[software key]
key_00/private_key_pkcs8.der
key_00/public_key_spki.der

[request]
certificate_request.cbor

[certificate]
chain_00/ordered_certificate_chain.der
chain_00/ordered_certificate_chain.pem

[proof]
FINAL_RESULT.json
REQUEST_AUDIT.json
key_00/key_summary.json
chain_00/chain_summary.json
K70E_google_rkp_sw_probe_modDICE_cleanDeviceInfo_20260906_195952_INDEPENDENT_AUDIT.json
```

如果赛事系统只允许三个上传项，可对应为：

1. 身份数据压缩包：scalar + source/request + verified registered UDS/DICE + empty top-level UdsCerts evidence + DeviceInfo + audit；
2. 私钥：`private_key_pkcs8.der`；
3. 证书：`ordered_certificate_chain.der`。

上传前根据赛事具体格式要求决定是否转 PEM，但不应重新生成私钥或重新向 Google 签发。

## 9. 绝对不要做

- 不要重跑 `run_k70e_modified_dice_clean_deviceinfo_once.py --execute-google-once`。
- 不要删除 `.k70e_google_rkp_hybrid_clean_di_ledger` 中的 claim。
- 不要为了确定三个 DeviceInfo 中的单一字段而继续消耗 Google 签发。
- 不要用旧 `K70E_CTF_SUBMISSION_google-rkp-sw_20260905_2244` 冒充本次成功包。
- 不要把手机已经修好写进报告；本次没有修手机。
- 不要宣称赛事方已接收；目前有的是 Google/密码学/PI 成功证据。

## 10. 另一台 K70E 怎么复现

另一台 K70E 不能复制这台机的 UDS、identity scalar、软件私钥或证书。它需要：

1. 自己的 native zero-key CSR，其中有该机注册 UDS 和完整 DICE。
2. 该机最终 DICE leaf 对应的 P-256 scalar，必须用公钥 SPKI 精确匹配证明。
3. 该型号/固件已知 Google-approved 的完整 DeviceInfo，保留类型；相同固件的 `vbmeta_digest` 可作为候选基线，但要在离线比对后才使用。
4. 一把在该次授权边界内新生成的软件 P-256 私钥。
5. 联网前先证明 DICE 5/5 签名、outer 签名、UDS exact match、scalar-to-leaf 和 software-key 关系。
6. 仅一次 fetch + sign，保存 raw evidence，签发后扫描全链 PI。

本次最重要的可移植知识是：不需要先拿到更底层 UDS/root seed 才能使用 proper-DICE；只要拿到与当前完整 DICE leaf 匹配的最终 scalar，就能给 outer request 签名。服务端是否批准则取决于它看到的整体 profile 和一致性，不是“字段看上去越安全越好”。

## 11. 阅读顺序

1. 文档 65：完整流水线和原始证据。
2. 本文档 66：路径、验收和交付。
3. 文档 67：坑和故障树。
4. 文档 68：正式根因报告。
5. 文档 69：Skill v3 和下一位 AI 的接手规则。
6. 文档 70：证据 SHA-256 清单。
