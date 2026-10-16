# KeyMint / Keystore Attestation Keybox 提取：快速复现教程

> 目标：在 Nothing Phone (2a) / Pacman / MT6886 上，基于已验证的 fenrir + patched TEE，提取 Android Keystore / KeyMint attestation keybox。  
> 结论：已完成。提取结果在 `extracted_keybox/`。

## 0. 方向确认

- Widevine keybox 不是本题目标；`MediaDrm` / `WVCdm` / `e97c270e` 路线已判定跑偏。
- 本题目标是 Android Keystore / KeyMint attestation keybox。
- 本设备存在 RKP 组件，但标准 attestation 触发时 RKP 无可用 key / 联网失败后会 fallback 到本地 TEE factory attestation chain。
- 最终有效对象：
  - KeyMint TA：`device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin`
  - encrypted keybox blob：`device_dump/persist/attest_keybox.so`
  - attestation ids blob：`device_dump/persist/attestation_ids.so`

## 1. 已验证设备前提

```bash
adb devices -l
adb shell 'for p in ro.product.model ro.product.device ro.hardware ro.build.display.id ro.build.version.release ro.boot.slot_suffix ro.boot.verifiedbootstate init.svc.tee-1-1 init.svc.keystore2; do echo "$p=$(getprop $p)"; done'
adb shell 'id; command -v su; su -c id'
adb shell 'service list | grep -Ei "keymint|provision|rkp|keystore"'
adb shell 'ps -A | grep -Ei "keymint|rkpd|keystore|tee"'
```

本机有效状态：

```text
serial=<TARGET_SERIAL>
model=A142 / device=Pacman / build=U2.5-240114-2323 / Android=14
slot=_a / verifiedbootstate=orange
tee-1-1=running / keystore2=running
su uid=0(root) context=u:r:magisk:s0
android.hardware.security.keymint.IKeyMintDevice/default
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
remote_provisioning
com.android.rkpdapp
android.hardware.security.keymint@2.0-service.trustonic
```

## 2. 关键文件与哈希

```text
pacman-fenrir-minimal.bin                    # LK / fenrir minimal，已验证
tee-patched-A-only.img                       # A slot t-base 签名校验 bypass，已验证
device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
device_dump/persist/attest_keybox.so
device_dump/persist/attestation_ids.so
keymint_tee_client/kmtee_probe.c
analysis/patch_0706_dump.py
analysis/extract_keybox_plain.py
patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
extracted_keybox/
```

已知哈希：

```text
070600...4d.tlbin original: ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
patched dump TA:            92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
attest_keybox.so:           64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69
attestation_ids.so:         5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74
```

## 3. 构建 probe

`kmtee_probe` 使用 Trustonic `libMcClient.so` 直接 `mcOpenTrustlet()`，不需要替换 `/vendor` 文件；patched TA 从 `/data/local/tmp` 以字节形式加载。

```bash
NDK=<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64
$NDK/bin/aarch64-linux-android33-clang -Wall -Wextra -O2 \
  keymint_tee_client/kmtee_probe.c \
  -o keymint_tee_client/kmtee_probe \
  -Ldevice_dump/vendor_lib64 -lMcClient -Wl,-rpath,/vendor/lib64
```

## 4. 生成 patched KeyMint TA

```bash
python3 analysis/patch_0706_dump.py
```

输出：

```text
patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
sha256=92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

补丁逻辑：

- dispatcher：`0x13b00`
- `0x00050202` handler：`0x1e430`，用于加载 `attest_keybox.so`
- `0x00050204` handler：`0x1e9a0`，用于加载 `attestation_ids.so`
- `0x1e430 -> 0x1de70 -> 0x22738 -> 0x1d9b8`
  - `0x22738` 解密 secure object 到临时 plaintext buffer。
  - `0x1d9b8` 解析 plaintext keybox 到 TA 全局结构。
- Patch 点：
  - `0x1df3c`：跳到 code cave，在 `0x1d9b8` parse 前把 plaintext 复制回 handler 的 heap input buffer。
  - `0x1e4d4`：跳到 code cave，把 heap input buffer 再复制回原始 mapped input buffer。
  - code cave：`0x411ac`，使用原 TA 内部 `memcpy` (`0x50f0`)。

## 5. 设备运行提取

```bash
adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

成功标志：

```text
mcOpenTrustlet ret=0x0
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

拉回输出：

```bash
mkdir -p keymint_tee_client/out_patched
adb exec-out su -c 'cd /data/local/tmp/kmtee_out && tar -cf - .' | tar -C keymint_tee_client/out_patched -xf -
```

关键输出：

```text
keymint_tee_client/out_patched/attest_keybox_buf_after.bin   # patched 后含明文 keybox 前缀
keymint_tee_client/out_patched/attest_keybox_before.bin      # 原 encrypted blob
keymint_tee_client/out_patched/attestation_ids_buf_after.bin # 本次未 patch ids，保持原样
```

`attest_keybox_buf_after.bin` 与原 blob 不同，且开头可见 DER：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 ...
```

## 6. 拆分明文 keybox

```bash
python3 analysis/extract_keybox_plain.py

for alg in ec rsa; do
  openssl pkey -inform DER -in extracted_keybox/${alg}_private_key.der -out extracted_keybox/${alg}_private_key.pem
  for i in 0 1 2; do
    openssl x509 -inform DER -in extracted_keybox/${alg}_cert_${i}.der -out extracted_keybox/${alg}_cert_${i}.pem
  done
  cat extracted_keybox/${alg}_cert_0.pem extracted_keybox/${alg}_cert_1.pem extracted_keybox/${alg}_cert_2.pem > extracted_keybox/${alg}_cert_chain.pem
done
```

输出结构：

```text
version_or_keybox_number=1
EC private key DER len=138
EC cert_count=3
  EC cert 0 len=503
  EC cert 1 len=920
  EC cert 2 len=1312
RSA private key DER len=1794
RSA cert_count=3
  RSA cert 0 len=1252
  RSA cert 1 len=1349
  RSA cert 2 len=1312
plaintext_len=8624
tail_unmodified_len=92
```

最终文件：

```text
extracted_keybox/attestation_keybox_plain.bin
extracted_keybox/ec_private_key.der
extracted_keybox/ec_private_key.pem
extracted_keybox/ec_cert_0.der .. ec_cert_2.der
extracted_keybox/ec_cert_chain.pem
extracted_keybox/rsa_private_key.der
extracted_keybox/rsa_private_key.pem
extracted_keybox/rsa_cert_0.der .. rsa_cert_2.der
extracted_keybox/rsa_cert_chain.pem
extracted_keybox/keybox.xml
```

## 7. 验证

### 7.1 私钥公钥与 leaf cert 匹配

```bash
for alg in ec rsa; do
  openssl pkey -in extracted_keybox/${alg}_private_key.pem -pubout -outform DER | shasum -a 256
  openssl x509 -inform DER -in extracted_keybox/${alg}_cert_0.der -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256
done
```

本机结果：

```text
EC  private pub == EC  leaf pub: 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA private pub == RSA leaf pub: f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

### 7.2 证书链验证

```bash
openssl verify -CAfile extracted_keybox/ec_cert_2.pem  -untrusted extracted_keybox/ec_cert_1.pem  extracted_keybox/ec_cert_0.pem
openssl verify -CAfile extracted_keybox/rsa_cert_2.pem -untrusted extracted_keybox/rsa_cert_1.pem extracted_keybox/rsa_cert_0.pem
```

本机结果：

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

### 7.3 私钥可签名且 cert 公钥可验签

```bash
echo test-message > extracted_keybox/sign_test.txt
for alg in ec rsa; do
  openssl dgst -sha256 -sign extracted_keybox/${alg}_private_key.pem -out extracted_keybox/${alg}_sig.bin extracted_keybox/sign_test.txt
  openssl dgst -sha256 -verify <(openssl x509 -in extracted_keybox/${alg}_cert_0.pem -pubkey -noout) -signature extracted_keybox/${alg}_sig.bin extracted_keybox/sign_test.txt
done
```

本机结果：

```text
Verified OK
Verified OK
```

### 7.4 与 Android Keystore 触发链对应

`keymint_trigger` 标准 attestation 生成的链：

```text
kmprobe EC chain:  leaf, extracted EC cert 0, extracted EC cert 1, extracted root
kmprobe RSA chain: leaf, extracted RSA cert 0, extracted RSA cert 1, extracted root
```

因此提取物确认为本地 TEE factory attestation keybox，而不是 Widevine，也不是 RKP 动态 leaf。

## 8. 踩坑

- 不要把 Widevine DRM keybox 当成 Keystore attestation keybox。
- 不要继续围绕 `MediaDrm`、`WVCdm`、`e97c270e` 做触发；那只会唤起 DRM 服务。
- 不要用旧 `tas/0717...drbin` 当设备真实 KeyMint 目标；本机实际 KeyMint TA 是 `070600...4d.tlbin`，以 `device_dump/` 为准。
- 不需要替换 `/vendor/app/mcRegistry` 文件；直接让 probe 用 `mcOpenTrustlet()` 加载 `/data/local/tmp` 的 patched TA 更稳。
- 必须先有 `tee-patched-A-only.img` 的 t-base signature bypass；否则 patched TA 不能被加载。
- 不要混刷 U2.6 TEE 到 U2.5 系统；之前会导致 recovery。
