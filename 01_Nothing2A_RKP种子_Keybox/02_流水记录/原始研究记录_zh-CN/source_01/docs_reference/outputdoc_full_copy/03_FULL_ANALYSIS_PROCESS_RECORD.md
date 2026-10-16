# KeyMint Attestation Keybox 全流程分析过程记录

项目根目录：`<PROJECT_ROOT>`

本文记录分析过程，解释每一步为什么这么走，以及最终如何完成提取。

## 1. 初始目标与路线偏差

最初围绕 `keybox` 进行 TEE / trustlet 研究时，先进入了 Widevine 路线：

```text
MediaDrm
WVCdm
/vendor/app/mcRegistry/e97c270e...
OEMCrypto_InitKeybox
DRM_KBF_BIN
```

这条路线能证明 Widevine DRM 服务可被触发，也能分析 DRM trustlet 的 keybox 处理路径，但它不是 Android Keystore / KeyMint attestation keybox。

关键纠偏：

```text
Widevine keybox != Android Keystore / KeyMint attestation keybox
```

后续所有分析转向：

```text
AndroidKeyStore / KeyMint / keystore2 / RKP / TEE factory attestation chain
```

## 2. 设备基础能力确认

设备信息：

```text
Nothing Phone (2a)
model=A142
device=Pacman
hardware=mt6886
Android=14
build=U2.5-240114-2323
slot=_a
verifiedbootstate=orange
```

基础控制面：

```text
Bootloader 已解锁
fenrir patched LK 已启动
patched TEE A-only 已启动
Magisk root 可用
tee-1-1 running
keystore2 running
android.hardware.security.keymint@2.0-service.trustonic running
```

这些条件让后续可以：

1. 从设备拉取 `/vendor` 和 `/persist` 目标文件。
2. 用 root 读取 persist blobs。
3. 加载 modified trustlet。
4. 通过 Trustonic direct client 直接触发 TA 命令。

## 3. RKP 与本地 factory keybox 判定

设备 binder/service 中存在：

```text
android.hardware.security.keymint.IKeyMintDevice/default
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
remote_provisioning
com.android.rkpdapp
```

因此不能直接假设它只使用传统本地 keybox。

构建标准 Android Keystore attestation 触发器：

```text
<PROJECT_ROOT>/keymint_trigger/build/kmprobe.apk
```

触发逻辑：

```java
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
.setAttestationChallenge(...)
.generateKeyPair()
KeyStore.getCertificateChain(alias)
```

实测日志：

```text
keystore2 -> get_rkpd_attestation_key()
rkpdapp -> remoteprovisioning.googleapis.com
RKP transient failure / network failure
then local TEE chain generated successfully
```

证书链结果：

```text
EC chain length=4
RSA chain length=4
leaf issuer=title=TEE, serialNumber=325d90cd5049b6c519af32bc6a413526
intermediate=title=TEE, serialNumber=aa3d661ed0862f74108b03a8dd8abb3e
root=serialNumber=f92009e853b6b045
```

分析结论：

- 设备支持 RKP。
- 但当前 RKP 不可用时 fallback 到本地 TEE factory attestation chain。
- 因此本地 `attest_keybox.so` 仍然是有效目标。

## 4. HAL 逆向与输入 blob 锁定

目标 HAL：

```text
<PROJECT_ROOT>/device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic
```

HAL 字符串证据：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
TEE_Open
TEE_AttestIds
TEE_GenerateAndAttestKey
TEE_AttestKey
TEE_ImportAndAttestKey
TEE_GenerateCertificateRequest
```

HAL 关键行为：

1. 打开 `070600...4d.tlbin` KeyMint TA。
2. 读取 `attest_keybox.so`。
3. 发送 TCI cmd `0x00050202`。
4. 读取 `attestation_ids.so`。
5. 发送 TCI cmd `0x00050204`。

TCI 结构由 HAL 逆向和 direct client 验证：

```text
TCI[0x00] = cmd
TCI[0x04] = return code
TCI[0x0c] = mcBulkMap_t.sVirtualAddr
TCI[0x10] = mcBulkMap_t.sVirtualLen
TCI size  = 0x140
```

## 5. KeyMint TA 识别

最终目标 TA：

```text
<PROJECT_ROOT>/device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
```

识别证据：

```text
KEYMINT
Keymint TA version 2.0
teeKeymint-package-2.0.0-20220420_214316_42257_1175e
decrypt_keybox
verify_keybox
Decrypting keybox is success!
Verify Keybox Signature...
rkp_bcc_km
boot_patch_level
bootloader_state
```

MCLF 结构：

```text
file size=0x44c33
text file offset=0xd0
text VA=0x1000
text length=0x43fe8
data file offset=0x440b8
data VA=0x46000
data length=0xa40
```

## 6. Dispatcher 分析

通过搜索 TCI command 常量与 dispatcher 逻辑定位：

```text
main dispatcher = 0x13b00
```

dispatcher 逻辑：

1. 从 TCI 开头读取 `cmd`。
2. 检查命令族 `0x0005xxxx`。
3. 对不同 command branch 到 handler。
4. handler 返回后写回 response bit 和 retcode。

关键命令映射：

```text
0x00050202 -> 0x1e430  # attest_keybox.so
0x00050204 -> 0x1e9a0  # attestation_ids.so
0x00050016 -> 0x13598  # close
```

## 7. `0x00050202` handler 分析

`0x1e430` handler：

```text
读取 TCI+0x0c 的 map info
验证 normal world mapped buffer
分配 heap buffer
memcpy(mapped encrypted attest_keybox.so -> heap)
调用 0x1de70(heap, len)
释放 heap
返回
```

`0x1de70` 函数：

```text
分配 plaintext buffer
调用 0x22738 解密 secure object
调用 0x1d9b8 parse plaintext keybox
释放 plaintext buffer
返回 ret
```

关键发现：

- 原始 TA 确实会在 secure world 中得到 plaintext keybox。
- 但 plaintext 只用于内部 parse，不会返回 normal world。
- 因此 direct client 对未 patch TA 发送 `0x00050202`，buffer before/after 完全一致。

## 8. 原生 direct client 验证

源码：

```text
<PROJECT_ROOT>/keymint_tee_client/kmtee_probe.c
```

未 patch TA 测试结果：

```text
mcOpenTrustlet ret=0x0
cmd 0x00050202 success tci_ret=0
cmd 0x00050204 success tci_ret=0
before/after buffer identical
```

结论：触发链路正确，但需要 patch TA 做明文导出。

## 9. Patch 思路形成

目标：不影响 TA 原始逻辑，最小侵入地把 plaintext 复制回 normal world mapped buffer。

可用寄存器/栈关系：

- `0x1de70` 中 plaintext buffer 和 plaintext length 存在栈上。
- `0x1e430` 中 mapped input 原始指针和 heap input buffer 仍可用。
- TA 内部有可复用 `memcpy`：`0x50f0`。
- text 区有 code cave：`0x411ac`。

Patch 分两段：

### 第一段：parse 前保存 plaintext

在 `0x1df3c` 原本准备调用 `0x1d9b8` parse plaintext 前跳到 code cave：

```text
memcpy(input_heap, plaintext, plaintext_len)
call original parse 0x1d9b8
return original flow at 0x1df44
```

### 第二段：handler 返回前写回 mapped buffer

在 `0x1e4d4` 原本 `mov w19,w0` 后跳到 code cave：

```text
if ret == 0:
    memcpy(mapped_input, input_heap, original_len)
return original flow at 0x1e4d8
```

这样 normal world 读取 mapped buffer 即得到明文 keybox 前缀。

## 10. Patch 实现

脚本：

```text
<PROJECT_ROOT>/analysis/patch_0706_dump.py
```

生成：

```text
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

哈希：

```text
original TA sha256=ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
patched  TA sha256=92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

## 11. 设备验证

运行方式：

```bash
adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

运行结果：

```text
tl=281651 keybox=8716 ids=892
mcOpenTrustlet ret=0x0
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

输出文件：

```text
<PROJECT_ROOT>/keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

该文件从 encrypted blob 变为明文结构：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 30 13 ...
```

## 12. 明文 keybox 结构分析

解析结果：

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

含义：

- keybox 中有一套 EC attestation private key。
- keybox 中有一套 RSA attestation private key。
- 两套 key 分别有 leaf/intermediate/root 三段 cert。
- 剩余 92 字节是原 mapped buffer 中未覆盖尾部，不属于解析出的明文 keybox 主体。

## 13. 证据验证

### 13.1 私钥与 cert0 匹配

```text
EC private public hash  = 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
EC cert0 public hash    = 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90

RSA private public hash = f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
RSA cert0 public hash   = f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

### 13.2 证书链有效

```text
openssl verify EC chain:  extracted_keybox/ec_cert_0.pem: OK
openssl verify RSA chain: extracted_keybox/rsa_cert_0.pem: OK
```

### 13.3 签名验证有效

```text
EC private key sign -> EC cert0 public key verify: Verified OK
RSA private key sign -> RSA cert0 public key verify: Verified OK
```

### 13.4 与 Android Keystore 实际触发链对应

标准 `kmprobe` 生成的 chain：

```text
kmprobe EC cert0 = generated key leaf
kmprobe EC cert1 = extracted EC cert0
kmprobe EC cert2 = extracted EC cert1
kmprobe EC cert3 = extracted root

kmprobe RSA cert0 = generated key leaf
kmprobe RSA cert1 = extracted RSA cert0
kmprobe RSA cert2 = extracted RSA cert1
kmprobe RSA cert3 = extracted root
```

这证明提取的是 KeyMint factory attestation keybox。

## 14. 最终判断

分析链路闭合：

```text
HAL 明文路径 -> TCI cmd -> TA dispatcher -> keybox handler -> secure object decrypt -> plaintext copy-out -> DER parser -> key/cert 验证 -> AndroidKeyStore chain 对照
```

本 CTF 目标已完成。
