# KeyMint Attestation Keybox 提取：必要实现流程记录

项目根目录：`<PROJECT_ROOT>`

## 1. 目标定义

本课题目标是提取 Android Keystore / KeyMint attestation keybox，即用于硬件密钥认证链路的本地 factory attestation 私钥与证书链。

明确排除：

- Widevine DRM keybox
- MediaDrm 触发路径
- `WVCdm` / `e97c270e` / DRM trustlet

最终有效对象：

```text
<PROJECT_ROOT>/device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
<PROJECT_ROOT>/device_dump/persist/attest_keybox.so
<PROJECT_ROOT>/device_dump/persist/attestation_ids.so
```

## 2. 设备基础条件

设备：Nothing Phone (2a) / A142 / Pacman / MT6886 / Android 14 / NOS U2.5-240114-2323。

必须满足：

1. Bootloader 已解锁。
2. 当前 slot 为 `_a`。
3. `tee-1-1`、`keystore2`、KeyMint HAL 正常运行。
4. 有 Magisk root。
5. 已刷入可加载 modified trustlet 的 patched TEE。

实测状态：

```text
serial=<TARGET_SERIAL>
ro.product.device=Pacman
ro.hardware=mt6886
ro.build.display.id=U2.5-240114-2323
ro.boot.slot_suffix=_a
ro.boot.verifiedbootstate=orange
init.svc.tee-1-1=running
init.svc.keystore2=running
su uid=0(root) context=u:r:magisk:s0
```

## 3. 启动链与 TEE 准备

### 3.1 fenrir / LK patch

使用 fenrir minimal patch 让解锁状态下 preloader 接受修改过的 bl2_ext / LK。

已验证产物：

```text
<PROJECT_ROOT>/pacman-fenrir-minimal.bin
```

作用：证明并利用 seccfg=unlock 时 preloader 对 bl2_ext 验签策略的缺陷。

### 3.2 t-base 签名校验 bypass

已验证产物：

```text
<PROJECT_ROOT>/tee-patched-A-only.img
```

作用：让 Trustonic t-base 接受后续 modified TA。

必要限制：

- 只使用 `tee-patched-A-only.img`。
- 不使用早期 A+B 补丁的 `tee-patched.img`。
- 不混刷 U2.6 TEE 到 U2.5 系统。

## 4. KeyMint / RKP 判定

用标准 Android Keystore attestation 触发器验证：

```text
<PROJECT_ROOT>/keymint_trigger/build/kmprobe.apk
```

观察到：

```text
keystore2 先调用 get_rkpd_attestation_key()
rkpdapp 尝试访问 remoteprovisioning.googleapis.com
RKP 失败后 fallback，本地 TEE attestation chain 生成成功
EC chain length=4
RSA chain length=4
```

结论：设备支持/优先尝试 RKP，但本次可提取的是本地 TEE factory attestation keybox。

## 5. HAL 到 TA 命令路径

KeyMint HAL：

```text
<PROJECT_ROOT>/device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic
```

HAL 明文引用：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
TEE_AttestIds
```

TCI 命令：

```text
0x00050202: 加载/处理 attest_keybox.so
0x00050204: 加载/处理 attestation_ids.so
0x00050016: close
```

TCI 结构：

```text
TCI size = 0x140
TCI[0x00:0x04] = cmd
TCI[0x04:0x08] = TA return code
TCI[0x0c:0x14] = mcBulkMap_t {sVirtualAddr, sVirtualLen}
```

## 6. 逆向定位 KeyMint TA

目标 TA：

```text
<PROJECT_ROOT>/device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
sha256=ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
```

MCLF 映射：

```text
text file offset 0xd0 -> VA 0x1000
text length 0x43fe8
file offset = VA - 0x1000 + 0xd0
```

关键 dispatcher 与 handler：

```text
0x13b00: main TCI dispatcher
0x00050202 -> 0x1e430
0x00050204 -> 0x1e9a0
0x00050016 -> 0x13598
```

`0x00050202` 关键链路：

```text
0x1e430
  -> 从 TCI+0x0c 取 map 信息
  -> copy mapped encrypted attest_keybox.so 到 heap
  -> call 0x1de70(heap, len)

0x1de70
  -> allocate plaintext buffer
  -> call 0x22738 解密 secure object
  -> call 0x1d9b8 parse plaintext keybox
  -> free plaintext
```

## 7. TA patch 实现

Patch 脚本：

```text
<PROJECT_ROOT>/analysis/patch_0706_dump.py
```

Patch 产物：

```text
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
sha256=92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

Patch 目标：把 `0x22738` 解出的 plaintext keybox 写回 normal world 可读的 mapped buffer。

Patch 点：

```text
0x1df3c -> branch 0x411ac
  在 parse 前执行 memcpy(input_heap, plaintext, plaintext_len)

0x1e4d4 -> branch 0x411cc
  在 handler 返回前执行 memcpy(mapped_input, input_heap, original_len)
```

Code cave：

```text
0x411ac
调用 TA 内部 memcpy: 0x50f0
```

## 8. Direct client 实现

源码：

```text
<PROJECT_ROOT>/keymint_tee_client/kmtee_probe.c
```

作用：

1. 直接 `mcOpenTrustlet()` 加载指定 TA 字节。
2. 读取 persist blob。
3. 发送 `0x00050202` 和 `0x00050204`。
4. 保存 TCI 和 mapped buffer 返回后的内容。

优点：

- 不需要替换 `/vendor/app/mcRegistry`。
- 不需要停止系统 KeyMint HAL。
- 不需要 bind mount。
- 单次运行、可控、低风险。

## 9. 提取与拆分

probe 输出：

```text
<PROJECT_ROOT>/keymint_tee_client/out_patched/attest_keybox_buf_after.bin
```

拆分脚本：

```text
<PROJECT_ROOT>/analysis/extract_keybox_plain.py
```

最终产物：

```text
<PROJECT_ROOT>/extracted_keybox/attestation_keybox_plain.bin
<PROJECT_ROOT>/extracted_keybox/ec_private_key.der
<PROJECT_ROOT>/extracted_keybox/ec_private_key.pem
<PROJECT_ROOT>/extracted_keybox/ec_cert_0.der
<PROJECT_ROOT>/extracted_keybox/ec_cert_1.der
<PROJECT_ROOT>/extracted_keybox/ec_cert_2.der
<PROJECT_ROOT>/extracted_keybox/rsa_private_key.der
<PROJECT_ROOT>/extracted_keybox/rsa_private_key.pem
<PROJECT_ROOT>/extracted_keybox/rsa_cert_0.der
<PROJECT_ROOT>/extracted_keybox/rsa_cert_1.der
<PROJECT_ROOT>/extracted_keybox/rsa_cert_2.der
<PROJECT_ROOT>/extracted_keybox/keybox.xml
```

## 10. 验证标准

必须同时满足：

1. TA probe 返回成功。
2. `attest_keybox_buf_after.bin` 开头出现 DER 结构。
3. 能按结构拆出 EC/RSA private key + cert chain。
4. 私钥公钥 hash 与 cert0 公钥 hash 一致。
5. `openssl verify` 证书链 OK。
6. 私钥签名、cert0 公钥验签 OK。
7. 提取出的 cert0/cert1/root 与标准 `kmprobe` attestation chain 的 cert1/cert2/cert3 对应。

已验证结果：

```text
EC private pub == EC cert0 pub: 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA private pub == RSA cert0 pub: f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
EC chain verify: OK
RSA chain verify: OK
EC sign verify: Verified OK
RSA sign verify: Verified OK
```
