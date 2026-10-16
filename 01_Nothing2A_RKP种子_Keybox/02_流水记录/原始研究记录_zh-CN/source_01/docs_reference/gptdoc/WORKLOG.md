# KeyMint / Keystore Attestation Keybox 提取：工作全流程记录

## 当前结论

已完成 CTF 主目标：从 Nothing Phone (2a) / Pacman / MT6886 的 Trustonic KeyMint TA 路径中 dump 出本地 TEE factory attestation keybox，并拆分出 EC/RSA attestation private key 与证书链。

最终产物：

```text
extracted_keybox/attestation_keybox_plain.bin
extracted_keybox/ec_private_key.der / .pem
extracted_keybox/ec_cert_0.der .. ec_cert_2.der
extracted_keybox/rsa_private_key.der / .pem
extracted_keybox/rsa_cert_0.der .. rsa_cert_2.der
extracted_keybox/keybox.xml
```

验证结果：

```text
EC private pub == EC cert0 pub
RSA private pub == RSA cert0 pub
EC/RSA cert chain verify OK
EC/RSA private key sign -> cert0 pub verify OK
extracted cert0/1/root 对应 kmprobe attestation chain 的 cert1/2/3
```

## 方向纠偏

Widevine keybox 与 Android Keystore / KeyMint attestation keybox 不是一个东西。  
之前 `MediaDrm` / `WVCdm` / `e97c270e` 方向只能证明 DRM 路径可触发，不能满足本题目标。

正确主线：

```text
/vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
```

## 设备与环境

```text
serial=<TARGET_SERIAL>
model=A142
product=PacmanEEA
device=Pacman
build=U2.5-240114-2323
Android=14 / SDK 34
slot=_a
verifiedbootstate=orange
tee-1-1=running
keystore2=running
root=/system_ext/bin/su uid=0(root) context=u:r:magisk:s0
```

已验证基础：

```text
pacman-fenrir-minimal.bin      # patched LK / fenrir minimal，可启动
tee-patched-A-only.img         # t-base signature bypass，可启动
```

## RKP 判定

设备存在：

```text
android.hardware.security.keymint.IKeyMintDevice/default
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
remote_provisioning
com.android.rkpdapp
```

用 `keymint_trigger/build/kmprobe.apk` 触发 Android Keystore attestation 后观察到：

```text
keystore2 -> Calling get_rkpd_attestation_key()
rkpdapp -> remoteprovisioning.googleapis.com
OUT_OF_KEYS_TRANSIENT_ERROR / 网络失败
随后 EC/RSA attestation chain 仍生成成功，chain length=4
```

结论：设备优先尝试 RKP；当前无可用 RKP key / 联网失败时 fallback 到本地 TEE factory attestation chain。本题提取的是本地 factory attestation keybox。

## HAL / TA 逆向要点

HAL 明文引用：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
TEE_AttestIds
TEE_GenerateAndAttestKey
TEE_AttestKey
TEE_ImportAndAttestKey
TEE_GenerateCertificateRequest
```

HAL `TEE_AttestIds` 行为：

```text
cmd 0x00050202 + mapped attest_keybox.so
cmd 0x00050204 + mapped attestation_ids.so
TCI size = 0x140
TCI[0x00] = cmd
TCI[0x0c:0x14] = mcBulkMap_t {sVirtualAddr, sVirtualLen}
TCI[0x04] = TA return code
```

KeyMint TA layout：

```text
file: device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
sha256: ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
MCLF text file offset 0xd0 -> VA 0x1000
text length 0x43fe8
```

关键字符串：

```text
KEYMINT
Verify Keybox fail (%d)!
Decrypting keybox is success!
Verify Keybox Signature...
verify_keybox
decrypt_keybox
rkp_bcc_km
```

Dispatcher：

```text
0x13b00: main TCI command dispatcher
0x00050202 -> 0x1e430  # attest_keybox.so loader
0x00050204 -> 0x1e9a0  # attestation_ids.so loader
0x00050016 -> 0x13598  # close
```

`0x00050202` handler flow：

```text
0x1e430:
  read map info from TCI+0x0c
  validate mapped buffer via 0xe470
  allocate heap buffer
  memcpy(mapped attest_keybox.so -> heap)
  call 0x1de70(heap, len)

0x1de70:
  allocate plaintext buffer
  call 0x22738(input encrypted blob, len, plaintext_out, plaintext_len)
  call 0x1d9b8(plaintext, plaintext_len) to parse/store keybox globals
  free plaintext
```

## Patch 设计与实现

目标：不替换系统 `/vendor`，只让 direct client 加载 patched TA，并把 `0x22738` 解密后的 plaintext keybox 复制回 caller mapped buffer。

Patch 文件：

```text
analysis/patch_0706_dump.py
patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
sha256=92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

Patch 点：

```text
0x1df3c -> branch 0x411ac
  在 0x1d9b8 parse 前：memcpy(input_heap, plaintext, plaintext_len)
  再回到 0x1df44 走原逻辑

0x1e4d4 -> branch 0x411cc
  0x1de70 返回后：如果 ret==0，memcpy(mapped_input, input_heap, original_len)
  再回到 0x1e4d8 走原 free/return 逻辑
```

Code cave：`0x411ac`，占用原 text 内连续 0 字节区，调用 TA 内部 `memcpy` (`0x50f0`)。

## Direct client

`keymint_tee_client/kmtee_probe.c` 已改成支持 argv 指定 TA 路径：

```bash
/data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
```

这样不需要 bind mount、不需要 stop/start system KeyMint HAL、不需要改 `/vendor`。

## 设备运行结果

命令：

```bash
adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

输出摘要：

```text
tl_path=/data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
tl=281651 keybox=8716 ids=892
mcOpenTrustlet ret=0x0 sessionId=0x1101
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

本地输出目录：

```text
keymint_tee_client/out_patched/
```

关键哈希：

```text
attest_keybox_before.bin     64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69
attest_keybox_buf_after.bin  de421186ae164c9d966f5a313ff5935a477366092890a91d26ee9f6322975ca7
attestation_ids_buf_after    5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74
```

`attest_keybox_buf_after.bin` 开头：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 30 13 ...
```

说明 mapped buffer 已被 patched TA 写回明文 keybox 前缀。

## 明文拆分

脚本：

```text
analysis/extract_keybox_plain.py
```

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

证书摘要：

```text
EC cert0 subject:  title=TEE, serialNumber=325d90cd5049b6c519af32bc6a413526
EC cert0 issuer:   title=TEE, serialNumber=aa3d661ed0862f74108b03a8dd8abb3e
EC cert1 subject:  title=TEE, serialNumber=aa3d661ed0862f74108b03a8dd8abb3e
Root subject:      serialNumber=f92009e853b6b045

RSA cert0 subject: title=TEE, serialNumber=325d90cd5049b6c519af32bc6a413526
RSA cert0 issuer:  title=TEE, serialNumber=aa3d661ed0862f74108b03a8dd8abb3e
RSA cert1 subject: title=TEE, serialNumber=aa3d661ed0862f74108b03a8dd8abb3e
Root subject:      serialNumber=f92009e853b6b045
```

验证：

```text
EC private pub hash  = EC cert0 pub hash  = 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA private pub hash = RSA cert0 pub hash = f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
openssl verify EC chain:  OK
openssl verify RSA chain: OK
EC/RSA sign verify:       Verified OK
```

与 `keymint_trigger/out/*` 对照：

```text
extracted_keybox/ec_cert_0.der  == keymint_trigger/out/ec_cert_1.der
extracted_keybox/ec_cert_1.der  == keymint_trigger/out/ec_cert_2.der
extracted_keybox/ec_cert_2.der  == keymint_trigger/out/ec_cert_3.der
extracted_keybox/rsa_cert_0.der == keymint_trigger/out/rsa_cert_1.der
extracted_keybox/rsa_cert_1.der == keymint_trigger/out/rsa_cert_2.der
extracted_keybox/rsa_cert_2.der == keymint_trigger/out/rsa_cert_3.der
```

这证明提取出的正是本地 TEE attestation keybox 中的 EC/RSA attestation key 与链。

## 收尾状态

- 没有替换设备 `/vendor` 文件。
- 没有重新刷机。
- patched TA 只由 direct client 作为字节加载。
- probe 后设备服务健康：

```text
tee-1-1=running
keystore2=running
android.hardware.security.keymint@2.0-service.trustonic running
vendor.trustonic.tee@1.1-service running
```

## 后续可选

1. 如需提交/导入格式，优先使用 `extracted_keybox/keybox.xml`。
2. 如需进一步完整性分析，可逆向 `attestation_ids.so` 的 `0x00050204 -> 0x1e9a0 -> 0x1e670` 路线；本题 keybox 主目标已完成。
3. 如果要对系统 HAL 生效，可再做 Magisk bind mount 替换 TA，但当前提取不需要，不建议作为复现主线。

## 2026-08-15 RKP pool dump

已从当前连接设备只读 dump `/data/user/0/com.android.rkpdapp/databases/rkpd_database`、`-wal`、`-shm` 和 RKPD shared prefs，输出目录：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725
```

结论：`provisioned_keys` 当前 12 条，3 条已有 `client_uid/key_id`，9 条未分配。每条包含 216B opaque `key_blob`、64B P-256 raw public key、4 张 DER RKP certificate chain；12/12 leaf public key 均匹配 DB `public_key`，12/12 openssl chain verify OK。详细记录见：

```text
<PROJECT_ROOT>/outputdoc/07_RKP_POOL_DUMP_20260815.md
```

## 2026-08-15 RKP dump directory cleanup

已新增整理后的 RKP dump 入口：

```text
<PROJECT_ROOT>/rkp_dumps
```

目录结构：一条 RKP provisioned key 一个文件夹，例如：

```text
rkp_dumps/rkp_00_rowid1_uid1017_keyid10138/key.xml
rkp_dumps/rkp_01_rowid2_uid1017_keyid10220/key.xml
...
rkp_dumps/rkp_11_rowid12_uidnone_keyidnone/key.xml
```

每个文件夹内包含 XML 格式 key、metadata、opaque key_blob、公钥、证书链、拆分证书和 openssl verify 输出。顶层有 `manifest.json`、`all_rkp_keys.xml`、`README.md`。原始取证目录 `rkp_research/current_device_dump_20260815_150725/` 保留不动。
## 2026-08-15 Google RKP attestation key capture attempt

Run dir:

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635
```

Validated `rkp_ptr196` patched KeyMint TA via direct probe: leaked 196B RKP keygen object, scalar at offset `0x98`, derived P-256 public key matches generated RKP public key for prod/test. Temporarily bind-mounted system UUID patched TA, restarted `vendor.keymint-trustonic`, backed up RKPD app data, cleared RKPD DB, woke BootReceiver, forced new RKPD jobs 26/27. Provisioning failed before Google cert issuance because the device had no Android default network (`Active default network: none`; RKPD DNS error for `remoteprovisioning.googleapis.com`). Restored original TA and RKPD DB from backup. Restored state verified: original TA SHA256 `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`, RKPD DB 12 rows of 216B opaque key_blob, `cmd remote_provisioning dump` OK. Full runbook: `outputdoc/08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md`.

## 2026-08-15 Current CTF / Google RKP target progress document

已新增当前 CTF/RKP 目标总进展文档：

```text
<PROJECT_ROOT>/outputdoc/09_CURRENT_CTF_RKP_PROGRESS_20260815.md
```

内容覆盖：factory keybox 成果、RKPD/RKP pool dump、`rkp_ptr196` patched TA 泄漏点、Google RKP provisioning capture 尝试、网络阻塞原因、恢复状态、继续执行计划和成功后的预期输出目录。同时清理并更新：

```text
<PROJECT_ROOT>/outputdoc/00_INDEX.md
```

## 2026-08-15 RKP capture continuation after network restored

网络恢复后已继续执行：

- `google_rkp_keydump_retry_20260815_161025`：原 helper 路线失败，根因是 RKPD app 子路径 SELinux label 为 `system_data_file`，WorkManager DB 被拒绝访问。
- `google_rkp_keydump_retry_pmclear_20260815_161655`：pm clear 路线修复 app data context，RKPD app 能启动，但 HAL 报 `TrustonicKeymintDeviceImpl: generate_ecdsa_p256_key: Invalid session handle`，`provisioned_keys=0`。
- 清理后原 TA hash 已恢复 `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`，无 bind mount，RKPD app data context 正常。
- 下一步需用户明确授权重启 `tee-1-1` / `vendor.keymint-trustonic` / `keystore2` 服务链，或重启设备，再重跑 pmclear helper。

最终只读核验：原 TA hash 为 `ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`，无 `070600` bind mount，RKPD app data context 为 `u:object_r:privapp_data_file:s0:c512,c768`。`cmd remote_provisioning dump` 正常，但 `cmd remote_provisioning csr default` 仍返回 code 1，logcat 为 `TrustonicKeymintDeviceImpl: generate_certificate_request: Invalid session handle`。

## 2026-08-15 16:41 RKP CTF current progress snapshot

已按当前证据输出进展快照：

```text
<PROJECT_ROOT>/outputdoc/10_RKP_CURRENT_PROGRESS_SNAPSHOT_20260815_164139.md
```

最新状态：网络可用，system RKPD 已进入 provisioning 并请求生成 12 条 key，但在 `IRemotelyProvisionedComponent.generateCertificateRequest` 阶段返回 `code 5`。根因判断为 `rkp_ptr196` 替换了 CSR 所需的原始 opaque private handle。下一步改 direct-only side-channel 补丁：保留 private handle，同时把 196B keygen object 额外写到 direct private mapped buffer 的尾部，然后验证 scalar 与 public key 匹配，再推进 `0x50402` CSR direct flow。

## 2026-08-15 16:47 RKP direct-only sideleak verified

实现并验证 direct-only side-channel 补丁：`patch_0706_rkp_sideleak.py`。TDD 测试 `test_rkp_sideleak_patch.py` 先失败于脚本缺失，再通过。设备验证 run：

```text
<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431
```

结果：prod/test `0x50401` 均成功，`priv_len=216`，保留 stock private handle；`private_full+0x400` 成功泄漏 196B object，`+0x98` scalar 与 public MacedPublicKey 匹配；生成的 debug PEM 可 openssl sign/verify。下一步转向 direct `0x50402` CSR。



---

## 2026-08-15 17:05:19 CST 更新：direct CSR/signCertificates 当前状态

详见快照：`<PROJECT_ROOT>/outputdoc/11_RKP_PROGRESS_SNAPSHOT_20260815_170519.md`

- 新增 `rkp_research/build_and_send_signcerts.py` 与 `rkp_research/test_build_signcerts.py`，按 RKPD 旧流程构造 `MacedKeysToSign` 与最终 `CertificateRequest`。
- `curve=2 + testMode=1` direct CSR 已确认成功：`dev_len=198`、`protected_len=433`、`maced_keys_len=32`。
- 用该 CSR 构造出的 `certificate_request.cbor` 长度为 `877`，sideleak scalar 与 public key 验证为 `true`。
- 已向 Google `v1:signCertificates` 提交，请求目录：`<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send`。
- Google 返回 `HTTP 400 Bad Request`，错误：`Invalid request payload: Failed to verify certificate chain`。
- 额外复测 `4d` production key + Google curve2：TA CSR 返回 `0xfffe795b` / signed `-100005`，未得到 production CSR。
- 下一步重点：解析 `ProtectedData` 内部链/根，追踪 `-100005` 路径，解决 production CSR 或 Google chain 验证问题。
