# RKP CTF Live Worklog - 2026-08-15

目标：完成 CTF RKP 小题，取得 RKP 申请下来的 attestation private key 与短期 attestation certificate chain。路线不限：

1. 直接从设备/TEE/RKPD 流程提取；或
2. 提取关键身份/CSR 信息后向 Google RKP endpoint 申请；或
3. 两者结合：side-channel 获取 private scalar，正常/复刻 RKP 获取 cert chain。

要求：每一步最大化记录，便于追溯、重放、复盘。

## 阶段 0：当前已知状态

- factory KeyMint keybox 已完成；不是本阶段最终目标。
- RKP pool dump 已有 12 条 Google provisioned keys，但 DB 中是 opaque 216B key_blob，不能直接得到 scalar。
- direct sideleak 补丁已能在 `GenerateEcdsaP256KeyPair` 保留 216B handle 的同时，从 private buffer `+0x400` 泄漏 196B keygen object。
- object `0x98..0xb7` 是 P-256 scalar，已验证 `scalar * G == MacedPublicKey public`。
- `testMode=1 + curve2` 可生成 CSR，但 ProtectedData recipient 不等于 Google curve2 EEK，Google signCertificates 返回 400。
- `testMode=0 + curve2` 目前 TA CSR 阶段返回 `0xfffe795b` / signed `-100005`。
- 2026-08-15 本轮新增自动诊断：`build_and_send_signcerts.py` 已能记录 recipient ↔ Google EEK 是否匹配。

## 阶段 1：本轮执行记录


### 2026-08-15 23:02 基线采集

命令：

```bash
adb devices
adb shell 'su -c "date; getprop ro.product.device; getprop ro.product.model; getprop ro.build.fingerprint; getprop init.svc.tee-1-1; getprop init.svc.vendor.keymint-trustonic; getprop init.svc.keystore2; sha256sum /vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin; cmd remote_provisioning dump; cmd connectivity airplane-mode; dumpsys connectivity | grep \"Active default network\"; ping -c 1 -W 3 remoteprovisioning.googleapis.com"'
```

结果摘要：

- adb device：`<DEVICE_SERIAL> device`
- device/model：`Pacman / A142`
- fingerprint：`Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`
- `tee-1-1` / `vendor.keymint-trustonic` / `keystore2`：均 running
- stock system TA hash：`ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2`
- `cmd remote_provisioning dump`：Trustonic, hwVersion=2, supportedEekCurve=2, supportedNumKeysInCsr=4
- airplane mode disabled；Active default network 101；`remoteprovisioning.googleapis.com` ping OK
- RKPD app data SELinux label：`privapp_data_file:s0:c512,c768`
- 设备端无 `sqlite3`，后续 DB 检查需 tar/pull 到主机。

结论：设备当前处于安全可继续实验状态；网络阻塞已不存在；system TA 当前为原版。

### 2026-08-15 23:03 stock `cmd remote_provisioning csr default` 基线

命令：

```bash
adb shell 'su -c "logcat -c; cmd remote_provisioning csr default 2>&1; logcat -d -v time | grep -iE ..."'
```

结果：

```text
android.os.ServiceSpecificException: (code 1)
IRemotelyProvisionedComponent$Stub$Proxy.generateCertificateRequest
shell_status=0
08-15 23:03:30.586 E/TlcKM: (keymaster_error_t)tci->response.header.returnCode == -38
08-15 23:03:30.586 E/TlcKM: transact(session_handle, tci) == -38
```

解释：stock system shell CSR 在当前状态下也失败，但错误码是 `-38`，而 direct production CSR 失败是 `-100005` / `0xfffe795b`。所以 `cmd remote_provisioning csr default` 不能作为“production CSR 能成功”的直接参照。后续需比较 RKPD app 正常 provisioning path 与 shell CSR path 的输入差异，不能只看 shell command。

## 阶段 2：解决 ProtectedData 绑定非 Google EEK / test EEK root

目标：先尝试不改设备/TA 的方式，用现有 testMode CSR 产物模拟/变体构造 Google `signCertificates` 请求，验证外层请求是否有机会绕过当前 `ProtectedData recipient != Google EEK` 问题；如果全部失败，则把结论固化为“必须让 TA 生成绑定 Google EEK 的 ProtectedData 或 patch/控制 EEK root 分支”。

计划：

1. 保留现有成功 CSR 三段：`DeviceInfo`、`ProtectedData`、`MacedKeysToSign MAC`。
2. 枚举外层请求变体：challenge 放 query/body、challenge 是否 bstr、UnverifiedDeviceInfo 是否为空/含 fingerprint、MacedKeysToSign 是否使用 COSE_Key payload raw、是否复用 TA 原始 MacedPublicKey。
3. 每次仅改变一个外层变量，记录 request sha256、长度、HTTP status、Google error。
4. 若错误始终是 `Failed to verify certificate chain`，说明 Google 已解析顶层但无法解密/验证 ProtectedData 内链，外层变体不可解决 EEK mismatch。
5. 后续转向 TA/RKPD 输入和 EEK root 分支。


### 2026-08-15 23:19 外层 signCertificates 变体发送结果

目录：

```text
rkp_research/signcerts_variants_20260815_outer_probe_send
```

发送 5 个变体：

| variant | HTTP | Google message |
|---|---:|---|
| `rkpd_old_exact` | 400 | `Failed to verify certificate chain` |
| `rkpd_old_empty_unverified` | 400 | `Failed to verify certificate chain` |
| `v2_append_unverified` | 400 | `Invalid type of first item in the CSR. Expected Array or UnsignedInteger, found MAP` |
| `raw_maced_public_payload` | 400 | `Failed to verify certificate chain` |
| `challenge_as_array_item` | 400 | `CertificateRequest deserialization failure - cannot deserialize MacedKeysToSign and/or Challenge` |

结论：

- Google 能解析 `rkpd_old_exact`，并进入 certificate chain verification；外层 old-flow 结构基本正确。
- 修改 UnverifiedDeviceInfo 或 MacedKeysToSign payload 外形不能绕过失败。
- V2-like 和故意错误 challenge 会改变错误类型，证明服务端确实在按结构解析。
- 外层变体不能解决核心问题，下一步必须看 ProtectedData 内部链/BCC/root/testMode 语义。

### 2026-08-15 23:22 重要纠偏：recipient public X 不应等于 Google EEK X

复核 COSE_Encrypt 语义后，前一阶段“ProtectedData recipient public X 与 Google EEK public X 不一致，所以 TA 没用 Google EEK”的判断需要修正：

- recipient unprotected header `-1` 内的 COSE_Key 是 ECDH ephemeral public key，正常情况下不等于 Google EEK public key。
- recipient unprotected header `4` 是 `kid`，才是绑定目标 EEK 的关键线索。
- 当前 ProtectedData recipient 的 `kid` 前缀是 `d0aec115ca2acf73...`，和 Google curve2 EEK COSE_Key 中 label `2` 的 key id 一致。

因此当前失败更可能是：ProtectedData 已绑定 Google EEK，但其加密内容内的 BCC / device chain / test root 不被 Google 验证通过，而不是 EEK 没绑定。


### 2026-08-15 23:25 当前 RKPD DB 只读拉取

目录：`rkp_research/live_device_db_20260815_2325`

结果：

```text
rkpd_database size=4096 sha256=49308f75ab55d1b7f401bc53fc950cf126290e9dd6114da0f99a93fc665ab1e0
provisioned_keys count = 0
```

解释：当前设备 RKPD DB 已是空池状态。下一步用 stock TA 触发系统 RKPD 正常 provisioning，验证系统 path 是否能拿到 Google 短期 cert chain。如果能成功，再回到“如何在同一系统 keygen 时泄漏 scalar”。

### 2026-08-16 14:53 stock TA 系统 provisioning 基线成功

目录：`rkp_research/stock_rkpd_provision_20260816_145343`

前置状态：

```text
tee-1-1/vendor.keymint-trustonic/keystore2 = running
stock system TA sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
Active default network = 101
remoteprovisioning.googleapis.com ping OK
```

执行方式：不 bind mount、不替换 TA，仅 force-stop `com.android.rkpdapp`，广播 `BootReceiver`，然后 force run RKPD WorkManager 对应的 jobscheduler job。

结果：

```text
provisioned_keys count = 12
key_blob len = 216B for all rows
public_key len = 64B for all rows
cert count = 4 for all rows
leaf public key matches DB public key = 12/12
openssl verify OK = 12/12
```

新池有效期集中在：

```text
2026-08-26T17:59:27+00:00 .. 2026-08-26T18:26:50+00:00
```

证书链摘要：

```text
leaf subject example = /O=TEE/CN=347743f59ffe8bc5800205412eb504e0
leaf issuer = /O=Google LLC/CN=Droid CA3
root = /CN=Key Attestation CA1/OU=Android/O=Google LLC/C=US
```

分析产物：

```text
rkp_research/stock_rkpd_provision_20260816_145343/parsed/summary.json
rkp_research/stock_rkpd_provision_20260816_145343/parsed/row_table.md
rkp_research/stock_rkpd_provision_20260816_145343/parsed/openssl_verify_all.txt
```

结论：

- stock 系统 provisioning 链路可用，Google endpoint、RKPD app、production BCC/chain 都不是根因。
- direct production CSR 的 `0xfffe795b` / `-100005` 更可能来自 direct client 的 `0x50402` 输入/初始化状态没有完全复刻 RKPD/HAL 路径。
- 下一步应比较 stock RKPD/HAL 的 `GenerateEcdsaP256KeyPair -> GenerateCertificateRequest` 输入布局与 direct client 当前 `rkp_tee_probe_csr.c`，尤其是 `0x50402` 是否缺少 private handle/key-count 结构、batch size、endpoint/challenge framing 或会话内初始化状态。

### 2026-08-16 15:10 obj216 方案：direct 成功、system 失败、已恢复 stock 池

新增 patch 脚本：

```text
rkp_research/patch_0706_rkp_obj216.py
```

生成文件：

```text
patched_ta/0706000000000000000000000000004d.rkp_obj216.tlbin
sha256=e801e3aee4b9c00832d29f256fb9df1f84cbe61e778d995d69b6ce606f6a09e9

patched_ta/0706000000000000000000000000004e.rkp_obj216.tlbin
sha256=11424f83ba8551682a01bde5edb96971959958ca15083eee28e6d2331491712c
```

patch 意图：

- hook `0x21fe0`，code cave `0x411ec`。
- 将 keygen 内部 `*[sp,#216]` 指向的 196B 对象复制到 `private_out`。
- 保留 stock `private_len=216`，不再像早期 direct-only patch 那样把长度改成 196。
- 目的是测试系统 RKPD 是否只要求 `private_len=216`，同时能让 DB 中 `key_blob` 变成含 scalar 的对象。

direct UUID `4e` 验证目录：

```text
rkp_research/direct_obj216_20260816_145932
```

结果：

```text
prod: pub_len=119, priv_len=216, scalar matches public key
test: pub_len=125, priv_len=216, scalar matches public key
```

直接调用证明：`obj216[0x98..0xb7]` 仍是对应 P-256 public key 的 private scalar。

system UUID `4d` 验证目录：

```text
rkp_research/system_obj216_capture_20260816_150026
```

结果：

```text
provisioned_keys count = 0
TlcKM returnCode == -100005
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
```

重要结论：

- 只保持 `private_len=216` 不够，系统路径仍会在 CSR 阶段失败。
- RKPD app Java 层虽然只把 `MacedPublicKey[]` 传给 `generateCertificateRequest`，但 keygen 返回的 216B private blob 可能仍与 TA 内部 CSR 状态绑定，或 hook 在返回 blob 时破坏了后续 CSR 所需的 TA-side key handle/state。
- 后续不应继续把 returned private blob 直接替换成泄漏对象；更优先的方向是“保持 stock 返回完全不变，同时从另一个输出通道或系统层旁路记录 scalar”。

恢复 stock 状态：

```text
rkp_research/stock_restore_after_obj216_20260816_150410
stock 4d sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
vendor.keymint-trustonic = running
provisioned_keys count = 12
key_blob len = 216B for all rows
public_key len = 64B for all rows
new expiration window = 2026-08-27T09:26:36Z .. 2026-08-27T09:54:09Z
```

下一步候选：

1. 找 keygen 结束附近是否有第二个 caller-controlled output buffer、log/debug copy、或不会被 RKPD/HAL 使用的 padding 区，可用来旁路写出 196B 对象，同时保持 stock private blob 不变。
2. 若 TA 内无安全输出通道，改走 system app/HAL 插桩：让 stock TA 正常 provision，记录 `MacedPublicKey`、DB row、以及可从 direct path 验证的对象布局，避免破坏 CSR。
3. 复核 direct `0x50402` 和 HAL `GenerateCertificateRequest` 的 exact TCI buffer/计数/端点布局，解释为什么 stock RKPD 成功而 direct prod CSR 返回 `-100005`。

### 2026-08-16 17:44 recopy-stock control：direct 成功，no-restart system 成功但结论需降级

新增 patch 脚本：

```text
rkp_research/patch_0706_rkp_recopy_stock.py
```

生成文件：

```text
patched_ta/0706000000000000000000000000004d.rkp_recopy_stock.tlbin
sha256=090c2ae6c2b8f10e5bc85fd905963a4fba7580b1462d6061e94e098c28a34313

patched_ta/0706000000000000000000000000004e.rkp_recopy_stock.tlbin
sha256=60ad15c49cbc86d06e18c57588e434fa2b82a2da9635a4e7336d02601206860a
```

意图：hook 同一 keygen success path，只把 stock private blob 再复制回 `private_out`，不改变返回内容和长度。

direct 验证目录：

```text
rkp_research/rkp_recopy_direct_20260816_174438
```

结果：

```text
prod/test private_len = 216
private first bytes = 01020000...
```

system no-restart 目录：

```text
rkp_research/system_recopy_stock_norestart_20260816_175253
```

结果：RKPD 成功 provision 12 条，`key_blob=216B`。

更正：这个 system no-restart 成功只能证明“bind 后不重启不会破坏已加载的 stock 会话”，不能证明 patched TA 在系统路径可用。后续 loaded-TA/no-op 实验证明，只要系统 CSR 实际加载修改过的 production `4d` TA，就会失败。

### 2026-08-16 17:58 biglen / HAL capacity / live HAL mem patch

新增 TA patch：

```text
rkp_research/patch_0706_rkp_sideleak_biglen.py

patched_ta/0706000000000000000000000000004d.rkp_sideleak_biglen.tlbin
sha256=9215e513c2c0ef730ffe94cce7db0f9175fbab9020c9fad548b523ceccd106a5

patched_ta/0706000000000000000000000000004e.rkp_sideleak_biglen.tlbin
sha256=9628e4bb1dd9b63c8f72d1001832b9fe29783209b1526b972884338caa96f561
```

逻辑：

- 保留前 216B stock private blob。
- 把 196B keygen object 写到 `private_out+0x400`。
- 将 TCI `private_len` 改为 `0x4c4`，希望 normal world 能带出侧漏尾部。

新增 HAL patch：

```text
rkp_research/patch_keymint_hal_rkp_privcap.py

patched_hal/android.hardware.security.keymint@2.0-service.trustonic.rkp_privcap_0x600
sha256=9549fe9c7fac42f5a445760a98874d1f8734163e0ac4a4fd038e1bbe149e8c91
```

HAL 修改点：

```text
file off 0x1d1b0: mov w8,#228 -> mov w8,#0x600
file off 0x1d1b8: mov w1,#228 -> mov w1,#0x600
```

direct 验证目录：

```text
rkp_research/direct_sideleak_biglen_20260816_175842
```

结果：

```text
prod/test private_len = 1220
前 216B 仍是 stock-looking private handle
private_out+0x400 处对象 first16 = 3c000000070000000a00001001000000
scalar matches public key
```

system HAL 文件 bind 尝试：

```text
rkp_research/system_sideleak_biglen_20260816_175908
rkp_research/system_sideleak_biglen_chmod_20260816_180304
```

结果：从 `/data/local/tmp` bind HAL binary 后 init/SELinux 不允许执行，出现 `nosuid_transition` / `execute_no_trans`，不可作为系统 HAL patch 方式。

可行替代：`/proc/$pid/mem` 可以在线 patch running HAL text mapping。已验证：

```text
before 0x1d1b0 = 881c8052
after  0x1d1b0 = 08c08052
before 0x1d1b8 = 811c8052
after  0x1d1b8 = 01c08052
```

system biglen + live HAL mem patch：

```text
rkp_research/system_sideleak_biglen_memhal_20260816_180805
rkp_research/system_sideleak_biglen_tarestart_memhal_20260816_181213
```

结果：

- no TA restart：DB 仍是 12 条 216B，基本仍在使用已加载 stock TA，会话未切到 patched TA。
- TA restart + HAL mem patch：DB 0，CSR 失败。

关键日志：

```text
TlcKM returnCode == -100005
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
```

结论：`private_len` 暴露为 1220 会破坏系统 CSR；即使 HAL 容量常量在线改大，系统 production path 仍不能接受这种 returned private blob 形态。

### 2026-08-16 18:19 stock-length sideleak + HAL memscan

新增运行脚本：

```text
rkp_research/run_system_sideleak_memscan.py
```

脚本动作：

1. bind `rkp_sideleak` TA，重启 KeyMint。
2. 在线 patch HAL private capacity 为 `0x600`。
3. 触发 RKPD provisioning。
4. provisioning 后扫描 HAL `rw-p` mappings，寻找对象签名 `3c000000070000000a00001001000000`，并用 `scalar -> public_xy` 匹配 DB public key。
5. finally 恢复 stock TA 并重启 KeyMint。

有效运行目录：

```text
rkp_research/system_sideleak_stocklen_memscan_20260816_181909
```

HAL mem patch 成功：

```text
pid = 18204
base = 0x57fa6af000
0x1d1b0 before 881c8052 after 08c08052
0x1d1b8 before 811c8052 after 01c08052
```

结果：

```text
db_rows = 0
hits = 0
matched_rowids = []
regions_scanned = 76
```

关键日志：

```text
RkpdProvisioner: Requested number of keys for provisioning: 12
TlcKM returnCode == -100005
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
```

结论：即便 app-visible `private_len` 保持 216，系统 CSR 只要实际加载 patched production `4d` TA 仍会失败；因此这条 memscan 路线不能依赖修改 production TA 来生成系统证书。

### 2026-08-16 18:22 loaded-TA recopy/no-op controls：production 4d TA 字节 patch 本身会触发 CSR 失败

新增通用 loaded-TA control 脚本：

```text
rkp_research/run_system_recopy_restart_control.py
```

它使用已验证可读的 `mobicore_vendor_file` label，bind patched TA 后重启 KeyMint，确保系统实际加载 patched TA，再触发 RKPD。

recopy-stock loaded-TA control：

```text
rkp_research/system_recopy_restart_control_20260816_182240
bind TA sha256 = 090c2ae6c2b8f10e5bc85fd905963a4fba7580b1462d6061e94e098c28a34313
KeyMint pid after TA restart = 20259
provisioned_keys count = 0
```

关键日志：

```text
TlcKM returnCode == -100005
Trustonic TEE: tlTeeKeymint: [WARNING] USING EEK ROOT KEY FROM VTS
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
```

新增 no-op branch patch：

```text
rkp_research/patch_0706_rkp_noop_branch.py

patched_ta/0706000000000000000000000000004d.rkp_noop_branch.tlbin
sha256=dbbfa9a938df70920da49eefb96ce42e9333e72a59a3e4248d606f9df2c20437

patched_ta/0706000000000000000000000000004e.rkp_noop_branch.tlbin
sha256=cc41551a1e237c0ff61c867de5917d78c3e90d7dcf27c18cf2e52439ed1ec739
```

no-op patch 只做：

```text
hook 0x21fe0 -> cave 0x411ec
cave:
  ldp x25,x26,[sp,#80]
  stur w21,[x27,#17]
  b 0x21c9c
```

system no-op loaded-TA control：

```text
rkp_research/system_noop_branch_restart_control_20260816_182637
bind TA sha256 = dbbfa9a938df70920da49eefb96ce42e9333e72a59a3e4248d606f9df2c20437
KeyMint pid after TA restart = 20530
provisioned_keys count = 0
```

关键日志同样是：

```text
TlcKM returnCode == -100005
Trustonic TEE: tlTeeKeymint: [WARNING] USING EEK ROOT KEY FROM VTS
RkpdSystemInterface: Failed to generate CSR blob. Failed with 5
```

后续 2026-08-16 18:40 stock HAL memory capture 纠偏：stock successful provisioning 也会出现 `USING EEK ROOT KEY FROM VTS`。因此该 warning 不能作为失败判据；真正的失败判据仍是 `TlcKM returnCode == -100005` / `RkpdSystemInterface: Failed to generate CSR blob. Failed with 5`。

重要结论：

- 生产系统 RKPD/CSR path 对 loaded `4d` TA 二进制完整性敏感；哪怕 no-op branch 完全重放原语义，也会转入 VTS/test-root 相关状态并在 CSR 阶段返回 `-100005`。
- 继续 patch production `4d.tlbin` 来泄漏系统 provisioning key 的路线不成立。
- 后续优先方向应改为 normal-world/HAL 侧观测 stock TA 运行时材料，或复刻 stock HAL 的 `0x50402` 输入让 direct production CSR 成功，而不是修改 production TA 文件。

### 2026-08-16 18:29 stock restore after patched-TA controls

新增恢复脚本：

```text
rkp_research/run_stock_rkpd_restore.py
```

恢复目录：

```text
rkp_research/stock_restore_rkpd_20260816_182943
```

前置 stock 哈希：

```text
HAL sha256 = bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a
TA  sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
```

恢复结果：

```text
provisioned_keys count = 12
key_blob len = 216B for all rows
public_key len = 64B for all rows
expiration window = 2026-08-26T12:54:09Z .. 2026-08-26T13:16:58Z
```

当前设备状态：stock TA + stock HAL + KeyMint running，可继续下一阶段。

### 2026-08-16 18:40 stock HAL memory capture：确定系统 CSR 的真实 12-key 形态

新增脚本：

```text
rkp_research/run_stock_hal_mem_capture.py
```

运行目录：

```text
rkp_research/stock_hal_mem_capture_20260816_184042
```

结果：

```text
stock HAL sha256 = bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a
stock TA  sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
KeyMint pid = 20967
RKPD DB rows = 12
key_blob len = 216B
public_key len = 64B
```

HAL memory 中捕获到一次成功 stock `0x50402` TCI：

```text
cmd=0x80050402
ret=0
testMode=0
keys_addr=0x300010
keys_len=0x5c8
endpoint_addr=0x3005d8
endpoint_len=0x10d
challenge_addr=0x3006e5
challenge_len=0x1d
device_addr=0x400480
device_len=0x120
protected_addr=0x500030
protected_len=0x1ae
maced_addr=0x600310
maced_len=0x20
```

关键结论：

- `keys_len=0x5c8 = 4 + 12*(4+119)`，stock HAL 一次 CSR 传入 12 个 `MacedPublicKey`。
- 早期 direct client 只传 1 个 key，因此 12-key batch 是必须复刻的变量。
- stock 成功日志也出现 `USING EEK ROOT KEY FROM VTS`，前文以该 warning 区分失败的判断已废弃。

### 2026-08-16 19:16 direct 12-key batch：keygen 全对，但 direct CSR 仍失败

更新文件：

```text
rkp_research/rkp_tee_probe_csr.c
rkp_research/run_direct_csr_batch.py
```

重要修复：

- `run_direct_csr_batch.py` 改用 `su -c sh` stdin 包装，确保整段设备脚本在 root 下执行。
- direct 前默认停止 `vendor.keymint-trustonic`，结束后恢复服务。
- push 前 root 清理 `/data/local/tmp` 旧文件，避免权限残留。

有效 direct batch：

```text
rkp_research/direct_csr_batch_sideleak4d_20260816_1916
```

结果：

```text
TA = patched_ta/0706000000000000000000000000004d.rkp_sideleak.tlbin
testMode = 0
key_count = 12
init_keymint_globals = OK
12/12 keygen tci_ret = 0
12/12 sideleak scalar * G == MacedPublicKey public
CSR keys_len = 1480 / 0x5c8
CSR ret = 0xfffe795b / -100005
```

结论：

- “只差 key 数量”假设被否；direct production CSR 仍缺少 stock KeyMint 服务路径中的某些上下文/初始化状态。
- 但该 run 产出了 12 个可证明有效的 private scalar + MacedPublicKey 对，可作为后续 stock Binder CSR 的输入。

### 2026-08-16 19:29 stock Binder CSR bridge：把 direct sideleak keys 接到 stock HAL CSR

新增 native Binder 客户端：

```text
rkp_research/rkp_binder_csr_client.cpp
rkp_research/rkp_binder_csr_client
rkp_research/run_binder_csr_from_direct.py
```

实现要点：

- 直接调用 declared HAL service：

```text
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
```

- 手写 AIDL Parcel：

```text
generateCertificateRequest(
  false,
  MacedPublicKey[12],
  geek_curve_2.cbor,
  challenge.bin,
  out DeviceInfo,
  out ProtectedData
) -> MacedKeysToSign MAC
```

首次使用旧 challenge 的 run：

```text
rkp_research/binder_csr_from_direct4d_20260816_1929
```

结果：

```text
client_status = 0
mac_len = 32
device_info_len = 288
protected_data_len = 430
stock HAL/TA hash OK
```

随后发送 Google `signCertificates` 因旧 challenge 过期返回：

```text
HTTP 403
Challenge validation failed
```

### 2026-08-16 19:44 fresh challenge + Binder CSR + Google signCertificates 成功

重新 fetch GEEK/challenge：

```text
rkp_research/geek_fetch_20260816_1942
challenge_hex = 000001a00a3f4e190120b4ad639787b34f1e4855ddfd2dca57d82bf31d
```

用 fresh GEEK/challenge 重新生成 stock Binder CSR：

```text
rkp_research/binder_csr_from_direct4d_freshgeek_20260816_1943
mac_len = 32
device_info_len = 288
protected_data_len = 430
stock HAL/TA hash OK
```

新增 batch signCertificates 构造/发送脚本：

```text
rkp_research/build_and_send_signcerts_batch.py
```

成功发送目录：

```text
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send
```

Google 响应：

```text
HTTP 200
response_len = 16108
chain_count = 12
cert_count per chain = 4
chain_count_matches_key_count = true
leaf_public_matches_private_public = true for 12/12
openssl verify OK = 12/12
```

产物：

```text
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_00/key.xml
...
rkp_research/signcerts_batch_binder4d_freshgeek_20260816_1944_send/chain_11/key.xml
```

每个 `key.xml` 均包含对应 direct sideleak private key 与 Google 返回的 4-cert RKP attestation chain。leaf cert public key 已逐条验证匹配本地 private scalar 推导出的 public key。

最终设备状态确认：

```text
HAL sha256 = bc3de2a984f9fdc418abdc3333f1cf75bde95d322037fe4c9375d52c2015810a
TA  sha256 = ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
vendor.keymint-trustonic = running
KeyMint pid = 23559
```
