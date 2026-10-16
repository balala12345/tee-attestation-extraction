# RKP Pool Dump 2026-08-15

项目根目录：`<PROJECT_ROOT>`

本轮目标：读取已连接设备当前 RKPD/RKP 池，把 `provisioned_keys` 里的临时证书链与对应 attestation key blob/public key 全量 dump 出来，并验证结构和有效性。

## 1. 设备与 RKP 环境

- 采集时间：2026-08-15 15:07 CST 左右。
- 设备：`<DEVICE_SERIAL>`，model `A142` / device `Pacman`。
- Build fingerprint：`Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys`。
- Android：`14`。
- Vendor security patch：`2026-07-05`。
- `su -c id`：`uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0`。
- KeyMint/RKP binder：
  - `android.hardware.security.keymint.IKeyMintDevice/default`
  - `android.hardware.security.keymint.IRemotelyProvisionedComponent/default`
  - `remote_provisioning: [android.security.rkp.IRemoteProvisioning]`
- RKPD app：`package:/apex/com.android.rkpd/priv-app/rkpdapp@UP1A.231005.007/rkpdapp.apk`，`versionCode=34`，`versionName=14`。
- `cmd remote_provisioning dump`：

```text
default:
  hwVersion=2
  rpcAuthorName=Trustonic
  supportedEekCurve=2
  uniqueId=Trustonic keymint
  supportedNumKeysInCsr=4
```

补充：`cmd remote_provisioning csr default` 当前返回 `android.os.ServiceSpecificException (code 1)`；不影响本次 DB 池离线 dump，但说明 shell 直接生成 CSR 当前不可用。

## 2. 原始数据位置

整理后的 RKP dump 入口：

```text
<PROJECT_ROOT>/rkp_dumps
```

该目录是一条 RKP provisioned key 一个文件夹；每个文件夹内都有 `key.xml`、`metadata.json`、opaque `key_blob`、public key、证书链和验证输出。顶层 `all_rkp_keys.xml` 是 12 条 `key.xml` 的聚合版，`manifest.json` 是总索引。

本次输出目录：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725
```

原始 RKPD app 数据 tar：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/rkpdapp_data.tar
```

从设备只读拉取的关键文件：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/data/user/0/com.android.rkpdapp/databases/rkpd_database
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/data/user/0/com.android.rkpdapp/databases/rkpd_database-wal
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/data/user/0/com.android.rkpdapp/databases/rkpd_database-shm
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/data/user_de/0/com.android.rkpdapp/shared_prefs/com.android.rkpdapp.utils.preferences.xml
```

完整 hash 记录：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw_file_hashes.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed_file_hashes.txt
```

## 3. RKPD 数据库结构

SQLite schema：

```sql
CREATE TABLE `provisioned_keys` (
  `key_blob` BLOB NOT NULL,
  `irpc_hal` TEXT NOT NULL,
  `public_key` BLOB NOT NULL,
  `certificate_chain` BLOB NOT NULL,
  `expiration_time` INTEGER NOT NULL,
  `client_uid` INTEGER,
  `key_id` INTEGER,
  PRIMARY KEY(`key_blob`)
);
CREATE UNIQUE INDEX `index_provisioned_keys_client_uid_key_id_irpc_hal`
  ON `provisioned_keys` (`client_uid`, `key_id`, `irpc_hal`);
CREATE INDEX `index_provisioned_keys_expiration_time`
  ON `provisioned_keys` (`expiration_time`);
```

`shared_prefs` 关键字段：

```xml
<int name="failure_counter" value="0" />
<int name="extra_keys" value="12" />
<long name="expiring_by" value="259200000" />
```

解释：当前池中共有 `12` 条 provisioned key；`extra_keys=12` 与 DB 行数一致。当前 `3` 条已有 `client_uid/key_id`，`9` 条未分配，仍处于可用池状态。

## 4. Dump 结果总览

每行均 dump 出：

- `key_blob.bin`：216 字节，对应 RKPD/KeyMint opaque attestation key blob。
- `public_key_raw_xy.bin`：64 字节 P-256 raw X||Y。
- `public_key_spki.der` / `public_key.pem`：由 raw X||Y 重建的 P-256 public key。
- `certificate_chain.bin`：拼接 DER 证书链。
- `cert_0.der` .. `cert_3.der`：拆出的 4 张 X.509 DER 证书。

主摘要：

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/summary.json
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/row_table.md
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/openssl_verify_all.txt
```

### 4.1 行级摘要

| idx | rowid | client_uid | key_id | expires UTC | leaf serial | leaf SHA256 fingerprint | leaf pub == DB public_key | chain verify |
|---:|---:|---:|---:|---|---|---|---|---|
| 00 | 1 | 1017 | 10138 | 2026-08-24T19:21:24+00:00 | D53130505FD1EA145A3CD1215DACE72C | `87:1B:9B:DD:8C:AE:12:05:90:D1:C1:BB:9E:A4:B6:4D:52:8E:50:0B:45:A2:34:3E:77:4C:40:07:BE:8F:E5:9C` | True | True |
| 01 | 2 | 1017 | 10220 | 2026-08-24T19:37:05+00:00 | 9663BBE51F7D79017F10712C662F7418 | `BD:31:76:6C:47:0D:8C:54:98:AF:65:87:37:5B:8F:B0:1B:DF:B2:BD:C2:43:44:46:97:A7:6C:A8:41:0B:62:1A` | True | True |
| 02 | 3 | 1017 | 1000 | 2026-08-24T19:31:11+00:00 | 2BBE4C11EF7DF2E65CE31DE7FEA3D9F9 | `58:43:04:C0:65:D1:67:13:C2:21:5B:FC:04:95:42:0B:53:05:05:9D:CB:B0:0F:35:7F:54:07:D0:6D:3E:7F:C2` | True | True |
| 03 | 4 |  |  | 2026-08-24T19:34:07+00:00 | 1FFBAAE292512BE63FAFF3271E7D728D | `7A:82:B0:62:CE:E7:C9:1A:1F:F0:21:25:1F:B5:9D:52:E6:5C:9F:7D:C0:32:F0:B8:C3:84:0A:96:55:82:0C:1C` | True | True |
| 04 | 5 |  |  | 2026-08-24T19:34:21+00:00 | 4A3F8CC0C5B63FC8D4EBD0CF4F4C5B75 | `23:5B:C3:36:05:BF:5A:DF:F8:DD:19:75:55:EB:58:32:C1:D9:7F:A5:4C:7D:DB:D1:04:B1:15:F0:79:FB:CE:91` | True | True |
| 05 | 6 |  |  | 2026-08-24T19:39:04+00:00 | C355CDE5C5372274107B1809E3913289 | `19:C0:95:0D:B3:34:51:2D:B0:BE:D8:37:C5:E0:52:CB:EB:BE:0F:3C:FE:6D:11:33:85:40:F0:1D:D3:B7:AE:0E` | True | True |
| 06 | 7 |  |  | 2026-08-24T19:19:40+00:00 | 7EB4166B01E376D7FD359FACD26F6433 | `2A:9E:50:E0:EC:C7:C2:DA:7F:57:7E:66:2D:34:20:FB:7F:49:58:E2:14:15:59:AA:24:91:28:09:FA:A9:F8:9A` | True | True |
| 07 | 8 |  |  | 2026-08-24T19:40:00+00:00 | 5ACAFC5858F55DFE83EB82BC199F5640 | `FD:5C:16:72:70:77:C5:66:1B:11:6D:B6:48:BD:F1:65:6D:DB:88:D9:A8:B7:31:19:BF:D1:B4:4C:62:06:E7:46` | True | True |
| 08 | 9 |  |  | 2026-08-24T19:39:01+00:00 | 5A64124011861E84849A9B73444720BD | `9F:EC:81:FB:5F:C7:CB:86:CD:A0:7D:ED:2F:E7:D0:65:65:45:B9:6F:43:D1:DA:C6:2B:75:B0:3E:DA:4C:07:52` | True | True |
| 09 | 10 |  |  | 2026-08-24T19:31:00+00:00 | B6BC939E530AB6371F740E05E24146FE | `07:62:0A:14:C1:F0:AB:93:B7:B0:F6:AF:7E:15:D9:81:DB:C9:F9:11:96:70:D7:58:E0:C9:55:7D:00:90:A0:F7` | True | True |
| 10 | 11 |  |  | 2026-08-24T19:16:06+00:00 | F3512D9302B8105657B9EE0B5FC67095 | `BB:C6:45:00:44:BC:51:CE:8F:C2:EB:4A:C5:23:3D:14:2C:A0:C7:93:1C:EE:C9:BC:5E:70:7E:FF:CE:14:57:13` | True | True |
| 11 | 12 |  |  | 2026-08-24T19:43:14+00:00 | B26A54C63E05DA1A8BF9E44F96878CF0 | `08:AF:AF:06:87:4E:A5:DB:4E:A2:BB:D1:05:B1:D8:90:53:71:16:D6:56:6B:09:88:CB:AC:D2:49:5E:0D:19:18` | True | True |

### 4.2 文件布局示例

```text
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_db_dump/row00_rowid1_uid1017_keyid10138/key_blob.bin
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_db_dump/row00_rowid1_uid1017_keyid10138/public_key_raw_xy.bin
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_db_dump/row00_rowid1_uid1017_keyid10138/public_key.pem
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_db_dump/row00_rowid1_uid1017_keyid10138/certificate_chain.bin

<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/row00_rowid1_uid1017_keyid10138/cert_0.der
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/row00_rowid1_uid1017_keyid10138/cert_1.der
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/row00_rowid1_uid1017_keyid10138/cert_2.der
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/row00_rowid1_uid1017_keyid10138/cert_3.der
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/row00_rowid1_uid1017_keyid10138/openssl_verify.txt
```

## 5. 结构和有效性判断

1. DB `certificate_chain` 是 4 张连续拼接的 DER X.509 证书：
   - `cert_0`：RKP 临时 leaf，subject 形如 `/O=TEE/CN=<16B serial>`，issuer `/O=Google LLC/CN=Droid CA3`。
   - `cert_1`：`Droid CA3`。
   - `cert_2`：`Droid CA2`。
   - `cert_3`：`Key Attestation CA1` root。
2. 12 条链的 `cert_1/cert_2/cert_3` 相同：`True`。
   - CA3 sha256：`2a1efd290df9d2f5c928dea52e4f387c140b1fd38d777faea8b13b47825b8c1b`
   - CA2 sha256：`b8b0741e7a5ad98c996cf81eb46ac2d3fb1c28a3bdb2b89eaa930a64ad871632`
   - Root sha256：`6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0`
3. 使用 `openssl verify -attime 2026-08-15T00:00:00Z -CAfile cert_3.pem -untrusted cert_1+cert_2 cert_0.pem` 验证：12/12 均 OK。
4. 每条 DB `public_key` 均为 64 字节 P-256 raw X||Y；由 leaf cert 提取出的 EC public key raw X||Y 与 DB `public_key` 逐字节一致：12/12 `True`。
5. 每条 `key_blob` 均为 216 字节；开头统一 `01 02 00 00`，熵约 6.93–7.12 bit/byte；未直接包含 DB raw public key，也未直接包含证书链前缀。结论：DB 中的 attestation key 是 Trustonic/KeyMint opaque wrapped blob，而不是 DER/PEM 明文私钥。对应关系通过同一行的 `public_key` 与 `cert_0` 公钥验证成立。
6. 当前 leaf 有效期集中在：`2026-08-11` 到 `2026-08-24 19:xx:xx UTC`，属于临时 RKP leaf 证书，不是上一轮提取的长期 factory keybox 链。

## 6. 与上一轮 factory keybox 的区别

上一轮 `extracted_keybox/` 中的是本地 factory attestation keybox：EC/RSA 长期私钥 + factory cert chain。  
本轮 `rkpd_database.provisioned_keys` 中的是 RKP 池条目：每条为动态 P-256 attestation key blob + 临时 RKP leaf cert chain。

关键区别：

- factory keybox 已拆出明文 EC/RSA 私钥。
- RKP pool DB 只直接给出 opaque `key_blob`、raw public key 和证书链；明文私钥不在 SQLite 中裸存。
- 本轮可确认所有 RKP 池证书链有效，且每条证书 leaf 公钥与同 row 的 `public_key` 一致。

## 7. 对下一轮攻击的直接结论

1. 当前设备确实有可用 RKP pool：12 条 provisioned keys。
2. 当前已消耗/分配 3 条：`(uid=1017,key_id=10138)`、`(uid=1017,key_id=10220)`、`(uid=1017,key_id=1000)`。
3. 未分配备用 9 条，证书链均有效。
4. 攻击面不在 SQLite 的证书解析本身；下一步要拿明文 RKP attestation private scalar，需要进入 KeyMint/Trustonic 对 `key_blob` unwrap/签名使用路径，而不是单纯读 RKPD DB。
5. 项目已有 `tas/device_u25/ENUM_NOTES.md` 指出 KeyMint TA 不用 SFS 持久化 RKP 密钥；运行时关键材料在 TA BSS 表/TCI 装表路径中。下一轮建议优先跟：
   - `IRemotelyProvisionedComponent.generateEcdsaP256KeyPair` 返回的 216B `key_blob` 结构；
   - keystore2 取用 RKPD key 后传入 KeyMint 的 attest/sign path；
   - Trustonic TA unwrap opaque `key_blob` 时的内存态。

## 8. 复现命令摘录

```bash
adb devices -l
adb shell 'id; getprop ro.product.model; getprop ro.build.fingerprint; getprop ro.vendor.build.security_patch'
adb shell 'su -c id'
adb shell 'service list | grep -Ei "keymint|provision|rkp|keystore"'
adb shell 'cmd remote_provisioning dump'

adb exec-out su -c 'tar -C / -cf - \
  data/user/0/com.android.rkpdapp/databases \
  data/user/0/com.android.rkpdapp/cache \
  data/user/0/com.android.rkpdapp/no_backup \
  data/user_de/0/com.android.rkpdapp/shared_prefs 2>/dev/null' \
  > "<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/raw/rkpdapp_data.tar"

python3 \
  "<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/analyze_rkp_pool.py" \
  "<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725"
```

## 9. 本轮产物清单

```text
<PROJECT_ROOT>/rkp_dumps/README.md
<PROJECT_ROOT>/rkp_dumps/manifest.json
<PROJECT_ROOT>/rkp_dumps/all_rkp_keys.xml
<PROJECT_ROOT>/rkp_dumps/rkp_00_rowid1_uid1017_keyid10138/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_01_rowid2_uid1017_keyid10220/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_02_rowid3_uid1017_keyid1000/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_03_rowid4_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_04_rowid5_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_05_rowid6_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_06_rowid7_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_07_rowid8_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_08_rowid9_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_09_rowid10_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_10_rowid11_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_dumps/rkp_11_rowid12_uidnone_keyidnone/key.xml
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/device_probe.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/rkp_framework_probe.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/remote_provisioning_cmd.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/db_schema.sql
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/db_table_probe.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/analyze_rkp_pool.py
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/analyze_run.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/summary.json
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_db_dump/summary.json
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/rkpd_certs/cert_summary.json
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed/openssl_verify_all.txt
<PROJECT_ROOT>/rkp_research/current_device_dump_20260815_150725/parsed_file_hashes.txt
```
