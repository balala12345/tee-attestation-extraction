# 脱离 AI 重做 KeyMint keybox 提取扩展：多设备复现与迁移指南

项目根目录：`<PROJECT_ROOT>`

本文目标：把当前依赖 AI 辅助分析才跑通的 KeyMint / Keystore attestation keybox 提取扩展，整理成一套人可以独立执行、脚本可以复核、报告可以审计的流程。

适用场景：公司授权渗透测试，需要在开源 `fenrir` 支持的设备范围内，快速验证哪些设备不仅支持公开启动链漏洞，还能继续支持本项目扩展出的 KeyMint factory keybox 提取路径。

重要边界：

- 本文只面向授权设备和授权固件。
- 多设备批量验证时，默认目标应是兼容性证明和风险确认，不应默认批量导出真实私钥。
- 完整导出 EC/RSA attestation private key 只应作为少量样机的最高影响证明，并单独加密封存。

---

## 1. 为什么现在看起来依赖 AI

当前 Pacman / Nothing Phone (2a) 已经完整跑通，核心成果在：

```text
PROGRESS.md
gptdoc/QUICK_REPRO.md
outputdoc/01_NECESSARY_IMPLEMENTATION_FLOW.md
outputdoc/02_FULL_REPLAY_REPRODUCTION.md
outputdoc/03_FULL_ANALYSIS_PROCESS_RECORD.md
outputdoc/06_FROM_REPO_TO_TEE_KEYBOX_EXTRACTION_GUIDE.md
extracted_keybox/
```

但如果换一台设备，不能直接照抄 Pacman 的 offset。当前已知 patch 强绑定这组事实：

```text
KeyMint TA UUID: 07060000-0000-0000-0000-00000000004d
MCLF text file offset: 0xd0
MCLF text VA base:     0x1000
TCI size:              0x140
cmd install keybox:    0x00050202
cmd install ids:       0x00050204
cmd close:             0x00050016
handler 0x00050202:    0x1e430
decrypt wrapper:       0x1de70
secure object decrypt: 0x22738
parse plaintext:       0x1d9b8
memcpy:                0x50f0
patch point 1:         0x1df3c
patch point 2:         0x1e4d4
code cave:             0x411ac
```

AI 之前主要帮忙做了三件事：

1. 在大量文档、dump、日志里归纳真实目标，不再走 Widevine 路线。
2. 从 HAL/TA 逆向结果中梳理调用链和 patch 点。
3. 把实验碎片整理成可复现脚本和报告。

要脱离 AI，就要把这三件事变成固定流程：

```text
目标识别 -> 证据采集 -> profile 化 -> 半自动匹配 -> 人工逆向确认 -> patch 生成 -> 真机验证 -> 报告归档
```

---

## 2. 必须区分两种“支持”

开源 `fenrir` 支持某设备，只代表启动链漏洞入口可能成立。它不等于 KeyMint keybox 提取扩展必然成立。

建议把每台设备分成 6 层判断：

| 层级 | 判断点 | 结果意义 |
|---|---|---|
| L0 | `fenrir` profile 支持，LK/bl2_ext patch 可生成 | 公开启动链漏洞入口成立 |
| L1 | patched LK 后 modified TEE 可启动 | 后续有机会加载 modified TEE / TA |
| L2 | TEE 是 Trustonic/t-base，且 trustlet 签名 bypass 可适配 | modified KeyMint TA 有机会被加载 |
| L3 | 系统使用 Trustonic KeyMint，存在 KeyMint TA、`attest_keybox.so`、`attestation_ids.so` | 进入本项目目标范围 |
| L4 | KeyMint TA 的 TCI command、handler、keybox 解密路径可匹配 | 可以移植 Pacman 的 patch 思路 |
| L5 | direct client 成功触发并证明 plaintext keybox 出现在 secure world | 扩展漏洞复现成功 |

最终报告不要只写“支持/不支持”，而应写：

```text
FENRIR_ONLY
TEE_PORT_NEEDED
KEYMINT_PROFILE_NEEDED
KEYBOX_PATH_CONFIRMED
PROOF_ONLY_SUCCESS
FULL_EXTRACTION_SUCCESS
NOT_APPLICABLE
BLOCKED
```

---

## 3. 多设备测试所需资产

每台设备建立一个独立工作目录：

```text
targets/<codename>/
  firmware/
  device_dump/
  profiles/
  patched/
  runs/
  reports/
```

每台设备至少收集：

```text
firmware/lk.img 或 lk_a.img
firmware/tee.img 或 tee_a.img
firmware/vendor.img / vendor_boot.img / super.img 解包结果
device_dump/vendor_app_mcRegistry/
device_dump/vendor_bin_hw/
device_dump/vendor_lib64/
device_dump/persist/
```

真机 root 后优先拉取：

```text
/vendor/app/mcRegistry/*
/vendor/bin/hw/*keymint*
/vendor/lib64/libMcClient.so
/system_ext/lib64/libMcClient.so
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
```

如果没有 root，则先从固件包解出 `/vendor`；但 `persist/attest_keybox.so` 通常是设备个体数据，固件里未必有。没有 persist blob 时，可以做 L0-L4 判断，但无法完成最终提取验证。

---

## 4. 第一阶段：离线预筛

离线预筛的目标是尽量不刷机、不运行 exploit，先判断这台设备是否值得进入真机验证。

### 4.1 检查 fenrir 支持

开源支持列表来自：

```text
fenrir/README.md
fenrir/injector/devices.py
```

当前本地仓库列出的设备包括：

```text
Pacman       Nothing Phone (2a)
PacmanPro    Nothing Phone (2a) Plus
Tetris       CMF Phone 1
peridotl     Lenovo IdeaTab Pro / Xiaoxin Pad Pro 12.7
LG7n         Tecno Pova 4
LG8n         Tecno Pova 4 Pro
LH7n         Tecno Pova 5
Q25          Zinwa Q25
duchamp      Redmi K70E / POCO X6 Pro 5G
rodin        Redmi Turbo 4 / POCO X7 Pro
dash         Redmi Turbo 5 Max / POCO X8 Pro Max
xaga         Redmi Note 11T Pro/Pro+/POCO X4 GT/Redmi K50i
plato        Xiaomi 12T
```

判断项：

- `devices.py` 是否已有 codename。
- 对应 `sec_get_vfy_policy` pattern 是否能在目标 LK 中命中。
- `match_mode=ALL` 时命中数量是否与 profile 预期一致。
- patched LK 是否只改动预期位置。

输出：

```text
fenrir_profile: known / unknown
lk_pattern_match: pass / fail
lk_patch_diff_count: <n>
fenrir_l0_verdict: pass / fail / needs_port
```

### 4.2 识别 TEE 类型

本项目扩展依赖 Trustonic Kinibi / t-base 和 Trustonic MCLF trustlet。离线检查：

```text
tee.img 中是否有 Trustonic/t-base/Kinibi 相关字符串
vendor/lib64 是否存在 libMcClient.so
vendor/app/mcRegistry 下是否存在 .tlbin/.tabin/.drbin
trustlet 是否有 MCLF magic
```

如果是 QSEE、OP-TEE、Microtrust 等其他 TEE，本项目 Pacman patch 不能直接复用，记录为：

```text
NOT_APPLICABLE_FOR_CURRENT_PROFILE
```

不是说设备没漏洞，而是当前 KeyMint keybox 扩展需要重建另一套 TEE profile。

### 4.3 识别 KeyMint HAL

对 `vendor/bin/hw/*keymint*` 做 strings/grep：

```text
attest_keybox.so
attestation_ids.so
/vendor/app/mcRegistry/
TEE_AttestIds
TEE_GenerateAndAttestKey
TEE_AttestKey
TEE_ImportAndAttestKey
TEE_GenerateCertificateRequest
TrustonicKeymint
```

关键结论：

- 如果 HAL 完全没有 `attest_keybox.so`，可能是 RKP-only 或使用其他存储路径。
- 如果 HAL 有 `attest_keybox.so`，但路径不同，要记录路径。
- 如果 HAL 有 Trustonic client 调用，则进入 L3。

### 4.4 识别 KeyMint TA

在 `vendor/app/mcRegistry/` 下扫描：

```text
KEYMINT
Keymint TA
teeKeymint
decrypt_keybox
verify_keybox
Verify Keybox Signature
rkp_bcc_km
bootloader_state
```

候选 TA 应输出：

```text
ta_path
ta_size
ta_sha256
mclf_uuid
mclf_version
text_file_offset
text_va
text_size
data_file_offset
data_va
data_size
strings_score
```

Pacman 已知目标：

```text
device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
sha256=ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
```

---

## 5. 第二阶段：建立 profile，而不是靠 AI 猜 offset

每个可疑设备都应建立一个 profile 文件。建议格式：

```json
{
  "device": "Pacman",
  "model": "Nothing Phone (2a)",
  "tee": "Trustonic t-base",
  "keymint_hal": {
    "path": "device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic",
    "sha256": "<hash>",
    "keybox_path": "/mnt/vendor/persist/attest_keybox.so",
    "ids_path": "/mnt/vendor/persist/attestation_ids.so",
    "ta_path": "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
  },
  "keymint_ta": {
    "path": "device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin",
    "sha256": "ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2",
    "uuid_hex": "0706000000000000000000000000004d",
    "text_base": "0x1000",
    "text_file_offset": "0xd0"
  },
  "tci": {
    "size": "0x140",
    "cmd_keybox": "0x00050202",
    "cmd_ids": "0x00050204",
    "cmd_close": "0x00050016",
    "map_offset": "0x0c",
    "ret_offset": "0x04"
  },
  "symbols": {
    "dispatcher": "0x13b00",
    "handler_keybox": "0x1e430",
    "handler_ids": "0x1e9a0",
    "decrypt_wrapper": "0x1de70",
    "decrypt_secure_object": "0x22738",
    "parse_plaintext": "0x1d9b8",
    "memcpy": "0x50f0"
  },
  "patch": {
    "mode": "dumpkeybox",
    "point_plaintext_copy": "0x1df3c",
    "point_map_copyback": "0x1e4d4",
    "code_cave": "0x411ac",
    "expected_bytes": {
      "0x1df3c": "e08744a9",
      "0x1e4d4": "f303002a"
    }
  },
  "status": "FULL_EXTRACTION_SUCCESS"
}
```

迁移到新设备时，先复制 Pacman profile，然后只允许改这些字段：

```text
ta_path / sha256 / uuid
MCLF text mapping
TCI command
function VA
patch points
expected bytes
code cave
memcpy VA
validation hashes
```

禁止只改文件名就套 patch。patch 脚本必须检查 expected bytes，检查失败就停止。

---

## 6. 第三阶段：无 AI 逆向方法

这一阶段目标是从新设备 KeyMint TA 中重建 Pacman 已知调用链：

```text
TCI dispatcher
  -> cmd 0x00050202 handler
  -> mapped keybox blob copy
  -> secure object decrypt wrapper
  -> plaintext parse
  -> free plaintext
```

### 6.1 解析 MCLF 并生成可分析文件

固定动作：

1. 读取 MCLF header。
2. 提取 UUID。
3. 记录 text/data segment file offset 与 VA。
4. 生成 raw text bin。
5. 生成 ELF wrapper，便于 Ghidra/IDA/Binary Ninja/rizin 识别地址。

Pacman 映射公式：

```text
file_offset = 0xd0 + (VA - 0x1000)
```

新设备不能假设一定是 `0xd0/0x1000`，必须从 MCLF header 解析。

### 6.2 从 HAL 找 TCI command

先逆向 HAL，而不是直接看 TA。原因：HAL 负责构造 TCI，路径和 command 常量更容易识别。

需要确认：

```text
TCI buffer size
cmd 写入 offset
retcode 读取 offset
mcMap 后 mapInfo 写入 offset
install keybox 使用的 cmd
install ids 使用的 cmd
close 使用的 cmd
```

Pacman 结果：

```text
TCI size  = 0x140
TCI[0x00] = cmd
TCI[0x04] = ret
TCI[0x0c] = mcBulkMap_t
0x00050202 = attest_keybox.so
0x00050204 = attestation_ids.so
0x00050016 = close
```

### 6.3 从 TA 找 dispatcher

无 AI 做法：

1. 在反汇编里搜索 command 常量。
2. 搜索读取 TCI[0] 的代码形态。
3. 找 switch/if-chain。
4. 找写回 TCI[4] 的位置。
5. 交叉引用到 command handler。

识别成功的最低证据：

```text
cmd_keybox -> handler_keybox
cmd_ids    -> handler_ids
cmd_close  -> handler_close
handler 返回值被写回 TCI ret offset
```

### 6.4 从 handler 找 keybox 解密路径

对 `handler_keybox` 做人工追踪：

```text
读取 TCI+map_offset
校验 mapped buffer
分配 heap
memcpy(mapped encrypted keybox -> heap)
调用下一层函数
释放 heap
返回
```

下一层函数通常具备特征：

```text
接收 encrypted keybox buffer 和长度
分配 plaintext buffer
调用 secure object decrypt
调用 parse/verify keybox
释放 plaintext buffer
```

Pacman 是：

```text
0x1e430 -> 0x1de70 -> 0x22738 -> 0x1d9b8
```

新设备要确认语义，而不是确认数值。

### 6.5 找 memcpy

可以通过三种方式确认：

1. 交叉引用常见 copy loop。
2. 从 handler 中原本的 mapped->heap copy 反推。
3. 用符号残留或 call graph 识别 libc wrapper。

Pacman 是：

```text
memcpy = 0x50f0
```

### 6.6 找 code cave

要求：

- 位于可执行 text 段。
- 原始内容为连续零或未引用填充。
- branch 距离在 AArch64 `b/bl` 范围内。
- 不覆盖 MCLF header、data、签名结构以外的运行必要区域。

Pacman 使用：

```text
code cave = 0x411ac
```

新设备应脚本扫描零洞，并人工确认没有交叉引用。

---

## 7. 第四阶段：patch 设计

建议保留两种 patch 模式。

### 7.1 Proof-only 模式

用于多设备批量验证，默认不导出私钥。

目标：

```text
证明 TA 已进入 keybox decrypt path
证明 plaintext 结构出现过
返回长度、DER header、证书数量、hash
不返回 EC/RSA private key DER
```

可选实现：

- 在 parse 前计算 plaintext hash 和结构摘要。
- 只把摘要写回 mapped buffer。
- 或只写一个固定 magic + plaintext_len + DER header hash。

推荐输出：

```text
KMKB_PROOF_V1
plaintext_len
first_der_offset
ec_private_der_len
ec_cert_count
rsa_private_der_len
rsa_cert_count
sha256(plaintext)
```

这足够证明扩展漏洞成立，又避免批量生成真实私钥文件。

### 7.2 Dump 模式

只用于少量授权样机最高影响证明。

Pacman 当前实现：

```text
patch point 1:
  在 parse 前 memcpy(input_heap, plaintext, plaintext_len)

patch point 2:
  在 handler 返回前，如果 ret == 0，memcpy(mapped_input, input_heap, original_len)

normal world:
  direct client 读取 mapped buffer after
```

当前脚本：

```text
analysis/patch_0706_dump.py
```

关键原则：

- patch 脚本必须检查 expected bytes。
- patch 前后必须输出 sha256。
- patch 后必须保存 diff。
- 不允许在未知 TA 上强行 patch。

---

## 8. 第五阶段：direct client 泛化

当前 direct client：

```text
keymint_tee_client/kmtee_probe.c
```

它做的事情：

```text
mcOpenDevice
mcOpenTrustlet(patched TA bytes)
读取 /mnt/vendor/persist/attest_keybox.so
读取 /mnt/vendor/persist/attestation_ids.so
mcMap keybox blob
发送 cmd_keybox
保存 tci 和 buffer after
mcMap ids blob
发送 cmd_ids
保存 tci 和 buffer after
发送 close
mcCloseSession
```

要多设备化，应该改成读取 profile，而不是写死：

```text
KEYMINT_TL
ATTEST_KEYBOX
ATTEST_IDS
OUTDIR
TCI_SIZE
CMD_ATTEST_KEYBOX
CMD_ATTEST_IDS
CMD_CLOSE
TCI map offset
TCI ret offset
libMcClient 搜索路径
```

建议实现：

```text
pentest_matrix/client/kmtee_probe_generic.c
pentest_matrix/profiles/<codename>.json
pentest_matrix/run_direct_probe.py
```

成功判据：

```text
mcOpenTrustlet ret=0
cmd_keybox tci_ret=0
cmd_ids tci_ret=0
before/after 符合 patch 预期
Proof-only 输出 magic 正确，或 Dump 输出 DER 结构正确
```

失败时必须记录：

```text
mcOpenTrustlet error
mcMap error
cmd tci_ret
logcat filtered KeyMint/TEE/TlcKM lines
TA hash
TEE service state
```

---

## 9. 第六阶段：keybox 解析和证明

Dump 模式得到 `attest_keybox_buf_after.bin` 后，不要人工肉眼判断，要固定解析。

当前解析脚本：

```text
analysis/extract_keybox_plain.py
```

它按以下结构解析：

```text
u32 version_or_keybox_number

EC:
  u32 private_key_der_len
  DER private key
  u32 cert_count
  repeated:
    u32 cert_der_len
    DER certificate

RSA:
  u32 private_key_der_len
  DER private key
  u32 cert_count
  repeated:
    u32 cert_der_len
    DER certificate
```

Pacman 已验证输出：

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

证明链：

```text
1. DER 长度字段和 DER 实际长度一致。
2. EC private key 可导出 public key。
3. EC private public key 与 EC leaf cert public key 一致。
4. RSA private public key 与 RSA leaf cert public key 一致。
5. EC/RSA cert chain openssl verify OK。
6. EC/RSA private key sign，leaf cert public key verify OK。
7. AndroidKeyStore 实际 attestation chain 中间证书与提取出的 cert 对应。
```

报告中默认只放：

```text
public key hash
certificate fingerprint
chain verify result
sign verify result
plaintext hash
```

不要把 private key PEM、DER、完整 keybox XML 放进普通报告。

---

## 10. 多设备标准流程

### 10.1 Phase 0：建档

每台设备先填：

```text
device_codename
marketing_name
SoC
Android version
build fingerprint
vendor security patch
bootloader unlock status
slot
firmware source
operator
authorization ticket
```

### 10.2 Phase 1：离线预筛

输出：

```text
reports/<codename>/01_offline_triage.md
profiles/<codename>/offline_profile.json
```

结论之一：

```text
NOT_FENRIR_SUPPORTED
FENRIR_PROFILE_MATCH
FENRIR_PROFILE_NEEDS_PORT
TRUSTONIC_KEYMINT_CANDIDATE
NON_TRUSTONIC_KEYMINT
NO_LOCAL_KEYBOX_PATH_FOUND
```

### 10.3 Phase 2：安全链路验证

只对授权样机进行。验证：

```text
patched LK 可启动
patched TEE 可启动
TEE service running
KeyMint service running
root 可用
原始 TA/KeyMint/RKP 状态可恢复
```

报告：

```text
reports/<codename>/02_bootchain_and_tee.md
```

### 10.4 Phase 3：Proof-only KeyMint 验证

优先运行 proof-only patched TA。

目标结果：

```text
modified TA loads
cmd_keybox reaches decrypt path
plaintext-like structure confirmed
no private key exported
```

报告：

```text
reports/<codename>/03_keybox_proof.md
```

### 10.5 Phase 4：受控完整提取

仅在需要最高影响证明时运行。

产物目录必须单独隔离：

```text
runs/<codename>/<timestamp>_full_extract_sensitive/
```

要求：

- 目录不进 git。
- 产物加密。
- 报告只引用 hash。
- 操作后恢复原始 TA/挂载状态。

报告：

```text
reports/<codename>/04_full_extraction_sensitive_summary.md
```

---

## 11. 兼容性矩阵模板

建议维护一个总表：

| codename | device | SoC | fenrir L0 | patched TEE L1 | Trustonic L2 | KeyMint keybox L3 | TA profile L4 | proof L5 | full extract | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| Pacman | Nothing Phone (2a) | MT6886 | pass | pass | pass | pass | pass | pass | pass | FULL_EXTRACTION_SUCCESS |
| PacmanPro | Nothing Phone (2a) Plus | TBD | todo | todo | todo | todo | todo | todo | no | UNKNOWN |
| Tetris | CMF Phone 1 | TBD | todo | todo | todo | todo | todo | todo | no | UNKNOWN |

verdict 枚举：

```text
UNKNOWN
NOT_TESTED
FENRIR_ONLY
TEE_PORT_NEEDED
NON_TRUSTONIC
NO_LOCAL_FACTORY_KEYBOX
KEYMINT_PROFILE_NEEDED
PROOF_ONLY_SUCCESS
FULL_EXTRACTION_SUCCESS
BLOCKED_BY_ROOT
BLOCKED_BY_FIRMWARE
BLOCKED_BY_BOOT
```

---

## 12. 常见失败与判断

### 12.1 fenrir 支持，但 KeyMint 扩展不支持

可能原因：

- TEE 不是 Trustonic。
- KeyMint TA 不是 MCLF。
- HAL 不使用 `/mnt/vendor/persist/attest_keybox.so`。
- 设备为 RKP-only，没有本地 factory keybox fallback。
- 厂商把 keybox 解密路径移到其他 TA 或 RPMB/SFS。

结论写：

```text
FENRIR_ONLY 或 NOT_APPLICABLE_FOR_CURRENT_KEYMINT_PROFILE
```

### 12.2 patched TA 无法加载

可能原因：

- t-base trustlet signature bypass 没有成功。
- TA UUID 与系统已有会话冲突。
- TEE 版本不匹配。
- `libMcClient.so` ABI 不同。

处理：

- 先用 UUID 变体做 direct-only 测试。
- 检查 `mcOpenTrustlet` 返回码。
- 检查 `tee-1-1` 和 KeyMint 服务是否仍正常。

### 12.3 cmd 返回非零

可能原因：

- TCI size/offset 错误。
- command 常量不同。
- `attest_keybox.so` 路径或权限错误。
- mapped buffer 长度不符合 TA 预期。
- TA global init 顺序不同，必须先 ids 或其他 init。

处理：

- 先用 stock TA + direct client 确认 command 是否能返回 0。
- 再运行 proof/dump patched TA。
- 对比 HAL 正常流程。

### 12.4 before/after 没变化

可能原因：

- stock TA 正常行为就是不返回 plaintext。
- patch point 未命中真实 plaintext path。
- copyback point 没执行。
- ret 非 0 跳过 copyback。

处理：

- 在 proof-only 模式写固定 magic 测试 code cave 是否执行。
- 在 dump 模式检查 expected bytes 和 branch 编码。
- 回到逆向确认 plaintext buffer 生命周期。

---

## 13. 工具化建设清单

为了真正脱离 AI，建议补齐这些脚本：

```text
pentest_matrix/
  README.md
  profiles/
    pacman_trustonic_km_v2.json
  tools/
    collect_device_info.sh
    pull_keymint_assets.sh
    triage_firmware.py
    parse_mclf.py
    scan_keymint_hal.py
    scan_keymint_ta.py
    make_ta_elf.py
    compare_profile.py
    find_code_caves.py
    build_patch_from_profile.py
    run_direct_probe.py
    parse_keybox.py
    make_report.py
  reports/
  runs/
```

最优先实现顺序：

1. `parse_mclf.py`：统一解析 MCLF，解决地址映射。
2. `scan_keymint_hal.py`：提取 keybox 路径、TA 路径、TCI command 候选。
3. `scan_keymint_ta.py`：用 strings + constants + MCLF 信息给 TA 打分。
4. `compare_profile.py`：把新 TA 与 Pacman profile 做语义差异表。
5. `build_patch_from_profile.py`：只按 profile 生成 patch，强制 expected bytes。
6. `run_direct_probe.py`：统一推送、运行、拉回、过滤日志。
7. `make_report.py`：输出矩阵和单设备报告。

人工逆向工具建议固定为一套：

```text
Ghidra 或 IDA：主反编译
llvm-objdump / rizin：批量反汇编和 grep
readelf / file / strings / xxd：基础取证
openssl：证书链和签名验证
Python：MCLF/profile/patch/keybox parser
```

---

## 14. 人工逆向检查表

迁移新设备时，人工必须在逆向工具里确认这些点：

```text
[ ] 找到 KeyMint TA，而不是 Widevine/DRM TA
[ ] TA 字符串包含 KEYMINT/teeKeymint 或同类证据
[ ] HAL 明确读取 keybox blob 和 ids blob
[ ] HAL command 与 TCI layout 已确认
[ ] TA dispatcher 已确认
[ ] keybox handler 已确认
[ ] mapped buffer copy 到 heap 已确认
[ ] decrypt wrapper 已确认
[ ] plaintext buffer 生命周期已确认
[ ] parse plaintext 调用点已确认
[ ] memcpy 或等价函数已确认
[ ] code cave 已确认
[ ] patch point expected bytes 已确认
[ ] proof-only patch 先跑通
[ ] full dump 只在授权样机运行
```

如果其中任意一项缺失，结论只能写：

```text
KEYMINT_PROFILE_NEEDED
```

不能写“漏洞不支持”，也不能写“完整复现成功”。

---

## 15. 报告格式建议

单设备报告应包含：

```text
1. 设备信息
2. 固件来源与 hash
3. fenrir L0 判断
4. TEE 类型与 patched TEE 状态
5. KeyMint HAL/TA 证据
6. keybox 路径证据
7. TA profile 匹配结果
8. proof-only 运行结果
9. full extraction 是否执行
10. 风险结论
11. 阻塞点或后续 profile port 工作
```

敏感字段处理：

- 报告允许出现证书 fingerprint、公钥 hash、TA hash、blob hash。
- 报告不应包含 private key、private scalar、完整 keybox XML。
- 完整提取产物只保存在加密目录，并写明销毁/封存状态。

---

## 16. 最终执行策略

建议实际测试按这个节奏：

```text
第一轮：只做 L0-L3 离线预筛
  从 fenrir 支持列表里排除明显不适配设备。

第二轮：对 Trustonic KeyMint 候选做 L4 profile port
  只做逆向和 proof-only patch，不导出私钥。

第三轮：每个设备族选 1 台授权样机做 L5 proof
  证明 keybox decrypt path 可达。

第四轮：每个设备族最多 1 台做 full extraction
  只作为最高影响证明。
```

这样可以把工作量从“每台设备都重新研究一遍”降到：

```text
每个设备族建立一个 profile
每个 firmware 版本只做 profile diff
每台真机只跑 collect/proof/report
```

这就是脱离 AI 的核心：把一次性的逆向发现，沉淀为 profile、检查脚本、expected bytes、报告模板和人工检查表。

---

## 17. Pacman 当前基线结论

当前仓库的 Pacman 基线可作为第一个完整 profile：

```text
device: Nothing Phone (2a) / Pacman / MT6886
build: NOS U2.5-240114-2323
TEE: Trustonic Kinibi/t-base
KeyMint TA: 0706000000000000000000000000004d.tlbin
factory keybox blob: /mnt/vendor/persist/attest_keybox.so
ids blob: /mnt/vendor/persist/attestation_ids.so
proof: pass
full extraction: pass
EC/RSA chain verify: pass
EC/RSA sign verify: pass
verdict: FULL_EXTRACTION_SUCCESS
```

后续所有设备都应与该基线做 profile 对比，而不是复制它的 offset。

---

## 18. 脚本化边界：按型号还是按固件版本

结论先行：

```text
fenrir 启动链入口：可以接近按型号/codename 管理。
KeyMint keybox 提取扩展：必须按 型号 + 固件/安全栈版本 管理。
如果能把测试机稳定降级/刷到同一已验证安全栈，才可以把日常测试简化为按型号。
```

原因是本项目至少依赖三层版本：

1. `LK / preloader`：决定公开 fenrir 入口是否成立。
2. `TEE / t-base`：决定 modified TA 是否能加载，以及 t-base 签名 bypass patch 是否有效。
3. `KeyMint HAL + KeyMint TA + persist keybox blob`：决定本项目的 TCI command、handler、decrypt path、patch offset 是否一致。

本仓库已有实证说明不能只按型号：

```text
U2.6 lk.img -> U2.5 系统：启动正常，说明 LK 层兼容性较宽。
U2.6 tee.img -> U2.5 系统：进 recovery / Can't load Android system。
U2.5-231207 tee.img -> U2.5-240114 系统：启动正常。
```

这说明同一型号内，不同分区的兼容边界不同：

- LK/preloader 可能跨小版本可用。
- TEE 不能随意跨大版本混刷。
- KeyMint TA/HAL offset 更不能假设跨版本不变。

所以脚本设计应是：

```text
先识别型号/codename
再识别 firmware fingerprint
再识别 bootchain hash
再识别 TEE hash/version
再识别 KeyMint HAL/TA hash
最后选择 profile
```

不要写成：

```text
if model == Pacman: apply Pacman patch
```

应写成：

```text
if codename == Pacman
  and tee_hash in known_good_tee_hashes
  and keymint_ta_hash in known_good_ta_hashes
  and expected bytes match:
      apply profile patch
else:
      run triage/profile-port mode
```

---

## 19. 降级/统一固件策略

降级的作用不是让漏洞“按型号存在”，而是让测试环境收敛到一个已验证的安全栈。

可以采用三种策略：

### 19.1 不降级，按现有固件建 profile

优点：

- 最贴近真实用户设备状态。
- 最适合做影响面统计。

缺点：

- 每个固件分支都可能需要 profile diff。
- 同一型号不同 OTA 可能结论不同。

适合输出：

```text
Pacman / U2.5-240114: FULL_EXTRACTION_SUCCESS
Pacman / U2.6-240828: TEE_PROFILE_NEEDED 或 KEYMINT_PROFILE_NEEDED
Pacman / NOS4 stable: FENRIR_REQUIRES_PRELOADER_MIX 或 PATCHED_BY_VENDOR
```

### 19.2 完整降级/平刷到已验证版本

优点：

- 测试脚本最简单。
- 同型号大量样机可以复用同一个 profile。

缺点：

- 会 wipe data。
- 可能需要解锁 bootloader。
- 可能受 Android rollback / OEM 限制影响。
- 需要每个型号确认救砖路径。

只有在确认以下条件后，才可把测试简化为“按型号”：

```text
目标型号有可用完整固件包或官方 rollback 包
能恢复到已验证版本
刷回后 boot/recovery/fastboot 均可用
TEE/KeyMint HAL/TA hash 与 profile 匹配
persist keybox blob 仍存在且可被该安全栈读取
```

### 19.3 不完整降级，只替换 bootchain 组件

这适用于公开 fenrir 入口被新版本修复，但旧/beta preloader 仍可与当前系统组合的场景。

该策略的判断重点：

```text
只替换 preloader/LK 是否足以恢复 fenrir L0/L1
当前系统的 TEE/KeyMint 是否保持原样
KeyMint 扩展 profile 是否需要重新适配当前系统
```

风险：

- preloader 刷错型号可能硬砖。
- 不能把“fenrir 入口恢复”误认为“KeyMint keybox 扩展已支持”。
- 仍然必须做 TEE/TA profile 检查。

---

## 20. 建议脚本拆分

要做成脚本，不建议一开始写“一键提取”。应先写一组小脚本，串成 pipeline。

### 20.1 `collect_live_device.sh`

用途：真机只读采集。

输出：

```text
ro.product.device
ro.product.model
ro.hardware
ro.build.fingerprint
ro.build.display.id
ro.vendor.build.security_patch
ro.boot.slot_suffix
ro.boot.verifiedbootstate
init.svc.tee-1-1
init.svc.keystore2
init.svc.vendor.keymint-trustonic
service list | grep keymint/rkp/keystore
ps -A | grep keymint/rkpd/tee
sha256sum /vendor/app/mcRegistry/*
sha256sum /vendor/bin/hw/*keymint*
ls -l /mnt/vendor/persist/attest_keybox.so
ls -l /mnt/vendor/persist/attestation_ids.so
```

不导出私钥，不 patch，不刷机。

### 20.2 `pull_keymint_assets.sh`

用途：授权 root 环境拉取 profile 所需资产。

输出：

```text
targets/<codename>/<build>/device_dump/vendor_app_mcRegistry/
targets/<codename>/<build>/device_dump/vendor_bin_hw/
targets/<codename>/<build>/device_dump/vendor_lib64/
targets/<codename>/<build>/device_dump/persist/
```

### 20.3 `triage_firmware.py`

用途：离线固件判断是否值得真机测试。

输入：

```text
lk.img
tee.img
vendor 解包目录
```

输出：

```json
{
  "codename": "Pacman",
  "fenrir_lk_pattern": "pass",
  "trustonic_tee": "pass",
  "libMcClient": "found",
  "keymint_hal": "found",
  "keybox_strings": "found",
  "keymint_ta_candidates": ["070600...4d.tlbin"],
  "verdict": "TRUSTONIC_KEYMINT_CANDIDATE"
}
```

### 20.4 `select_profile.py`

用途：按 hash 和 expected bytes 选 profile。

逻辑：

```text
codename match
build fingerprint match or known compatible
tee hash match or known compatible
keymint_ta hash match
expected bytes match
```

输出：

```text
FULL_PROFILE_MATCH
PROFILE_DIFF_REQUIRED
UNKNOWN_FIRMWARE
NOT_SUPPORTED_BY_CURRENT_PROFILES
```

### 20.5 `build_patch_from_profile.py`

用途：按 profile 生成 proof-only 或 dump patched TA。

必须：

- 检查 MCLF UUID。
- 检查 text mapping。
- 检查每个 patch point 的 expected bytes。
- 输出原始 hash、patched hash、patch diff。

### 20.6 `run_proof_probe.py`

用途：只跑 proof-only，不导出真实私钥。

输出：

```text
mcOpenTrustlet ret
cmd_keybox ret
cmd_ids ret
proof magic
plaintext structure summary hash
```

### 20.7 `run_sensitive_extract.py`

用途：少量样机完整提取。

必须默认关闭，要求显式参数：

```text
--i-understand-this-exports-attestation-private-keys
--case-id <公司授权编号>
--encrypt-output
```

输出目录必须带 `sensitive` 标记，不进入普通 reports。

---

## 21. 降级可行性检查脚本

建议做一个只判断、不执行刷机的脚本：

```text
check_downgrade_feasibility.py
```

输入：

```text
current_build_fingerprint
current_slot
target_firmware_dir
target_preloader_hash
target_lk_hash
target_tee_hash
target_vendor_hash 或 vendor build id
```

输出：

```text
FULL_DOWNGRADE_POSSIBLE_UNKNOWN
BOOTCHAIN_MIX_POSSIBLE
TEE_MIX_FORBIDDEN
NEEDS_UNLOCKED_BOOTLOADER
NEEDS_FACTORY_RESET
NEEDS_SIGNED_DA_OR_FASTBOOT
HIGH_BRICK_RISK
```

规则应包含本仓库已验证经验：

```text
禁止把 U2.6 tee 直接混刷到 U2.5 系统作为默认路径。
允许把 LK/preloader 兼容性作为单独实验项，但不能推导 TEE 兼容。
同一型号的不同大版本，必须先做 TEE/KeyMint hash/profile 检查。
刷 preloader 必须严格匹配型号和 slot。
```

---

## 22. 实际决策

最终建议：

```text
测试管理维度：按型号建目录。
技术 profile 维度：按 型号 + 固件/安全栈版本 建 profile。
如果确认可稳定降级到同一已验证安全栈，再把执行层简化为按型号。
```

也就是：

```text
targets/Pacman/
  profiles/
    U2.5-240114_trustonic_km_v2.json
    U2.5-240301_trustonic_km_v2.json
    NOS4_stable_preloader_mix_pending.json
  reports/
```

脚本不应该问“这个型号能不能提”，而应该回答：

```text
这个型号 + 当前固件 + 当前 TEE/TA hash，匹配哪个 profile？
```

这样以后如果降级路线确认可用，可以在矩阵里标：

```text
Pacman: normalize_to=U2.5-240114, profile=FULL_EXTRACTION_SUCCESS
```

如果不能降级或不允许 wipe，就保留固件维度：

```text
Pacman / U2.5-240114: full success
Pacman / U2.6-240828: needs profile diff
Pacman / NOS4 stable: fenrir requires bootchain mix, KeyMint profile unknown
```
