# K70E CTF `PASS_CLEAN_HYBRID` 正式提交包与校验器

> 日期：2026-09-07  
> 技术结果：`PASS_CLEAN_HYBRID`（原始程序字段 `PASS_CLEAN`）  
> Provisioning Info：`APPROVED` / 全链 `NOT_APPROVED=0` / 解析错误 0  
> 赛事方接收：尚无回执  
> 手机恢复：独立问题，尚未解决；不影响本包离线交付

## 1. 本次收拢结果

已把题目要求的三类原始产物冻结到一个私密提交候选目录：

```text
<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL
```

该目录含 41 个普通文件，总计 223018 bytes；目录模式 0700，文件模式 0600，无符号链接、特殊文件或硬链接。其 `SHA256SUMS.txt` 覆盖除清单自身外的全部 40 个文件。

冻结清单 SHA-256：

```text
cea16a1d15a61e2546f3245da2a4dc283b6543d3177c6bc7c140dc48abde6505
```

## 2. 赛事三项上传映射

### 2.1 用户 `google-rkp-sw` 身份数据

目录：

```text
01_identity/
```

核心文件：

```text
native_identity_authenticated_request.cbor
google_rkp_sw_cdi_leaf_p256_scalar.bin
cdi_leaf_public_spki.der
verified_registered_uds_and_dice.cbor
verified_top_level_uds_certs.cbor
clean_device_info.json
identity_verification.json
native_identity_verification.json
```

`google_rkp_sw_cdi_leaf_p256_scalar.bin` 是 32-byte P-256 final measurement-bound DICE leaf scalar。它派生的 SPKI 精确等于该五层 DICE 最终 leaf SPKI：

```text
64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
```

它不是 raw UDS/HUK，也不是能从根部重建全部 DICE 的通用 CDI seed；但它正是给 proper-DICE outer AuthenticatedRequest 签名所需的匹配私钥。

### 2.2 一次 `google-rkp-sw` 成功产生的软件私钥

```text
02_generated_key/private_key_pkcs8.der
```

属性：

```text
format  canonical unencrypted PKCS#8 DER
curve   P-256
size    138
sha256  58da03dc8361b42b6946c798ff609e825a4bd6263852e59cbd98b300e869f2d8
SPKI    1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

该 SPKI 同时等于实际请求中唯一的 KeysToSign 公钥和 Google leaf 证书公钥，并且不同于 DICE identity SPKI。

### 2.3 一次 `google-rkp-sw` 成功产生的 Google 证书链

```text
03_certificate_chain/ordered_certificate_chain.der
03_certificate_chain/ordered_certificate_chain.pem
```

DER 链：

```text
certificate count  4
size               2486
sha256             423116069703debf65c4c34e17657a2b7f9fc43d281f4386f723518c0e312d20
```

leaf Provisioning Info 精确内容：

```text
{1:32, 3:"Xiaomi", 5:{1:"APPROVED", 2:"acaa9258a1d3bf97006baf17735504ec976c27ff4f6568d4803726f7b840b6e9"}}
```

四张证书的签名链接、root 自签、Google root DER/SPKI pin 均通过。

## 3. 原始请求和服务端证据

`04_proof/` 保留：

- 实际 `certificate_request.cbor`；
- 本次 challenge；
- fetchEekChain 请求、原始响应和 HTTP 200 元数据；
- signCertificates 原始响应和 HTTP 200 元数据；
- `FINAL_RESULT.json`、`REQUEST_AUDIT.json`、`INPUT_AUDIT.json`、`SUCCESS.json`。

原始 signCertificates 响应严格解码后得到的唯一链与冻结 DER 链逐字节一致，不是事后拼接的另一套证书。

## 4. 专用离线校验器

位置：

```text
02_脚本与补丁/verify_k70e_hybrid_submission.py
05_Skill/k70e-rkp-ctf/scripts/verify_hybrid_submission.py
提交包/99_verifier/verify_k70e_hybrid_submission.py
```

三份 SHA-256：

```text
b1c946f4e78c99319aa0373be2cef08b1c8b5f06382f9a455e1b394a2c328934
```

执行：

```bash
PY='<PROJECT_ROOT>/third_party/google-rkp-sw/.venv/bin/python'
BUNDLE='<PROJECT_ROOT>/<DEVICE_WORKSPACE>/03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL'
"$PY" "$BUNDLE/99_verifier/verify_k70e_hybrid_submission.py" "$BUNDLE"
```

校验器只离线读取，检查：

1. 文件集合、权限、硬链接/符号链接和全覆盖清单；
2. scalar 合法范围、scalar→identity SPKI→DICE leaf；
3. registered UDS + 五层 DICE，5/5 签名和 identity outer 签名；
4. 实际请求原样使用该 DICE、clean DeviceInfo、唯一 software key，且 request outer 签名有效；
5. PKCS#8 canonical P-256、随机 nonce PoP、private→request key→Google leaf；
6. 原始 Google 响应与保存链逐字节关系；
7. 四证书唯一有序链、全部签名、root 自签和 pin；
8. 全链 OID `1.3.6.1.4.1.11129.2.1.30` 严格 CBOR 解析与递归 `NOT_APPROVED` 扫描；
9. semantic-hybrid、fully-stock=false、organizer pending 标签不能被抹掉。

外部验收结果：

```text
03_提取结果/K70E_CTF_SUBMISSION_google-rkp-sw_PASS_CLEAN_HYBRID_20260906_FINAL_VERIFICATION.json
sha256 9e2cb8fb517dc60a6a3085240e64e90160a0516543d608def45d4472e9b31bd7
status PASS_CLEAN_HYBRID
```

## 5. 新发现并修复的校验器坑

原 `audit_provisioning_info.py` 直接访问 `cbor2.FrozenDict`。当前固定环境的 `cbor2 6.1.4` 只导出小写 `cbor2.frozendict`，导致真实 APPROVED 扩展被误报为：

```text
AttributeError: module 'cbor2' has no attribute 'FrozenDict'
```

已改为运行时兼容两种导出名称，安装 Skill 和项目 Skill 同步。修复后：

- 新 APPROVED 四证书链：exit 0，`ctf_no_not_approved=true`；
- 旧 NOT_APPROVED 四证书链：exit 1，精确命中 `$/5/1`；
- 脚本 SHA-256：`dc808ae4668a5470a891b300697907b65778e5c82f060d7bdeea881ad8a38f58`。

## 6. DICE、DeviceInfo 与根因结论

本成功请求没有换成历史 clean DICE；它保留 exact modified five-layer DICE，只换入同机历史 clean DeviceInfo。因此已经直接证明：

- 当前 final DICE leaf scalar 是正确且可用的 outer signing identity；
- 这套 modified DICE 不是旧 `NOT_APPROVED` 的充分原因；
- host `google-rkp-sw` 路线本身可以得到合法 `APPROVED` 链；
- 不是“尝试次数太多导致该 identity 被统一风控”；
- 设备控制的首要嫌疑是 `vb_state`、`bootloader_state`、`vbmeta_digest` 三项或其服务端一致性规则，其中回显的 clean vbmeta digest 是最强线索。

三项同时变化，challenge、software key、request_id、时间和不透明服务端状态也变化，所以不能伪称完成单字段严格因果隔离。

## 7. 为什么现在不买 BROM key

BROM key 只可能用于修复参考手机或做 future fully-stock same-run recapture，不是得到本次 clean Google 证书的前置。当前技术三件套已经通过专用校验器。

参考手机仍有独立故障：stock vbmeta/LK 下遗留 OrangeFox `vendor_boot_a` 和 Magisk `init_boot_a`，构成双 AVB mismatch；stock Fastboot 写入曾被 `No support by lock control` 拒绝。BROM 只到 challenge，未获 SLA/auth、未进 DA、未发生分区 I/O。

因此现在没有花钱购买 key 的必要。只有用户明确要修手机/做 strict-stock，同机在场、Recovery/MiAssistant 路线不可用、Fastboot 仍被 lock control 阻塞，并且商家确认 MT6897/0x1203、SPFT V6、challenge-specific SLA/auth 和 DA 都支持时，才重新评估。

任何恢复都不得只刷一个分区；必须通过已证明的写通道成对恢复 official CN304 `vendor_boot_a` 和 `init_boot_a`。禁止再刷 TEE。

## 8. 终态和下一步

```text
Google / crypto / PI            PASS_CLEAN_HYBRID
raw FINAL_RESULT.status          PASS_CLEAN
formal frozen bundle             COMPLETE
dedicated offline verifier       PASS
organizer acceptance             NOT RECORDED
fully-stock same-run provenance  NOT CLAIMED
phone recovery                   SEPARATE / UNRESOLVED
BROM key purchase                NOT JUSTIFIED NOW
```

下一步不是继续试探 Google，也不是先修手机；而是按赛事上传格式提交这份冻结候选，并保存赛事方原始回执。如果赛事方明确拒绝 semantic hybrid 或要求 fresh fully-stock same-run provenance，再进入手机恢复/stock-log 支线。
