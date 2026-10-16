# Keybox 泄漏状态与价值评估

项目根目录：`<PROJECT_ROOT>`

## 1. 被评估对象

本次提取的是 Android Keystore / KeyMint factory attestation keybox，不是 Widevine keybox。

核心产物：

```text
<PROJECT_ROOT>/extracted_keybox/ec_private_key.pem
<PROJECT_ROOT>/extracted_keybox/rsa_private_key.pem
<PROJECT_ROOT>/extracted_keybox/ec_cert_chain.pem
<PROJECT_ROOT>/extracted_keybox/rsa_cert_chain.pem
<PROJECT_ROOT>/extracted_keybox/keybox.xml
```

## 2. 可公开对照指纹

完整指纹记录：

```text
<PROJECT_ROOT>/outputdoc/keybox_public_fingerprints.txt
```

关键公开标识：

```text
EC cert0 sha256  = b033890beef5b64ea51428693c60588769f302e030ac27b2f445fe529b078fca
EC cert1 sha256  = 624d1e0419c880581fdfc0dde131bd4e6899b7e196c49eb5ebf36b9a64ad7fbe
RSA cert0 sha256 = 45c1c2411ff098dab61c18f0934fa38ac2b98950dcb857e652b29a815890d5c2
RSA cert1 sha256 = 13a0f8a9e60fc88bccc8615ba845313c03051a87c4f29e385fccf7f13e39327e
Root sha256      = cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc

EC leaf serial   = <TARGET_SERIAL>
RSA leaf serial  = <TARGET_SERIAL>
Intermediate serials:
  EC  = EE8A6BFFB47EA2C708D0D530C1826649
  RSA = 5B47602E9EDB1E4C8677DE72E2D8FFB1
Root serial      = <TARGET_SERIAL>

Subject serialNumber:
  leaf         = 325d90cd5049b6c519af32bc6a413526
  intermediate = aa3d661ed0862f74108b03a8dd8abb3e
  root          = f92009e853b6b045
```

## 3. 公开泄漏检查结论

已做 exact-match 公开检索的项目：

```text
b033890beef5b64ea51428693c60588769f302e030ac27b2f445fe529b078fca
45c1c2411ff098dab61c18f0934fa38ac2b98950dcb857e652b29a815890d5c2
cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc
325d90cd5049b6c519af32bc6a413526
aa3d661ed0862f74108b03a8dd8abb3e
f92009e853b6b045
088F0AD2356102AC66A9FE50D823B974
99F44FB48537777B249D0BA06E0FC4F4
```

初步结果：未发现公开 exact-match 命中。

判断：

```text
当前没有公开证据表明该 keybox 已经被大范围公开泄漏。
```

限制：

- exact-match 搜索不能覆盖私有库、Telegram/论坛附件、未索引压缩包、私下流通数据集。
- 公开无命中不等于未被他人提取过。
- 若服务端已有内部 revoke / denylist，外部搜索无法直接确认。

## 4. 本 keybox 的真实性与可用性证据

### 4.1 私钥与证书匹配

```text
EC private pub hash  = EC cert0 pub hash  = 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA private pub hash = RSA cert0 pub hash = f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

### 4.2 证书链验证通过

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

### 4.3 私钥签名验证通过

```text
EC sign verify:  Verified OK
RSA sign verify: Verified OK
```

### 4.4 与 AndroidKeyStore 触发链对应

```text
extracted EC cert0/1/root  == kmprobe EC cert1/2/3
extracted RSA cert0/1/root == kmprobe RSA cert1/2/3
```

这说明提取物不是随机 DER，也不是普通证书备份，而是当前设备 KeyMint factory attestation chain 的上层签名材料。

## 5. 价值评估

### 5.1 CTF / 研究价值

评级：高。

原因：

1. 证明了完整攻击链：boot/TEE bypass -> modified KeyMint TA -> attestation keybox plaintext dump。
2. 产物可验证，私钥、证书链和 AndroidKeyStore 实际触发链闭合。
3. 可作为报告、writeup、复现材料。
4. 同类 Trustonic/MediaTek 设备上方法具有迁移参考价值。

### 5.2 实际使用价值

评级：中到高，取决于验证方策略。

有价值的条件：

1. 验证方接受本地 factory TEE attestation chain。
2. 该 chain 没有被加入 denylist / revocation list。
3. 验证方没有强制要求 RKP 证书链。
4. 验证方没有严格检查 boot state / patch level / device properties 与签名上下文的一致性。

价值下降的条件：

1. 服务端强制 RKP。
2. 服务端拒绝旧式 factory attestation chain。
3. 服务端检查 revoked/known leaked serial。
4. 服务端检查 generated key leaf 的 attestation extension 与设备状态。
5. 该 keybox 后续被公开或被提交到风控样本库。

### 5.3 稀缺性判断

从当前公开 exact-match 检索看，没有发现相同 cert 指纹/serial 的公开泄漏。  
如果该设备的 leaf/intermediate 是设备唯一或小批次唯一，则稀缺性较高。  
如果该链是批量共享，则价值会下降，但仍具研究价值。

当前证据中：

```text
EC/RSA leaf subject serialNumber 相同：325d90cd5049b6c519af32bc6a413526
EC/RSA intermediate subject serialNumber 相同：aa3d661ed0862f74108b03a8dd8abb3e
root serialNumber：f92009e853b6b045
```

这更像厂商/批次 TEE attestation chain，而不是一次性 RKP leaf。

## 6. 结论

```text
是否已经公开泄漏：目前公开 exact-match 未见命中，暂按“未见公开泄漏证据”处理。
价值：CTF/研究价值高；实际使用价值取决于服务端是否接受本地 factory attestation chain、是否检查 RKP/撤销/boot state。
```

若要进一步确认真实世界可用性，下一步应测试目标验证服务对该 chain 的接受程度，以及查询/模拟其 revocation 策略。
