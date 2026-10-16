# K70E 活动 `GenerateRkpKey` 私钥生成路径静态闭合

日期：2026-08-30（Asia/Taipei）  
设备：Redmi K70E / `duchamp`  
范围：原厂 Mitee KeyMint TA 的离线静态分析；设备下班后保持不动，不执行刷写、重启或在线探测。

## 结论

当前活动 RKP 路径已经可以静态闭合到“P-256 私钥被序列化为 KeymasterBlob”的边界：

```text
活动命令 0xc94d8
  └─ BL 0x61960   GenerateRkpKey
       ├─ 0x610e8  GenerateKey/工厂分发
       │    └─ factory vtable +0x10
       │         └─ 0xa2fd0  EcKeyFactory::GenerateKey
       │              ├─ 0xfb0f0   EVP_PKEY_new（P-256 分支）
       │              ├─ 0x114fe0  选择 P-256 group
       │              ├─ 0x116770  EC_KEY_set_group
       │              ├─ 0x116c28  EC_KEY_generate_key
       │              ├─ 0x116a28  EC_KEY_check_key
       │              ├─ 0xfb3e0   EVP_PKEY_set1_EC_KEY
       │              ├─ 0xa79d0   EvpKeyToKeyMaterial（私钥材料序列化）
       │              └─ 后续 vtable  CreateKeyBlob（生成 opaque key blob）
       └─ 0xa7b88  GetEcdsa256KeyFromCert（只取证书公钥 X/Y）
```

因此，`0xa7b88` 不是私钥比较器，也不是 `CDI_Leaf` 提取点。此前在该处导出的两个 32 字节值应标记为错误分支：它们是证书 EC 公钥坐标/内部大整数对象相关数据，不能作为 scalar、seed 或 IDC。

## 证据链

### 1. 活动入口到密钥工厂

原厂 TA（整体 SHA-256：
`facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`）中：

* `0xc94d8` 直接 `BL 0x61960`；
* `0x61960` 保存上下文、请求和响应结构，并经上下文 vtable `+0xb8` 取得活动对象；
* `0x61960` 在 `0x61c78` 调用 `0x610e8`；
* `0x610e8` 从上下文取得算法工厂，并在 `0x6124c` 通过工厂 vtable `+0x10` 分发到具体 `GenerateKey` 实现。

这条调用图与 Android Keymaster 的 `GenerateRkpKey → GenerateKey → key_blob + MacedPublicKey` 结构一致；官方实现会从生成证书取出 EC 公钥 X/Y，并把 key blob 与 MacedPublicKey 分开返回（参见 [Android Keymaster GenerateRkpKey](https://android.googlesource.com/platform/system/keymaster/%2B/master/android_keymaster/android_keymaster.cpp)）。

### 2. P-256 生成的非 25519 分支

`0xa2fd0` 与 AOSP `EcKeyFactory::GenerateKey` 的控制流逐段对应。曲线字段不为 25519 时：

| TA 地址 | 静态对应 | 作用 |
|---|---|---|
| `0xfb0f0` | `EVP_PKEY_new` 包装 | 创建 EVP_PKEY 容器 |
| `0x114fe0` | `ChooseGroup`/曲线组选择 | P-256 的 group/NID 映射 |
| `0x116770` | `EC_KEY_set_group` 包装 | 绑定 P-256 group |
| `0x116c28` | `EC_KEY_generate_key` 包装 | 生成随机私钥 scalar 与公钥点 |
| `0x116a28` | `EC_KEY_check_key` 包装 | 检查 EC key 一致性 |
| `0xfb3e0` | `EVP_PKEY_set1_EC_KEY` 包装 | 将 EC_KEY 放入 EVP_PKEY |

`0x116c28` 是私钥 scalar 首次确定存在于 EC 对象内的生成边界；但此时仍在 TA 内存中，不能把该地址本身当作可读私钥。

### 3. 私钥材料进入 KeymasterBlob

生成成功后，`0xa2fd0` 在 `0xa3210` 取回 EVP_PKEY，并在 `0xa32ac` 调用 `0xa79d0`：

```text
0xa3210  ldr x0, [sp,#0x40]   // EVP_PKEY
0xa32ac  mov x1, x25          // KeymasterBlob*（本地输出结构）
0xa32b4  BL  0xa79d0
0xa32b8  str w0, [error]
```

`0xa79d0` 的第一步是调用 `0xfb218` 读取 EVP 对象的类型字段；随后 EC 分支通过 `0xee7c0`、`0xf91c8` 和 `0xee918` 取得私钥材料指针/长度，分配新缓冲区并复制到输出 `KeymasterBlob`。其中 `0xf91c8` 读取 `EVP_PKEY` 内部方法表 `+0x30` 并间接跳转，正是私钥 DER 编码的动态分发边界；`0xa7aa4` 明确调用 `memcpy`，把该临时编码复制到 `x19` 指向的输出 blob。对应的 AOSP [`EvpKeyToKeyMaterial`](https://android.googlesource.com/platform/system/keymaster/%2B/eb51e7fc8367d59061fc8970d5c1f519995b0029/km_openssl/openssl_utils.cpp) 使用 `i2d_PrivateKey` 将 `EVP_PKEY` 序列化为 DER（EC 通常是 `ECPrivateKey`，不是 32 字节裸窗口）。在 `0xa32b4` 返回之后，`x25` 指向的结构已经包含序列化私钥材料；紧接着的后续 vtable 调用才把它包装为 opaque key blob。

这给出了下一次在线验证的最小、确定性观测点：在**原始 `BL 0xa79d0` 完成后、进入 CreateKeyBlob 前**，读取 `x25` 指向的 `(data, length)`，然后只把这段材料保存到诊断输出；绝不扫描任意 32 字节窗口，也不改写生成逻辑。若输出是 PKCS#8/DER，应直接解析；若输出是原始 32 字节大端 scalar，则转成 PKCS#8 前必须通过同次 `MacedPublicKey` 的 X/Y 精确匹配。

### 4. `0xa7b88` 的正确语义

`0xa7b88` 的反汇编明确显示：

* 强制 `x2 == 0x20`、`x4 == 0x20`；
* 从证书/密钥对象取出两个字段；
* 经 `0x1157d0` 和 `0xee560` 处理两个 32 字节输出；
* 调用位置紧邻字符串 `GenerateRkpKey GetEcdsa256KeyFromCert`。

这对应“从证书提取 P-256 公钥 X/Y”，不是私钥 scalar。现有诊断目录中的 `comparison_value_0.bin`、`comparison_value_1.bin` 和 275 字节对象前缀因此只能作为排错记录，不得提交为私钥。

## 主机侧严格匹配工具

已新增：

`02_脚本与补丁/verify_rkp_private_matches_maced.py`

输入为一个候选私钥（接受 32 字节大端 scalar，或未加密 EC 私钥 PEM/DER，包括 `i2d_PrivateKey` 产生的传统 ECPrivateKey DER）和同次 `maced_public_key.bin`。工具会：

1. 解码 COSE_Mac0 载荷并确认 `P-256 / ES256 / crv=1`；
2. 从候选私钥推导公钥 X/Y；
3. 对 X、Y 做逐字节精确比较；
4. 只有匹配时才写出 PKCS#8 PEM，且以 `0600` 权限保存；
5. 拒绝 275 字节 opaque KeyMint handle，并且从不打印私钥字节。

已用现有材料验证门禁行为：

* `private_key_blob_opaque.bin`（275 字节）→ `FAIL: opaque KeyMint handle`；
* 外来 FF06 候选 PKCS#8 → `FAIL: public_x_match=false, public_y_match=false`；
* 内存合成的 P-256 正例 → `SELFTEST PASS`。

## 设备恢复后的最小验证顺序

设备重新在线后，先只读确认原厂启动链和 TA 哈希；清理此前未使用的 `.armed` 诊断标记；确认 `ro.boot.verifiedbootstate=green`、`tee-supplicant` 与 `vendor.keymint-mitee` 正常。之后再由用户在场、逐步验证一个“只捕获 `a79d0` 返回后 KeymasterBlob”的诊断构建。

判定标准固定为：

```text
私钥材料存在
  AND 长度/格式可解析
  AND 推导的 P-256 X/Y == 同次 MacedPublicKey 的 X/Y
  AND 用该私钥生成/提交 CSR 后 Google HTTP 200
```

在四项全部满足前，工作区仍不能声称已经取得赛事要求的“私钥 + Google 证书”最终产物。当前原生目录中的证书链和 275 字节 opaque blob 仍是半成品，不改变这一结论。

## 相关文件哈希

```text
原厂 TA：facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32
MacedPublicKey：cc5025fffaa8696e6dbe085988e851f31591629c78b86c4b7407ff8fd95db45d
匹配工具：a77aeebbc22adbdc8d9efdb4e19cdd2ee24477152c9c0b9a7131016ee18fcd15
```
