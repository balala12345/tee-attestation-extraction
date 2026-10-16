# K70E MiTEE ta-mgr TA 签名校验绕过分析

日期：2026-09-01（Asia/Taipei）  
范围：对已保存的 `tee_a.bin` 镜像中 ta-mgr 二进制做只读反汇编分析，定位 TA 签名/哈希校验的精确 patch 点。  
状态：**分析完成，patch 方案未实施**——实施需要完整的启动链绕过（engineering preloader → Fenrir LK → patched TEE），且需要可恢复方案确认后方可刷写。

> **2026-09-05 复核更正（后续工作以此为准）**
>
> 1. `0x70414930` 在本机 ta-mgr 中实际是 **RSA-PSS / SHA-256 / MGF1-SHA256 / saltLen=32**，不是下文早期记录的 PKCS#1 v1.5。用 ta-mgr 内置 RSA-2048 公钥对 5 份原厂 dba51 TA（2023-09 至当前 2025-08）逐份验签，全部通过。
> 2. 真正的 `check_ta_version()` 位于 ta-mgr `0x22d98`，调用点为 `0x1e248`、`0x1e740`；`0x233c0` 实际是保存 TA 到安全文件系统的路径，不是版本检查函数。
> 3. 防回滚比较的是 `TrustApp` note descriptor `+0x1c` 的 16 位 TA 版本。上述 5 份同 UUID 原厂样本均为 `101`，因此相对当前 ta-mgr 的静态签名、哈希和版本加载门全部通过。这个结论只证明字节级静态门，不等于手机已实际替换或执行旧 TA。
>
> 可复跑证据：`02_脚本与补丁/audit_k70e_signed_ta_history_hostonly.py` 与 `03_提取结果/K70E_dba51_原厂签名与回滚门_hostonly_20260905/audit.json`。下文保留为 2026-09-01 当时的历史分析，其中与本更正冲突的算法/地址说明不得继续引用。

## 结论

在 ta-mgr 二进制中找到了 **2 个精确的 4 字节 patch 点**，可分别绕过 RSA 签名校验和 SHA 哈希校验。Patch 效果是：无论 TA 文件的签名和哈希是否正确，ta-mgr 都会走"校验通过"分支继续加载 TA。

但 patch ta-mgr 只解决了三层启动链中的最内层。要让 patched TEE 实际运行，还需要：
1. **engineering preloader 绕过 bl2_ext 签名校验**（加载 Fenrir LK）
2. **Fenrir LK 绕过 TEE 镜像签名校验**（加载 patched TEE）
3. **patched TEE 中的 ta-mgr 绕过 TA 签名+哈希校验**（本文档定位的 patch）

## 1. TEE 镜像结构

```
tee_a.bin (5,242,880 bytes)
├── MTK LK image header (magic 0x58881688)
├── Partitions:
│   ├── atf      @ 0x00000
│   ├── cert1    
│   ├── cert2    
│   ├── tee      @ 0xe9f30 (3,106,816 bytes)
│   │   ├── "EET KTM " header (Zircon kernel)
│   │   ├── Kernel code
│   │   └── LZ4 compressed bootfs @ tee+0xdc058
│   │       └── Decompressed: 4,505,600 bytes, 30 entries
│   │           ├── bin/ta-mgr (315,024 bytes) @ bootfs+0x068000
│   │           ├── bin/bootsvc, devhost, devmgr, fshost, svchost, se-svc
│   │           ├── ta/tee-info
│   │           ├── driver/*.so (9 个)
│   │           └── lib/*.so (12 个)
│   └── spmc_dtb @ 0x3e17e0
```

## 2. ta-mgr TA 加载校验流程

ta-mgr 是 AArch64 PIE/DYN ELF（stripped），包含 TA 加载和验证逻辑。源码引用：`system/core/ta-mgr/ta_load.cpp`。

### 2.1 校验调用链

```
TA 加载主函数 (~0x1d678):
  │
  ├── shdr_alloc_and_copy()  @ bl 0x25430    // 解析 TA header，检查 magic
  │   └── 失败 → log "shdr_alloc_and_copy failed res %x"
  │
  ├── [log shdr 字段: sig_ver, algo, img_type, hash_size, sig_size, hd_size]
  │
  ├── shdr_verify_signature() @ bl 0x25918   // RSA 签名校验 ★★★
  │   ├── 内部调用 crypto_acipher_rsassa_verify() @ bl 0x2ec18
  │   ├── 成功 → log "crypto_acipher_rsassa_verify success"
  │   └── 失败 → log "crypto_acipher_rsassa_verify faild" → return 0xFFFF000F
  │
  ├── shdr_check_digest()    @ bl 0x25610    // SHA 哈希校验 ★★★
  │   ├── 计算 TA image SHA-256/384
  │   ├── 与 header 中的 expected hash 比较
  │   └── 失败 → log "img hash digest compare failed" → return 0xFFFF000F
  │
  ├── check_ta_version()     @ bl 0x233c0    // 版本防回滚（在另一个函数中调用）
  │
  └── ta_permission check                     // 权限校验
      └── 失败 → log "ta_permission not right 0x%lx"
```

### 2.2 关键汇编代码（调用点）

```asm
;; TA 加载主函数中的签名校验调用和结果检查

0x01dbd4: bl       #0x25918        ; call shdr_verify_signature(shdr)
0x01dbd8: cbz      w0, #0x1dc08    ; if w0==0 (成功) → 跳到 digest check
0x01dbdc: mov      w21, w0         ; else 保存错误码
0x01dbe0: [设置 "shdr_verify_signature failed: %x" 参数]
0x01dc04: b        #0x1dc3c        ; → 跳到清理/失败路径

0x01dc08: ldr      x0, [x25, x23]  ; 签名校验通过，继续
0x01dc0c: bl       #0x25610        ; call shdr_check_digest(shdr)
0x01dc10: cbz      w0, #0x1dd14    ; if w0==0 (成功) → 跳到成功路径
0x01dc14: mov      w21, w0         ; else 保存错误码
0x01dc18: [设置 "shdr_check_digest failed %x" 参数]

0x01dd14: [成功路径：继续 TA 加载流程]
```

## 3. 精确 Patch 方案

### 方案 A：Patch 调用点的条件跳转（推荐，最小改动）

| Patch | ta-mgr 偏移 | bootfs 偏移 | 原始字节 | 原始指令 | Patch 字节 | Patch 指令 |
|-------|-------------|-------------|----------|----------|------------|------------|
| **P1** | `0x1dbd8` | `0x085bd8` | `80 01 00 34` | `cbz w0, #0x1dc08` | `0c 00 00 14` | `b #0x1dc08` |
| **P2** | `0x1dc10` | `0x085c10` | `20 08 00 34` | `cbz w0, #0x1dd14` | `41 00 00 14` | `b #0x1dd14` |

**效果**：将"校验返回值为 0 时才继续"改为"无条件继续"。shdr_verify_signature 和 shdr_check_digest 仍然会执行（日志仍会输出），但其返回值被忽略。

**改动量**：共 8 字节（2 × 4 字节指令）

### 方案 B：Patch 函数入口直接返回 0（备选）

| Patch | ta-mgr 偏移 | bootfs 偏移 | 原始字节 | Patch 字节 | Patch 指令 |
|-------|-------------|-------------|----------|------------|------------|
| **ALT-A** | `0x25918` | `0x08d918` | `f9 0f 1b f8 f8 5f 01 a9` | `e0 03 1f 2a c0 03 5f d6` | `mov w0, wzr; ret` |
| **ALT-B** | `0x25610` | `0x08d610` | `f9 0f 1b f8 f8 5f 01 a9` | `e0 03 1f 2a c0 03 5f d6` | `mov w0, wzr; ret` |

**效果**：函数不执行任何校验，直接返回 TEE_SUCCESS(0)。

**改动量**：共 16 字节（2 × 8 字节）

## 4. shdr_verify_signature 函数分析

函数地址：ta-mgr+0x25918（bootfs+0x08d918）  
大小：约 512 字节（0x25918-0x25b40）

```
shdr_verify_signature(shdr):
  ├── 调用 0x2e948 (crypto context 初始化)
  │   └── 失败 → return error
  ├── 调用 0x305a8 (加载签名算法参数, w1=4=RSA)
  │   └── 失败 → return error
  ├── 调用 0x305a8 (加载公钥, w1=0x100=256字节=2048-bit RSA)
  │   └── 失败 → return error
  ├── 设置算法 ID: w21 = 0x70414930 ("0IAp" → RSA PKCS#1 v1.5 with SHA-256)
  ├── 调用 0x2ec18 (crypto_acipher_rsassa_verify)
  │   ├── 参数: algo, key, hash, hash_len, sig, sig_len
  │   ├── 成功 → log "crypto_acipher_rsassa_verify success"
  │   │         → 清理 → return 0 (TEE_SUCCESS)
  │   └── 失败 → log "crypto_acipher_rsassa_verify faild: %x"
  │             → 清理 → return 0xFFFF000F (TEE_ERROR_SECURITY)
  └── 返回: w0 = 0 (成功) 或 0xFFFF000F (失败)
```

RSA 公钥长度 256 字节（2048-bit），签名算法为 RSASSA-PKCS1-v1_5-SHA-256。公钥嵌入在 TEE 镜像内部（ta-mgr 或其关联的数据段），不从外部加载。

## 5. shdr_check_digest 函数分析

函数地址：ta-mgr+0x25610（bootfs+0x08d610）  
大小：约 768 字节（0x25610-0x25918）

```
shdr_check_digest(shdr):
  ├── 调用 0x2c2e8 (hash context alloc, algo=0x50000004=SHA-256)
  ├── 调用 0x2c420 (hash init)
  ├── 调用 0x2c478 (hash update: TA header)
  ├── 调用 0x2c4e8 (hash final: 得到 32 字节 digest)
  ├── 调用 0x48ff0 (memcmp: 比较 computed vs expected, 32 字节)
  │   ├── 不匹配 → log "img hash digest compare failed" → return error
  │   └── 匹配 → 继续
  ├── 第二轮 hash (可能是 TA body 的 hash):
  │   ├── hash init → hash update (body data) → hash final
  │   └── memcmp → 匹配 → log success
  └── 返回: w0 = 0 (成功) 或 0xFFFF000F (失败)
```

该函数做两轮 SHA-256 hash：一轮验证 TA header，一轮验证 TA body。

## 6. TEE 镜像重建链

要将 patched ta-mgr 放回 TEE 镜像，需要：

```
步骤 1: 在 decompressed bootfs 中替换 ta-mgr 的 2 个（或 4 个）字节
         └── bootfs offset 0x085bd8: 80010034 → 0c000014
         └── bootfs offset 0x085c10: 20080034 → 41000014

步骤 2: 用 LZ4 frame 格式重新压缩 bootfs
         └── 原始压缩数据位于 tee partition data + 0xdc058
         └── 压缩后大小可能不同，需要调整 partition header

步骤 3: 替换 TEE partition 中的压缩 bootfs
         └── 更新 partition 大小字段（如果压缩后大小改变）

步骤 4: 重建 MTK LK image
         └── 更新 partition table entry
         └── cert1/cert2 可能包含 hash/签名，需要处理

步骤 5: 刷写 patched tee_a
         └── 需要 Fenrir LK 跳过 TEE 签名校验
```

### 6.1 cert 签名问题

MTK LK image 的 cert1/cert2 partition 通常包含：
- 各 partition 的 SHA-256 hash
- 用 OTP root key 或 SBC key 签名的 hash 链

即使在 bootfs 中 patch 了 ta-mgr，TEE partition 的 hash 会变化，导致 cert 校验失败。这就是为什么需要 Fenrir LK 来跳过这一层校验。

## 7. 完整启动链绕过

```
第一层: Engineering Preloader → 跳过 bl2_ext(LK) 签名校验
        └── 状态：未确认。eng preloader 中存在 img_auth_required 检查，
            但未找到明确的 bypass 逻辑。需要设备实测或更深入分析。

第二层: Fenrir LK → 跳过 TEE 镜像签名校验
        └── 状态：已知 Fenrir 通过 patch sec_get_vfy_policy 跳过启动镜像校验。
            但当前设备 sbcen_unlock=2 → img_auth_required=1，
            stock preloader 下 Fenrir LK 本身无法通过校验加载。

第三层: Patched TEE ta-mgr → 跳过 TA 签名+哈希校验
        └── 状态：本文档定位了精确 patch 点。2×4 字节修改。
```

### 7.1 关键阻塞

**当前最大阻塞仍在第一层和第二层**：

- Stock preloader 在 `sbcen_unlock=2` 时强制 `img_auth_required=1`，不允许加载未签名的 LK（包括 Fenrir）
- Engineering preloader 是否跳过此检查尚未确认
- 即使 engineering preloader 可用，它本身需要通过 BootROM 校验（BootROM 的 SBC fuse 控制）

## 8. 安全约束

以下操作在本文档范围内 **禁止**：

- 不刷写 preloader、seccfg、proinfo、persist、nvram、nvdata、efuse、RPMB、userdata
- 不刷 LK、替换 TA、锁 BL 或联网提交，除非先取得新的明确证据和可恢复方案
- 不把公钥、MAC、签名、EEK、ProtectedData 或 275 字节 opaque blob 当成 IDC

原厂备份 SHA-256：
- `lk_a` 原始备份: `9c760f784a8621682f85a58617a6332ae372cd208d41a7d4ddf475531bbfcb35`
- `tee_a.bin`: `18227785891a3db4119fb3055ae09bb538a6a8e9ce874876b34d287386eaf21d`
- Stock TA: `facdfe3d8cb546acbbb4dc233b139a4dfd65f01e4791bbc26c474eb2eb0a3f32`

## 9. 完整启动链层级分析

```
                    ┌─────────────────────────────────┐
  第零层 (硬件)     │ BROM SLA (Secure Link Auth)      │ ← 当前设备 VID_0E8D PID_0003
                    │ 阻止加载未授权 DA/preloader       │    SLA status 0x1D0D
                    │ 状态: 阻塞。无公开 MT6897 绕过    │    Chimera 有私有能力但不公开
                    └─────────────┬───────────────────┘
                                  ▼
  第一层 (preloader) │ Engineering Preloader             │ ← 768KB, 有 USB cmd loop
                    │ SEND_DA 仍做签名校验 (0x7024 fail) │    GET_SOC_ID/GET_ME_ID 无 SLA 检查
                    │ 状态: 即使加载，仍不能 bypass       │    CVE-2026-20435 仅 info disclosure
                    │         bl2_ext 签名               │
                    └─────────────┬───────────────────┘
                                  ▼
  第二层 (LK)       │ Fenrir LK                         │ ← patch sec_get_vfy_policy
                    │ 跳过启动镜像签名校验               │    但 sbcen_unlock=2
                    │ 状态: 可用，但需要第一层放行        │    → img_auth_required=1 不可绕过
                    └─────────────┬───────────────────┘
                                  ▼
  第三层 (TEE)      │ Patched TEE ta-mgr                │ ← 本文档分析的目标
                    │ 2×4字节 patch 绕过 TA sig+hash    │    精确 patch 点已定位
                    │ 状态: 方案就绪，等待上层链路打通    │
                    └─────────────┬───────────────────┘
                                  ▼
  第四层 (TA)       │ 自定义诊断 TA                      │ ← 需构造 MiTEE TA 格式
                    │ 导出 CDI/UDS 私密材料              │    Magic + header + ELF body
                    │ 状态: 待实现                       │
                    └─────────────────────────────────┘
```

### 9.1 CVE-2026-20435 旁路可能性

Ledger Donjon 的 RECON 2026 摘要称其 PoC "asks the phone for all inputs needed to derive the TEE cryptographic root"。如果成立：

- 通过 preloader USB 命令（GET_SOC_ID、GET_ME_ID 等）获取设备唯一标识符
- 结合 TEE key derivation 算法逆向，离线推导 TEE cryptographic root
- **不需要修改任何固件**

但限制：
1. RECON slides/PoC 未公开（`resources: []`）
2. 仍需要"initial encrypted-flash read"
3. BROM SLA 可能阻止 preloader 命令访问

### 9.2 可行的后续路径（按可能性排序）

1. **Chimera 商业工具**：唯一已确认的 MT6897 firmware 操作能力。可能允许刷入 patched TEE。但属于付费工具且可能有法律限制。
2. **CVE-2026-20435 公开后复现**：等待 Ledger Donjon 的 PoC 发布，可能直接提供 TEE root derivation。
3. **TEE 运行时漏洞**：如果 MiTEE/Zircon 存在内存安全漏洞（如 Zircon 历史 CVE），可以在不修改镜像的情况下在 secure world 执行代码。
4. **赛事方/厂商提供签名材料**：等待工程签名 TA 或测试 TEE。
5. **mtkclient V6 BROM exploit**：`KamakiriPl` 代码存在但处于注释状态，无 MT6897 验证。需要 Linux/libusb 环境测试。

## 10. MiTEE TA 文件格式（完整解码）

```
偏移         大小    字段           值（原厂 KeyMint TA）
───────────────────────────────────────────────────────────
0x00-0x07    8      Magic          fd 89 ee 6d 69 74 65 65 (MiTEE 固定魔数)
0x08         1      sig_ver        0x01 (签名版本)
0x09         1      flags?         0x81
0x0a         1      algo           0x00
0x0b         1      img_type       0x00
0x0c-0x0f    4      img_size(BE)   0x00156300 (1,401,600 = TA body 大小, 大端序)
0x10-0x2f    32     header_ext     (header 扩展数据)
0x30-0x4f    32     sha256_hash    TA body 的 SHA-256 摘要
0x50-0x14f   256    rsa2048_sig    RSA-2048 PKCS#1 v1.5 签名
0x150-EOF    N      ta_elf_body    AArch64 ELF DYN 可执行文件
```

关键约束（来自 ta-mgr 代码分析）：
- `sig_size` = 0x100 (256 bytes) — **硬编码在 ta-mgr 中**
- `hd_size` = 0x150 (336 bytes) — **硬编码在 ta-mgr 中**
- TA 文件最小大小 > 0x150 bytes（否则 `shdr_alloc_and_copy` 拒绝）
- Magic 必须精确匹配 `fd89ee6d69746565`（否则 log "magic match failed!!"）
- `img_size` 字段 = 文件大小 - 0x150（大端序 4 字节）
- RSA 公钥（2048-bit）嵌入在 TEE 镜像内部，不从 TA 文件中读取

构造自定义 TA 时（在 patch 生效后）：
- Magic 必须正确
- `img_size` 必须正确反映 body 大小
- `sha256_hash` 和 `rsa2048_sig` 字段可以填充任意值（patch 后被忽略）
- body 必须是有效的 AArch64 ELF DYN

## 附录：已验证的字节级证据

```
bootfs[0x085bd8] = 80 01 00 34  → cbz w0, #0x1dc08  (sig verify result check)
bootfs[0x085c10] = 20 08 00 34  → cbz w0, #0x1dd14  (hash digest result check)

shdr_verify_signature entry @ bootfs[0x08d918] = f9 0f 1b f8  (str x25, [sp, #-0x50]!)
shdr_check_digest entry    @ bootfs[0x08d610] = f9 0f 1b f8  (str x25, [sp, #-0x50]!)

crypto_acipher_rsassa_verify 调用: ta-mgr+0x25a98 → bl 0x2ec18
RSA 公钥长度: 0x100 (256 bytes = 2048-bit)
签名算法 ID: 0x70414930 (RSASSA-PKCS1-v1_5-SHA-256)
Hash 算法 ID: 0x50000004 (SHA-256)
错误返回值: 0xFFFF000F (TEE_ERROR_SECURITY)
成功返回值: 0x00000000 (TEE_SUCCESS)
```
