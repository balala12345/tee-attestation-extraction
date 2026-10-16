# K70E CTF DeviceInfo / `NOT_APPROVED` 最终踩坑与故障树

> 本文是文档 47、55、61的最新增量。旧文档仍保留历史事实，但凡是与本文“modified DICE + clean DeviceInfo 已获 `APPROVED`”冲突的因果或完成状态，以本文和文档 65、68 为准。

---

## 1. 把“DICE 变了”直接写成 `NOT_APPROVED` 原因

### 旧推理

modified 环境的 DICE 第 1、2、4 层 claim 不同，Google 返回 `NOT_APPROVED`，因此 DICE hash 就是拒绝原因。

### 错在哪里

旧请求同时改变了 DICE 和 DeviceInfo，只有相关性，没有单独因果。

### 新证据

同一 exact modified 五层 DICE，仅换入历史 clean DeviceInfo 后，Google 返回 `APPROVED`。DICE 5/5 签名和 outer 签名全部通过。

### 正确结论

这套 modified DICE 不是触发 `NOT_APPROVED` 的充分条件。不能泛化为“Google 从不看 DICE”。

## 2. 认为 `green + locked` 一定比 `orange + unlocked` 更容易获批

这是本次最重要的坑。

实际对照：

```text
NOT_APPROVED  green / locked   / b9b1d867...9744
APPROVED      orange / unlocked / acaa9258...b6e9
```

Google 不是对三个字符串做“看上去安全”排序。更合理的解释是：服务端需要 DeviceInfo 与已注册设备/固件 profile 相符。伪装成更安全反而会造成不一致。

## 3. 宣称已精确证明单一字段

本次一次替换了：

- `vb_state`；
- `bootloader_state`；
- `vbmeta_digest`。

所以安全结论是：clean DeviceInfo tuple 对该次 exact modified DICE 请求足以获批；在设备控制的 signed approval profile 内，这三项或它们的一致性组合是首要嫌疑。新 challenge、software key、request_id、时间与不透明的服务端状态也随请求变化，不能宣称完成了严格因果隔离。

Google leaf 的 PI `5/2` 精确回显 clean `vbmeta_digest`，使 digest/一致性成为最强线索，但这仍不等于严格 A/B 单字段证明。

现在已有干净证书，为满足好奇而继续烧 Google 请求没有必要。

## 4. 把 `count=32` 写成尝试次数风控

新 APPROVED leaf 同样包含：

```text
Provisioning Info key 1 = 32
```

而 `NOT_APPROVED` 命中为 0。这与历史 12 张 clean count-32 证书一致。

所以：

- `count=32` 不是本项目中“风控已触发”的证据；
- 没有 429、quota、abuse、`Retry-After` 时，不应以这个数字停止离线根因调查；
- 现在同一 modified UDS/DICE/final-leaf identity 已获批，“当前 identity 被统一封锁”的说法不成立；这不等于否认 Google 可能存在其他 rate/risk 策略。

## 5. 把 HTTP 200 当成赛事 PASS

旧失败和新成功都是 HTTP 200。真正分界在 Google-signed leaf Provisioning Info：

```text
old  5/1 = NOT_APPROVED
new  5/1 = APPROVED, 5/2 = acaa9258...b6e9
```

每次必须扫描全部四张证书的 OID `1.3.6.1.4.1.11129.2.1.30`，不只是看 HTTP、不只是看证书能解析。

## 6. 只检查 leaf 或只扫描 JSON 里已知字段

正确的 PI 验证必须：

- 枚举全链每一张证书；
- 每个扩展精确解码一个 CBOR item；
- 无 trailing bytes；
- 检查重复/等价 key collision；
- 递归扫描未知键、值、数组和 tag；
- 任何 `NOT_APPROVED` 精确命中或解析错误都拒绝。

本次为 1 个已解析扩展、0 解析错误、0 命中。

## 7. 混淆四把钥匙/秘密

本项目至少要分清：

| 名称 | 作用 | 本次是否秘密 |
|---|---|---:|
| K70E UDS public root | DICE 注册根公钥 | 否（公钥） |
| final DICE leaf scalar | 签 outer AuthenticatedRequest | 是 |
| final DICE leaf public key | 身份链最后一层 | 否（公钥） |
| 新 software P-256 private key | 本次请 Google 签发的 key | 是 |

两个关键公钥：

```text
identity leaf SPKI  64c672084035d3b8af4c7f2b036ce8905c06cd60bf39fa9bd6ec44cbe0ba4ad2
software/Google leaf 1e5ec6f483c8fb632305a7aa4e2b0be4a1a2fa4aca0c38408a932b3d5a84bc67
```

二者必须不同。

## 8. 把 final leaf scalar 当成最底层 CDI/UDS seed

当前 32-byte 值派生公钥精确等于 modified DICE 最终 leaf，因此它的实证语义是：

```text
final measurement-bound P-256 DICE leaf private scalar
```

不要因变量名叫 `cdi_leaf_priv` 就把它说成 raw UDS、HUK 或能重建五层 DICE 的根 seed。

但也不要走到另一个极端：它已经足够签 proper-DICE 的 outer request，新成功就是直接证据。为完成当前 CTF，不需要再挖更底层 root seed。

## 9. 乱改 DICE hash 或伪造五层链

DICE 每层负责签下一层。任意改 payload/hash 会破坏签名链，除非持有对应前级私钥并重签后续全链。当前 final leaf scalar 只能签 outer request，不能反向修改早期 DICE 层。

而且本次已证明原样 modified DICE 可以获批，没有继续伪造 DICE 的必要。

## 10. 认为必须先刷回 fully stock 才能得到 clean Google 证书

这个命题被本次 host-only 成功推翻。

正确分流：

- 要已有参考机的 hybrid 成功三件套：不需要先修手机。
- 要 fresh fully-stock same-run provenance：仍需要恢复手机、stock log、same-run DeviceInfo+DICE。
- 要修好手机日常使用：这是另一个恢复任务，不能把本次证书成功写成手机已修复。

文档 59–64 的双 AVB mismatch、locked Fastboot 和 BROM 事实仍有效，只是不再是使用本次已有成功包的前置条件。

## 11. 将 `PASS_CLEAN_HYBRID` 写成赛事方已接收

两个状态必须分开：

```text
Google / crypto / PI class      PASS_CLEAN_HYBRID
raw FINAL_RESULT.status          PASS_CLEAN
organizer acceptance receipt    PENDING / not recorded
```

新 run 自标 `research_only_semantically_hybrid=true`；这是正确的证据边界，不能为了“结题”把该字段删掉或重解释。

## 12. 重跑已成功的 one-shot

全局 claim 状态：

```text
CONSUMED_NO_RETRY
```

成功目录已有 fetch/sign 各一个 NETWORK_STARTED 和 `SUCCESS.json`。

不得：

- 换目录重跑；
- 删 claim；
- 删 marker；
- 把新 key 当旧 key 的 retry；
- 见到证书过期就未经新授权自动重签。

## 13. 把文件 SHA 和内容 SHA 混在一起

典型例子：

```text
clean DeviceInfo canonical CBOR SHA  19f9f9b0...8fd921
clean_device_info.json file SHA      843cddbb...94336
```

两者语义不同。报告必须标明是“规范编码内容”还是“实际文件字节”。

## 14. 秘密处理坑

禁止：

- `cat`/`xxd`/`hexdump`/`base64` 私钥或 scalar；
- 把私钥放到 Markdown code block；
- 公开 Git 提交；
- 上传到公开网盘；
- 在 shell 开 `set -x`；
- 为“方便”在多处复制私钥。

允许记录：

- 绝对路径；
- mode/owner/size；
- 私钥文件 SHA-256；
- 派生 SPKI SHA-256；
- 关系验证布尔值；
- 新 nonce PoP 验证结果。

## 15. 故障树

```text
Google 返回证书
|
+-- HTTP 不是 200
|   +-- 429/quota/abuse -> 保存证据，暂停外部请求
|   +-- 超时/结果未知 -> 本 attempt 按已消耗，不重放
|   +-- 444 DeviceNotRegistered -> 身份/profile 结构不被接受
|
+-- HTTP 200
    |
    +-- 证书链/公钥关系失败
    |   +-- 不是可交付包，保留 raw response 离线调查
    |
    +-- PI 解析错误
    |   +-- FAIL，不能忽略未知字段
    |
    +-- PI 中 NOT_APPROVED
    |   +-- 该 attempt 失败；对照 DICE/DeviceInfo 精确差分
    |
    +-- PI 中 APPROVED，NOT=0
        +-- 检查 private=request=leaf、四证书、Google root pin
            +-- 全通过 -> PASS_CLEAN_HYBRID 候选，进入离线交付
```

## 16. 最终十问

任何 AI 在声称本包可交付前，必须回答：

1. identity scalar 派生 SPKI 是否等于本次 DICE leaf？
2. DICE 是否恰好五层且 5/5 签名通过？
3. outer 签名是否通过？
4. DeviceInfo 是否精确等于历史 clean 值和类型？
5. 新 software key 是否为 P-256，且在联网前保存？
6. private SPKI = request 唯一 key = Google leaf SPKI 是否全部成立？
7. software key 是否与 identity key 不同？
8. 链是否恰好四张、签名和 Google root pin 全通过？
9. 全链 `NOT_APPROVED=0` 和 PI parse error=0 是否成立？
10. 是否正确区分了 `PASS_CLEAN_HYBRID`、原始 `PASS_CLEAN` 字段与尚未记录的赛事方回执？

本次前 9 项全部为是；第 10 项必须持续保留边界。
