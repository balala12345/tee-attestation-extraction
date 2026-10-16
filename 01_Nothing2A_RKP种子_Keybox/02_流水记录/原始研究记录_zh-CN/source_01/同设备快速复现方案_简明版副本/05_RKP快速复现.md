# RKP 快速复现

## 人话版

RKP 比 Keybox 多一步，因为它要跟 Google 交互。

最终路线是：

```text
patched direct TA：只负责泄漏 12 个 RKP private scalar
stock HAL/TA：负责生成 Google 接受的 CSR 材料
Google：返回 12 条证书链
```

## 最快条件

```text
stock KeyMint TA/HAL 正常
patched TEE 能 direct 加载 modified TA
root 可用
设备/主机网络能访问 Google RKP
```

## 可以复用的东西

- `rkp_tee_probe_csr`
- `rkp_binder_csr_client`
- `070600...4d.rkp_sideleak.tlbin`
- `fetch_google_geek.py`
- `build_and_send_signcerts_batch.py`
- 验证脚本

## 每次必须新做的东西

- fresh GEEK/challenge
- 当前设备当前 run 的 12 个 private scalar
- 当前 run 的 Binder CSR 材料
- 当前 run 的 Google response
- 当前 run 的 12 个 RKP `key.xml`

## 最终输出应该长这样

```text
runs/<serial>/rkp/
  direct_sideleak/
  binder_csr/
  geek_fetch/
  final_google_signcerts_12chains/
    response_http.json
    response.cbor
    signed_chains_summary.json
    openssl_verify_all.json
    chain_00/key.xml
    ...
    chain_11/key.xml
  verify.json
  hashes.txt
```

## 判断成功

成功标准：

```text
Google signCertificates HTTP = 200
chain_count = 12
12/12 leaf public matches private public
12/12 openssl verify OK
```

## 不要误解

- 没有提取 EEK 私钥。
- 用的是 Google 返回的 GEEK/EEK 公钥链和 fresh challenge。
- RKP 不能完全离线新发证，Google 请求这步仍需要网络。
- direct CSR 失败不是终点，最终走 stock Binder CSR。

## 不要做

- 不要把 modified RKP TA 替换进系统路径。
- 不要用旧 challenge。
- 不要把 RKPD DB 的 216B key blob 当 raw private key。
- 不要继续死磕 direct CSR 的 `-100005`。

