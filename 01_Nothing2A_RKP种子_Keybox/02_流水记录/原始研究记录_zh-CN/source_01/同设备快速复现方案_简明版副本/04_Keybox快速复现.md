# Keybox 快速复现

## 人话版

Keybox 复现最简单。

它需要做的是：

```text
让 patched KeyMint TA 在 TEE 里跑一次
把 secure world 里的明文 keybox 拿回来
解析成 keybox.xml
```

## 最快条件

```text
stock KeyMint TA hash 一样
patched TEE 能加载 modified TA
root 可用
persist 里的 attest_keybox.so 还在
```

## 可以复用的东西

- `kmtee_probe`
- `070600...4d.dumpkeybox.tlbin`
- `extract_keybox_plain.py`
- OpenSSL 验证流程

## 每台设备必须重新生成的东西

- 这台设备自己的 `keybox.xml`
- 这台设备自己的 EC/RSA private key
- 这台设备自己的证书链
- 这台设备自己的验证报告

## 最终输出应该长这样

```text
runs/<serial>/keybox/
  keybox.xml
  ec_private_key.pem
  rsa_private_key.pem
  ec_cert_chain.pem
  rsa_cert_chain.pem
  verify.json
  hashes.txt
```

## 判断成功

成功标准不是“脚本没报错”，而是：

```text
能解析出 keybox.xml
EC 私钥和 EC leaf cert 公钥匹配
RSA 私钥和 RSA leaf cert 公钥匹配
EC/RSA 证书链 verify OK
EC/RSA 签名验签 OK
```

## 不要做

- 不要把 Widevine 当 Keybox。
- 不要替换系统 `/vendor/app/mcRegistry` 里的 stock KeyMint TA。
- 不要擦 persist。
- 不要在 TA hash 不一致时硬套旧 patched TA。

