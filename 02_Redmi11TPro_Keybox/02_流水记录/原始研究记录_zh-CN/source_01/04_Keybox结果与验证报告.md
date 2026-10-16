# Keybox 结果与验证报告

## 1. 结论

Keybox 第一阶段已在序列号 `<DEVICE_SERIAL>` 的 Redmi Note 11T Pro / xaga 实机上成功。读取命令、TA 状态和客户端返回码均为 0，得到 8578 字节载荷和 168 字节描述区。

主结果：`03_提取结果/Keybox实机成功提取_20260826_2139/`

## 2. 调用结果

```text
InitializeContext=0x00000000
OpenSession=0x00000000 origin=0x00000004
InvokeCommand=0x00000000 origin=0x00000004
TA status=0x00000000 payload=8578 descriptor=168 saved=yes
```

设备端流程日志中还有：

- `client_rc=0`
- `XAGA_KEYBOX_EXTRACTION_VERIFIED`
- 原厂 TA 覆盖前 SHA256 `0fafcb88...e52f`
- bind mount 后 SHA256 `97e1c1b3...b2f5`
- `提取错误日志.txt` 为 0 字节

## 3. 载荷完整性

- payload 长度：8578
- payload SHA256：`fc7d68b66302469e5baad6761a692302ade54c4c161613b2b8f88c452a8df498`
- payload MD5：`635c04aa3590d2cbe7ce3dfa79c3e3c7`
- descriptor MD5：`635c04aa3590d2cbe7ce3dfa79c3e3c7`
- descriptor magic：`0x12345678`
- MD5 匹配：是

## 4. EC 条目

- 私钥 DER 大小：121 字节
- 私钥 DER SHA256：`88ab172c180aaee97097a980fff4111ae343282e488e3fb0d3260bdf94bb4dc1`
- 私钥导出 SPKI SHA256：`e5eb3f8b35531f5e413226beebc9a8af0684b85a0244f2fba760b4b4e0f51f28`
- 叶证书 SPKI SHA256：同上
- 私钥与叶证书匹配：是
- 证书数：3
- OpenSSL 链验证：`OK`

EC 叶证书：

- Subject：`title=TEE/serialNumber=bd99e81eca9b2bb7ab0b801f66f12743`
- Issuer：`title=TEE/serialNumber=d8bfe951c840a04d5170b5ade06d3a54`
- Not Before：2022-01-25 23:33:27 GMT
- Not After：2032-01-23 23:33:27 GMT

## 5. RSA 条目

- 私钥 DER 大小：1769 字节
- 私钥 DER SHA256：`330ae41f468bdd67068ae557d85c6eb4377829066a700c571559a4945c6fa394`
- 私钥导出 SPKI SHA256：`ef8a561334b0a56e2589078f6c497577a43d4a672b1fbb4895fd8bee8b2cbd3f`
- 叶证书 SPKI SHA256：同上
- 私钥与叶证书匹配：是
- 证书数：3
- OpenSSL 链验证：`OK`

RSA 叶证书：

- Subject：`title=TEE/serialNumber=bd99e81eca9b2bb7ab0b801f66f12743`
- Issuer：`title=TEE/serialNumber=d8bfe951c840a04d5170b5ade06d3a54`
- Not Before：2022-01-25 23:33:26 GMT
- Not After：2032-01-23 23:33:26 GMT

## 6. 根证书

EC 和 RSA 链最终使用同一根证书：

- Subject/Issuer：`serialNumber=f92009e853b6b045`
- 自签名：是
- Not Before：2021-11-17 23:10:42 GMT
- Not After：2036-11-13 23:10:42 GMT
- DER SHA256：`ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a`

## 7. 有效期解读

对 Keybox 的实际使用上限应首先看叶证书，而不是根证书。本次 EC/RSA 叶证书都到 2032-01-23 到期；根证书到 2036-11-13。因此这不是“只有十几天”的 RKP 短期证书，而是一套更长期的设备 Keybox 凭据。

## 8. 证据路径

- 原始二进制：`...客户端输出/keybox_原始载荷.bin`
- 描述区：`...客户端输出/keybox_描述区.bin`
- 总清单：`...解析验证结果/解析与验证总清单.json`
- EC 结果：`...解析验证结果/条目1_EC/`
- RSA 结果：`...解析验证结果/条目2_RSA/`
- 现场日志：`...提取流程日志.txt`、`...调用前_logcat.txt`、`...调用后_logcat.txt`、`...调用前_dmesg.txt`、`...调用后_dmesg.txt`

## 9. 最终判定

本阶段不是“看起来提取到了”，而是已完成以下闭环：原厂失败对照 -> 最小只读补丁 -> 实机命令成功 -> 完整性检查 -> 两种私钥可解析 -> 私钥/叶证书公钥匹配 -> 两条证书链通过。
