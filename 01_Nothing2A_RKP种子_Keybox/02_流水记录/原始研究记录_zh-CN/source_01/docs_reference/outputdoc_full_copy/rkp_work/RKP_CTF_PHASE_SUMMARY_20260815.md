# RKP CTF Phase Summary - 2026-08-15

## 总目标

取得一组可验证的 RKP attestation private key + 短期 Google/Droid RKP attestation certificate chain，并整理为可重放产物。

## 阶段总结

### Phase 0 - 初始证据整理

已确认：

- sideleak scalar 可用。
- testMode CSR 的 ProtectedData recipient 与 Google EEK 不匹配。
- production CSR 的当前阻塞是 TA 内 `0xfffe795b`。

下一阶段：先基线设备，再追踪 `0x50402 -> 0x21190` 的失败路径，同时扩展 direct CSR matrix 以获得更多输入/输出证据。
