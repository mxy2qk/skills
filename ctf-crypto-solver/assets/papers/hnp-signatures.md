# HNP / 签名 nonce 泄漏（4 篇）

隐藏数问题及其变体，签名随机数泄漏（偏置 nonce、符号、Hamming 重量）。CTF 里表现为：ECDSA/DSA/阈值签名泄漏少量位。

| ID | 日期 | 标题 | 标签 | 评级 | 简述 | 对应模板/工具 |
|---|---|---|---|---|---|---|
| [2026/2566](https://eprint.iacr.org/2026/2566) | 2026-10-20 | Fault-Induced Nonce Repetition in Threshold Lattice Signatures: A Reveal-Structure Criterion, Cross-Scheme Analysis, and Detection Boundaries | 阈值签名, 故障, nonce 重放, ML-DSA | 4 | 证明阈值格签名的物理故障可导致跨会话 nonce 重放：单方 RNG 状态回滚即可泄漏其 share，t-of-n 中只需故障 t 台设备即可恢复完整签名密钥，且每条签名单独看都合法。在 Mithril 上端到端验证（96/96 精确恢复，无需格归约），并给出 reveal-structure 判据与检测边界。 | `—` |
| [2026/1808](https://eprint.iacr.org/2026/1808) | 2026-10-12 | Cross-Signature Signing-Key Recovery and Domain-Separation Repair for SDitH v2 | SDitH, code-based, PRG 复用 | 3 | 对 SDitH v2 给出跨签名签名密钥恢复：VOLEitH PRG 以 AES/Rijndael 计数器模式从零开始，导致每条签名/每个 leaf 使用相同输入，一次加密即可测试候选 seed；结合 RSD 约束过滤假候选，找到 seed 即得长期 witness。q=2^12 次选择消息签名比 AES-128/192/256 暴力搜索便宜 11.23–11.67 bit。 | `—` |
| [2026/1366](https://eprint.iacr.org/2026/1366) | 2026-07-02 | Halfspace Learning for Lattice Signature Key Recovery from Signs | 签名泄漏, 半空间学习, HAWK/Falcon/ML-DSA | 4 | 证明对 HAWK、Falcon、ML-DSA，即使只泄漏随机数某个坐标的 Hamming 重量或单个 bit，也能推断该坐标符号；把密钥恢复建模为 Learning a Halfspace。HAWK 128-bit 下 30 条签名 10 分钟恢复，Falcon 100 条不到 1 分钟（比已有攻击少 250×），ML-DSA 19 万条秒级恢复，且可抗 30%–35% 噪声。 | `hnp_ecdsa.py` |
| [2026/423](https://eprint.iacr.org/2026/423) | 2026-03-02 | Coppersmith's Method for Solving Modular Inversion Hidden Number Problem via Determinant-Based Elimination | HNP, MIHNP, Coppersmith, ICG | 5 | 提出基于行列式消元的 shift 多项式选取策略，改进多元模方程的 Coppersmith 方法；在 MIHNP 与 Inversive Congruential Generator 预测上理论上和实践上均优于先前方法，并证明 MIDHNP 不比 MIHNP 难，推翻 Boneh 等（Asiacrypt 2001）的猜想。 | `coppersmith_multi.sage / hnp_ecdsa.py` |
