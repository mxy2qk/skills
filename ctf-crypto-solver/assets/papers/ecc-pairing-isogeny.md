# ECC / 配对 / 同源（7 篇）

椭圆曲线离散对数、配对降级、超奇异同源问题与 SNARK 中的曲线 gadget。部分可直接用 smart_anomalous.sage / mov_fr.sage。

| ID | 日期 | 标题 | 标签 | 评级 | 简述 | 对应模板/工具 |
|---|---|---|---|---|---|---|
| [2026/2560](https://eprint.iacr.org/2026/2560) | 2026-10-22 | Graphs and cycles in curve-based collision walks | 多用户, 碰撞攻击, ECDLP, isogeny | 3 | 研究椭圆曲线与同源问题在多用户场景下的碰撞攻击：综述 van Oorschot–Wiener 型攻击，提出更适合无限制同源路径问题的伪随机游走，并分析同时恢复 L 个公钥所需的碰撞数；例如 F_{p^2} 超奇异同源约需 L+log L 次碰撞且无需 infiltrator。 | `—` |
| [2026/1823](https://eprint.iacr.org/2026/1823) | 2026-08-28 | HyperSolver: Asymptotically and Concretely Accelerating the Delfs–Galbraith Attack using Isogeny Ladders | Delfs-Galbraith, isogeny ladder, SQIsign | 3 | 给出 Delfs–Galbraith 算法的无内存新变体，用 isogeny ladder 寻找从任意超奇异曲线到已知自同态环曲线的同源路径，进而解超奇异自同态环问题。任意特征下渐近优于此前最好变体一个对数因子，具体成本也更低；100-bit 实例 <100 GPU 小时，影响 SQIsign 等参数估计。 | `—` |
| [2026/1776](https://eprint.iacr.org/2026/1776) | 2026-08-22 | Cofactor-torsion attacks on hinted scalar multiplications in SNARK circuits | SNARK, ECC, cofactor, hinted scalar mult | 4 | 指出 Eagen 等（Latincrypt 2025）的 hinted scalar multiplication 系列依赖“素数阶”隐含假设：认证恒等式在完整 E(F_p) 上检查，只有 cofactor 为 1 时才强制 Q 落入素阶子群。在 cofactor 曲线上给出两类伪造（any-scalar 与 chosen-scalar），可让 gadget 接受 Q'=[k]P+T；已在 BLS12-381/BN254/BW6-761 上验证。 | `—` |
| [2026/1623](https://eprint.iacr.org/2026/1623) | 2026-08-05 | Triple Cryptanalysis of Isogeny-Based VRFs from Asiacrypt 2025 | isogeny VRF, radical-CGL, 密钥恢复 | 4 | 对 Asiacrypt 2025 的 radical-CGL 同源 VRF 给出三阶段攻击：先利用公钥只存 j-invariant 而计算用两系数表示的差异破坏唯一可验证性，再利用这些系数在 1536 次查询、30 分钟内恢复 256-bit 密钥；并对同文的 group-action VRF 给出单查询攻击。 | `—` |
| [2026/1575](https://eprint.iacr.org/2026/1575) | 2026-07-31 | Solving the supersingular isogeny problem in time $p^{2/5+o(1)}$ using bivariate multipoint evaluation | supersingular isogeny, 双变量多点求值 | 3 | 给出超奇异同源问题的无条件攻击，时间与内存 p^{2/5+o(1)}，基于 Kedlaya–Umans 等高度理论化的多元多点求值算法；与 Wesolowski 的 p^{1/3+o(1)} 启发式攻击同属“寻找曲线到其 Galois 共轭的可分同源以构造非标量自同态”的路线。作者明确说明该结果只有理论意义，不威胁实际同源密码系统。 | `—` |
| [2026/1486](https://eprint.iacr.org/2026/1486) | 2026-07-20 | The supersingular isogeny problem in time and memory $p^{1/3+o(1)}$ | supersingular isogeny, 复杂度 | 3 | 在关于随机整数光滑性的合理启发式假设下，证明超奇异同源问题可在时间与内存 p^{1/3+o(1)} 内求解，改进此前 p^{1/2+o(1)}；但 o(1) 中的超多项式开销与高内存使具体参数影响尚不明确。 | `—` |
| [2026/1002](https://eprint.iacr.org/2026/1002) | 2026-05-21 | On weak keys of POKE | POKE, isogeny PKE, 弱密钥 | 3 | 研究 POKE（基于同源的 PKE）的安全性：指出其存在弱密钥可降低某些攻击复杂度；POKE-2D 因弱密钥概率极低而不受影响，但 POKE-4D 受威胁，需修改参数（修改后性能优势消失）。 | `—` |
