# 2026 年密码分析论文选题库（精选）

> 收录范围：2026-01-01 — 2026-10-28；仅攻击 / 密码分析类；共 91 篇。
> 生成脚本：`scripts/papers/build_assets.py`（数据源 `papers.json`）。
> 评级：5 = 直接可出 CTF 题 / 核心方法；1 = 背景参考。

| 方向 | 篇数 | 文件 |
|---|---|---|
| LWE / 带 hint 与格参数评估 | 21 | [lattice-lwe-hints.md](lattice-lwe-hints.md) |
| PQC 实现攻击（侧信道 / 故障） | 25 | [pqc-implementation.md](pqc-implementation.md) |
| SIS / 理想格 / LIP / HAWK | 23 | [sis-lip-ideal.md](sis-lip-ideal.md) |
| Coppersmith / RSA 变体 | 11 | [coppersmith-rsa.md](coppersmith-rsa.md) |
| HNP / 签名 nonce 泄漏 | 4 | [hnp-signatures.md](hnp-signatures.md) |
| ECC / 配对 / 同源 | 7 | [ecc-pairing-isogeny.md](ecc-pairing-isogeny.md) |

## LWE / 带 hint 与格参数评估（21 篇）

LWE/MLWE 的带信息攻击、稀疏 secret、dual/hybrid attack 与具体安全评估。CTF 里表现为：给 A,b,q 外加泄漏位/模 q hint/已知错误，要求自己建 hint 格。

- **2026/2654** (2026-10-27) [When Algebraic Structure Meets Too Many Hints](https://eprint.iacr.org/2026/2654) — ★★★★★ | `结构化 hint 的必读论文`
- **2026/2638** (2026-10-25) [Decision Attacks on Known-Covariance Ring-LWE via Public Gram Determinants](https://eprint.iacr.org/2026/2638) — ★★★ | `带协方差泄漏的 RLWE`
- **2026/2565** (2026-10-20) [Further Elaborations on the Provable Dual Attack](https://eprint.iacr.org/2026/2565) — ★★ | `参数评估`
- **2026/2186** (2026-09-23) [Provable FFT-Accelerated Dual Attack on LWE Using the General Dual Lattice](https://eprint.iacr.org/2026/2186) — ★★ | `参数评估`
- **2026/2166** (2026-09-23) [A Provable Correctness Analysis of the MATZOV-Style FFT Dual Attack on ML-KEM](https://eprint.iacr.org/2026/2166) — ★★ | `参数评估`
- **2026/2117** (2026-09-20) [Provable dual attack on LWE via lattice projection](https://eprint.iacr.org/2026/2117) — ★★ | `参数评估`
- **2026/1720** (2026-08-18) [Improved Polynomial-Memory Algorithms via Nested Collision Search: Applications to Small Max-Norm LWE and Subset-Sum](https://eprint.iacr.org/2026/1720) — ★★★ | `小范数 LWE / 子集和`
- **2026/1400** (2026-10-13) [What Happens When Integrating Modulus Switching and Lossy Source Coding: A New Dual Attack Variant on LWE](https://eprint.iacr.org/2026/1400) — ★★ | `参数评估`
- **2026/1326** (2026-10-15) [LaMS: A p-adic Layered Modulus Switching for Provable Dual Attacks on LWE](https://eprint.iacr.org/2026/1326) — ★★ | `参数评估`
- **2026/1081** (2026-05-28) [From Perfect to Approximate Hints: Efficient LWE Secret Recovery Leveraging Low Hamming Weight](https://eprint.iacr.org/2026/1081) — ★★★★★ | `LWE 带 hint 的核心论文`
- **2026/1060** (2026-05-26) [An Improved Hybrid Dual Attack on LWE with Sparse Secrets and its Application to FHE](https://eprint.iacr.org/2026/1060) — ★★★ | `FHE 稀疏 secret`
- **2026/1048** (2026-10-14) [Unified Dual Attack Analyses: Covariance-Based Score Distribution Prediction for LWE](https://eprint.iacr.org/2026/1048) — ★★ | `参数评估`
- **2026/1041** (2026-05-23) [CoNAN: A Structure-Aware Framework for Lattice Cryptanalysis](https://eprint.iacr.org/2026/1041) — ★★★ | `环/模结构利用`
- **2026/688** (2026-05-23) [Too Far Behind? Narrowing the Gap with a Dual-Enhanced Two-Stage Algebraic Algorithm for LWE](https://eprint.iacr.org/2026/688) — ★★★★ | `少样本 LWE + hint`
- **2026/630** (2026-03-31) [Asymptotic Analysis of Ternary Sparse LWE](https://eprint.iacr.org/2026/630) — ★★★★ | `小 k 稀疏 LWE`
- **2026/614** (2026-07-02) [Spectral Method attacks Sparse LWE, Sparse LPN and Beyond](https://eprint.iacr.org/2026/614) — ★★★ | `稀疏方程判定/攻击`
- **2026/612** (2026-03-27) [Improving ML Attacks on LWE with Data Repetition and Stepwise Regression](https://eprint.iacr.org/2026/612) — ★★ | `ML 辅助 LWE（较少见）`
- **2026/421** (2026-03-11) [Cryptanalysis of Polynomial Learning With Errors (PLWE): A Survey](https://eprint.iacr.org/2026/421) — ★★★ | `PLWE/RLWE 归约错误识别`
- **2026/366** (2026-08-30) [Careful with the Ring: Enhanced Hybrid Decoding Attacks against Module/Ring-LWE](https://eprint.iacr.org/2026/366) — ★★★★ | `稀疏 Ring-LWE/FHE 参数`
- **2026/279** (2026-10-04) [On the Concrete Hardness Gap Between MLWE and LWE](https://eprint.iacr.org/2026/279) — ★★★ | `环对称性导致的 MLWE/LWE 难度差`
- **2026/177** (2026-04-11) [A Practical Neighborhood Search Attack on Oracle MLWE](https://eprint.iacr.org/2026/177) — ★★★★ | `带线性泄漏/恶意公钥的 MLWE；Sage 几秒出结果`

## PQC 实现攻击（侧信道 / 故障）（25 篇）

ML-KEM/ML-DSA/NTRU/Falcon 等标准实现的侧信道与故障攻击。CTF 里表现为：给实现/容器/泄漏 trace，先定位缺陷，再回落为格或线性恢复。

- **2026/2643** (2026-10-26) [Non-profiled Single-Trace ML-DSA Secret Key Recovery by Horizontal Distribution Analysis](https://eprint.iacr.org/2026/2643) — ★★★ | `单 trace 侧信道`
- **2026/2567** (2026-10-20) [A Systematic Evaluation of Fault Attacks and Countermeasures on ML-DSA Rejection Sampling](https://eprint.iacr.org/2026/2567) — ★★★★ | `故障攻击与对策评估`
- **2026/2448** (2026-10-12) [Breaking First-Order Masked Kyber with Belief Propagation Alone](https://eprint.iacr.org/2026/2448) — ★★★ | `掩码 Kyber`
- **2026/2258** (2026-09-29) [Superposition Key-Recovery Attacks on Dilithium and Fiat-Shamir Signature Schemes](https://eprint.iacr.org/2026/2258) — ★★ | `量子对抗模型`
- **2026/2211** (2026-09-25) [Structural Cryptanalysis of Polar-KEM: Direct Recovery of the Secret Isometry](https://eprint.iacr.org/2026/2211) — ★★★ | `LIP/构造缺陷`
- **2026/2137** (2026-09-21) [Too Small to Hide: Single-Trace Key Recovery from  ML-KEM Key Generation](https://eprint.iacr.org/2026/2137) — ★★★ | `单 trace 侧信道`
- **2026/2124** (2026-09-20) [Every Signing Leaks: Breaking Falcon via Floating-Point Conversion Leakage](https://eprint.iacr.org/2026/2124) — ★★★★ | `Falcon 侧信道 + LLL/BKZ`
- **2026/2091** (2026-09-18) [Keep Track of Your Errors: Solving ILWE and Improving Attacks on ML-DSA](https://eprint.iacr.org/2026/2091) — ★★★★ | `ILWE / 噪声泄漏`
- **2026/2069** (2026-09-17) [Default Correct: A New Fault Surface in the Comparison Booleanisation of Kyber-KEM](https://eprint.iacr.org/2026/2069) — ★★★★ | `故障攻击`
- **2026/1904** (2026-09-11) [When Module Lattice Leaks: Horizontal Fusion Attacks on ML-DSA Implementation](https://eprint.iacr.org/2026/1904) — ★★★★ | `ML-DSA 少 trace 侧信道`
- **2026/1712** (2026-08-17) [Statistical Inference from Noisy Randomness Leakage for ML-DSA Attacks](https://eprint.iacr.org/2026/1712) — ★★★ | `ML-DSA 泄漏预处理`
- **2026/1682** (2026-08-13) [Incomplete Ciphertext Comparison in ML-KEM: From an IND-CCA2 Break to Key Recovery](https://eprint.iacr.org/2026/1682) — ★★★★ | `实现缺陷→线性泄漏`
- **2026/1668** (2026-08-19) [A Key-Recovery Attack on TALUS-MPC in TALUS v4](https://eprint.iacr.org/2026/1668) — ★★★★ | `阈值签名 nonce 复用`
- **2026/1448** (2026-07-16) [Improving Skipping Fault Correction Attacks on Randomized Dilithium via MILP](https://eprint.iacr.org/2026/1448) — ★★★ | `随机化 Dilithium 的跳过故障`
- **2026/1386** (2026-07-07) [Key-Recovery Attacks on TALUS: A Cryptanalytic Note](https://eprint.iacr.org/2026/1386) — ★★★★ | `协议实现缺陷→线性恢复`
- **2026/1344** (2026-06-30) [Public Coefficient Matters: A Practical Differential Fault Attack on ML-DSA and HAETAE](https://eprint.iacr.org/2026/1344) — ★★★ | `故障攻击`
- **2026/981** (2026-05-18) [Profiling-Device-Free SASCA Framework for ML-KEM](https://eprint.iacr.org/2026/981) — ★★ | `侧信道框架`
- **2026/820** (2026-04-27) [Improving Correlation Power Analysis on Masked CRYSTALS-Kyber with Lattice Attack](https://eprint.iacr.org/2026/820) — ★★★★ | `部分密钥 + Kannan/Bai-Galbraith 嵌入`
- **2026/582** (2026-03-24) [FrozenTRU: Cold Boot Attacks on NTRU-Based Hash-and-Sign Signatures](https://eprint.iacr.org/2026/582) — ★★★ | `冷启动/部分系数泄漏 + 格`
- **2026/580** (2026-03-23) [Exploiting noisy single-bit leakage in ML-DSA](https://eprint.iacr.org/2026/580) — ★★★★ | `ML-DSA 单位泄漏`
- **2026/528** (2026-03-16) [Full Secret Key Recovery of First-order Masked Crystals-Kyber implementation using multiple distinct chosen-ciphertexts](https://eprint.iacr.org/2026/528) — ★★★ | `一阶掩码 Kyber`
- **2026/472** (2026-03-06) [Descent into Broken Trust: Uncovering ML-DSA Subkeys with Scarce Leakage and Local Optimization](https://eprint.iacr.org/2026/472) — ★★★★ | `ML-DSA 少量泄漏签名`
- **2026/070** (2026-01-16) [Unlocking the True Potential of Decryption Failure Oracles: A Hybrid Adaptive-LDPC Attack on ML-KEM Using Imperfect Oracles](https://eprint.iacr.org/2026/070) — ★★★★ | `解密失败/明文检查 oracle`
- **2026/064** (2026-02-02) [Breaking the KAZ Suite: Practical Key Recovery Attacks on MySEAL 2.0’s Post-Quantum Candidates](https://eprint.iacr.org/2026/064) — ★★★★★ | `光滑群阶 + 两条签名 HNP`
- **2026/056** (2026-01-16) [Rejection Matters: Efficient Non-Profiling Side-Channel Attack on ML-DSA via Exploiting Public Templates](https://eprint.iacr.org/2026/056) — ★★★★ | `ML-DSA 非模板侧信道`

## SIS / 理想格 / LIP / HAWK（23 篇）

短整数解、理想格、格同构问题（LIP）、HAWK 签名与 knapsack/NTRU 变体。多为高门槛论文题，需 fpylll/理想格工具。

- **2026/2543** (2026-10-19) [A Key-Recovery Attack on the GTLN Knapsack Cryptosystem via Continued Fractions](https://eprint.iacr.org/2026/2543) — ★★★★ | `knapsack 公钥秒破`
- **2026/2527** (2026-10-18) [How Secure are NTRU+ Keys? Analysing the Best Module Attacks](https://eprint.iacr.org/2026/2527) — ★★★ | `NTRU+/module 攻击`
- **2026/2420** (2026-10-08) [Provable Subexponential Algorithms for Module-SIS and Module-LWE](https://eprint.iacr.org/2026/2420) — ★★ | `参数评估`
- **2026/2381** (2026-10-06) [The Lattice Isomorphism Problem with Hints](https://eprint.iacr.org/2026/2381) — ★★★★ | `LIP + 侧信道 hint`
- **2026/2325** (2026-10-03) [On the hull attacks against Construction A lattices](https://eprint.iacr.org/2026/2325) — ★★★ | `LIP`
- **2026/2281** (2026-09-30) [Poisoned Cryptography: Solving Direct-Sum LIP in Half the Dimension](https://eprint.iacr.org/2026/2281) — ★★★ | `LIP 降维`
- **2026/2225** (2026-09-26) [Breaking the G\'omez-Torrecillas--Lobillo--Navarro Cryptosystem: LLL Recovers the Secret Key Within Seconds](https://eprint.iacr.org/2026/2225) — ★★★★ | `knapsack 公钥秒破`
- **2026/2198** (2026-09-24) [Lifting Symmetries for Dimension Reduction in Module-LIP: rank 2 and rank 4](https://eprint.iacr.org/2026/2198) — ★★★ | `HAWK/module-LIP`
- **2026/2083** (2026-09-18) [Two-Bit Lifting for Ternary SIS: Polynomial-Time Collision Attacks on LtHash](https://eprint.iacr.org/2026/2083) — ★★★★ | `SIS/LtHash 碰撞`
- **2026/2042** (2026-09-15) [On Solving Ideal-SVP and Ideal-BDD with Group Representations](https://eprint.iacr.org/2026/2042) — ★★★ | `理想格降维`
- **2026/1755** (2026-08-20) [QuaILLL: Quaternion Ideal LLL and BKZ](https://eprint.iacr.org/2026/1755) — ★★★ | `HAWK/nrd-PIP`
- **2026/1705** (2026-08-16) [New Attacks on Mersenne Number-Based Cryptosystems: Relaxing Size Constraints](https://eprint.iacr.org/2026/1705) — ★★★ | `NTRU 变体`
- **2026/1642** (2026-08-14) [A Torus-Structured Generalisation of NTRU: the NTC Assumption, its Cryptanalysis, and a Compact KEM](https://eprint.iacr.org/2026/1642) — ★★ | `NTRU 变体识别`
- **2026/1593** (2026-08-03) [HAWK-$n$ Key Recovery Reduces to SVP in Dimension $n/2 + 1$](https://eprint.iacr.org/2026/1593) — ★★★★ | `HAWK 归约到 SVP`
- **2026/1560** (2026-08-03) [Dimension Reduction for SVP in Hawk: A Trace-Zero Approach](https://eprint.iacr.org/2026/1560) — ★★★ | `HAWK/理想格降维`
- **2026/1554** (2026-08-15) [On the Hardness of some Vandermonde Knapsack problems](https://eprint.iacr.org/2026/1554) — ★★★ | `代数 knapsack`
- **2026/1377** (2026-07-05) [HAWK ``Guessing Game'' is not Polynomial-Time](https://eprint.iacr.org/2026/1377) — ★★ | `HAWK 攻击可行性`
- **2026/1349** (2026-06-30) [Sharper and Closed-Form Attacks on $\mathsf{SIS}$ When Modulus Is Small](https://eprint.iacr.org/2026/1349) — ★★★★ | `小模数 SIS/伪造`
- **2026/1318** (2026-07-05) [Cryptanalysis of HAWK: a Guessing Game](https://eprint.iacr.org/2026/1318) — ★★★ | `HAWK 启发式攻击`
- **2026/1298** (2026-06-21) [Weak Keys Break the BUFF Security of HAWK](https://eprint.iacr.org/2026/1298) — ★★★ | `弱公钥/校验缺失`
- **2026/890** (2026-06-17) [Cryptanalysis of Definite and Indefinite Lattice Isomorphism Problems With Applications to DEFI](https://eprint.iacr.org/2026/890) — ★★★★ | `LIP 签名密钥恢复`
- **2026/722** (2026-04-20) [(Mis)using the Lattice Isomorphism Problem. Cryptanalysis of the double-LIP and Construction of LIP-Based Blind Signatures](https://eprint.iacr.org/2026/722) — ★★★ | `LIP 协议缺陷`
- **2026/699** (2026-09-10) [HAWK with Hint: Algebraic Key Recovery from Side-Channel Leakage](https://eprint.iacr.org/2026/699) — ★★★★ | `HAWK + LIP hint`

## Coppersmith / RSA 变体（11 篇）

小根、部分密钥暴露、CRT-RSA 小指数、广义 Wiener 与多元多项式求解。CTF 里表现为：部分 p/q/dp/dq、自构造 RSA 方程、参数卡在旧界边缘。

- **2026/2620** (2026-10-26) [When Elliptic-Curve Semiprimality Certificates Reveal Factors](https://eprint.iacr.org/2026/2620) — ★★★ | `RSA/EC 证书侧信道`
- **2026/2109** (2026-10-18) [Attacking CRT-RSA with Small Exponents via Unravelled Linearization](https://eprint.iacr.org/2026/2109) — ★★★★★ | `CRT-RSA 小 dp/部分位（核心）`
- **2026/1969** (2026-09-21) [Efficient Polynomial System Solving via Dixon Resultants: Applications to AO Primitives](https://eprint.iacr.org/2026/1969) — ★★★ | `多元多项式系统求解`
- **2026/1908** (2026-09-10) [A Generalized Wiener-type Attack Against a Family RSA-like Cryptosystems](https://eprint.iacr.org/2026/1908) — ★★★ | `n=2^i 的广义 Wiener`
- **2026/1529** (2026-07-26) [Generalized Wiener-Type Attacks on Two RSA-Like Cryptosystems](https://eprint.iacr.org/2026/1529) — ★★★ | `非平衡模数的广义 Wiener`
- **2026/1357** (2026-07-02) [A refined cryptanalytic attack against a generalized cubic Pell RSA scheme](https://eprint.iacr.org/2026/1357) — ★★★ | `RSA 变体超界`
- **2026/1295** (2026-06-25) [A new attack to RSA with small private exponent and partial information.](https://eprint.iacr.org/2026/1295) — ★★★★ | `Wiener 变体 + 部分信息`
- **2026/1137** (2026-06-02) [A Review of Lattice Attacks Applied to Two Types of RSA Variants](https://eprint.iacr.org/2026/1137) — ★★★ | `RSA 变体综述`
- **2026/1027** (2026-09-18) [Computing Asymptotic Bounds for the Automated Coppersmith Method via Linear Programming](https://eprint.iacr.org/2026/1027) — ★★★★★ | `判断 Coppersmith 参数是否可行`
- **2026/519** (2026-03-14) [A Generalized Partial Exposure Lattice Attack Against an RSA variant Based on Cubic Pell Curves](https://eprint.iacr.org/2026/519) — ★★★★ | `RSA 变体 + 已知部分 p/q 位`
- **2026/244** (2026-02-13) [Revisit Unravelled Linearization with Erhart (quasi-)Polynomial](https://eprint.iacr.org/2026/244) — ★★★★ | `多元 Coppersmith 参数/界`

## HNP / 签名 nonce 泄漏（4 篇）

隐藏数问题及其变体，签名随机数泄漏（偏置 nonce、符号、Hamming 重量）。CTF 里表现为：ECDSA/DSA/阈值签名泄漏少量位。

- **2026/2566** (2026-10-20) [Fault-Induced Nonce Repetition in Threshold Lattice Signatures: A Reveal-Structure Criterion, Cross-Scheme Analysis, and Detection Boundaries](https://eprint.iacr.org/2026/2566) — ★★★★ | `阈值 ML-DSA 故障`
- **2026/1808** (2026-10-12) [Cross-Signature Signing-Key Recovery and Domain-Separation Repair for SDitH v2](https://eprint.iacr.org/2026/1808) — ★★★ | `code-based 签名实现缺陷`
- **2026/1366** (2026-07-02) [Halfspace Learning for Lattice Signature Key Recovery from Signs](https://eprint.iacr.org/2026/1366) — ★★★★ | `签名随机数的符号/Hamming 重量泄漏`
- **2026/423** (2026-03-02) [Coppersmith's Method for Solving Modular Inversion Hidden Number Problem via Determinant-Based Elimination](https://eprint.iacr.org/2026/423) — ★★★★★ | `模逆 HNP / ICG 预测`

## ECC / 配对 / 同源（7 篇）

椭圆曲线离散对数、配对降级、超奇异同源问题与 SNARK 中的曲线 gadget。部分可直接用 smart_anomalous.sage / mov_fr.sage。

- **2026/2560** (2026-10-22) [Graphs and cycles in curve-based collision walks](https://eprint.iacr.org/2026/2560) — ★★★ | `多用户 ECDLP/isogeny`
- **2026/1823** (2026-08-28) [HyperSolver: Asymptotically and Concretely Accelerating the Delfs–Galbraith Attack using Isogeny Ladders](https://eprint.iacr.org/2026/1823) — ★★★ | `isogeny`
- **2026/1776** (2026-08-22) [Cofactor-torsion attacks on hinted scalar multiplications in SNARK circuits](https://eprint.iacr.org/2026/1776) — ★★★★ | `SNARK 曲线 gadget`
- **2026/1623** (2026-08-05) [Triple Cryptanalysis of Isogeny-Based VRFs from Asiacrypt 2025](https://eprint.iacr.org/2026/1623) — ★★★★ | `isogeny VRF`
- **2026/1575** (2026-07-31) [Solving the supersingular isogeny problem in time $p^{2/5+o(1)}$ using bivariate multipoint evaluation](https://eprint.iacr.org/2026/1575) — ★★★ | `isogeny`
- **2026/1486** (2026-07-20) [The supersingular isogeny problem in time and memory $p^{1/3+o(1)}$](https://eprint.iacr.org/2026/1486) — ★★★ | `isogeny 参数评估`
- **2026/1002** (2026-05-21) [On weak keys of POKE](https://eprint.iacr.org/2026/1002) — ★★★ | `isogeny 弱密钥`
