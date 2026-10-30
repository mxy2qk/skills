# LIP / 理想格 / HAWK（高门槛论文题）

格同构问题（Lattice Isomorphism Problem, LIP）是较新的格假设，支撑 HAWK 签名与
若干 LIP-based 构造。2026 年对 LIP/理想格/HAWK 有大量攻击。多数 CTF 题是
**识别 + 论文路径**，现成模板少；本页给识别特征与论文索引。

## 1. 问题定义

- **LIP**：两个格 `L, L'` 是否等距（存在正交矩阵 `O` 使 `L' = O·L`），并求 `O`。
- **module-LIP**：环上模格版本的 LIP，HAWK 的安全基础。
- **理想格 / Ideal-SVP / Ideal-BDD**：数域理想上的短向量/有界距离解码。
- **SIS**：找短 `z` 使 `A·z ≡ 0 (mod q)`；LtHash 增量哈希基于三元 SIS。
- **nrd-PIP / double-LIP**：LIP 的变体/推广。

## 2. 识别特征

| 题面信号 | 方向 | 代表论文 |
|---|---|---|
| HAWK 签名（module-LIP、浮点-free、无 rejection） | module-LIP / nrd-PIP | 2026/699, 1593, 1560, 1755, 2198, 2381 |
| DEFI 签名（各向同性二次型） | LIP（indefinite forms） | 2026/890 |
| 基于 LIP 的盲签名 / double-LIP | LIP | 2026/722 |
| LtHash 增量哈希（三元 SIS） | SIS mod 2^d | 2026/2083 |
| knapsack / NTRU 变体（GTLN、AJPS、NTC） | 格/连分数 | 2026/2225, 2543, 1705, 1642, 1554 |
| 理想格 / Construction A / Barnes-Wall | 理想格 / LIP | 2026/2042, 2325, 2281 |

## 3. 关键攻击思想（2026 主要进展）

- **HAWK 密钥恢复归约到 SVP**：
  - 2026/1593：`HAWK-n` 无条件归约到维数 `n/2+1` 的精确 SVP；HAWK-512 密钥恢复
    从 2^150 降到 2^108（门计数）。HAWK-256 端到端数小时恢复。
  - 2026/1560：trace-zero 方法把 rank-2 module-LIP 降到 rank-3 模块格，SVP 维数
    `3m/8+1`。
  - 2026/2198：对称平方 / 共轭 Hodge star 把 rank-4 module-LIP 降到 `3n/2+1` 维 SVP。
  - 2026/1755：**四元数理想 LLL/BKZ**，维数比标准实嵌入小 4×，用于 nrd-PIP。
- **LIP with hints / 侧信道**：2026/2381 把 hint 融入 LIP 的 SVP 嵌入，HAWK-1024
  估计损失 ~11 bit；2026/699 把采样器泄漏（系数/符号）放大为密钥恢复。
- **符号泄漏 → Halfspace 学习**：2026/1366 对 HAWK/Falcon/ML-DSA，泄漏符号即可
  恢复密钥（Learning a Halfspace）。
- **弱密钥 / 校验缺失**：2026/1298 弱公钥破 HAWK 的 BUFF；2026/1377 反驳
  “Guessing Game”的多项式时间声称。
- **SIS 小模数**：2026/1349 改进 Large Norm 攻击，Falcon-256 成本降 11×，
  Dilithium 型 `ISIS^∞` ≤1.6s。
- **LtHash**：2026/2083 two-bit lifting 三元 SIS，LtHash16 从 2^180 降到 2^101 操作。
- **knapsack**：2026/2225 LLL 秒破 GTLN；2026/2543 连分数同效。

## 4. 工具

| 任务 | 工具 |
|---|---|
| module-LIP 降维到 SVP | 论文 2026/1593 的方法；fpylll BKZ |
| 理想格 / nrd-PIP | 四元数 LLL/BKZ（2026/1755）或 Sage 理想格 |
| LIP 同构检测（toy 维 ≤7） | `lip_check.sage`（不变量 + 符号置换穷举） |
| 符号泄漏恢复 | Halfspace 学习（2026/1366）；或转成 `lwe_hints.sage` 的近似 hint |
| 小模数 SIS / knapsack | `lwe_bkz.sage`、`ctfkit.lattice.ntru_recover`、连分数 |

## 5. 工程要点

- 高门槛：多数攻击依赖精确 SVP oracle（模拟）或论文专用归约，CTF 里若出现通常是
  **参数缩小到可用 fpylll BKZ/穷举的 toy 版本**。
- 见到 `module-LIP / HAWK / DEFI / LtHash / GTLN` 等词 → 先在论文库检索
  （`scripts/papers/search.py --tag HAWK`），再判断参数规模。
- 符号/Hamming 泄漏比完整系数泄漏更容易在题面中给出，优先走 2026/1366 或
  `lwe_hints.sage`。

## 6. 论文索引

`sis-lip-ideal` 方向共 23 篇，见 `assets/papers/sis-lip-ideal.md` 与 `paper-map.md`。
