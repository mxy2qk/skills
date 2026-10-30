# LWE dual / hybrid 攻击（参数评估为主）

dual attack 是评估 LWE/ML-KEM/ML-DSA 具体安全的主力；2026 年大量论文在完善
**可证明的（provable）dual attack**。CTF 里它们主要用于**判断参数是否可攻**，
偶尔直接出题（稀疏 secret / hint 配合）。

## 1. 基本思想

给定 `A·s + e = b (mod q)`：

- **primal（嵌入）**：构造 `[[qI,0],[Aᵀ,I]]` 找短向量/Babai——`lwe_bkz.sage`
  与 `ctfkit.lattice.lwe_cvp_solve` 走这条。
- **dual（对偶区分）**：找对偶格中短向量 `y`（`A·y = 0 mod q`），则
  `<y, b> = <y, e>` 是高斯分布而 `<y, A·s>` 消失；猜测 secret 的若干坐标，
  用分数分布区分正确/错误候选。
- **hybrid**：把 secret 拆成猜的部分（MITM/枚举）与格恢复的部分，结合 dual
  （2026/1060 面向 FHE 稀疏 secret 的 hybrid dual）。

## 2. 2026 主要进展

| 论文 | 贡献 |
|---|---|
| 2026/2117 | provable dual 用格投影降低采样维数，改进 26–44 bit |
| 2026/2565 | 无启发式假设的 provable dual，统一 Pouly–Shen / Bashiri–Wiemers；ML-KEM 提升 22–52 bit |
| 2026/2186 | FFT dual 推广到一般对偶格，样本 `m≈2n→n` |
| 2026/2166 | MATZOV 型 FFT dual 的正确性分析，ML-KEM-512/768/1024 = 210/300/410 bit |
| 2026/1048 | 分数分布的统一协方差模型（修独立性假设） |
| 2026/1326 | p-adic 分层模切换（LaMS），比 CRT 型省猜测 |
| 2026/1400 | 模切换 + 有损信源编码，降 FFT/解码成本 |
| 2026/688 | dual 增强的两阶段代数算法（dual 归约 + resultant） |
| 2026/1060 | hybrid dual 稀疏 secret，破 EUROCRYPT'24 加速 BGV |
| 2026/1720 | 小 max-norm LWE 的碰撞搜索（多项式内存） |
| 2026/279 | MLWE 系数等距导致比 LWE 更易攻（hybrid） |

## 3. CTF 使用方式

- **判断可行性**：给定参数（n, q, secret 分布），用 lattice-estimator 或上述
  论文的估计判断 `BKZ block size` / 时间是否现实。若 block < 40 且 n 小 → 直接
  `lwe_bkz.sage`；否则提示参数不可攻或需 hint。
- **稀疏/三元 secret**：优先 hybrid（MITM 猜稀疏位 + dual/嵌入恢复），配合
  `lwe_hints.sage` 的 hint。
- **环/模结构**：2026/279、366 说明不可把 MLWE 当 LWE 估计——系数等距/环结构
  可能让攻击更有效（FHE 稀疏参数最多差 14.2 bit）。

## 4. 与 primal 的取舍

| 场景 | 用哪个 |
|---|---|
| 小 n、小噪声、无结构 | primal 嵌入 + Babai（`lwe_bkz.sage`） |
| 稀疏/三元 secret，n 大 | hybrid（MITM + dual 或嵌入） |
| 带 hint | `lwe_hints.sage`（消元/追加行） |
| 参数评估（判断能否出题/能攻） | dual/估计算子（本文档 + 论文 2117/2565/2166） |

## 5. 相关资源

- `scripts/templates/lwe_bkz.sage`、`lwe_hints.sage`、`scripts/ctfkit/lattice.py`
- 论文库 `lattice-lwe-hints` 方向（21 篇）与 `paper-map.md`
