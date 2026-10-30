# LWE with hints（带额外信息的 LWE）

`b = A·s + e (mod q)`，外加若干关于 `s` 的**线性 hint**：`<v_i, s> = l_i (mod q)`。
hint 可能是精确（perfect）、带小误差（approximate / modular），也可能只给部分坐标或
模 q 残差。这类题目近两年是论文驱动的主流：hint 把不可解的 LWE 变成可解的。

## 1. 什么时候用它

- 题面给 `A, b, q`，**并额外给出**：若干系数泄漏、模 q 线性组合、已知部分 secret、
  错误可猜、侧信道 trace、故障输出。
- 参数“刚好超出”普通 LWE 的可解范围，但 hint 数量/质量足够把难度拉回来。
- 原语带环/模结构（Kyber 系、FHE 参数、NTRU 变体）时，hint 往往以 NTT 域残差或
  有限精度采样的形式出现。

## 2. hint 类型与论文背景

| 类型 | 形式 | 说明 |
|---|---|---|
| perfect | `<v,s> = l (mod q)` 精确成立 | 直接消元，几乎免费 |
| modular | `<v,s> ≡ l (mod q)` | 同 perfect，但要求 q 素 |
| approximate | `<v,s> = l + e'`，`|e'| ≤ e` | 增加噪声 |
| coordinate | `s_j = c` | 单位向量 hint 的特例 |
| sign/HW | `s_j` 的符号或 Hamming 重量 | 需先转成近似 hint（见下） |

- **DDGR（CRYPTO 2020）**：把 hint 按代数形式分类，给出可被 LLL 破解的 hint 数量阈值。
- **May–Nowakowski（ASIACRYPT 2023）/ Cao–Jiang–Cheng（CRYPTO 2025）**：完善
  “too many hints”阈值。
- **ePrint 2026/2654**：**警告**——DDGR 分类是“语法层”的，不反映真实代数结构。
  Kyber-512 上 NTT 域残差只需约一半的均匀界、有限精度 FFT 近似 hint 只需 25%–55%。
  所以拿到 hint 时**要看它的代数来源**，不要只看数量。
- **ePrint 2026/1081**：稀疏三元 secret 只需 `O(h log h)` 个 hint（h 为 Hamming 重量），
  而不是 `n/2`。对 FHE 型稀疏参数尤其适用。

## 3. 主要做法：消元（把 hint 当作变量替换）

核心思路：若 hint 足够多且线性无关，就能把 `s` 的一部分坐标用其余坐标 + hint 表达，
代入 `A·s = b` 得到一个**更低维的普通 LWE 实例**，然后用嵌入 + Babai 解。

设 hint 矩阵 `V`（h×n）、`l`（h）。在模 q 上做行阶梯消元得到 `h'` 个独立 hint 与
枢轴列 `P`（|P|=h'）、非枢轴列 `N`：

```
V_P · s_P + V_N · s_N = l      (mod q)
s_P = V_P^{-1}(l - V_N·s_N)    (mod q)
```

代入 `A_P·s_P + A_N·s_N = b`（`A_P = A[:,P]`, `A_N = A[:,N]`）：

```
(A_N - A_P·V_P^{-1}·V_N) · s_N  =  b - A_P·V_P^{-1}·l   (mod q)
```

得到维数 `n - h'` 的普通 LWE（模数仍为 q）。噪声来自原误差 `e`；若 hint 是
approximate，还要计入映射过去的 hint 误差（变大则需 BKZ）。

解出 `s_N` 后回代得 `s_P`，拼回完整 `s`，中心化到 `[-q/2, q/2)`。

**实现**：`scripts/templates/lwe_hints.sage`（Sage，纯线性代数 + 嵌入/Babai）。

## 4. 替代做法：把 hint 编进 CVP 嵌入

不消元也可以：在 `[[q·I, 0], [Aᵀ, I]]` 嵌入上**追加 hint 行**，构造

```
[ q·I   0      0  ]
[ Aᵀ    I      0  ]
[ Vᵀ    0      I  ]
```

目标向量 `(b, 0, l)`。让 `V·s = l` 进入格，缩短可恢复子空间。维数比消元法高
`h`，噪声处理方式相同。消元法更省维数，一般优先用它。

## 5. 工程要点

- **q 必须为素数**（消元要除 `V_P^{-1} mod q`）。复合模先分解或换做法。
- **噪声大小决定成败**：噪声小用 LLL + Babai；噪声大/维数高用 BKZ（block 20–40）。
- **验证**：恢复的 `s` 必须满足 `A·s + e = b (mod q)` 且每个残差都很小；hint 残差
  `<v_i,s> - l_i (mod q)` 也应小。
- **坐标 hint**：`s_j = c` 即 `v = e_j`、`l = c`。
- **符号/Hamming hint**：先估计每个坐标的取值区间（如 ±1 或区间中心），转成
  approximate hint，误差取区间半径。
- 稀疏 secret（FHE 型）参考 2026/1081：hint 需求随 Hamming 重量增长，而非维数。

## 6. 相关工具与模板

| 资源 | 用途 |
|---|---|
| `scripts/templates/lwe_hints.sage` | 消元 + 嵌入/Babai，支持 perfect/approximate |
| `scripts/templates/lwe_bkz.sage` | 无 hint 的普通 LWE（BKZ 可选） |
| `scripts/ctfkit/lattice.lwe_cvp_solve` | 纯 Python 小规模 LWE |
| `scripts/ctfkit/lattice.lwe_with_hints` | 纯 Python 小规模 LWE + hint（把 hint 追加为额外样本） |
| `scripts/papers/search.py hint` | 论文库中 hint/LWE 相关论文 |
