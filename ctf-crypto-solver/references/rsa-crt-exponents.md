# CRT-RSA 小指数与部分 CRT 指数

CRT-RSA 用两个小指数加速解密：`d_p = d mod (p-1)`、`d_q = d mod (q-1)`。
两类攻击：**未知但很小**的 `d_p, d_q`（TLP / unravelled linearization），以及
**部分已知**（已知 MSB 或 LSB）的 `d_p, d_q`（Approximate Divisor Multiples）。
此外 RSA-like 变体（`ed - k(p^n-1)(q^n-1) = 1`）可用**广义 Wiener**。

## 1. 区分两种题型

| 题面 | 攻击 | 工具 |
|---|---|---|
| `d_p, d_q < N^δ`（δ 未知但小，约 <0.122） | Takayasu–Lu–Peng（TLP）三元格；2026/2109 用 unravelled linearization 把格维数砍半 | Sage 格攻击，参数需看论文 |
| 已知 `d_p`/`d_q` 的**部分位**（MSB 或 LSB） | Approximate Divisor Multiples：`d_p` 是某个小数的倍数 → Coppersmith | `crt_rsa_partial.sage` |
| RSA-like 变体 `ed - k(p^n-1)(q^n-1)=1` | 广义 Wiener（连分数 + 格） | `boneh_durfee.sage` 思想 / 论文公式 |

## 2. 未知小 CRT 指数（TLP / 2026/2109）

密钥方程：

```
e·d_p - 1 = k_p·(p-1)    e·d_q - 1 = k_q·(q-1)     (k_p, k_q ∈ [1, e))
```

### 2a. TLP（Takayasu–Lu–Peng, eprint 2017/092, JoC 2019）——6 变量格

解 mod e 的四个方程 + 一个乘积方程：

```
f_{p,1} = N + x_{p,1}(N−y_p) ≡ 0       根 (x_{p,1}, y_p) = (k_q−1, p)
f_{q,1} = 1 + x_{q,1}(y_q−1) ≡ 0       根 (x_{q,1}, y_q) = (k_q, q)
f_{p,2} = 1 + x_{p,2}(y_p−1) ≡ 0       根 (x_{p,2}, y_p) = (k_p, p)
f_{q,2} = N + x_{q,2}(N−y_q) ≡ 0       根 (x_{q,2}, y_q) = (k_p−1, q)
h = (N−1)·x_{p,1}·x_{p,2} + x_{p,1} + N·x_{p,2} ≡ 0 (mod e)   # 由 (k_q−1)(k_p−1) ≡ k_q k_p N (mod e)
```

根界：`|x| ≤ X = N^{α+δ−1/2}`，`|y| ≤ Y = N^{1/2}`；平衡素数、全尺寸 `e` 时
**δ < 1/2 − 1/√7 ≈ 0.122**（优于 Jochemsz–May 的 0.073、该文前期 0.091）。
shift 多项式为 `g[i1,i2,j1,j2,u] = x_{p,1}^{j1} x_{p,2}^{j2} y_q^{(i1+i2)/2}
f_{p,1}^{i1} f_{p,2}^{i2} h^u e^{m−(i1+i2+u)}` 等，三角格 + LLL + 代数独立多项式求根。

### 2b. 2026/2109——unravelled linearization（格维数约为 TLP 一半）

五个线性化变量与三条模方程：

```
A = k_p·k_q        B = k_p + k_q − 1      T = k_p·p + k_q·q
L = p + q          C = T − B − A·L        （C 用 L 表示 → unravelled）

f = B + (N−1)·A ≡ 0 (mod e)
g = C + (N+1)·A ≡ 0 (mod e²)
h = T − B + 1     ≡ 0 (mod e)
```

根界：`X_A = N^{2δ+2α−1}, X_B = N^{α+δ−1/2}, X_C = N^{2δ+2α−1/2}, X_T = N^{α+δ}, X_L = N^{1/2}`。
LLL 后用 Gröbner 恢复 `A,B,C,T`，再分解：

```
k_p, k_q  ←  t² − (B+1)·t + A = 0 的根
k_p·p, k_q·q  ←  z² − T·z + A·N = 0 的根
p = (k_p·p)/k_p
```

**界不变（δ < 0.122）**，但格维数减半、理论估计与实验吻合；并扩展到 `p+q`
与 `d_p,d_q` 的 MSB 泄漏模型（泄漏越多界越好）。

### 2c. 工程状态（2026-10-29 已实现并验证）

- 两篇论文全文已下载：`ctf-crypto-solver-workspace/research/`
  （`mirror_2017_092.pdf` / `mirror_2026_2109.pdf`，文本 `tlp_2017.txt` /
  `a2109_2026.txt`）。
- **已提供可运行模板** `scripts/templates/crt_rsa_small_dp.sage`（实现 2026/2109
  unravelled linearization）：
  - 读 `instance.json`（`N, e, delta, m_list`），按上面的线性化方程建格、LLL、
    Howgrave-Graham 选短向量、Gröbner 恢复 `A,B,C` 并分解。
  - **已在 toy 参数端到端验证**（N=80-bit、`d_p=d_q=1`、m=6 → 精确恢复 p,q；
    33/42 个 LLL 向量在真根上消掉）。验证记录见
    `ctf-crypto-solver-workspace/crt-rsa-small-validation/`。
  - 规模限制（诚实说明）：δ≲0.02 时 m=6 可行；δ 更大需更大 m，而维数随 m³ 增长，
    真实 1024-bit、δ≈0.12 的实例需要很大格，脚本级实现不现实（需大 LLL + Gröbner）。
- 若题目给的是**部分已知** `d_p,d_q`（更常见），仍用第 3 节
  `crt_rsa_partial.sage`（已验证）。

## 3. 部分 CRT 指数分解（Approximate Divisor Multiples）

已知 `d_p` 的 MSB（或 LSB），构造 `d_p = 2^u·d_pM + x`（MSB 情形，x < 2^u），
利用 `e·d_p ≡ 1 (mod p-1)` 得 `e·d_p - 1 = k_p(p-1)`，即 `d_p` 是
`gcd(e·d_p - 1, N)` 的非平凡因子。jvdsn `known_crt_exponents.py` 的实现：

- **MSB 情形（robust）**：由两个 `d_p, d_q` 的 MSB 构造 `mod e` 的二次多项式，其根 `k`
  对应 `k_p, k_q`；对每个 `k` 解单变量模 `k·N` 的 Coppersmith（`beta=0.5`，根落在
  因子 `p` 上），根 `x0` 给出 `d_p = f(x0)`，再 `p = gcd(d_p, N)`。
- **LSB 情形（best-effort）**：两个 LSB 已知 → 双变量模 `2^i·e` 的 Herrmann–May 格。
  注意常数项 `A ≡ -1 (mod e)` 但 `mod 2^i` 可能为偶（不可逆），而本模板复用的
  `coppersmith_multi.small_roots` 需要常数可逆，此时会跳过——MSB 表述更稳。
- 界：`δ = log(max(2^u, 2^v), N) < min(1/4+α, 1/2-2α)`，`α = log(e,N)`。
  对 1024-bit N、e≈2^16：`δ < 0.2656`，即约需已知 `d_p,d_q` 一半以上的位。

**模板**：`scripts/templates/crt_rsa_partial.sage`（MSB 已端到端验证）。

## 4. 广义 Wiener（RSA-like 变体）

对 `ed - k(p^n-1)(q^n-1) = 1`（n 小），`k/d` 是 `e/(p^n-1)(q^n-1)` 连分数逼近，
结合格处理。代表：2026/1908（n=2^i 组合连分数+格）、2026/1529（非平衡 p,q）、
2026/1295（小 d + p+q 部分信息，纯连分数）。见到"RSA 变体 + 特殊密钥方程" →
论文库 `coppersmith-rsa` 方向检索（`scripts/papers/search.py --tag Wiener`）。

## 5. 工程要点

- `α = log(e,N)` 用 2 为底：`log(e,2)/log(N,2)`。
- 根解出后必须验证 `p*q == N`；`k=0` 的根跳过。
- Sage 内置单变量 `f.small_roots(X, m, t)` 可做 Coppersmith；双变量用
  `coppersmith_multi.sage` 的 `small_roots`。
- 一个 `d_p` 已知（另一个未知）也能攻：遍历 `e` 的奇数候选，用
  `_get_possible_primes` 枚举 `p = (e·d_p - 1)/k + 1` 再 `N % p` 校验。
