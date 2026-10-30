# 论文 ↔ 题型映射表（2026 精选）

> 由 `papers.json` 自动生成（`build_assets.py`）。按题面信号组织：
> 看到这些特征，先查速查表定位方向，再按 ID 回查对应方向 md 里的完整简述。

## 题面信号 → 方向速查

| 题面信号 | 方向 | 代表论文 |
|---|---|---|
| 给 LWE/MLWE + 泄漏位、模 q hint、已知错误、FHE 稀疏参数 | `lattice-lwe-hints` | 2026/2654, 2026/1081, 2026/366 |
| 出现 ML-KEM/ML-DSA/NTRU/Falcon/HAWK 实现 + trace/故障/oracle | `pqc-implementation` | 2026/1904, 2026/070, 2026/2124 |
| HAWK / LIP / 理想格 / SIS / knapsack / NTRU 变体 | `sis-lip-ideal` | 2026/1593, 2026/2083, 2026/2225 |
| 部分 p/q/dp/dq、CRT-RSA 小指数、RSA 变体、广义 Wiener | `coppersmith-rsa` | 2026/2109, 2026/1027, 2026/1529 |
| 签名偏置/泄漏 nonce、截断 PRNG、模逆 HNP、阈值签名 | `hnp-signatures` | 2026/423, 2026/1366, 2026/2566 |
| 超奇异曲线 / 配对 / 同源 / SNARK 曲线 gadget | `ecc-pairing-isogeny` | 2026/1823, 2026/1776, 2026/1623 |

## LWE / 带 hint 与格参数评估

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2654](https://eprint.iacr.org/2026/2654) | 结构化 hint 的必读论文 | LWE hints, NTT, Kyber, 结构 | `lwe_hints.sage` |
| [2026/2638](https://eprint.iacr.org/2026/2638) | 带协方差泄漏的 RLWE | Ring-LWE, known covariance, 判定攻击 | `—` |
| [2026/2565](https://eprint.iacr.org/2026/2565) | 参数评估 | provable dual, ML-KEM, ML-DSA | `—` |
| [2026/2186](https://eprint.iacr.org/2026/2186) | 参数评估 | provable dual, FFT, 一般对偶格 | `—` |
| [2026/2166](https://eprint.iacr.org/2026/2166) | 参数评估 | dual attack, ML-KEM, 正确性分析 | `—` |
| [2026/2117](https://eprint.iacr.org/2026/2117) | 参数评估 | provable dual, 格投影 | `—` |
| [2026/1720](https://eprint.iacr.org/2026/1720) | 小范数 LWE / 子集和 | LWE, subset-sum, 碰撞搜索 | `lwe_bkz.sage` |
| [2026/1400](https://eprint.iacr.org/2026/1400) | 参数评估 | dual attack, FFT, modulus switching | `—` |
| [2026/1326](https://eprint.iacr.org/2026/1326) | 参数评估 | dual attack, p-adic, modulus switching | `—` |
| [2026/1081](https://eprint.iacr.org/2026/1081) | LWE 带 hint 的核心论文 | LWE hints, 稀疏 secret, 近似 hint | `lwe_hints.sage` |
| [2026/1060](https://eprint.iacr.org/2026/1060) | FHE 稀疏 secret | hybrid dual, 稀疏 secret, FHE | `—` |
| [2026/1048](https://eprint.iacr.org/2026/1048) | 参数评估 | dual attack, 分数分布 | `—` |
| [2026/1041](https://eprint.iacr.org/2026/1041) | 环/模结构利用 | 结构感知, 格分析框架 | `—` |
| [2026/688](https://eprint.iacr.org/2026/688) | 少样本 LWE + hint | LWE, dual, Arora-Ge, hints | `lwe_hints.sage` |
| [2026/630](https://eprint.iacr.org/2026/630) | 小 k 稀疏 LWE | ternary sparse LWE, 渐近分析 | `lwe_bkz.sage` |
| [2026/614](https://eprint.iacr.org/2026/614) | 稀疏方程判定/攻击 | sparse LWE, sparse LPN, 谱方法 | `lwe_bkz.sage` |
| [2026/612](https://eprint.iacr.org/2026/612) | ML 辅助 LWE（较少见） | LWE, 机器学习, 稀疏 secret | `—` |
| [2026/421](https://eprint.iacr.org/2026/421) | PLWE/RLWE 归约错误识别 | PLWE, 综述 | `—` |
| [2026/366](https://eprint.iacr.org/2026/366) | 稀疏 Ring-LWE/FHE 参数 | Ring-LWE, hybrid decoding, 稀疏 secret | `lwe_bkz.sage` |
| [2026/279](https://eprint.iacr.org/2026/279) | 环对称性导致的 MLWE/LWE 难度差 | MLWE, 系数等距, hybrid | `lwe_bkz.sage` |
| [2026/177](https://eprint.iacr.org/2026/177) | 带线性泄漏/恶意公钥的 MLWE；Sage 几秒出结果 | Oracle MLWE, 泄漏, 邻域搜索 | `lwe_hints.sage` |

## PQC 实现攻击（侧信道 / 故障）

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2643](https://eprint.iacr.org/2026/2643) | 单 trace 侧信道 | ML-DSA, 单 trace, GMM | `—` |
| [2026/2567](https://eprint.iacr.org/2026/2567) | 故障攻击与对策评估 | ML-DSA, rejection sampling, 故障 | `—` |
| [2026/2448](https://eprint.iacr.org/2026/2448) | 掩码 Kyber | Kyber, 掩码, belief propagation | `—` |
| [2026/2258](https://eprint.iacr.org/2026/2258) | 量子对抗模型 | Dilithium, 量子, Fiat-Shamir | `—` |
| [2026/2211](https://eprint.iacr.org/2026/2211) | LIP/构造缺陷 | Polar-KEM, 同构, 结构攻击 | `—` |
| [2026/2137](https://eprint.iacr.org/2026/2137) | 单 trace 侧信道 | ML-KEM, 单 trace, 密钥生成 | `—` |
| [2026/2124](https://eprint.iacr.org/2026/2124) | Falcon 侧信道 + LLL/BKZ | Falcon, 浮点泄漏, LWE/NTRU 格 | `—` |
| [2026/2091](https://eprint.iacr.org/2026/2091) | ILWE / 噪声泄漏 | ILWE, belief propagation, ML-DSA | `—` |
| [2026/2069](https://eprint.iacr.org/2026/2069) | 故障攻击 | Kyber, 故障, FO 比较 | `—` |
| [2026/1904](https://eprint.iacr.org/2026/1904) | ML-DSA 少 trace 侧信道 | ML-DSA, 水平融合, 侧信道 | `—` |
| [2026/1712](https://eprint.iacr.org/2026/1712) | ML-DSA 泄漏预处理 | ML-DSA, 噪声估计, 泄漏 | `—` |
| [2026/1682](https://eprint.iacr.org/2026/1682) | 实现缺陷→线性泄漏 | ML-KEM, FO 比较, 线性泄漏 | `—` |
| [2026/1668](https://eprint.iacr.org/2026/1668) | 阈值签名 nonce 复用 | TALUS, nonce 复用, 阈值 | `—` |
| [2026/1448](https://eprint.iacr.org/2026/1448) | 随机化 Dilithium 的跳过故障 | Dilithium, 故障攻击, MILP | `—` |
| [2026/1386](https://eprint.iacr.org/2026/1386) | 协议实现缺陷→线性恢复 | TALUS, 阈值签名, 线性恢复 | `—` |
| [2026/1344](https://eprint.iacr.org/2026/1344) | 故障攻击 | ML-DSA, HAETAE, 故障攻击 | `—` |
| [2026/981](https://eprint.iacr.org/2026/981) | 侧信道框架 | ML-KEM, SASCA, 侧信道 | `—` |
| [2026/820](https://eprint.iacr.org/2026/820) | 部分密钥 + Kannan/Bai-Galbraith 嵌入 | Kyber, CPA, 格嵌入 | `lwe_bkz.sage` |
| [2026/582](https://eprint.iacr.org/2026/582) | 冷启动/部分系数泄漏 + 格 | NTRU, 冷启动, 位翻转 | `—` |
| [2026/580](https://eprint.iacr.org/2026/580) | ML-DSA 单位泄漏 | ML-DSA, 单位泄漏, 噪声 | `—` |
| [2026/528](https://eprint.iacr.org/2026/528) | 一阶掩码 Kyber | Kyber, 掩码, 侧信道 | `—` |
| [2026/472](https://eprint.iacr.org/2026/472) | ML-DSA 少量泄漏签名 | ML-DSA, 泄漏, 局部优化 | `—` |
| [2026/070](https://eprint.iacr.org/2026/070) | 解密失败/明文检查 oracle | ML-KEM, 解密失败 oracle, LDPC | `—` |
| [2026/064](https://eprint.iacr.org/2026/064) | 光滑群阶 + 两条签名 HNP | PQC 假方案, 光滑群阶, HNP | `hnp_ecdsa.py / lwe_bkz.sage` |
| [2026/056](https://eprint.iacr.org/2026/056) | ML-DSA 非模板侧信道 | ML-DSA, 侧信道, non-profiling | `pqc 侧信道流程（待补）` |

## SIS / 理想格 / LIP / HAWK

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2543](https://eprint.iacr.org/2026/2543) | knapsack 公钥秒破 | knapsack, 连分数, 密钥恢复 | `—` |
| [2026/2527](https://eprint.iacr.org/2026/2527) | NTRU+/module 攻击 | NTRU+, module-BKZ, 参数评估 | `—` |
| [2026/2420](https://eprint.iacr.org/2026/2420) | 参数评估 | Module-SIS, Module-LWE, 次指数 | `—` |
| [2026/2381](https://eprint.iacr.org/2026/2381) | LIP + 侧信道 hint | LIP, hints, HAWK | `—` |
| [2026/2325](https://eprint.iacr.org/2026/2325) | LIP | LIP, Construction A, hull | `—` |
| [2026/2281](https://eprint.iacr.org/2026/2281) | LIP 降维 | LIP, direct sum, Barnes-Wall | `—` |
| [2026/2225](https://eprint.iacr.org/2026/2225) | knapsack 公钥秒破 | knapsack, LLL, 密钥恢复 | `lwe_bkz.sage` |
| [2026/2198](https://eprint.iacr.org/2026/2198) | HAWK/module-LIP | module-LIP, 降维, rank 4 | `—` |
| [2026/2083](https://eprint.iacr.org/2026/2083) | SIS/LtHash 碰撞 | SIS, LtHash, 碰撞 | `—` |
| [2026/2042](https://eprint.iacr.org/2026/2042) | 理想格降维 | Ideal-SVP, Ideal-BDD, 群表示 | `—` |
| [2026/1755](https://eprint.iacr.org/2026/1755) | HAWK/nrd-PIP | 四元数, LLL/BKZ, module-LIP | `—` |
| [2026/1705](https://eprint.iacr.org/2026/1705) | NTRU 变体 | AJPS, NTRU, Mersenne | `—` |
| [2026/1642](https://eprint.iacr.org/2026/1642) | NTRU 变体识别 | NTC, NTRU 推广, 构造+分析 | `—` |
| [2026/1593](https://eprint.iacr.org/2026/1593) | HAWK 归约到 SVP | HAWK, SVP, 密钥恢复 | `—` |
| [2026/1560](https://eprint.iacr.org/2026/1560) | HAWK/理想格降维 | HAWK, SVP, trace-zero | `—` |
| [2026/1554](https://eprint.iacr.org/2026/1554) | 代数 knapsack | Vandermonde Knapsack, vSIS, 环 | `—` |
| [2026/1377](https://eprint.iacr.org/2026/1377) | HAWK 攻击可行性 | HAWK, 复杂度 | `—` |
| [2026/1349](https://eprint.iacr.org/2026/1349) | 小模数 SIS/伪造 | SIS, Large Norm, Falcon, Dilithium | `—` |
| [2026/1318](https://eprint.iacr.org/2026/1318) | HAWK 启发式攻击 | HAWK, module-LIP, nrdPIP | `—` |
| [2026/1298](https://eprint.iacr.org/2026/1298) | 弱公钥/校验缺失 | HAWK, 弱密钥, BUFF | `—` |
| [2026/890](https://eprint.iacr.org/2026/890) | LIP 签名密钥恢复 | LIP, DEFI, 二次型 | `—` |
| [2026/722](https://eprint.iacr.org/2026/722) | LIP 协议缺陷 | LIP, blind signature, 双 LIP | `—` |
| [2026/699](https://eprint.iacr.org/2026/699) | HAWK + LIP hint | HAWK, 侧信道, LIP | `—` |

## Coppersmith / RSA 变体

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2620](https://eprint.iacr.org/2026/2620) | RSA/EC 证书侧信道 | EC 半素性证书, 分解, CM | `—` |
| [2026/2109](https://eprint.iacr.org/2026/2109) | CRT-RSA 小 dp/部分位（核心） | CRT-RSA, 小 dp/dq, Unravelled Linearization, MSB 泄漏 | `coppersmith_multi.sage` |
| [2026/1969](https://eprint.iacr.org/2026/1969) | 多元多项式系统求解 | Dixon resultant, 多元多项式, Gröbner | `coppersmith_multi.sage` |
| [2026/1908](https://eprint.iacr.org/2026/1908) | n=2^i 的广义 Wiener | RSA 变体, 广义 Wiener, 连分数+格 | `boneh_durfee.sage` |
| [2026/1529](https://eprint.iacr.org/2026/1529) | 非平衡模数的广义 Wiener | RSA 变体, 广义 Wiener, Coppersmith | `boneh_durfee.sage` |
| [2026/1357](https://eprint.iacr.org/2026/1357) | RSA 变体超界 | RSA 变体, cubic Pell, 格攻击 | `coppersmith_multi.sage` |
| [2026/1295](https://eprint.iacr.org/2026/1295) | Wiener 变体 + 部分信息 | RSA, 小 d, 部分 p+q, 连分数 | `boneh_durfee.sage` |
| [2026/1137](https://eprint.iacr.org/2026/1137) | RSA 变体综述 | RSA 变体, 综述, 格攻击 | `coppersmith_multi.sage` |
| [2026/1027](https://eprint.iacr.org/2026/1027) | 判断 Coppersmith 参数是否可行 | Automated Coppersmith, 线性规划, EC-HNP | `coppersmith_multi.sage / ec_hnp.sage` |
| [2026/519](https://eprint.iacr.org/2026/519) | RSA 变体 + 已知部分 p/q 位 | RSA 变体, cubic Pell, 部分暴露 | `coppersmith_multi.sage` |
| [2026/244](https://eprint.iacr.org/2026/244) | 多元 Coppersmith 参数/界 | Coppersmith, Unravelled Linearization, Ehrhart | `coppersmith_multi.sage` |

## HNP / 签名 nonce 泄漏

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2566](https://eprint.iacr.org/2026/2566) | 阈值 ML-DSA 故障 | 阈值签名, 故障, nonce 重放, ML-DSA | `—` |
| [2026/1808](https://eprint.iacr.org/2026/1808) | code-based 签名实现缺陷 | SDitH, code-based, PRG 复用 | `—` |
| [2026/1366](https://eprint.iacr.org/2026/1366) | 签名随机数的符号/Hamming 重量泄漏 | 签名泄漏, 半空间学习, HAWK/Falcon/ML-DSA | `hnp_ecdsa.py` |
| [2026/423](https://eprint.iacr.org/2026/423) | 模逆 HNP / ICG 预测 | HNP, MIHNP, Coppersmith, ICG | `coppersmith_multi.sage / hnp_ecdsa.py` |

## ECC / 配对 / 同源

| ID | 题面特征 | 标签 | 对应模板/工具 |
|---|---|---|---|
| [2026/2560](https://eprint.iacr.org/2026/2560) | 多用户 ECDLP/isogeny | 多用户, 碰撞攻击, ECDLP, isogeny | `—` |
| [2026/1823](https://eprint.iacr.org/2026/1823) | isogeny | Delfs-Galbraith, isogeny ladder, SQIsign | `—` |
| [2026/1776](https://eprint.iacr.org/2026/1776) | SNARK 曲线 gadget | SNARK, ECC, cofactor, hinted scalar mult | `—` |
| [2026/1623](https://eprint.iacr.org/2026/1623) | isogeny VRF | isogeny VRF, radical-CGL, 密钥恢复 | `—` |
| [2026/1575](https://eprint.iacr.org/2026/1575) | isogeny | supersingular isogeny, 双变量多点求值 | `—` |
| [2026/1486](https://eprint.iacr.org/2026/1486) | isogeny 参数评估 | supersingular isogeny, 复杂度 | `—` |
| [2026/1002](https://eprint.iacr.org/2026/1002) | isogeny 弱密钥 | POKE, isogeny PKE, 弱密钥 | `—` |
