#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the curated paper library under the skill's assets/papers/.

Merges metadata (selected_full.json) with hand-written Chinese summaries,
then emits papers.json + index.md + one markdown per direction.

Run from the research directory:
    python build_assets.py
"""
import json
import os

RES = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.abspath(os.path.join(RES, "..", "..", "ctf-crypto-solver"))
OUT_DIR = os.path.join(SKILL, "assets", "papers")

DIRS = {
    "lattice-lwe-hints": {
        "title": "LWE / 带 hint 与格参数评估",
        "desc": "LWE/MLWE 的带信息攻击、稀疏 secret、dual/hybrid attack 与具体安全评估。"
                "CTF 里表现为：给 A,b,q 外加泄漏位/模 q hint/已知错误，要求自己建 hint 格。",
    },
    "pqc-implementation": {
        "title": "PQC 实现攻击（侧信道 / 故障）",
        "desc": "ML-KEM/ML-DSA/NTRU/Falcon 等标准实现的侧信道与故障攻击。"
                "CTF 里表现为：给实现/容器/泄漏 trace，先定位缺陷，再回落为格或线性恢复。",
    },
    "sis-lip-ideal": {
        "title": "SIS / 理想格 / LIP / HAWK",
        "desc": "短整数解、理想格、格同构问题（LIP）、HAWK 签名与 knapsack/NTRU 变体。"
                "多为高门槛论文题，需 fpylll/理想格工具。",
    },
    "coppersmith-rsa": {
        "title": "Coppersmith / RSA 变体",
        "desc": "小根、部分密钥暴露、CRT-RSA 小指数、广义 Wiener 与多元多项式求解。"
                "CTF 里表现为：部分 p/q/dp/dq、自构造 RSA 方程、参数卡在旧界边缘。",
    },
    "hnp-signatures": {
        "title": "HNP / 签名 nonce 泄漏",
        "desc": "隐藏数问题及其变体，签名随机数泄漏（偏置 nonce、符号、Hamming 重量）。"
                "CTF 里表现为：ECDSA/DSA/阈值签名泄漏少量位。",
    },
    "ecc-pairing-isogeny": {
        "title": "ECC / 配对 / 同源",
        "desc": "椭圆曲线离散对数、配对降级、超奇异同源问题与 SNARK 中的曲线 gadget。"
                "部分可直接用 smart_anomalous.sage / mov_fr.sage。",
    },
}

# id -> (tags, rating 1-5, mapped tool, ctf_note, chinese summary)
INFO = {
    # ---------------- lattice-lwe-hints ----------------
    "2026/177": (["Oracle MLWE", "泄漏", "邻域搜索"], 4, "lwe_hints.sage",
                 "带线性泄漏/恶意公钥的 MLWE；Sage 几秒出结果",
                 "针对 Oracle MLWE（允许对 secret 的掩码线性泄漏）提出邻域搜索攻击：利用敌手可选的挑战矩阵、小环维数与低范数 secret，通过有界搜索恢复舍入误差，进而恢复 MLWE secret。作者用 Sage 实现，对 Asiacrypt 2025 的 mmKEM 参数几秒内恢复他人封装密钥，推翻其 128-bit 安全声明。"),
    "2026/279": (["MLWE", "系数等距", "hybrid"], 3, "lwe_bkz.sage",
                 "环对称性导致的 MLWE/LWE 难度差",
                 "指出“把 MLWE 等价为 LWE 估计安全”的启发式在真实参数下失效：二次分圆环存在系数等距（signed permutation），可产生共享 A 的多个派生实例，与 hybrid attack 的离线预处理复用。稀疏 RLWE 最多出现 14.2 bit 差距，Kyber/ML-KEM 约 1 bit。"),
    "2026/366": (["Ring-LWE", "hybrid decoding", "稀疏 secret"], 4, "lwe_bkz.sage",
                 "稀疏 Ring-LWE/FHE 参数",
                 "利用多项式环 Z_q[x]/(x^N+1) 的结构加速 hybrid decoding 的猜测与解码步骤，稀疏 secret 下复杂度改善线性于 N。在 FHE 基准上比 SOTA 快 17–114 倍，16 组参数中 12 组降到 128-bit 以下，最多降 13 bit。"),
    "2026/421": (["PLWE", "综述"], 3, "—", "PLWE/RLWE 归约错误识别",
               "系统综述 PLWE 的脆弱实例与攻击，并讨论何时可迁移到 RLWE。适合作为识别“题目用了 PLWE 而非 RLWE”的索引。"),
    "2026/612": (["LWE", "机器学习", "稀疏 secret"], 2, "—", "ML 辅助 LWE（较少见）",
               "用更大训练集与重复样本，让 ML 攻击能恢复更稠密的 binary/ternary secret；并提出 stepwise regression 恢复“cool bits”。属于 ML 与格结合的方向。"),
    "2026/614": (["sparse LWE", "sparse LPN", "谱方法"], 3, "lwe_bkz.sage",
                 "稀疏方程判定/攻击",
                 "对任意有限环上的 k-稀疏线性方程组，给出谱方法判定右端是随机还是带噪秘密赋值，并给出样本-时间权衡；推广了 Z_2 上的 Kikuchi 方法。可用于判断 sparse LWE/LPN 实例是否可攻。"),
    "2026/630": (["ternary sparse LWE", "渐近分析"], 4, "lwe_bkz.sage",
                 "小 k 稀疏 LWE",
                 "对三元稀疏 LWE 做渐近分析：q>3^k 时每行化为 k 维 SVP（筛法 2^{0.292k}），q≤3^k 时用贪心坐标恢复（O(m·k·3^k)）。结论是 k 很小时即使 n 很大也可攻。"),
    "2026/688": (["LWE", "dual", "Arora-Ge", "hints"], 4, "lwe_hints.sage",
                 "少样本 LWE + hint",
                 "提出两阶段代数算法：先用 dual 格归约把样本降到低维（变量变少、噪声变大），再用利用错误分布的新多项式构造 + resultant 解系统，替代经典 Arora-Ge。可直接纳入 perfect/modular/approximate hints。"),
    "2026/1041": (["结构感知", "格分析框架"], 3, "—", "环/模结构利用",
               "CoNAN 是结构感知的格安全估计框架：常见估计器对不同代数结构“一视同仁”，而代数诱导的同态可得到更低维的格表示，从而更高效地攻击。以 NTRU 类构造为主，复现 NTRU Composite、BQTRU、multivariate LWE 等已知攻击，并指出非交换群环/半直积上的 LWE 具体安全比标准估计低至少 60 bit。"),
    "2026/1048": (["dual attack", "分数分布"], 2, "—", "参数评估",
               "提出统一的 dual attack 分数期望/方差预测模型，覆盖原始 dual、带模切换的 dual、带 decoding 的 dual 三类；关键观察是不同短向量夹角的余弦近似正态分布，据此估计分数协方差。相比以往独立性假设，在中高维下更准确，并扩展了 Ducas–Pulles 对错误猜测尾部行为的刻画。"),
    "2026/1060": (["hybrid dual", "稀疏 secret", "FHE"], 3, "—", "FHE 稀疏 secret",
               "系统分析 May MITM 的不同 list/hash 变体，提出改进的 hybrid dual attack，缓解错误枚举与 hash 标签瓶颈，并给出不依赖问题独立性假设的分析。使 EUROCRYPT 2024 的加速 BGV 最多降 18 bit。"),
    "2026/1081": (["LWE hints", "稀疏 secret", "近似 hint"], 5, "lwe_hints.sage",
                  "LWE 带 hint 的核心论文",
                  "研究稀疏三元 secret 下的 perfect/approximate hint：先前需要约 n/2 个 hint，本文在 GAA 下只需 O(h log h) 个（h 为 Hamming 重量）。例如 (n,h)=(2^15,32) 只需 320 个 hint 即可多项式时间恢复，是构造 hint 格的关键参考。"),
    "2026/1326": (["dual attack", "p-adic", "modulus switching"], 2, "—", "参数评估",
               "提出 p-adic 分层模切换（LaMS）：固定一个小素数 p，逐位恢复 secret 的 p-adic 展开，把 CRT 型 provable dual attack 的猜测成本从受最大 CRT 素数支配降到 O(log_p q · p^{n_guess})。修正旧工作后 Kyber 再降约 1 bit。"),
    "2026/1400": (["dual attack", "FFT", "modulus switching"], 2, "—", "参数评估",
               "把模切换与有损信源编码结合进 dual-sieve-FFT 攻击，使 FFT 枚举规模从 q^{n_fft} 降到 p^{k_fft}；Kyber 上总复杂度有改进，解码/FFT 成本分别降 1–6 与 2–7 bit。"),
    "2026/1720": (["LWE", "subset-sum", "碰撞搜索"], 3, "lwe_bkz.sage",
                  "小范数 LWE / 子集和",
                  "用精化的嵌套碰撞搜索与新的表示结构，在保持多项式内存的前提下改进小 max-norm LWE 的渐近复杂度：三元 secret 从 2^{0.926n} 降到 2^{0.8595n}；并略改进随机子集和的 2^{0.645n}→2^{0.6432n}。"),
    "2026/2117": (["provable dual", "格投影"], 2, "—", "参数评估",
               "发现当格的第一极小值较大时可显著改进 Banaszczyk 不等式，并据此提出基于格投影的 provable dual attack：在选定的子格上采样，降低维数从而加速离散高斯采样。相比原框架提升 26.1–43.7 bit。"),
    "2026/2166": (["dual attack", "ML-KEM", "正确性分析"], 2, "—", "参数评估",
               "对 MATZOV 型 FFT dual attack 给出严格正确性分析（分别处理正确/错误候选），得到 ML-KEM-512/768/1024 的攻击成本 210/300/410 bit，相比基线降低 28/47/68 bit。"),
    "2026/2186": (["provable dual", "FFT", "一般对偶格"], 2, "—", "参数评估",
               "把 Guo–Johansson 型 FFT dual attack 的正确性分析从正交格推广到一般对偶格 L_q(A^T)，把所需样本从 m≈2n 降到 m≈n。ML-KEM 成本 216/317/426 bit，比之前最好的 provable dual 降 22/30/52 bit。"),
    "2026/2565": (["provable dual", "ML-KEM", "ML-DSA"], 2, "—", "参数评估",
               "给出无启发式假设的 provable dual attack，统一 Pouly–Shen 与 Bashiri–Wiemers 的方法，用错误的候选的一阶矩估计去掉若干假设。ML-KEM 上比首个 provable dual 改进 22–52 bit（有界秩时 47–100 bit），并实验演示 ML-DSA 小实例；作者声明不威胁两者安全。"),
    "2026/2638": (["Ring-LWE", "known covariance", "判定攻击"], 3, "—", "带协方差泄漏的 RLWE",
               "研究 Known-Covariance RLWE（公开 secret/error 的精确二次摘要），利用公开样本与协方差 hint 构成 bordered Gram 矩阵，其行列式暴露分布不同的残量，从而给出多项式时间判定攻击；覆盖多类奇素数模，并讨论复合模的因子归约迁移。"),
    "2026/2654": (["LWE hints", "NTT", "Kyber", "结构"], 5, "lwe_hints.sage",
                  "结构化 hint 的必读论文",
                  "指出 DDGR hint 分类与“too many hints”阈值只是语法层描述：在 Kyber-512 上，NTT 域残差虽形式上是 mod-q hint，却只需约一半的均匀界；有限精度 FFT 样本属近似 hint，却只需 25%–55% 的 hint 预算。结论是评估真实泄漏必须考虑 hint 向量的代数结构。"),

    # ---------------- pqc-implementation ----------------
    "2026/056": (["ML-DSA", "侧信道", "non-profiling"], 4, "pqc 侧信道流程（待补）",
                 "ML-DSA 非模板侧信道",
                 "利用被拒签名与最终接受签名的双重泄漏，提出基于公开数据的模板（PTA）再做 CPA；ML-DSA-44 上 96 条 trace 恢复 challenge c、约 300 条恢复密钥，比先前少 10×，且 hedged 模式同样无效。"),
    "2026/064": (["PQC 假方案", "光滑群阶", "HNP"], 5, "hnp_ecdsa.py / lwe_bkz.sage",
                 "光滑群阶 + 两条签名 HNP",
                 "完全攻破 MySEAL 2.0 的四个 KAZ 方案。primorial 模使群阶 φ(N) 极光滑，KAZ-KA/KEM 可按小素数因子枚举并解小群 DLP；KAZ-SIGN v2 的线性签名结构化为 HNP，用格归约、仅两条签名即恢复私钥。"),
    "2026/070": (["ML-KEM", "解密失败 oracle", "LDPC"], 4, "—", "解密失败/明文检查 oracle",
                 "重新审视 ML-KEM 的解密失败（DF）oracle：自适应查询生成 + LDPC belief propagation，在多个 secret 系数上构造平衡校验以最大化每次查询的信息量。ML-KEM-768 在 95% oracle 准确率下仅需 2950 次查询，接近 Shannon 下界。"),
    "2026/472": (["ML-DSA", "泄漏", "局部优化"], 4, "—", "ML-DSA 少量泄漏签名",
                 "把 ML-DSA 子密钥恢复重构为约束满足问题，用局部优化（多层爬山）求解；只需 5000–35000 条 informative relation（比之前少 37–68×），并扩展到噪声模型（bit 错误率高达 45%）。"),
    "2026/528": (["Kyber", "掩码", "侧信道"], 3, "—", "一阶掩码 Kyber",
                 "对一阶掩码 Kyber 提出新区分器，联合多份不同密文解密请求的信息；在 SNR 0.67 的高噪声环境、75000 条 trace 下达到 95% 全密钥恢复成功率。"),
    "2026/580": (["ML-DSA", "单位泄漏", "噪声"], 4, "—", "ML-DSA 单位泄漏",
                 "用随机模型而非具体攻击分析 ML-DSA 的 bit 泄漏：给出成功恢复所需签名数的理论下界，并设计几乎达到该下界的攻击；bit 错误率高达 0.49、泄漏位索引低至 4/5 仍可用，无噪声时签名需求降到 1000 以下。"),
    "2026/582": (["NTRU", "冷启动", "位翻转"], 3, "—", "冷启动/部分系数泄漏 + 格",
                 "把冷启动攻击用于 Falcon 及其前身 DLP（NTRU 型 hash-and-sign 签名）：这些方案的签名私钥在内存中主要是浮点数，密钥系数间的关系只近似成立，恢复更复杂。在典型位翻转概率下，模拟可高概率恢复所有参数的 Falcon/DLP 密钥，并在 Raspberry Pi 上做了真实冷启动实验；同时给出低开销对策。"),
    "2026/820": (["Kyber", "CPA", "格嵌入"], 4, "lwe_bkz.sage",
                 "部分密钥 + Kannan/Bai-Galbraith 嵌入",
                 "改进掩码 Kyber 的相关功耗分析：不仅用恢复出的部分密钥，还利用每个系数的绝对值，采用 Kannan 与 Bai-Galbraith 结合的嵌入恢复符号与剩余部分。400 条 trace 即恢复全密钥（此前 7000 条），并可迁移到 SABER/Dilithium。"),
    "2026/981": (["ML-KEM", "SASCA", "侧信道"], 2, "—", "侧信道框架",
                 "提出首个无需模板设备的 ML-KEM SASCA 框架：通过选择密文控制 NTT 输入训练泄漏模型，再利用 NTT/INTT 相似性与对抗式无监督域适应微调，在真实嵌入式设备上以相近 trace 数恢复密钥。"),
    "2026/1344": (["ML-DSA", "HAETAE", "故障攻击"], 3, "—", "故障攻击",
                 "指出 challenge sampling 本身是可攻击面：对确定性 ML-DSA 与 HAETAE 注入单次故障即可恢复签名密钥并伪造，且 ML-DSA 攻击无需直接访问故障 challenge，仅用公开信息即可区分预期与非预期故障（识别率 100%）。"),
    "2026/1386": (["TALUS", "阈值签名", "线性恢复"], 4, "—", "协议实现缺陷→线性恢复",
                 "攻破 TALUS（阈值 ML-DSA）：Feldman commitment 用公开矩阵 A 左乘 secret 值，而 A 在 ML-DSA 各参数下左可逆，故可用高斯消元直接恢复 s1 与签名 nonce；去掉 rejection sampling 后 s2 用最小二乘从约 1e8 签名恢复。"),
    "2026/1448": (["Dilithium", "故障攻击", "MILP"], 3, "—", "随机化 Dilithium 的跳过故障",
                 "改进随机化 Dilithium 的 skipping fault correction 攻击：证明无需满秩收集，推导最小故障数 M_min 与依赖密钥的趋势，并把密钥恢复建模为 MILP；相比 Krahmer 等减少 13–26% 所需故障。"),
    "2026/1668": (["TALUS", "nonce 复用", "阈值"], 4, "—", "阈值签名 nonce 复用",
                 "对 TALUS-MPC v4 给出两转录攻击：协调者 + T-1 个恶意方复用同一 pooled nonce，用两个不同 challenge 的响应相减消去 nonce，在分圆域中直接恢复 s1；不需要任何 R_q 可逆假设。"),
    "2026/1682": (["ML-KEM", "FO 比较", "线性泄漏"], 4, "—", "实现缺陷→线性泄漏",
                 "发现 wolfSSL 手写 SIMD 的 FO 重加密比较只比较了部分密文字节（AVX2 1536/1568，NEON 约一半）。未比较的尾字节携带解密噪声的尾部，而噪声是密钥的精确线性函数；变化这些字节并观察解密输出即可逐坐标读出噪声，用最小二乘（无需格）恢复 98% 以上 ML-KEM-1024 密钥。"),
    "2026/1712": (["ML-DSA", "噪声估计", "泄漏"], 3, "—", "ML-DSA 泄漏预处理",
                 "利用 |z̃| 的两分量混合分布，给出 bit 错误率的矩估计与每条 relation 的后验正确概率，从而修正被翻转的泄漏；作为预处理使 Schubert 等攻击所需 relation 减少 20–44%，并改善低泄漏区间的可行性。"),
    "2026/1904": (["ML-DSA", "水平融合", "侧信道"], 4, "—", "ML-DSA 少 trace 侧信道",
                 "揭示 ML-DSA 矩阵-向量乘中 y 的行复用：单次签名泄漏 k 个同一秘密中间值、但系数已知的实例。提出基于方差的加权融合与 INTT 代数筛，非模板攻击仅 4 条 trace 恢复 ML-DSA-87，90 条 trace 破一阶掩码实现。"),
    "2026/2091": (["ILWE", "belief propagation", "ML-DSA"], 4, "—", "ILWE / 噪声泄漏",
                 "指出从侧信息导出 ILWE 样本时记录误差分布可大幅减少所需签名数：由 ILWE 样本导出 distribution hints，用 belief propagation 求解；无噪声下签名需求从 1.39e8 降到 2.25e6（62×），并分析 ML-DSA 的时序泄漏。"),
    "2026/2124": (["Falcon", "浮点泄漏", "LWE/NTRU 格"], 4, "—", "Falcon 侧信道 + LLL/BKZ",
                 "利用 Falcon 高斯采样器在 ⌊μ⌋ 整数转回浮点时的 signed-exponent 泄漏（把中心分成 17 个区间），用 CB-MLE 估计中心分类，再以 ISD 式搜索 + LLL/BKZ 在 NTRU 格上恢复密钥。Falcon-512 仅需 20 条（-O0）/56 条（-O3）签名即 100% 恢复。"),
    "2026/2258": (["Dilithium", "量子", "Fiat-Shamir"], 2, "—", "量子对抗模型",
                 "在允许量子资源与签名者交互的扩展量子模型（Q2）下，发展实现任意比特相对相位 oracle 的叠加攻击技术，利用输出仿射结构对多个格识别方案做全密钥恢复，并扩展到 Fiat-Shamir 签名。可攻破原始 CRYSTALS-Dilithium 及 NIST 第 1/2 轮提案，但 ML-DSA 最终版在标准过程中引入的修改阻止了该攻击。"),
    "2026/2448": (["Kyber", "掩码", "belief propagation"], 3, "—", "掩码 Kyber",
                 "用约 2200 条解封装功耗 trace、仅合法密文，恢复一阶掩码 Kyber768 的长期密钥：用带模板的神经网络估计两个算术 share 的 Hamming 重量分布，合成解密噪声的似然，再用带 Onsager 修正的 belief propagation 累积；无需格归约即恢复全部 1536 个 secret/error 系数。2000 trace 下 BP hint 只把 BKZ block size 从 624 降到 505，格攻击仍不可行。"),
    "2026/2567": (["ML-DSA", "rejection sampling", "故障"], 4, "—", "故障攻击与对策评估",
                 "系统评估 ML-DSA rejection sampling 的故障攻击：证明某专利第三检查只是重复 check 2 已保证的条件，六个实施例退化为两个独立条件；3 万次故障注入显示对跳过 z-范数检查的检出率为 0，并据此在“受第三检查保护”的实现上完整恢复 s1。"),
    "2026/2643": (["ML-DSA", "单 trace", "GMM"], 3, "—", "单 trace 侧信道",
                 "提出非模板单 trace 攻击：用高斯混合模型比较观测样本分布与预期 Hamming 重量泄漏分布，横向堆叠 trace 获得多次观测，并用信息集解码纠正错误分类；ML-DSA-65 在 ARM Cortex-M4 上以 99% 成功率从单条 trace 恢复全密钥。"),
    "2026/2069": (["Kyber", "故障", "FO 比较"], 4, "—", "故障攻击",
                 "暴露 Kyber-KEM FO 比较流水线中被忽视的 Booleanisation 阶段：一次 clock glitch 可令 mismatch flag 为 0，使解封装接受任意密文。该故障位于 default-fail cmov 的上游，绕过 Xagawa 对策；在 pqm4/PQClean/参考实现上均成功，并用明文检查 oracle 单次运行恢复 Kyber-512/768/1024 全密钥。"),
    "2026/2137": (["ML-KEM", "单 trace", "密钥生成"], 3, "—", "单 trace 侧信道",
                 "指出 ML-KEM 密钥生成的 CBD 采样与随后 NTT 泄漏互补信息：CBD 把系数存为 16-bit 补码，几乎无误差地泄漏符号；NTT 与公开 twiddle 相乘则泄漏幅度。把二者作为 hint 做 primal 格攻击，ML-KEM-768 的估计 BKZ block size 从 624 降到 129（core-SVP 2^182.2→2^37.7）。作者同时给出 CBD 内的 q-randomization 对策，把 block size 拉回 611。"),
    "2026/2211": (["Polar-KEM", "同构", "结构攻击"], 3, "—", "LIP/构造缺陷",
                 "对 Polar-KEM 做结构分析：其密钥生成从公开参数确定 frozen set → 极码链 → Construction-D 基 → 公开 LLL 归约，敌手可复现同一 reduced basis；若公钥 B_pk=O·B_red，则秘密正交矩阵直接由 O=B_pk·B_red^{-1} 线性代数恢复，无需解 SVP 或一般 LIP。作者还指出 erasure 参数未指定，不能作为秘密熵来修复。"),

    # ---------------- sis-lip-ideal ----------------
    "2026/699": (["HAWK", "侧信道", "LIP"], 4, "—", "HAWK + LIP hint",
                 "把 HAWK 签名采样器的物理泄漏形式化为 HAWK with Hint，研究全系数、精确符号与带噪符号泄漏，结合公开签名信息与 HAWK 的 Gram 矩阵结构给出多项式时间恢复算法，说明无需完整恢复采样器输出即可恢复密钥。HAWK-1024：全系数泄漏单条签名即可；参考实现 14 条 trace 提取全部 28672 个符号、约 157 秒恢复；10% 符号错误需 420 条、40% 需 13397 条。"),
    "2026/722": (["LIP", "blind signature", "双 LIP"], 3, "—", "LIP 协议缺陷",
                 "分析基于 LIP 的盲签名：证明 Abe–Okamoto 框架在 LIP 下不能得到安全实例，并给出对 double-LIP 的攻击——从两个一般 LIP 实例恢复秘密幺模矩阵。最后提出结合 LIP、CVP 与模 SIS 的新盲签名构造。"),
    "2026/890": (["LIP", "DEFI", "二次型"], 4, "—", "LIP 签名密钥恢复",
                 "结合二次型算术与算法，攻击基于各向同性二次型的 DEFIv2 签名：证明在若干假设下 genus、spinor genus 与等价类重合，从而对 Decision/Distinguishing-LIP 有多项式时间算法，并在作者公开挑战上分钟级伪造签名；对 HAWK 无效。"),
    "2026/1298": (["HAWK", "弱密钥", "BUFF"], 3, "—", "弱公钥/校验缺失",
                 "反驳 HAWK 规范“天然满足 BUFF”的声明：参考验证器几乎不检查公钥，构造退化弱公钥可使全零签名对几乎所有 challenge 通过，从而破坏 message-bound signatures、exclusive ownership 与非重签名性。"),
    "2026/1318": (["HAWK", "module-LIP", "nrdPIP"], 3, "—", "HAWK 启发式攻击",
                 "给出恢复 HAWK 私钥的经典算法：把 rank-2 module-LIP 归约到 O-nrdPIP，用随机下三角幺模矩阵共轭公钥 Gram 矩阵并重采样直到出现可用 Lenstra–Silverberg 子域求解的实例。后续作者承认其中启发式不足以支撑多项式时间。"),
    "2026/1377": (["HAWK", "复杂度"], 2, "—", "HAWK 攻击可行性",
                 "实现并实验“Guessing Game”攻击，指出其运行时间远高于声称的多项式时间，存在超多项式的类数障碍，并给出机器检验的条件归约；结论是该攻击当前不威胁 HAWK。"),
    "2026/1349": (["SIS", "Large Norm", "Falcon", "Dilithium"], 4, "—", "小模数 SIS/伪造",
                 "改进 Ducas–Espitau–Postlethwaite 的 Large Norm 攻击成本模型（计入筛法长度分布、用联合概率），使 Falcon-256 成本降低约 11×；并提出闭式 ℓ∞ 变体（Z-shape 攻击）攻击小到中等模数的 Dilithium 型 ISIS^∞，三种预设均 ≤1.6 秒。"),
    "2026/1554": (["Vandermonde Knapsack", "vSIS", "环"], 3, "—", "代数 knapsack",
                 "研究 Vandermonde Knapsack 家族（含 PV Knapsack 与 vSIS commitment）：对二次分圆环给出新攻击，结合 Das–Joux 攻击证明比已知更大比例的密钥是弱密钥，并扩展到整数版 vSIS 的特定参数区间。"),
    "2026/1560": (["HAWK", "SVP", "trace-zero"], 3, "—", "HAWK/理想格降维",
                 "利用 trace-zero 方法，把 O_E 上的 rank-2 module-LIP 多项式时间归约到 O_K 上的 rank-3 module-LIP；对 HAWK 的 O_E^2 得到维数至多 3m/8+1 的精确 SVP 调用即可破密钥恢复（此前为 m/2+1）。"),
    "2026/1593": (["HAWK", "SVP", "密钥恢复"], 4, "—", "HAWK 归约到 SVP",
                 "给出无条件确定性多项式时间归约：HAWK-n 密钥恢复可归约为维数 n/2+1 的精确 SVP 调用，利用 Galois 对合 τ:ζ↦−ζ 提供的密钥格自同构。门计数模型下 HAWK-512 从 2^150 降到 2^108、HAWK-1024 从 2^288 降到 2^182，并端到端恢复 HAWK-256；对 conductor 为 p^k/2p^k 的参数无效。"),
    "2026/1705": (["AJPS", "NTRU", "Mersenne"], 3, "—", "NTRU 变体",
                 "重新分析基于 Mersenne 数的 AJPS 密码系统，用连分数与模多项式方程的格求解（而非直接格归约）放宽未知私钥的尺寸约束，扩大弱密钥攻击范围并提高非平衡参数下的成功率。"),
    "2026/1755": (["四元数", "LLL/BKZ", "module-LIP"], 3, "—", "HAWK/nrd-PIP",
                 "给出首个用于密码场景的四元数环格归约算法与四元数 BKZ：扩展到非极大序上的 LLL（先在 Euclidean overlattice 上归约再后处理），并应用于 nrd-PIP/module-LIP 的理想格，维数比标准实嵌入小 4×。"),
    "2026/2042": (["Ideal-SVP", "Ideal-BDD", "群表示"], 3, "—", "理想格降维",
                 "用群表示论解 Ideal-uSVP 与 Ideal-BDD：对 Galois 群已知的 abelian 扩张，用稳定子群 H 的不可约表示构造投影算子，把理想分解为低维格并分别求解再组合。首次把群表示直接用于格密码分析，并可处理 BDD。"),
    "2026/2083": (["SIS", "LtHash", "碰撞"], 4, "—", "SIS/LtHash 碰撞",
                 "改进 Regev–CLZ 的三元 SIS mod 2^d 算法：每层消去两个模数 bit 而保持三元系数，把 LtHash 碰撞所需查询从 O(N^d) 降到 O(N^{ceil(d/2)})。对 Facebook/Solana 使用的 LtHash16 (N,d)=(1024,16) 约需 2^81 次查询、≤2^101 次 F2 运算，远低于宣称的 200-bit 安全。"),
    "2026/2198": (["module-LIP", "降维", "rank 4"], 3, "—", "HAWK/module-LIP",
                 "用对称平方与 Hodge star 对 module-LIP 做降维：rank-2 复现 3n/4+1 的界，rank-4 则用外平方上的共轭 Hodge star 公开构造等距于 Z^{3n} 的格，把 4n 维问题降到至多 3n/2+1 维 SVP 调用（通用界为 2n+1）。"),
    "2026/2225": (["knapsack", "LLL", "密钥恢复"], 4, "lwe_bkz.sage",
                  "knapsack 公钥秒破",
                  "攻破 GTLN 的 knapsack McEliece 型公钥：利用系数和为 0 的公开项组合消去掩码，若该组合与公钥正交且足够短，则其坐标可被私钥整数整除；模数造成的范数间隙使 LLL 可恢复这些短向量，再用 gcd 恢复私钥。Sage 实现在 3 秒内破全部 24 组参数。"),
    "2026/2281": (["LIP", "direct sum", "Barnes-Wall"], 3, "—", "LIP 降维",
                 "分析 Ducas–van Woerden 框架在两个缩放 Barnes-Wall 格直和上的实例：g^2-hull 可由公钥计算，把两类格互相映射并把问题拆成半维 Barnes-Wall 格的同构问题。d=1024,g=43 时密钥恢复成本从 220 降到 124 bit。"),
    "2026/2325": (["LIP", "Construction A", "hull"], 3, "—", "LIP",
                 "把 Ducas–Gibbons 的方法推广到 hull 维数任意的 Construction A 格：给出解 LIP 的算法，运行时间 2^O(n)，成功概率 1+o(1)（对随机码），突破了原方法只支持平凡 hull 的限制。"),
    "2026/2381": (["LIP", "hints", "HAWK"], 4, "—", "LIP + 侧信道 hint",
                 "研究带部分信息的 LIP：把 LIP 嵌入到与 HAWK 规范不同的 SVP 格以容纳 hint，并给出把任意线性组合上的泄漏转换为目标格 hint 的技术。用 LeakyLWEEstimator 估计 HAWK 密钥恢复安全，指出签名本身携带密钥信息，HAWK-1024 约损失 11 bit。"),
    "2026/2420": (["Module-SIS", "Module-LWE", "次指数"], 2, "—", "参数评估",
                 "把 Ducas–Engelberts–Loyer 的 Wagner 型可证明次指数算法推广到二次分圆环上的 module 矩阵（任意剩余次数），给出 Module-SIS 与 decision/search Module-LWE 的次指数时间；并证明保样本的 scalar search-LWE 与 narrow Module-LWE 算法。"),
    "2026/2527": (["NTRU+", "module-BKZ", "参数评估"], 3, "—", "NTRU+/module 攻击",
                 "分析 module-BKZ 对 NTRU+（韩国 KEM 标准）的实际威胁：引入相对 canonical/系数嵌入，刻画不同子域下嵌入何时一致（rad(c)/rad(ℓ)∈{1,2}），指出短向量在系数几何中短而 module-BKZ 在 canonical 几何中工作。结论是最佳攻击仅省 4–10 个 blocksize，NTRU+ 最多损失 3 bit。"),
    "2026/2543": (["knapsack", "连分数", "密钥恢复"], 4, "—", "knapsack 公钥秒破",
                 "对 GTLN knapsack 公钥给出连分数攻击：公钥差值之比逼近小分母有理数，可精确恢复；整除关系经 gcd 得到两个私钥整数的倍数，再用有界余因子搜索与模逆恢复模数与 shift。2400 次试验全部成功，每次 <0.05 秒。"),
    "2026/1642": (["NTC", "NTRU 推广", "构造+分析"], 2, "—", "NTRU 变体识别",
                 "提出 NTC（Noisy Torus Conjugation）假设：短 secret 限制在非分裂极大环面中，通过共轭作用于均匀矩阵并加短误差，NTRU 是其 k=1 特例。含结构理论、search-to-decision 归约与格攻击分析，并给出紧凑 KEM；属构造+分析，CTF 中用于识别新型 NTRU 变体。"),

    # ---------------- coppersmith-rsa ----------------
    "2026/244": (["Coppersmith", "Unravelled Linearization", "Ehrhart"], 4, "coppersmith_multi.sage",
                 "多元 Coppersmith 参数/界",
                 "用 Ehrhart 理论严格分析 Coppersmith + Unravelled Linearization 的格构造：指出以往用 Lagrange 插值、假设格维数是 m 的多项式并不总成立（可能是拟多项式），并给出 DimOracle 同时估计格维数与行列式。作为应用改进五个结果（LCG、二次生成器、子集和 PRG、POKE 同源的部分密钥攻击等），把 POKE 所需 MSB 泄漏从 85.29% 降到 79.81%（特殊情形 79.08%）。"),
    "2026/519": (["RSA 变体", "cubic Pell", "部分暴露"], 4, "coppersmith_multi.sage",
                 "RSA 变体 + 已知部分 p/q 位",
                 "针对 Nitaj–Seck 基于 cubic Pell 方程的 RSA 变体（N=p^r q^s），在已知 p 或 q 的部分比特时，对密钥方程 eu0-(p-1)^2(q-1)^2 v0=w0 给出推广的部分暴露格攻击，扩展了 Rahmani–Nitaj 仅 r=s=1 的结果。"),
    "2026/1027": (["Automated Coppersmith", "线性规划", "EC-HNP"], 5, "coppersmith_multi.sage / ec_hnp.sage",
                  "判断 Coppersmith 参数是否可行",
                  "把 Meers–Nowakowski 的 Automated Coppersmith 渐近界计算转化为线性规划，得到可证明正确且显式可算的公式；应用于 Commutative Isogeny HNP、MIHNP、EC-HNP、未知乘子 LCG、POKE 的 Leveled Isogeny Problem 等五个场景，改进其界。是判断“题目参数能否用 Coppersmith 打”的核心工具。"),
    "2026/1137": (["RSA 变体", "综述", "格攻击"], 3, "coppersmith_multi.sage",
                  "RSA 变体综述",
                  "综述 Gaussian 整数模 N=pq 与 cubic Pell 两类 RSA 变体的格攻击：先给出多项式时间求解 xH(y)+cz≡0 mod β（H 为首一多项式）的一般方法并推广已有界，再应用于两类方案在部分密钥信息等场景下的分解。"),
    "2026/1295": (["RSA", "小 d", "部分 p+q", "连分数"], 4, "boneh_durfee.sage",
                  "Wiener 变体 + 部分信息",
                  "给出 Wiener 连分数攻击的简单修改：当已知 p+q 的 δ 比例最高位时，可在 d<n^{(1+δ)/2} 时分解 n，且该算法无条件（不依赖 Coppersmith）。示例可破 512-bit 模数、d<n^{0.3}。"),
    "2026/1357": (["RSA 变体", "cubic Pell", "格攻击"], 3, "coppersmith_multi.sage",
                  "RSA 变体超界",
                  "针对 Cotan–Teșeleanu 的广义 cubic Pell RSA（ed-1≡0 mod ψ_n(N)），给出格技术恢复私钥，可超过此前 N^{0.292(n-1)} 的界，条件是 p、q 共享足够多的最低位。"),
    "2026/1529": (["RSA 变体", "广义 Wiener", "Coppersmith"], 3, "boneh_durfee.sage",
                  "非平衡模数的广义 Wiener",
                  "把两个 RSA-like 密钥方程（(p^4-1)(q^4-1) 与 (p-1)^2(q-1)^2）的攻击从平衡模数推广到任意素数 p,q 的 N=pq；结合 Coppersmith 与连分数，在 x,y,ω 满足一定条件时分解 N。"),
    "2026/1908": (["RSA 变体", "广义 Wiener", "连分数+格"], 3, "boneh_durfee.sage",
                  "n=2^i 的广义 Wiener",
                  "对 Cotan–Teșeleanu 的 ed-k(p^n-1)(q^n-1)=1（n=2^i, i>2）结合连分数与格方法给出新攻击，延续此前 n=1,2,4 的结果。"),
    "2026/1969": (["Dixon resultant", "多元多项式", "Gröbner"], 3, "coppersmith_multi.sage",
                  "多元多项式系统求解",
                  "重新审视 Dixon resultant 作为同时消去多个变量的工具：用格路径计数给出 Dixon 矩阵规模上界与复杂度估计，并给出开源 C 实现 DRSolve。在低变量/高次数场景优于 Magma/msolve，适合欠定系统的参数消元。"),
    "2026/2109": (["CRT-RSA", "小 dp/dq", "Unravelled Linearization", "MSB 泄漏"], 5, "coppersmith_multi.sage",
                  "CRT-RSA 小 dp/部分位（核心）",
                  "用 unravelled linearization 给出平衡 CRT-RSA 小 dp,dq 的新 Coppersmith 格攻击：实际效果与 Takayasu–Lu–Peng 相当，但格维数约为其一半，理论估计与实验更吻合；并扩展到 p+q 与 dp,dq 的 MSB 泄漏模型（p+q MSB 泄漏为首个此类攻击）。"),
    "2026/2620": (["EC 半素性证书", "分解", "CM"], 3, "—", "RSA/EC 证书侧信道",
                 "形式化 Goldwasser–Kilian 型椭圆曲线半素性证书：对 CM 构造的证书，仅凭 (N,S,D) 即可用 norm-lattice 重构在期望多项式时间分解 N（当 Frobenius 落在已知虚二次域或迹为零）。据此分解 Reble 的 1084 位与 Broadhurst 的 5061 位模数。"),

    # ---------------- hnp-signatures ----------------
    "2026/423": (["HNP", "MIHNP", "Coppersmith", "ICG"], 5, "coppersmith_multi.sage / hnp_ecdsa.py",
                 "模逆 HNP / ICG 预测",
                 "提出基于行列式消元的 shift 多项式选取策略，改进多元模方程的 Coppersmith 方法；在 MIHNP 与 Inversive Congruential Generator 预测上理论上和实践上均优于先前方法，并证明 MIDHNP 不比 MIHNP 难，推翻 Boneh 等（Asiacrypt 2001）的猜想。"),
    "2026/1366": (["签名泄漏", "半空间学习", "HAWK/Falcon/ML-DSA"], 4, "hnp_ecdsa.py",
                  "签名随机数的符号/Hamming 重量泄漏",
                  "证明对 HAWK、Falcon、ML-DSA，即使只泄漏随机数某个坐标的 Hamming 重量或单个 bit，也能推断该坐标符号；把密钥恢复建模为 Learning a Halfspace。HAWK 128-bit 下 30 条签名 10 分钟恢复，Falcon 100 条不到 1 分钟（比已有攻击少 250×），ML-DSA 19 万条秒级恢复，且可抗 30%–35% 噪声。"),
    "2026/1808": (["SDitH", "code-based", "PRG 复用"], 3, "—", "code-based 签名实现缺陷",
                 "对 SDitH v2 给出跨签名签名密钥恢复：VOLEitH PRG 以 AES/Rijndael 计数器模式从零开始，导致每条签名/每个 leaf 使用相同输入，一次加密即可测试候选 seed；结合 RSD 约束过滤假候选，找到 seed 即得长期 witness。q=2^12 次选择消息签名比 AES-128/192/256 暴力搜索便宜 11.23–11.67 bit。"),
    "2026/2566": (["阈值签名", "故障", "nonce 重放", "ML-DSA"], 4, "—", "阈值 ML-DSA 故障",
                 "证明阈值格签名的物理故障可导致跨会话 nonce 重放：单方 RNG 状态回滚即可泄漏其 share，t-of-n 中只需故障 t 台设备即可恢复完整签名密钥，且每条签名单独看都合法。在 Mithril 上端到端验证（96/96 精确恢复，无需格归约），并给出 reveal-structure 判据与检测边界。"),

    # ---------------- ecc-pairing-isogeny ----------------
    "2026/1002": (["POKE", "isogeny PKE", "弱密钥"], 3, "—", "isogeny 弱密钥",
                 "研究 POKE（基于同源的 PKE）的安全性：指出其存在弱密钥可降低某些攻击复杂度；POKE-2D 因弱密钥概率极低而不受影响，但 POKE-4D 受威胁，需修改参数（修改后性能优势消失）。"),
    "2026/1486": (["supersingular isogeny", "复杂度"], 3, "—", "isogeny 参数评估",
                 "在关于随机整数光滑性的合理启发式假设下，证明超奇异同源问题可在时间与内存 p^{1/3+o(1)} 内求解，改进此前 p^{1/2+o(1)}；但 o(1) 中的超多项式开销与高内存使具体参数影响尚不明确。"),
    "2026/1575": (["supersingular isogeny", "双变量多点求值"], 3, "—", "isogeny",
                 "给出超奇异同源问题的无条件攻击，时间与内存 p^{2/5+o(1)}，基于 Kedlaya–Umans 等高度理论化的多元多点求值算法；与 Wesolowski 的 p^{1/3+o(1)} 启发式攻击同属“寻找曲线到其 Galois 共轭的可分同源以构造非标量自同态”的路线。作者明确说明该结果只有理论意义，不威胁实际同源密码系统。"),
    "2026/1623": (["isogeny VRF", "radical-CGL", "密钥恢复"], 4, "—", "isogeny VRF",
                 "对 Asiacrypt 2025 的 radical-CGL 同源 VRF 给出三阶段攻击：先利用公钥只存 j-invariant 而计算用两系数表示的差异破坏唯一可验证性，再利用这些系数在 1536 次查询、30 分钟内恢复 256-bit 密钥；并对同文的 group-action VRF 给出单查询攻击。"),
    "2026/1776": (["SNARK", "ECC", "cofactor", "hinted scalar mult"], 4, "—", "SNARK 曲线 gadget",
                 "指出 Eagen 等（Latincrypt 2025）的 hinted scalar multiplication 系列依赖“素数阶”隐含假设：认证恒等式在完整 E(F_p) 上检查，只有 cofactor 为 1 时才强制 Q 落入素阶子群。在 cofactor 曲线上给出两类伪造（any-scalar 与 chosen-scalar），可让 gadget 接受 Q'=[k]P+T；已在 BLS12-381/BN254/BW6-761 上验证。"),
    "2026/1823": (["Delfs-Galbraith", "isogeny ladder", "SQIsign"], 3, "—", "isogeny",
                 "给出 Delfs–Galbraith 算法的无内存新变体，用 isogeny ladder 寻找从任意超奇异曲线到已知自同态环曲线的同源路径，进而解超奇异自同态环问题。任意特征下渐近优于此前最好变体一个对数因子，具体成本也更低；100-bit 实例 <100 GPU 小时，影响 SQIsign 等参数估计。"),
    "2026/2560": (["多用户", "碰撞攻击", "ECDLP", "isogeny"], 3, "—", "多用户 ECDLP/isogeny",
                 "研究椭圆曲线与同源问题在多用户场景下的碰撞攻击：综述 van Oorschot–Wiener 型攻击，提出更适合无限制同源路径问题的伪随机游走，并分析同时恢复 L 个公钥所需的碰撞数；例如 F_{p^2} 超奇异同源约需 L+log L 次碰撞且无需 infiltrator。"),
}

DIRS_ORDER = ["lattice-lwe-hints", "pqc-implementation", "sis-lip-ideal",
              "coppersmith-rsa", "hnp-signatures", "ecc-pairing-isogeny"]


def main():
    data = json.load(open(os.path.join(RES, "selected_full.json"), encoding="utf-8"))
    records = []
    for rec in data:
        pid = rec["id"]
        if pid not in INFO:
            print("WARN no summary for", pid)
            continue
        tags, rating, mapped, note, summary = INFO[pid]
        records.append({
            "id": pid,
            "title": rec["title"],
            "authors": rec["authors"],
            "date": rec["date"],
            "direction": rec["direction"],
            "tags": tags,
            "summary": summary,
            "ctf_relevance": rating,
            "ctf_note": note,
            "mapped": mapped,
            "url": rec["url"],
        })
    records.sort(key=lambda r: (DIRS_ORDER.index(r["direction"]),
                                -int(r["id"].split("/")[1])))
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "papers.json"), "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)

    # ---- index.md ----
    lines = [
        "# 2026 年密码分析论文选题库（精选）",
        "",
        "> 收录范围：2026-01-01 — 2026-10-28；仅攻击 / 密码分析类；共 %d 篇。" % len(records),
        "> 生成脚本：`scripts/papers/build_assets.py`（数据源 `papers.json`）。",
        "> 评级：5 = 直接可出 CTF 题 / 核心方法；1 = 背景参考。",
        "",
        "| 方向 | 篇数 | 文件 |",
        "|---|---|---|",
    ]
    for d in DIRS_ORDER:
        n = sum(1 for r in records if r["direction"] == d)
        lines.append("| %s | %d | [%s](%s) |" % (DIRS[d]["title"], n, d + ".md", d + ".md"))
    lines.append("")
    for d in DIRS_ORDER:
        items = [r for r in records if r["direction"] == d]
        lines.append("## %s（%d 篇）" % (DIRS[d]["title"], len(items)))
        lines.append("")
        lines.append(DIRS[d]["desc"])
        lines.append("")
        for r in sorted(items, key=lambda x: -int(x["id"].split("/")[1])):
            stars = "★" * r["ctf_relevance"]
            lines.append("- **%s** (%s) [%s](%s) — %s | `%s`"
                         % (r["id"], r["date"], r["title"], r["url"], stars, r["ctf_note"]))
        lines.append("")
    open(os.path.join(OUT_DIR, "index.md"), "w", encoding="utf-8").write("\n".join(lines))

    # ---- per-direction md ----
    for d in DIRS_ORDER:
        items = [r for r in records if r["direction"] == d]
        out = ["# %s（%d 篇）" % (DIRS[d]["title"], len(items)), "",
               DIRS[d]["desc"], "",
               "| ID | 日期 | 标题 | 标签 | 评级 | 简述 | 对应模板/工具 |",
               "|---|---|---|---|---|---|---|"]
        for r in sorted(items, key=lambda x: -int(x["id"].split("/")[1])):
            out.append("| [%s](%s) | %s | %s | %s | %d | %s | `%s` |"
                       % (r["id"], r["url"], r["date"], r["title"],
                          ", ".join(r["tags"]), r["ctf_relevance"],
                          r["summary"], r["mapped"]))
        out.append("")
        open(os.path.join(OUT_DIR, d + ".md"), "w", encoding="utf-8").write("\n".join(out))

    # ---- paper-map.md: challenge-signal -> paper -> template ----
    lines = [
        "# 论文 ↔ 题型映射表（2026 精选）",
        "",
        "> 由 `papers.json` 自动生成（`build_assets.py`）。按题面信号组织：",
        "> 看到这些特征，先查速查表定位方向，再按 ID 回查对应方向 md 里的完整简述。",
        "",
        "## 题面信号 → 方向速查",
        "",
        "| 题面信号 | 方向 | 代表论文 |",
        "|---|---|---|",
        "| 给 LWE/MLWE + 泄漏位、模 q hint、已知错误、FHE 稀疏参数 | `lattice-lwe-hints` | 2026/2654, 2026/1081, 2026/366 |",
        "| 出现 ML-KEM/ML-DSA/NTRU/Falcon/HAWK 实现 + trace/故障/oracle | `pqc-implementation` | 2026/1904, 2026/070, 2026/2124 |",
        "| HAWK / LIP / 理想格 / SIS / knapsack / NTRU 变体 | `sis-lip-ideal` | 2026/1593, 2026/2083, 2026/2225 |",
        "| 部分 p/q/dp/dq、CRT-RSA 小指数、RSA 变体、广义 Wiener | `coppersmith-rsa` | 2026/2109, 2026/1027, 2026/1529 |",
        "| 签名偏置/泄漏 nonce、截断 PRNG、模逆 HNP、阈值签名 | `hnp-signatures` | 2026/423, 2026/1366, 2026/2566 |",
        "| 超奇异曲线 / 配对 / 同源 / SNARK 曲线 gadget | `ecc-pairing-isogeny` | 2026/1823, 2026/1776, 2026/1623 |",
        "",
    ]
    for d in DIRS_ORDER:
        items = [r for r in records if r["direction"] == d]
        lines.append("## %s" % DIRS[d]["title"])
        lines.append("")
        lines.append("| ID | 题面特征 | 标签 | 对应模板/工具 |")
        lines.append("|---|---|---|---|")
        for r in sorted(items, key=lambda x: -int(x["id"].split("/")[1])):
            lines.append("| [%s](%s) | %s | %s | `%s` |"
                         % (r["id"], r["url"], r["ctf_note"],
                            ", ".join(r["tags"]), r["mapped"]))
        lines.append("")
    open(os.path.join(OUT_DIR, "paper-map.md"), "w", encoding="utf-8").write("\n".join(lines))

    print("wrote %d records to %s" % (len(records), OUT_DIR))


if __name__ == "__main__":
    main()
