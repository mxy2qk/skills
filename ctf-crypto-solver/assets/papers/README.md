# 2026 年密码分析论文选题库

面向 CTF 出题/解题的精选论文库。收录 **2026-01-01 — 2026-10-28** 的 IACR ePrint
攻击/密码分析类论文，按方向分类并附中文简述、出题评级与可对应模板。

## 内容

| 文件 | 说明 |
|---|---|
| `index.md` | 总索引：按方向分组，每篇一行（ID/日期/标题/评级/题型） |
| `papers.json` | 结构化主数据，供脚本检索 |
| `<direction>.md` | 分方向清单，含完整中文简述与标签 |
| `../scripts/papers/search.py` | 检索脚本 |

六个方向：

- `lattice-lwe-hints` — LWE/MLWE、hint、稀疏 secret、dual/hybrid
- `pqc-implementation` — ML-KEM/ML-DSA/NTRU/Falcon 的侧信道与故障
- `sis-lip-ideal` — SIS、理想格、LIP、HAWK、knapsack/NTRU 变体
- `coppersmith-rsa` — Coppersmith、RSA 变体、部分密钥暴露
- `hnp-signatures` — HNP、签名 nonce/随机数泄漏
- `ecc-pairing-isogeny` — ECC、配对、同源、SNARK 曲线 gadget

## 字段

`papers.json` 每条记录：

| 字段 | 含义 |
|---|---|
| `id` | ePrint 编号，如 `2026/2654` |
| `title` / `authors` / `date` | 元数据 |
| `direction` | 六个方向之一 |
| `tags` | 关键词 |
| `summary` | 中文简述（问题、方法、结果、可出题性） |
| `ctf_relevance` | 1–5；5 = 直接可出题/核心方法 |
| `ctf_note` | 一句话题型提示 |
| `mapped` | 对应模板或工具 |
| `url` | ePrint 链接 |

## 检索

```bash
PY=/c/code/miniconda/python.exe

# 按关键词（标题/简述/标签）
"$PY" ../scripts/papers/search.py hint
"$PY" ../scripts/papers/search.py --direction lattice-lwe-hints
"$PY" ../scripts/papers/search.py --min-rating 4 --tag Coppersmith
```

## 更新

1. 在 workspace 的 `research/` 下运行抓取脚本（见 `scripts/papers/README.md`）。
2. 修改 `build_assets.py` 中的 `INFO`（中文简述）与 `DIRS`（分类）。
3. 重新生成：`python build_assets.py`。

## 说明

- 只收攻击/密码分析类；协议、构造、FHE/ZK 等仅在与攻击直接相关时收录。
- 评级与简述是面向 CTF 的主观判断，不替代原文。
- 本库随 skill 分发，体积极小（纯文本）；全量抓取缓存留在 workspace。
