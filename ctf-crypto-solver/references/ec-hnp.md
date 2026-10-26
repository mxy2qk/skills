# EC-HNP — Elliptic-Curve Hidden Number Problem

Use this when a service or ciphertext leaks **most significant bits (or LSBs) of
the x-coordinate of `a·P`** for points `P` you can choose, and the secret is the
x-coordinate of a shared point `a·B` (ECDH-style). Typical CTF origin: the
`babyDH2` family (AliyunCTF 2024) and its harder sequels.

Not to be confused with **ECDSA nonce HNP** (`references/ecc.md`, template
`hnp_ecdsa.py`): there the unknown is a scalar with linear leak equations. Here
the unknown is a *point's x-coordinate* and the equations are quadratic.

## 0. Feasibility check BEFORE writing code

The published attack is the lattice `L(n,d,t)` of

> J. Xu, S. Sarkar, H. Wang, L. Hu, *Improving Bounds on Elliptic Curve Hidden
> Number Problem for ECDH Key Exchange*, Asiacrypt 2022, **eprint 2022/1239**.

Its cost and success depend on three numbers, so write them down first:

* `pbits` = bit length of the field prime;
* `K` = number of **unknown** low bits per leak (`known = pbits - K`);
* `n` = number of **pairs** = `(queries - 1) / 2` (the oracle needs `0` and `±m`).

Dimension and stored memory:

```
w = dim(n,d,t) = (t+1)·C(n,d+1) + 2d·Σ_{l=0..d} C(n,l)
flatter time  ~ O(w^3)   (with the entry bit-size as a factor)
flatter RSS   ~ O(w^2)   (measured: 906 -> 3.8 GB, 1158 -> 6.35 GB)
```

The number of samples is the binding constraint: for fixed `n`, increasing `d`
does **not** buy much more unknown-bit tolerance. Rule of thumb from the
paper's tables / the determinant condition: with `n≈9`, the reachable unknown
bound is `X ≈ 2^209..2^215` depending on `d,t`. For `K = 235` on a 521-bit
curve (`δ = K/pbits = 0.451`) that is ~20+ bits short regardless of `d`.

If your parameters are outside the reachable box, **stop here** and look for a
different weakness (more queries, a second oracle, a protocol bug) — do not
spend hours on LLL runs that cannot certify.

Quick anchors (521-bit curve, n=9): `d=2,t=0 -> 268`, `d=2,t=1 -> 352`,
`d=3,t=0 -> 906`, `d=3,t=2 -> 1158`, `d=4,t=0 -> 2174`.

If the service enforces a timeout (common: `signal.alarm(600)` from connect),
the whole collect + reduce + solve + reply must fit. Sage's LLL is 20-50x
slower than flatter; at `w ≈ 900` flatter already needs tens of minutes on a
laptop-grade machine. Dimensions above ~600-800 are usually incompatible with
a 600 s service budget.

## 1. The math in one page

Oracle model: `O_{P,R}(m) = MSB(x(P + m·R))`, `R` a known point, `P` hidden.
`2n+1` calls: `m = 0, ±1, …, ±n`.

For ECDH, with `A = a·G`, `B = b·G`, `S = a·B`, query `P_m = B + m·G`;
then `a·P_m = S + m·A`, so the oracle leaks `x(S + mA)`.

Pairing `m` with `-m` eliminates `y(S)` (addition formula, paper eq. (7)):

```
x(S+iA) + x(S-iA) = 2·(x_Q·x_S² + (a+x_Q²)·x_S + a·x_Q + 2b) / (x_S - x_Q)²,
Q = i·A, x_Q = x(Q).
```

Let `x_S = h0 + x0` (`h0 = leak_0 << K`, `x0 < 2^K`),
`x(S+iA) = h_i + e_i` with `e_i < 2^K`.  For each `i`:

```
F_i(x0, y_i) = A_i + B_i·x0 + C_i·x0² + D_i·y_i + E_i·x0·y_i + x0²·y_i ≡ 0 (mod p)
y_i = e_i + e_{-i} < 2^(K+1)
A_i = H_i(h0-Qx_i)² - 2h0²Qx_i - 2(a+Qx_i²)h0 - 2aQx_i - 4b
B_i = 2(H_i(h0-Qx_i) - 2h0Qx_i - a - Qx_i²)
C_i = H_i - 2Qx_i
D_i = (h0-Qx_i)²
E_i = 2(h0-Qx_i)
H_i = (leak_i + leak_{-i}) << K,  Qx_i = x(i·A)
```

This is exactly the `Coe` function in the public reference solution
(`DH2.sage`) and in `scripts/templates/ec_hnp.sage`.

Lattice `L(n,d,t)` (paper § 4.1). Index sets, with `l = i1+…+in`:

```
I1 = { 0 <= i0 <= 2d-1, i1..in in {0,1}, 0 <= l <= d }
I2 = { 0 <= i0 <= t,     i1..in in {0,1}, l = d+1 }
```

Case A shifts are `p^(d+1-l)·x0^i0·y^e`, `p^(d-l)·x0^(i0-2l)·ΠF`, and the
`i0 <= 2l-1` branch uses the inverse `W` of the 2l x 2l matrix built from the
quadratics `x0² + E_j x0 + D_j` (the “Case B” linear combinations). Case I2
uses `H+J+K mod p^d`. The basis is triangular with diagonal
`p^(d+1-l)X^(i0+l)`, `p^(d-l)X^(i0+l)`, `X^(i0+d+1)`.

Coppersmith condition (paper Lemma 1/2, eq. (4)) for the first `n+1` reduced
vectors:

```
2^((w-1)/(4(w-n))) · det(L)^(1/(w-n)) · sqrt(w) < p^d
```

then a Gröbner basis extracts `(x0, y)`. `x(S) = h0 + x0`.

Two consequences that cost people days if missed:

* **There is no cheap lift to a higher modulus.** Every row is only
  `≡ 0 mod p^d` at the root (Case A rows carry `d` (or `d-1`) F-factors;
  Den Case B `H+J+K` products carry `d` F-factors). Multiplying low-divisibility
  rows by `p` and using modulus `p^(d+1)` is uniform scaling and neutral.
* **The norm certificate is often empty even when the attack works.** On the
  original babyDH2 instance (`d=4`), zero rows satisfy
  `‖row‖ < p^d/sqrt(w)`, yet 84 rows vanish exactly over `Z` and the Gröbner
  basis solves in 0.3 s. Plan for heuristic selection + verification.

## 2. Working pipeline (validated end-to-end)

1. **Verify oracle semantics with `P = G`.** The response must equal
   `x(A) >> K` (this also distinguishes MSB from LSB framing, and confirms the
   point encoding). One connection, one query.
2. **Collect `2n+1` leaks** (and the final ciphertext/prompt if the service
   encrypts a token). Buffer input lines carefully: the last leak, ciphertext
   and prompt often arrive in one TCP segment.
3. **Build `F_i`** with `Coe` (above). Use symmetric coefficient
   representatives (−p/2, p/2) if the ring allows it.
4. **Build the shifts** `build_ff(d,t)` including the `W`-matrix inverse over
   `Zmod(p^(l-1))` and the `H+J+K` third loop.
5. **Build the integer matrix** rows = shifts, columns = monomials, and
   **scale every column by its monomial bound before LLL**
   (`X0=2^K` or `2^(K+1)`, `Xi=2^(K+1)`). Omitting this scaling silently
   produces a meaningless reduced basis — it is the single most common port bug.
6. **Reduce with flatter** (not Sage's LLL). Parse the FPLLL text output.
7. **Select short polynomials.** First take rows with
   `‖row‖ < p^d/sqrt(#cols)` (rigorous, usually 0 rows). Otherwise take the
   shortest `k` rows and/or windows `rows[s:s+k]` and random subsets, then rely
   on step 8's verification.
8. **Solve and verify.** Write the selected polynomials to msolve
   (`vars`, characteristic `0`, `poly,` lines). Use a hard timeout: msolve can
   hang indefinitely on inconsistent systems. Parse integer solutions,
   form `Sx = h0 + x0`, and **verify by re-substituting into the oracle**:
   for both signs of `S` and both signs of `A`, check
   `x(S + m·A) >> K == leak[m]` for all `m`. If a ciphertext exists,
   AES-decrypt with `sha256(str(Sx).encode())` and require a printable
   token/flag shape.
9. **Reply inside the alarm window.** After the queries the server blocks on
   `input()`; at the alarm it dies and the instance is gone. A saved leak set
   from a dead connection can still be used to *validate* an attack offline,
   but cannot earn the flag.

## 3. Calibration case — run this before trusting any port

`babyDH2`: NIST256p, `K=92`, `n=5`, `d=4` → `w=249`.

Expected: flatter ≈ 20-30 s; ~84 rows vanishing over `Z`; msolve/GB returns
the root in well under a second; `S.x` matches the synthetic truth.
If you do not reproduce this, the bug is in `get_M`, the support/shift
construction, or the column scaling — not in the parameters.

## 4. Toolchain pitfalls (Sage 10+, flatter, msolve)

* **Sage >= 10 removed `Sequence.coefficient_matrix()`.** The public
  `DH2.sage` reference crashes on modern Sage. Rebuild the coefficient matrix
  manually from `poly.dict()` (keys are exponent tuples).
* **flatter is C++/CMake now** (not the old Rust build): `cmake -B build
  -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`, needs GMP, MPFR,
  LAPACK and Eigen3. Link against ONE coherent set of libraries: building
  against Sage's `libfplll.so` while using the system MPFR aborts at runtime
  with `MPFR assertion failed`. `libfplll-dev` 5.4.x on Ubuntu works.
  Use the absolute binary path and add its dir to `PATH` for child processes.
* **Sage's `.LLL()`** uses fplll and can be 20-50x slower than flatter
  (268 dims: ~25 min vs ~50 s).
* **msolve needs a word-size characteristic.** `p = 2^521-1` is not accepted.
  Run msolve **over Q** to extract integer roots, or use
  `I.variety()`/Singular over `GF(p)` + CRT for reconstruction.
* **fgb_sage is not on PyPI** and is absent from `sagemath` images; Singular
  `groebner_basis`/`variety` is slower but usable.
* **Warm container.** Container start + Sage import can be ~60 s; keep one
  container alive (`docker run -d ... sleep infinity`, then `docker exec`) and
  only pay the ~3 s Sage import per run.

## 5. Diagnosing “no exact zero rows”

Use a **synthetic instance with known truth** (simulate `a, b`, the leaks, and
run the same code). Then inspect `h(root)/p^d`:

* histogram of `bit_length(h(root)/p^d)` over all rows;
* shortest Euclidean norm vs `p^d/sqrt(w)`.

If the shortest nontrivial quotient needs tens of bits → parameters are far
away; single digits → close but still may be unreachable. Extra shifts `t`,
symmetric residues, tighter `x0` bounds (`2^K` instead of `2^(K+1)`) and
stronger flatter targets usually give 0-4 bits and rarely change the verdict.
Increasing `d` at fixed `n` has diminishing returns and multiplies `w`
(and flatter memory ~ `w²`).

## 6. The multi-centre trap (do not sink days here)

With `2n+1` queries you can pair them in `C(2n+1,2)` ways; when the pair sums to
`2(S+cA)`, the leak at the centre `c` is one of the queries, so you get many
equations with different centres and shared low-bit errors `e_t`. It is
tempting to believe “81 equations, 36 unknowns”. In fact:

* the equations hold for **every** hidden point (a 1-dimensional algebraic
  family) — smallness of all `x0_c, e_t` is what selects the root;
* plain XL is degenerate: at level 0 the coefficient matrix has
  rank 81 of 378 columns (nullity 297); one level of shifts gives 2997 rows vs
  10411 monomials with nullity ≥ 7414 — it never closes;
* a joint Coppersmith over 36 variables is beyond current practical lattices.

Individual (unpaired) samples do not help either: the x-coordinate equation is
degree 6 in `x0` and quadratic in the error, not the linear-error Coe form.

## 7. Finding the right paper fast (the step that saves the most time)

1. Use the challenge's own words/description and search for a writeup:
   `"<exact description>" writeup`, `babyDH2 <curve> Coppersmith`, plus
   `site:github.com`. Chinese blogs often have the intended parameters.
2. **eprint.iacr.org/search?q=...** is the most reliable scholarly source.
   Google/Bing/Baidu/DuckDuckGo frequently return captchas to automated
   fetchers; the arXiv API rate-limits (HTTP 429) and eprint PDF URLs may 403
   while the abstract pages work.
3. For the babyDH2 lineage the chain is:
   * AliyunCTF 2024 `babyDH2` → public reference solution
     `github.com/zarismine/AliyunCTF2024_DH1DH2` (`DH2.sage`), which implements
     **eprint 2022/1239** (Asiacrypt 2022 `L(n,d,t)` lattice above).
   * eprint search for “elliptic curve hidden number problem” also surfaces
     **2023/1409** (Automated Coppersmith, CSIDH/CSURF; code
     `github.com/juliannowakowski/automated-coppersmith`, ~200 lines) and
     **2026/1027** (LP-computed asymptotic bounds; code
     `github.com/ZhaopengDing1/Coppersmith-LP`), which explicitly lists EC-HNP
     among the improved settings.
4. GitHub repository search works unauthenticated:
   `api.github.com/search/repositories?q=<term>`. Read the (small) algorithms
   and reimplement them in your own script if the sandbox forbids executing
   downloaded code.
5. **Validate a reimplementation on the paper's own demo** before trusting it.
   Example: the automated-Coppersmith MIHNP demo must give `δ = 11/24`
   (`0.45833`); a Monte-Carlo LP implementation gave `0.45838`.

## 8. Case study — `theorezhnp` (AliyunCTF 2024 babyDH2 sequel)

Service: NIST521p, 19 queries, `leak = x(a·P) >> 235` (`K=235`, known 286,
`δ = 0.451`), final AES-ECB ciphertext keyed by `sha256(str(S.x))`;
`signal.alarm(600)` at connect (verified empirically); off-curve points are
rejected; concurrent connections get fresh keys; the banner already contains
the team token and both public keys (send `131-hex x`, newline, `131-hex y`,
newline).

What was tried and what it showed:

| config | dim | flatter | exact-zero rows | shortest norm vs `p^d/√w` |
|---|---|---|---|---|
| d=2,t=0..4 | 268..604 | 0.8-10 min | 0 | quotient ~2^35..2^89 |
| d=3,t=0 | 906 | ~28 min | 3 | 1563.0 vs 1558.1 (5-bit gap) |
| d=3,t=0 tight bound | 906 | ~25 min | 3 | same |
| d=3,t=2 | 1158 | ~67 min | 1 | same |
| d=3,t=0, flatter -rhf 1.005 | 906 | ~26 min | 3 (identical basis) | same |
| real instance, d=3,t=0 tight | 906 | ~27 min | (no truth; certified 0) | 1563.0 |

* `d=4,t=0` (2174 dims) needs ~22-30 GB (flatter RSS ~ w², entries up to
  ~4700 bits, plus the Sage matrix/string on our side), i.e. a ≥64 GB machine;
  and fixed `n=9` caps the bound near `X≈2^209..2^211` anyway.
* Multi-centre/shared-error route: XL rank 81/378 (nullity 297); level 1
  2997/10411 (nullity ≥7414) — dead.
* Difference identity `x(S+mA)-x(S-mA) = -4y(S)y(mA)/(x(S)-x(mA))²` eliminates
  `y(S)` pairwise but yields linear-in-`{1,x0,x0²,d_j x0^i}` systems with rank
  8/36 at the first level and growing nullity under XL — dead.
* Monte-Carlo LP of the raw-`F_i` automated-Coppersmith polytopes gives
  `δ≈0.09..0.19` (the hand Case-B lattice is much stronger, so this is not a
  proof of infeasibility, but it is a warning that the automated route is not
  automatically better).

**Conclusion:** with 19 queries (`n=9`) the published lattice cannot reach
`K=235`; the paper's own tables put the required `n` near 37 at `d=2`. The
battle is lost at intake, not at LLL. Check the sample count and the bound
before building any lattice; if they do not fit, either find additional
samples/another oracle or get the author's technique.
