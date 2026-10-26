# Lattices and Coppersmith

`ctfkit.lattice` implements LLL and univariate Coppersmith in pure Python.
It is sized for CTF lattices (roughly dimension ≤ 40). For larger or
bivariate attacks, use Sage/fpylll.

## 1. LLL in one paragraph

Given a basis of a lattice, LLL produces a shorter, nearly orthogonal basis in
polynomial time. In CTF terms: if a secret vector is unusually short compared
to the lattice determinant, LLL finds it. The attack works by encoding the
unknown as a lattice vector whose coefficients are small exactly when the
guess is correct.

```python
from ctfkit.lattice import lll_reduce
reduced = lll_reduce(basis)     # rows of integers
```

Scale columns by powers of the bound `X` so that all coordinates are
comparable; otherwise large-degree coefficients dominate and LLL finds the
wrong vector.

## 2. Coppersmith univariate

**Theorem (informal).** Let `f(x)` be monic of degree `d`, and suppose
`f(x0) ≡ 0 (mod b)` where `b | N` and `b ≥ N^beta`. If

```
|x0| < N^(beta^2 / d)
```

then `x0` can be found in polynomial time (for large enough lattice
parameters).

**Construction.** Choose `m`, `t`. Build polynomials

```
g_{i,j}(x) = N^(m-i) * x^j * f(x)^i     for 0 ≤ i < m, 0 ≤ j < d
h_j(x)     = x^j * f(x)^m               for 0 ≤ j < t
```

Scale `x -> X*x`, build the coefficient matrix, LLL-reduce, and take short
vectors. A short vector gives a polynomial `h(x)` with `h(x0) = 0` over the
integers; extract its integer roots.

**Parameters.** With `X = N^delta` and slack `eps = beta^2/d - delta`:

```
m = ceil(beta^2 / (d * eps))
t = floor(d * m * (1/beta - 1))
dimension = d*m + t
```

`ctfkit.lattice.coppersmith_univariate` picks these automatically; override
`m`/`t` if the default dimension is too large or the attack almost works.

```python
from ctfkit.lattice import coppersmith_univariate
roots = coppersmith_univariate(
    f_coeffs,          # low degree first, monic mod N
    N,
    beta=1.0,
    X=root_bound,
)
```

The leading coefficient must be invertible mod `N`. If it is not,
`gcd(lc, N)` may factor `N` directly.

## 3. Common Coppersmith patterns

### Partial factor (known high bits of p)

`p = p_high * 2^shift + x`, `|x| < 2^shift`, `beta = 0.5`, degree 1.
The root bound is `~N^(0.25)` for `beta = 0.5`.

```python
from ctfkit.lattice import factor_with_known_high_bits
got = factor_with_known_high_bits(N, p_high, shift)
```

### Stereotyped message

`m = known + x` with small unknown `x`, `e` small:

```python
f = [(known - 0)]  # build (known + x)^e - c mod N as a coefficient list
# e = 3 example: f(x) = (known + x)^3 - c
# coefficients: [known^3 - c, 3*known^2, 3*known, 1] mod N
roots = coppersmith_univariate(f, N, beta=1.0, X=bound)
m = known + roots[0]
```

### Small root of a modular polynomial

Any challenge of the form "find small `x` with `f(x) ≡ 0 mod N`" is this
attack. Examples: `x^3 ≡ c`, `x^2 ≡ c`, `(x + a)^e ≡ c`.

### Partial `dp` / `dq`

If you know many bits of `dp`, model `dp = known + x` and use the relation
`e*dp ≡ 1 (mod p-1)`; a bivariate formulation or a lattice on the
`(p-1)` divisor. Sage is usually easier here.

## 4. Bivariate and related-message attacks

**Franklin-Reiter** is often simpler than a lattice: two polynomials with a
shared linear factor; compute their polynomial gcd over `Z_n`. `rsa.franklin_reiter`
does this for messages related by `m2 = a*m1 + b`.

**Related messages with small difference.** If `m2 = m1 + delta` and `delta`
is small, compute the resultant of `x^e - c1` and `(x + delta)^e - c2`,
then find its small roots. This is a bivariate Coppersmith when `delta` is
unknown but bounded.

**Boneh-Durfee (small `d`).** A bivariate lattice for `d < N^0.292`. It needs
a large lattice (dimension 20–50+) and careful parameter tuning; use Sage.

## 5. Practical tips

- **Keep the polynomial monic mod N.** Multiply by the inverse of the leading
  coefficient; if the inverse does not exist, `gcd(lc, N)` may factor `N`.
- **Scale correctly.** Every column `k` must be multiplied by `X^k`. The
  vector coefficients are then divisible by `X^k`; divide before extracting
  roots.
- **Check the bound first.** If `|x0| > N^(beta^2/d)`, no amount of lattice
  tuning will work. Re-read the challenge for a smaller unknown.
- **Root extraction.** Short vectors give polynomials whose integer roots are
  the candidates. `ctfkit` uses sympy's `ground_roots`; without sympy it
  falls back to numeric roots or a bounded scan.
- **Multiple roots.** Test every short vector, not only the first. A useful
  root may be in the second or third.
- **Dimension vs. time.** Pure-Python LLL is `O(dim^4)` with rational
  arithmetic. If it is slow, reduce `m` (and accept a smaller bound) rather
  than waiting.
- **Verify candidates.** For `beta < 1`, check `gcd(f(x0), N)` is a nontrivial
  factor; the root is modulo an unknown divisor, not `N`.

## 6. More lattice attacks

### Hidden Number Problem (HNP)

Given `a_i * x + b_i ≡ e_i (mod m)` with `|e_i| < X`, recover `x`. This is the
standard attack on biased/partial ECDSA nonces, truncated LCGs, and many
"small error" systems.

The workable embedding centers the error at `X/2` and scales by `X/m`:

```
[ m     0   ... 0   0    0 ]
[ 0     m   ... 0   0    0 ]
...
[ a_1   a_2 ... a_n X    0 ]
[ b_1'  b_2'... b_n' 0   m*X ]
```

where `b_i' = b_i - X/2`. Clear the rational `X/m` by multiplying the whole
matrix by `m`; this is what `ctfkit.lattice.hnp_solve` does.

```python
from ctfkit import lattice
ys = lattice.hnp_solve(a, b, m, X)
```

For ECDSA partial nonces, use the wrapper:

```python
lattice.ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, t)
```

Rules of thumb:

- Need roughly `m.bit_length() / t` signatures, where `t` is the number of
  unknown bits per nonce.
- More signatures and fewer unknown bits make the lattice easier.
- Always verify the candidate by recomputing `r`/the recurrence.
- A naive `q^2` lattice without centering/scaling can return trivial vectors.

### LWE / CVP

Given `b = A*s + e (mod q)` with small `s, e`, build the embedding

```
[ q*I   0 ]
[ A^T   I ]
```

and find the closest vector to `b` with Babai/CVP; project the result to the
expected range (e.g. ternary `{-1,0,1}`). If the noise is tiny, plain LLL/Babai
is enough. If the secret is binary/ternary and the dimension is moderate,
`fpylll` is much faster.

```python
from ctfkit.lattice import lwe_cvp_solve
s, e = lwe_cvp_solve(A, b, q)   # A is m x n, b = A*s + e mod q
```

`lwe_cvp_solve` builds the embedding, LLL-reduces it, and runs Babai's
nearest plane. It returns centered `s` and `e`; verify `b - A*s mod q` is
small. For larger dimensions use fpylll/BKZ and the same embedding.

Practical checks:

- Is `q` the stated modulus in every equation?
- Are coefficients centered (negative values represented as `q-x`)?
- Is the encoding little-endian or big-endian?
- Do you have enough samples? LWE needs `n` or more; more samples help.

### Subset sum / knapsack

For `sum(a_i*x_i) = target`, `x_i ∈ {0,1}`, build

```
[ 1 0 ... 0 a_1 ]
...
[ 0 0 ... 1 a_n ]
[ 0 0 ... 0 -target ]
```

LLL finds a row with last coordinate 0 and first `n` in `{0,1}`. Low density
(`n / log2(max a_i) < ~0.4`) works with LLL; higher density needs BKZ or more
structure.

```python
bits = lattice.subset_sum_solve(weights, target)
```

### NTRU

Public `h = g * f^{-1} mod q` with small `f, g`. Build

```
B = [[q*I, 0],
     [H,   I]]
```

where `H` is the (negacyclic) multiplication matrix of `h`. LLL/BKZ finds a
short vector encoding `(f, g)`. In CTF, `N` is often small or `f, g` sparse;
use `fpylll`/Sage BKZ for realistic sizes.

```python
from ctfkit.lattice import ntru_recover
for f, g in ntru_recover(h, q, negacyclic=True, max_coeff=2):
    # verify h*f == g mod q and use f as the private key
    ...
```

`ntru_recover` is a toy/weak-parameter helper (pure LLL); for real NTRU use
BKZ. The returned vectors may be rotations/signs of the original `(f, g)`;
verify by multiplication.

### Ring-LWE / Module-LWE

Look for polynomial multiplication modulo `x^N+1` (negacyclic) or `x^N-1`
(cyclic), a modulus like 3329/12289/8380417, and small noise. Many challenges
weaken the parameters (tiny noise, leaked coefficients, wrong NTT) enough to
flatten the problem to plain LWE. Check:

- the ring and modulus,
- coefficient packing (little-endian, bit-reversed NTT),
- whether compression/decompression discards more bits than intended,
- whether a few secret coefficients leak.

### Orthogonal lattices and hidden subspaces

Hidden-subset/subspace problems may require recovering an orthogonal lattice
first, then reconstructing the binary/short basis from its complement. Use
LLL on the dual, then intersect with the original lattice.

### BKZ / Babai

- **LLL** is the default; it is fast but gives a weaker approximation.
- **BKZ** (block size 20–60) is much stronger; use it when LLL "almost"
  finds the vector (short but not short enough).
- **Babai** gives an approximate closest vector after reduction; good for
  LWE/CVP.
- Pure Python is not suitable for BKZ; use `fpylll` or Sage.

## 7. When to reach for Sage

- Boneh-Durfee and other bivariate attacks at realistic sizes.
- Partial-key exposure with many unknown bits.
- Lattices above dimension ~40–50.
- Pairing-based attacks (MOV) and Smart's attack.

Say so explicitly and provide the Sage code path; do not claim the pure-Python
implementation handles those scales.

Useful external implementations:

- `https://github.com/jvdsn/crypto-attacks` — Coppersmith, HNP, LWE, ECDSA,
  and many CTF-oriented lattice attacks (Sage/fpylll).
- `https://github.com/mimoo/RSA-and-LLL-attacks` — `boneh_durfee.sage`,
  `coppersmith.sage`, and related RSA lattices.
- `https://github.com/defund/coppersmith` — univariate/bivariate Coppersmith
  templates.
- `fpylll` — BKZ/CVP for dimensions where the built-in LLL is too weak.
