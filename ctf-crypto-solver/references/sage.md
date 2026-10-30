# SageMath quick start

Heavy-number-theory attacks (pairings, p-adics, large lattices, exact
modular algebra) are typed far more quickly in Sage than in pure Python.
The skill does **not** assume Sage; the built-in `ctfkit` covers the common
cases. Reach for Sage when a reference says so, or when a pure-Python attempt
is obviously too slow / inaccurate.

## Running a `.sage` file

```bash
sage scripts/templates/smart_anomalous.sage instance.json
```

- `.sage` files are prepared (preprocessed) by Sage: `^` becomes `**`, and
  `R.<x,y> = PolynomialRing(...)` syntax is real. Prefer `**` explicitly to
  avoid surprises when copying snippets between `.py` and `.sage`.
- Pass instance data as JSON (an `instance.json` sidecar) rather than editing
  the script, so the same template serves many challenges. Integer fields may
  be decimal or `0x`-hex strings; the templates' `zz()` helper accepts both.
- Inside a challenge directory running the templates through `docker run --rm`
  requires mounting the directory; see the container note at the end.

## Docker (recommended on this machine)

No native Sage install exists; use the official image:

```bash
MSYS_NO_PATHCONV=1 docker run --rm -it \
  -v "C:/path/to/challenge:/work" -w /work \
  sagemath/sagemath:latest sage script.sage
```

- Without `-it` (e.g. in CI / a non-interactive shell), `sage` may fail to
  start a REPL wrapper; use `docker run --rm` without `-it` and call
  `sage script.sage` as the command.
- The plain `sagemath` image has **no** `flatter` and no `fgb_sage`; the
  EC-HNP template additionally needs those binaries (see `references/ec-hnp.md`).
- Container start + first import of `sage.all` can take ~60 s; keep one
  container warm for multi-run debugging.

## Moving between `.py` and `.sage`

| Python (`ctfkit`) | Sage |
|---|---|
| `pow(a, -1, m)` | `inverse_mod(a, m)` or `a**-1` (in a field) |
| `sympy.ntheory` | `factor(n)`, `is_prime(p)`, `euler_phi(n)` |
| small LLL — `ctfkit.lattice.lll_reduce` | `M.LLL()` on `matrix(ZZ,...)` |
| — | `M.BKZ(block_size=40, proof=False)` for larger dimensions |
| modular poly roots | `65537` ring: `R.<x> = PolynomialRing(Zmod(N))`; `f.roots()` |
| ECC arithmetic `ctfkit.ecc` | `E = EllipticCurve(GF(p), [a,b])`; `E(Gx,Gy)`; `n*G` |
| pairings / p-adics / formal groups | only in Sage: `weil_pairing`, `tate_pairing`, `Qp/Qq` |

## When to prefer Sage over `ctfkit`

- **Smart's attack** (`#E == p`): p-adic lift, `references/ecc.md` §4.
- **MOV / Frey-Rück**: embedding degree + pairing transfer.
  Templates: `smart_anomalous.sage`, `mov_fr.sage`.
- **Boneh-Durfee / bivariate Coppersmith**: dimension 20–60 LLL, resultant
  recovery. Template: `boneh_durfee.sage`, `coppersmith_multi.sage`.
- **CRT-RSA partial exponents**: MSB of `dp`/`dq` → univariate Coppersmith
  (`beta=0.5`). Template: `crt_rsa_partial.sage`; see `rsa-crt-exponents.md`.
- **LWE / NTRU at production sizes**: BKZ. Template: `lwe_bkz.sage`.
- **LWE with extra hints**: perfect hints → elimination, approximate hints →
  appended noisy rows. Reference `lwe-hints.md`; template `lwe_hints.sage`.
- **EC-HNP / babyDH2**: the Asiacrypt-2022 lattice `L(n,d,t)`,
  `references/ec-hnp.md` has its own toolchain (flatter + msolve).
  Template: `ec_hnp.sage`.

Every CDN-ready template reads an `instance.json` sidecar and prints the
recovered secret plus any `flag{...}`. Copy the closest one into the
challenge directory and adapt the key derivation / banner parsing.

## Pitfalls (Sage-version specific)

- **Sage 10 removed `Sequence.coefficient_matrix()`.** `coppersmith_multi.sage`
  and `ec_hnp.sage` build the lattice matrix by hand for exactly this reason.
- `f.coefficients()` drops zero coefficients; for a dense matrix use
  `f.monomial_coefficient(m)` per monomial or `f.dict()`.
- `x^...` in a `.sage` file is power, but in a `.py` executed *inside Sage*
  (`sage -python`) it stays XOR. Keep `**` for portability.
- Integer modulus exponentiation `N ** 0.5` returns a real number; use
  `floor(N ** (1/2))` or `isqrt(N)` for exact floor sqrt.
- `IntegerMod(N)` element inverses: `x.inverse_mod(N)` works; division `1/x`
  in a ring of non-prime modulus may raise. Use `inverse_mod(ZZ(x), N)`.

## External implementations worth cloning

- `https://github.com/jvdsn/crypto-attacks` — Coppersmith (small_roots), HNP,
  LWE, ECDSA, pairings, Smart (MIT).
- `https://github.com/mimoo/RSA-and-LLL-attacks` — `boneh_durfee.sage`,
  `coppersmith.sage`.
- `https://github.com/defund/coppersmith` — univariate/bivariate templates
  (note: uses the removed `Sequence.coefficient_matrix` on Sage 10; patch by
  building the matrix manually).