# RSA Attacks

Notation: `n = p*q`, `phi = (p-1)(q-1)`, `c = m^e mod n`, `d = e^-1 mod phi`.

## Decision tree

```
Given n, e, c:
  e small (3,5,17)?            -> exact e-th root / k*n search / Hastad
  multiple (n_i, e_i, c_i)?    -> common modulus / common factor / Hastad
  d small?                     -> Wiener (d < n^0.25/3)
  p, q close?                  -> Fermat
  n factorable by rho/p-1?     -> factor and decrypt
  leaked phi/d/dp/dq/p-bits?   -> factor from the leak
  message partially known?     -> Coppersmith (stereotyped message)
  two related messages?        -> Franklin-Reiter / short-pad
  e = 2?                       -> Rabin square roots
```

## 1. Basic decryption

```python
from ctfkit import rsa
p, q = rsa.factor_int(n)          # or any factorisation
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
pt = rsa.decrypt_bytes(c, d, n)
```

If `n` has more than two prime factors, `phi = prod(p_i - 1)` and factor
recursively. `sympy.factorint` handles small multi-prime moduli.

## 2. Small public exponent

**Unpadded message.** If `m^e < n`, then `c` is an exact e-th power:

```python
m = rsa.small_e_root(c, e, n)     # is_perfect_power(c, e)
```

If `m^e = c + k*n` for small `k` (message slightly larger than `n`):

```python
m = rsa.small_e_search(c, e, n, max_k=10000)
```

**Hastad broadcast.** The same `m` is encrypted under `e` different moduli
with exponent `e`. CRT the ciphertexts, then take the exact e-th root:

```python
m = rsa.hastad_broadcast(ciphertexts, moduli, e)   # needs len >= e
```

If the moduli are not coprime, use the shared factor instead.

**Stereotyped message.** `m = known_prefix + x` with small unknown `x`:

```python
f = [known_prefix - ???]  # see references/lattice.md
```

Build the polynomial `(known + x)^e - c mod n` and run Coppersmith.

## 3. Common modulus

Same `n`, two exponents `e1, e2` with `gcd(e1, e2) = 1`, same message:

```python
m = rsa.common_modulus(n, e1, e2, c1, c2)
```

Uses Bezout: `a*e1 + b*e2 = 1`, so `m = c1^a * c2^b mod n`; negative
exponents become modular inverses. If `gcd(e1, e2) = g > 1`, this recovers
`m^g`, not `m`.

## 4. Wiener's attack (small `d`)

Condition: `d < n^0.25 / 3`. The fraction `e/n` has a continued-fraction
convergent `k/d`. For each convergent, test whether

```
phi = (e*d - 1) / k
```

gives integer `p, q` from `x^2 - (n - phi + 1)x + n = 0`.

```python
res = rsa.wiener_full(n, e)   # (d, p, q) or None
```

**Boneh-Durfee** extends this to `d < n^0.292` using a bivariate
Coppersmith lattice. It is significantly heavier; use Sage's implementation
or a dedicated bivariate Coppersmith if you need it. The pure-Python LLL in
`ctfkit.lattice` is not sized for typical Boneh-Durfee dimensions.

## 5. Factoring shortcuts

**Fermat.** `p` and `q` close: `a = ceil(sqrt(n))`, `b^2 = a^2 - n`,
increment `a` until `b^2` is a square.

```python
rsa.fermat_factor(n, max_iter=1_000_000)
```

**Pollard rho.** Factors up to ~10^12 quickly; good for one small prime.

```python
rsa.pollard_rho(n)
```

**Pollard p-1.** Works when `p-1` is smooth. Increase the bound if the first
attempt fails.

```python
rsa.pollard_pm1(n, bound=1_000_000)
```

**Shared primes.** Across a set of moduli, compute pairwise gcds:

```python
factors = rsa.common_factor(moduli)   # {index: factor}
```

**Small factors.** Trial division up to 10^5 catches many "small prime"
challenges.

## 6. Leaks in the challenge

**`phi` leaked.** `p + q = n - phi + 1`; solve the quadratic.

```python
rsa.factor_from_phi(n, phi)
```

**`d` leaked.** `k = e*d - 1` is a multiple of `phi`. Factor `k = 2^s * t`;
for random `a`, repeated squaring of `a^t` finds a nontrivial square root of
1 mod n, hence a factor.

```python
rsa.factor_from_d(n, e, d)
```

**`dp = d mod (p-1)` leaked.** For random `a`,
`a^(e*dp) ≡ a (mod p)`, so `gcd(a^(e*dp) - a, n) = p`.

```python
rsa.factor_from_dp(n, e, dp)
```

`dq` is symmetric.

**High bits of `p` leaked.** `p = p_high * 2^shift + x` with small `x`.
Coppersmith with `beta=0.5`:

```python
from ctfkit import lattice
lattice.factor_with_known_high_bits(n, p_high, shift)
```

The unknown part must be below roughly `n^(0.25)` for `beta=0.5`, degree 1.

## 7. Related messages

**Franklin-Reiter.** `c1 = m^e`, `c2 = (a*m + b)^e`. Compute
`gcd(x^e - c1, (a*x+b)^e - c2)` over `Z_n[x]`; the gcd is linear in `m`.

```python
m = rsa.franklin_reiter(c1, c2, e, n, a=1, b=1)
```

The default handles messages differing by 1.

**Short-pad attack.** Two ciphertexts of `m` with different random padding,
`e = 3`. The difference is small; Coppersmith bivariate. Sage recommended.

**Coppersmith related-message.** If `m2 = m1 + delta` with small `delta`,
build the resultant of the two encryption polynomials and find small roots.

## 8. Rabin (`e = 2`)

Decryption gives four square roots. Recover both `sqrt(c) mod p` and
`mod q`, CRT the four combinations, and pick the printable one:

```python
roots = rsa.rabin_roots(c, p, q)
for r in roots:
    pt = r.to_bytes((r.bit_length()+7)//8, "big")
    if b"flag" in pt: ...
```

The same idea applies when `gcd(e, phi) > 1`: there are multiple e-th roots;
enumerate them with `sympy.nthroot_mod` or by factoring the polynomial.

## 9. Oracle attacks

**LSB/parity oracle.** The oracle tells you the parity of the decrypted
`c * 2^e mod n`, i.e. the least significant bit of `2m mod n`. This is a
binary search for `m`: after `~log2(n)` queries you know `m` to full
precision. The same works for any single-bit oracle (MSB, Jacobi).

**Padding oracle on RSA.** Usually a Bleichenbacher attack; needs many
queries and careful interval bookkeeping. Check whether the challenge is
really CBC before going down this path.

## 10. Pitfalls

- **`e` and `phi` not coprime.** `pow(e, -1, phi)` raises. There are multiple
  roots; use `sympy.nthroot_mod` or factor the polynomial `x^e - c`.
- **`n` is prime.** Then `phi = n-1`; this happens in "RSA with a prime
  modulus" challenges.
- **`c >= n`.** Reduce mod n, but if the challenge gave `c` as a raw integer
  power, consider `m^e = c` without reduction.
- **Leading zero bytes.** `i2b` without a length drops them; use a known
  length when the plaintext format requires it.
- **Float roots.** `int(c ** (1/3))` fails for large integers. Use `iroot`.
- **Wiener false positives.** Verify `p*q == n` before trusting a convergent.
- **Coppersmith bound.** If the root is above `n^(beta^2/d)`, the attack will
  not work no matter the lattice size.

## 10. Oracle attacks and specialized variants

### LSB / parity oracle

The oracle returns `LSB(Dec(ct))`. Query `ct = c * 2^(e*i) mod n`; the parity
bits are the binary digits of `m/n`. Reconstruct the bits directly:

```python
from ctfkit import rsa
cands = rsa.lsb_oracle_candidates(oracle, c, e, n, extra_bits=8, window=8)
m = rsa.lsb_oracle_attack(oracle, c, e, n, verify=check_flag)
```

The estimate can be off by a few units, so pass a **strong** `verify` (full
flag regex, printable bytes, recomputed ciphertext) rather than a loose
substring check. Query count ≈ `n.bit_length()`.

### Manger's oracle

The oracle says whether the decrypted message is below `B = 2^(8*(k-1))`
(PKCS#1/OAEP-style threshold). Phase 1 multiplies `c` by `f^e` until the
threshold is crossed; phase 2 binary-searches the multiplier. ~`log2(n)`
queries. The same idea works for a timing oracle that distinguishes
`Y == 0` from `Y != 0`.

```python
from ctfkit import rsa
m = rsa.manger_attack(oracle, n, e, c, oracle_returns_valid=True,
                      max_queries=10000)
```

`oracle(ct)` returns True when `Dec(ct) < B = 2^(8*(k-1))` (valid OAEP
leading zero). If the service returns True for the invalid case, pass
`oracle_returns_valid=False`. Typical OAEP blocks need ~`2*bit_length(n)`
queries; an `m` extremely close to `B` can need more.

### Bleichenbacher / PKCS#1 v1.5

The oracle says whether the decrypted block starts with `0x00 0x02`.
Maintain intervals `[a, b]` for `m`; multiply by `s^e`, narrow the interval,
and use the known padding structure. ~10k queries for RSA-2048, highly
data-dependent. Use a library or a careful interval implementation; this is
not a "one-line" attack.

```python
from ctfkit import rsa
m = rsa.bleichenbacher_attack(oracle, n, e, c, max_queries=200_000)
```

`oracle(ct)` returns True for valid PKCS#1 v1.5 padding (`00 02 || PS || 00`,
at least 8 nonzero PS bytes). The helper bounds a remote run with
`max_queries`; typical query counts are tens of thousands.

### CRT fault attack (Bellcore)

One faulty CRT signature and one correct message:

```python
g = gcd(pow(faulty_sig, e, n) - m, n)   # yields p or q
```

```python
rsa.crt_fault_factor(n, e, m, faulty_sig)
```

The same applies to a faulty decryption that leaks `m` under one prime.

### Partial `dp` / `dq`

If `dp = d mod (p-1)` is fully known:

```python
g = gcd(pow(a, e*dp, n) - a, n)   # p for random a
```

If only high bits of `dp` are known, use Coppersmith on
`e*dp - 1 = k*(p-1)` (bivariate; Sage is easier). A small `dp, dq`
(`< N^0.073`) is the "small CRT exponent" lattice attack. For partial MSB/LSB
of both `dp` and `dq`, see `references/rsa-crt-exponents.md` and the runnable
`scripts/templates/crt_rsa_partial.sage` (MSB path validated).

### `gcd(e, phi) > 1`

`pow(e, -1, phi)` fails. Let `g = gcd(e, phi)`, `e' = e/g`,
`d' = e'^{-1} mod phi`. Then `c^{d'} = m^g mod n`; take the integer `g`-th
root if `m^g < n`, or enumerate all `g`-th roots modulo `p` and `q`:

```python
roots = rsa.nth_roots_mod(c, e, p, q)
for m in roots:
    print(i2b(m))
```

### Signature forgeries

- **Multiplicative homomorphism:** `S(a)*S(b) = S(a*b)`. If the oracle
  blacklists the target, sign its factors and multiply.
- **`e = 1` / crafted modulus:** if the verifier accepts user-supplied
  `(n, e)`, choose `e=1` and `n` so the padded hash equals the signature.
- **Bleichenbacher low-exponent:** with `e=3`, find a value whose cube root
  has the correct PKCS#1 prefix; trailing bytes absorb the error.
- **PKCS#1 v1.5 signature padding:** a verifier that ignores trailing bytes
  after the hash accepts a forged block.

### Homomorphic decryption oracle

If the oracle decrypts arbitrary ciphertexts but refuses the target, blind it:
`c' = c * r^e mod n`, get `m' = m*r`, then divide by `r`.

### Multi-prime and structured primes

- `n = ∏ p_i`: factor each, `phi = ∏(p_i-1)`, decrypt; use CRT for speed.
- `p = k*B + t` with small `k`: mixed-radix/Coppersmith.
- `q = next_prime(p)` or `q ≈ k*p`: Fermat or Coppersmith on the difference.
- `p = q`: the server's `phi = (p-1)^2` is wrong; validate and exploit.
- Restricted-digit primes: digit-by-digit factoring with modular pruning.

## Function map

| Task | Function |
|---|---|
| factor from phi | `rsa.factor_from_phi` |
| factor from d | `rsa.factor_from_d` |
| factor from dp/dq | `rsa.factor_from_dp`, `rsa.factor_from_dq` |
| small e root | `rsa.small_e_root`, `rsa.small_e_search` |
| common modulus | `rsa.common_modulus` |
| Hastad | `rsa.hastad_broadcast` |
| Wiener | `rsa.wiener`, `rsa.wiener_full` |
| Fermat | `rsa.fermat_factor` |
| rho / p-1 | `rsa.pollard_rho`, `rsa.pollard_pm1` |
| shared primes | `rsa.common_factor` |
| related messages | `rsa.franklin_reiter` |
| Rabin | `rsa.rabin_roots` |
| PEM keys | `rsa.load_pem`, `rsa.load_pem_private` |
