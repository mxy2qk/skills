# Elliptic Curve Attacks

Curve: `y^2 = x^3 + a*x + b (mod p)`. Points are `(x, y)`; infinity is `None`.
Group order `#E`; generator `G` of order `n`.

## 1. Before attacking: validate the setup

- Check `G` is on the curve: `y^2 == x^3 + ax + b mod p`.
- Check the order. If the challenge gives `n`, verify `n*G == infinity`.
  If not, compute the order for small curves by repeated addition.
- Compute the discriminant `4a^3 + 27b^2 mod p`. Zero means singular (section 3).
- Factor the order. Smooth order is the most common weakness.

```python
from ctfkit import ecc
curve = ecc.Curve(p, a, b)
assert curve.is_on(G)
```

## 2. Smooth order: Pohlig-Hellman

If `n = prod(q_i^e_i)` with small prime factors, solve the DLP in each
prime-power subgroup with BSGS, then CRT the residues.

```python
from ctfkit import ecc
k = ecc.pohlig_hellman(curve, G, Q, order)
```

Conditions: the largest prime factor must be small enough for BSGS
(`sqrt(q)` steps). If `q` is huge, this fails; look for another weakness.

**Small subgroup / invalid point.** If the server does not validate points and
the curve has small-order points, send a point of small order to learn the
private key modulo that order, then CRT across several. This needs an oracle
that multiplies your point by the secret.

```python
# conceptual: for each small-order point P, query d*P, then dlp in that subgroup
```

## 3. Singular curves

If `4a^3 + 27b^2 ≡ 0 mod p`, the curve is isomorphic to a simpler group.

Find a root `r` of `x^3 + a*x + b`. Translate `u = x - r`, `v = y`; the curve
becomes `v^2 = u^2 (u + c)` with `c = 3r`.

- **Cusp (`c = 0`):** `v^2 = u^3`. The group is the additive group of `F_p`
  under `t = u/v`. If `Q = k*G`, then `k = t_Q / t_G mod p`.
- **Split node (`c` is a quadratic residue):** the map
  `t = (v + sqrt(c)*u) / (v - sqrt(c)*u)` sends the group to `F_p^*`. Solve the
  DLP in `F_p^*` with Pohlig-Hellman.
- **Non-split node (`c` non-residue):** the group is the norm-one subgroup of
  `F_{p^2}^*`; implement the extension-field arithmetic or use Sage.

```python
k = ecc.singular_curve_dlog(curve, G, Q)
```

## 4. Anomalous curves (`#E = p`)

Smart's attack lifts the curve to the `p`-adics, where the DLP becomes
additive. Requires `#E == p` and `p` prime. There is no pure-Python helper in
`ctfkit`; use Sage:

```python
# Sage
E = EllipticCurve(GF(p), [a, b])
# check E.order() == p
# Smart's attack: lift points to Qp, use the formal group
```

If Sage is unavailable, say so rather than attempting an unreliable
implementation. Runnable template: `scripts/templates/smart_anomalous.sage`
(reads an `instance.json`; retries the p-adic precision automatically).

## 5. Invalid-curve attack

The server accepts a point without checking it is on the curve. Send points
on a related curve with a small-order subgroup; each query leaks the secret
mod that order. CRT the results. Requires an oracle and a curve with suitable
small subgroups.

## 6. MOV / pairing attacks

If the embedding degree `k` (smallest `k` with `n | p^k - 1`) is small, the
DLP transfers to `F_{p^k}^*`. Useful for supersingular curves. Sage has
`EllipticCurve.weil_pairing`; pure Python pairings are a project, not a quick
solve. Runnable template: `scripts/templates/mov_fr.sage` (MOV/Weil or
Frey-Rück/Tate; it reconciles the log modulo `ord(alpha)` when `n` is
composite).

## 7. ECDSA

Signature: `r = (k*G).x mod n`, `s = k^{-1}(z + r*d) mod n`.

**Nonce reuse.** Two signatures with the same `k` and same `r`:

```
k = (z1 - z2) / (s1 - s2) mod n
d = (s1*k - z1) / r mod n
```

```python
k, d = ecc.ecdsa_recover_private_key(r, s1, s2, z1, z2, n)
```

**Known nonce.** `d = (s*k - z) / r mod n`.

**Biased nonce (HNP).** If `k` has a few known high/low bits, recover `d`
with a lattice (Hidden Number Problem). Sage/`fpylll` recommended; the
pure-Python LLL can handle small instances only.

**Reused nonce with different messages** is the same as nonce reuse; if `r`
differs, the nonces differed and this does not apply.

**Fault attacks.** A faulty signature that reuses `k` or leaks a bit of `d`
can be combined with a correct signature to factor/recover.

## 8. Additional ECC / DSA attacks

### Invalid-curve attack

The server accepts a point without checking `y^2 == x^3 + a*x + b`. Send a
point on a different curve with the same `a` but a `b` whose group order has
small factors. Each query reveals the secret modulo that small order; CRT the
results.

Workflow:

1. Find a `b'` such that `#E'` has small factors.
2. Pick a point `P'` of small order `r` on `E'`.
3. Query `d*P'` (the server multiplies by its secret).
4. Brute-force `d mod r` by comparing the result.
5. CRT across several `r_i`.

### Smart's attack (anomalous curves)

If `#E == p`, lift the curve and points to the `p`-adics and use the formal
group; the DLP becomes additive. Needs Sage. Standard implementation:

```python
from sage.all import *

def smart_attack(P, Q, p):
    E = P.curve()
    # Lift the curve to Qp with random lifts of the coefficients.
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])
    P_Qp = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    Q_Qp = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    p_times_P = p * P_Qp[0]
    p_times_Q = p * Q_Qp[0]
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()
    phi_P = -(x_P / y_P)   # formal group log at p*P
    phi_Q = -(x_Q / y_Q)
    k = phi_Q / phi_P
    return ZZ(k) % p

# Preconditions:
#   E = EllipticCurve(GF(p), [a, b]); E.order() == p
#   P, Q in E with Q = k*P
# If lift_x returns two points, try both; if phi_P == 0, try the other lift
# or a different base point.
```

Do not attempt a pure-Python implementation unless you have verified it on a
test vector. For a curve with `#E = p`, Smart's attack is O(1) after the
lift; do not waste time on BSGS.

### MOV / pairing attack

If the embedding degree `k` (smallest `k` with `n | p^k - 1`) is small, the
ECDLP transfers to `F_{p^k}^*`. Useful for supersingular curves. Sage's
`weil_pairing`/`tate_pairing` is the practical tool.

### DSA

The nonce-reuse formula is identical to ECDSA:

```
k = (z1 - z2) / (s1 - s2) mod q
d = (s1*k - z1) / r mod q
```

```python
k, d = ecc.dsa_recover_private_key(r, s1, s2, z1, z2, q)
```

Also check:

- **Small `k`:** brute-force `k` and check `pow(g, k, p) % q == r`.
- **Predictable `k`:** if `k` is derived from a weak PRNG or
  `MD5(prefix || counter)`, recover/predict it (MD5 collision can force reuse).
- **Shared prime:** `gcd(n1, n2)` across curves/moduli.

### Ed25519 / X25519

- **Ed25519 torsion:** cofactor 8. If key derivation uses
  `key = master * uid mod l`, query powers of two and check y-coordinate
  consistency to leak scalar bits.
- **X25519 low-order points:** `u = 0, 1` (and other low-order values) can
  force an all-zero shared secret. A missing all-zero check is a 1–2 query
  break.

### Biased / partial nonce HNP

If each nonce `k_i` is small or its high bits are known, write
`k_i = leaked_i * 2^t + delta_i` with `0 <= delta_i < 2^t`. With
`a_i = r_i/s_i` and `b_i = h_i/s_i - leaked_i*2^t mod q`:

```
a_i * d + b_i ≡ delta_i (mod q)
```

This is an HNP instance.

```python
from ctfkit import lattice
cands = lattice.ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, t)
```

For non-ECDSA contexts (truncated LCG/LFSR, DSA, generic modular equations),
the same reduction is `lattice.hnp_partial_bits(a, b, m, leaked, bits)`:
`a_i*y + b_i ≡ leaked_i*2^bits + delta_i (mod m)` with small `delta_i`.

### HNP variants (paper-level)

- **Unknown modulus.** If `m` is unknown, solve for both `m` and `y` with a
  multivariate/Coppersmith approach (see `coppersmith_multi.sage`); or reduce
  modulo known divisors first. Paper: 2026/1027 (LP bounds), 2026/423.
- **Multiple unknowns (multivariate HNP).** Several coupled `y_j` → LWE-shaped;
  treat each equation as `a·y + b = small (mod m)` and use `lwe_hints.sage`.
- **Modular-inversion HNP (MIHNP).** Equations involve `(a_i*y+b_i)^{-1} mod m`;
  handled by Coppersmith over multivariate modular polynomials (2026/423).
- **Sign / Hamming-weight leakage** (HAWK/Falcon/ML-DSA randomness): a leaked
  bit reveals `sign(<b, w>)`; model as *Learning a Halfspace* (2026/1366), or
  convert to approximate hints for `lwe_hints.sage`.
- **Threshold signatures.** Fault-induced nonce reuse across sessions leaks a
  share per device (2026/2566); two distinct challenges cancel the nonce
  (2026/1668). Watch for reveal-structure rather than nonce uniformity.

Rules of thumb:

- Need roughly `q.bit_length() / t` signatures; more is safer.
- `t` is the number of unknown low bits per nonce.
- If only the low bits are known, transform the equations (multiply by the
  inverse shift) or use the extended HNP.
- Verify the candidate by recomputing `r` from `k = a_i*d + b_i`.

### Fault injection

A faulty signature that used the correct `k` but a corrupted computation can
leak the key or a factor. Compare correct vs faulty outputs; check
`gcd(s^e - m, n)` for RSA-CRT, or solve the signature equations for ECDSA.

### Clock group and other algebraic groups

- **Clock group `x^2 + y^2 = 1`:** order `p+1`, not `p-1`; use Pohlig-Hellman
  when `p+1` is smooth.
- **Twist attacks:** if the implementation does not check the point is on the
  curve but uses the twist, the twist's order may be smooth.
- **Shared prime:** multiple curves with a shared modulus factor;
  `gcd(n1, n2)` reveals it.

## 9. Common curve pitfalls

- **Point at infinity.** Handle `None` explicitly; doubling a point with
  `y = 0` gives infinity.
- **Non-invertible denominator.** If `x1 == x2` and `y1 == -y2`, the result is
  infinity, not a division by zero.
- **Curve order vs. generator order.** A generator may have a smaller order
  than `#E`; use the generator's order for DLP.
- **Cofactor.** Points in small cosets can leak information; check
  `#E / n`.
- **`p` not prime.** Composite moduli need different attacks (factor `p`
  first).
- **Parameters outside the field.** Reduce `a, b, x, y` mod `p` before use.

## Function map

| Task | Function |
|---|---|
| curve arithmetic | `ecc.Curve.add`, `.mul`, `.is_on` |
| BSGS | `ecc.bsgs` |
| Pohlig-Hellman | `ecc.pohlig_hellman` |
| singular curve DLP | `ecc.singular_curve_dlog` |
| ECDSA nonce reuse | `ecc.ecdsa_recover_private_key` |
| DLP in `F_p^*` | `ecc.dlog_prime_field` |
| parse a point | `ecc.point_from_text` |
