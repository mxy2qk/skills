# Finite-Field Diffie-Hellman Attacks

Classic DH: public `p, g`, peer values `A = g^a`, `B = g^b`, shared
`S = g^(ab)`. The key is usually `KDF(S)`, and the oracle is "does this
ciphertext/MAC verify?".

## 1. Triage order

1. Trivial generator or peer values (`0`, `1`, `p-1`, `p`).
2. `p-1` smooth → Pohlig-Hellman.
3. Static key + small factors in `p-1` → small-subgroup confinement.
4. Weak/export-grade `p` (512–768 bits) → Logjam/precomputation.
5. X25519 low-order points → all-zero shared secret.

```python
from ctfkit import dh
dh.is_trivial_generator(g, p)
dh.factor_p_minus_1_bits(p)
dh.pohlig_hellman_fp(g, h, p)
```

## 2. Trivial values

If the server accepts `g` or the peer public value without validation:

- `g = 0` → shared secret `0`.
- `g = 1` → shared secret `1`.
- `g = p-1` (order 2) → shared secret `1` or `p-1`; leaks the parity of the
  private exponent.
- Peer `A = 0, 1, p-1, p` → shared secret is a known constant.

Try each candidate key against the oracle before any DLP:

```python
for S in dh.trivial_shared_secrets(p):
    if oracle_accepts(KDF(S)):
        ...
```

## 3. Pohlig-Hellman

If `p-1 = ∏ q_i^e_i` with all `q_i` small, solve the DLP in each prime-power
subgroup with BSGS and CRT the residues.

```python
k = dh.pohlig_hellman_fp(g, h, p)  # h = g^x
```

Conditions: the largest prime factor must be small enough for `sqrt(q)`
steps. If `q` is large, this fails; look for a small subgroup or another bug.

## 4. Small-subgroup confinement / Lim-Lee

Static server key `b`, `p-1 = q*h` with many small factors in `h`. Send an
element `w` of exact order `r | h`; the server computes `S = w^b`; the oracle
reveals `b mod r` by trying `w^j` for `j = 0..r-1`. Repeat for coprime `r_i`
and CRT to recover `b` (or enough of it).

```python
w = dh.subgroup_element(g, p, r)          # exact order r
b_mod_r = dh.recover_secret_mod_r(w, r, p, check)  # check(S_candidate)
```

Oracle shapes: server returns `HMAC(KDF(S), msg)`, encrypts known plaintext
under `KDF(S)`, or accepts/rejects a ciphertext. The candidate `S_j = w^j`
that the oracle accepts gives `b ≡ j (mod r)`.

Mitigations to recognize: safe prime `p = 2q+1` (only order 2), subgroup
membership test `A^q == 1 mod p`, cofactor clearing, ephemeral keys.

## 5. X25519 low-order points

X25519 has cofactor 8. If the peer accepts a low-order `u`-coordinate, the
shared secret becomes all-zero (or a small set). Probe `u = 0, 1` and other
known low-order values; check whether the implementation rejects all-zero.

```python
dh.x25519_low_order_u()
```

## 6. Logjam / export-grade

If `p` is 512–768 bits or a known RFC group, precomputation makes the DLP
cheap. In CTF terms, a small `p` usually means "factor `p-1` or use BSGS".
Check `p.bit_length()` and whether `p` is reused across challenges.

## 7. Other DH variants

- **ElGamal over DH:** same DLP; see `references/exotic.md`.
- **Matrix DH:** `A = G^a` in `GL(n, F_p)`; solve via eigenvalues/Jordan form
  or linear algebra.
- **Braid group DH:** Alexander polynomial is multiplicative; the shared
  secret can be computed from public braids.
- **Tropical semiring DH:** residuation recovers the shared secret directly.
- **ECDH:** see `references/ecc.md` for invalid-curve/small-subgroup.

## 8. Pitfalls

- The shared secret is often hashed before use; try `SHA256(S)`, `MD5(S)`,
  and raw bytes.
- `p` may be composite; factor it first.
- `g` may have a smaller order than `p-1`; use the actual order.
- A "safe prime" still leaks 1 bit via `p-1`; combine with other leaks.
- The server may rotate `p` per connection; solve within one session.
