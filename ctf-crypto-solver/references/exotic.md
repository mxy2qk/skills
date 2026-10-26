# Exotic Public-Key and Algebraic Structures

These schemes appear in "exotic crypto" challenges. The math is usually
simple once you recognize the structure; the trap is assuming standard
padding or a secure implementation.

## 1. Paillier

Key: `n = p*q`, `g = n+1`, `lambda = lcm(p-1, q-1)`, `mu = L(g^lambda mod n^2)^-1 mod n`,
where `L(x) = (x-1)/n`.

Encryption: `c = g^m * r^n mod n^2`. Decryption:
`m = L(c^lambda mod n^2) * mu mod n`.

Additive homomorphism:

```
Enc(m1) * Enc(m2) = Enc(m1 + m2)
Enc(m)^k          = Enc(k*m)
```

```python
from ctfkit import exotic
n, g, lam, mu = exotic.paillier_keygen(p, q)
c = exotic.paillier_encrypt(m, n, g, r)
exotic.paillier_decrypt(c, n, lam, mu)
exotic.paillier_add(c1, c2, n)
exotic.paillier_mul_const(c, k, n)
```

**LSB oracle via homomorphic doubling.** If the server decrypts and returns
the LSB, query `Enc(2m) = c^2`; the parity tells whether `2m mod n` wrapped.
This is a binary search for `m` (same shape as the RSA LSB oracle).

**Other patterns:**

- Decryption oracle without the key: use homomorphism to blind `c` and divide
  out the blinding factor.
- Re-encryption: `c * r^n` is a fresh encryption of the same message; useful
  for unlinkability/round-trip tests.
- `g = n+1` is standard; a different `g` changes the `L` formula.

## 2. ElGamal

Public `(p, g, h = g^x)`. Encryption with ephemeral `k`:
`(c1, c2) = (g^k, m * h^k mod p)`. Decryption: `m = c2 * (c1^x)^-1 mod p`.

```python
from ctfkit import exotic
c1, c2 = exotic.elgamal_encrypt(m, p, g, h, k)
m = exotic.elgamal_decrypt(c1, c2, x, p)
```

Attacks:

- **Reused `k`:** same `c1`; then `c2a / c2b = ma / mb`. With one known
  plaintext, recover the other.
- **Trivial `h`:** `h = 1` or `p-1` gives a known shared secret.
- **Small subgroup:** `p-1` smooth or `g` of small order.
- **Universal re-encryption:** `(c1 * g^r, c2 * h^r)` is a fresh encryption;
  if the server accepts re-encrypted ballots, you can vote twice.
- **Malleability:** without a MAC, flipping `c2` flips the plaintext.

## 3. Goldwasser-Micali

Encrypts one bit at a time: `c = r^2 * x^b mod n`, where `x` is a non-residue
with Jacobi symbol `+1`.

Decryption with `p, q`: bit `0` iff `c` is a quadratic residue modulo both
primes.

```python
bits = exotic.gm_decrypt(ciphertexts, p, q)
data = exotic.gm_bits_to_bytes(bits)
```

**Replication oracle:** if a single ciphertext bit is reused as an N-bit key,
the key is all-zero or all-one; a hash/decryption oracle distinguishes them.
This can recover a full AES key in ~128 queries.

## 4. Rabin

`c = m^2 mod n = p*q`. Decryption yields four roots; pick the printable one.

```python
from ctfkit import rsa
roots = rsa.rabin_roots(c, p, q)
```

**Parity/LSB oracle:** querying `c * 4^i mod n` doubles the plaintext modulo
`n`; the parity gives a binary search, same as RSA LSB.

## 5. Matrix / non-commutative DH

- **Matrix DH over `GL(n, F_p)`:** public `G`, `A = G^a`, `B = G^b`. If `G` is
  diagonalizable, compute eigenvalues and solve the DLP in `F_p^*`; if not,
  use Jordan form or linear algebra.
- **Braid group DH:** the Alexander polynomial is multiplicative under braid
  concatenation, so the shared secret can be computed from the public braids
  without solving the conjugacy problem.
- **Tropical semiring DH:** `(min, +)` has residuation; the shared secret is
  recoverable directly from the public matrices:
  `b* = max(Mb[i] - M[i][j])`.
- **Cayley-Purser:** a flawed matrix scheme where the private key can be
  recovered from the public matrices with linear algebra.

## 6. Isogenies and pairing-based

- **Isogeny graph:** vertices are curves, edges are isogenies; a path can be
  found with modular polynomials and LCA/meet-in-the-middle.
- **MOV:** if the embedding degree is small, transfer the ECDLP to `F_{p^k}^*`
  and use index calculus/PH.
- **Pairing oracle:** a pairing oracle that accepts attacker points can leak
  the trapdoor or let you forge.

These usually need Sage; do not claim a pure-Python solve.

## 7. Signature and protocol quirks

- **RSA multiplicative homomorphism:** `S(a)*S(b) = S(ab)`; sign factors and
  multiply if the target message is blacklisted.
- **RSA `e=1`:** if the verifier accepts user-supplied `(n, e)`, choose
  `e=1` and a modulus that makes the padded hash equal the signature.
- **Bleichenbacher low-exponent signature forgery:** with `e=3`, craft a
  value whose cube root has the correct PKCS#1 prefix; trailing bytes absorb
  the error.
- **Merkle-Hellman knapsack:** low-density subset sum; use
  `lattice.subset_sum_solve` or a dedicated LLL/BKZ attack.
- **FPE/Feistel:** a small round key is brute-forceable; the remaining affine
  layer is solved with GF(2) linear algebra.

## 8. Pitfalls

- **No padding:** exotic schemes are often textbook; homomorphism and
  malleability are the intended attacks.
- **Encoding:** bits may be packed MSB-first, LSB-first, or as separate
  integers.
- **Wrong modulus:** Paillier uses `n^2`; ElGamal uses `p`; GM uses `n`.
- **Group order:** ElGamal/Paillier attacks depend on the order of `g`;
  factor `p-1` or `lambda`.
- **Sage-only paths:** isogenies, pairings, and large matrix groups often
  need Sage; state that clearly.
