# Post-Quantum Cryptography in CTFs

PQ challenges are usually about **implementation bugs**, **leaked
randomness**, or **too-small noise**, not about breaking the underlying
assumption. Recognize the scheme first, then look for the CTF-sized weakness.

## 1. Recognition

| Scheme | Parameters / clues |
|---|---|
| ML-KEM / Kyber | `q = 3329`, `N = 256`, `k = 2/3/4`, `eta1 = 3/2`, `eta2 = 2`, `du/dv`, byte arrays `u`, `v` |
| ML-DSA / Dilithium | `q = 8380417`, `N = 256`, `(k, l) = (4,4)/(6,5)/(8,7)`, `gamma1`, `gamma2`, `tau`, `beta` |
| Falcon | `N = 512/1024`, `q = 12289`, short basis `B`, floating-point FFT |
| NTRU / NTRU Prime | `q = 2048/12289/3329`, ring `Z_q[x]/(x^N-1)` or `(x^N+1)`, small `f, g` |
| Saber | `q = 8192` (or 2^13), `N = 256`, module rank |
| HQC / BIKE | code-based; large parity-check matrices |

The ring (`x^N+1` negacyclic vs `x^N-1` cyclic), `N`, `q`, and the module rank
are the fingerprints.

## 2. Common CTF weaknesses

### ML-KEM / Kyber

- **FO failure oracle:** the decapsulation re-encrypts the decrypted message
  and compares ciphertexts. If the server reveals success/failure (or timing),
  it is an oracle. Use it to mount a chosen-ciphertext attack or to recover
  the shared secret bit-by-bit.
- **Tiny noise:** if `e1, e2` are much smaller than the parameters (e.g. only
  a few bits), reduce to LWE and solve with CVP/Babai.
- **Nonce/randomness reuse:** a reused `r` or seed makes the encryption
  deterministic; XOR ciphertexts to cancel the message.
- **Compression bugs:** `du/dv` compression/decompression may discard more
  bits than intended; this leaks the high bits of `u`/`v`.
- **Representation bugs:** coefficients packed little-endian vs big-endian,
  bit-reversed NTT, or a wrong modulus in one step.
- **Leaked secret coefficients:** if a few coefficients of `s` or `e` are
  known, the rest may be recoverable by linear algebra.

### ML-DSA / Dilithium

- **Nonce leakage:** `y` is sampled from a bounded range; if the RNG is weak
  or a few bits leak, use HNP/lattice.
- **Rejection sampling bugs:** a biased rejection loop leaks information about
  `y` or the secret.
- **Hint leakage:** `hint`/`make_hint` may reveal more than intended.
- **Weak seed:** deterministic key generation with a small seed.
- **Signature malleability:** a missing check on `z`/`c` lets you forge or
  reuse a signature.

### Falcon

- **Gaussian sampler issues:** floating-point precision bugs or a weak RNG
  leak the short vector.
- **Nonce reuse / deterministic signing:** recover the private basis.
- **Side channels:** timing or power on the FFT/sampler.
- **Small `N`:** a 512-dimensional NTRU lattice may be tractable with BKZ in a
  CTF if the parameters are weakened.

### NTRU / NTRU Prime

Public `h = g * f^{-1} mod q` with small `f, g`. Build the NTRU lattice:

```
B = [[q*I, 0],
     [H,   I]]
```

where `H` is the (negacyclic) multiplication matrix of `h`. LLL/BKZ finds a
short vector encoding `(f, g)`. In CTF, `N` is often small (e.g. 64–256) or
`f, g` are sparse, so LLL/BKZ works. `ctfkit.lattice` can handle small
dimensions; larger ones need fpylll/BKZ.

## 3. Lattice flattening

Many PQ schemes look intimidating but reduce to plain LWE:

```
b = A*s + e (mod q)
```

If `s` or `e` is small, sparse, ternary, or partially leaked, build the
standard embedding:

```
[ q*I   0 ]
[ A^T   I ]
```

and use Babai/CVP or LLL to find the closest vector. Check the noise width and
the number of samples: a CTF instance with tiny noise usually falls to Babai.

## 4. NTT and representation bugs

- The NTT may use a different root of unity, bit-reversal, or modulus than the
  spec.
- Coefficients may be serialized in a different order (Montgomery form,
  centered vs. non-negative).
- A missing `mod q` can produce negative coefficients that leak the secret.
- Compression/decompression may round differently than expected.

When the scheme's math "almost" works, compare a known test vector (e.g.
Kyber KAT) to the challenge implementation.

## 5. Practical workflow

1. Identify the scheme and parameters.
2. Check for a failure/timing oracle, nonce reuse, or a small seed.
3. Check whether the noise is small enough to flatten to LWE.
4. If the secret is partially known, set up a lattice with the known
   coefficients.
5. Only then consider a full BKZ attack; it is usually not the intended path.

Fast start: `python scripts/templates/pqc_triage.py <challenge-dir>` scans the
files for moduli / ring degrees / scheme names and implementation-bug clues and
prints the matching references, paper directions and templates.

## 6. Tooling added for PQ (2026)

`ctfkit.pqc`:

```python
from ctfkit import pqc
pqc.detect(q=3329)                 # -> ['ML-KEM/Kyber']
M = pqc.negacyclic_matrix(h, q)    # multiplication-by-h in Z_q[x]/(x^N+1)
pqc.negacyclic_mul(f, g, q)        # ring product
s, e = pqc.flatten_lwe(A, b, q)    # tiny-noise PQ instance -> LWE solve
```

Templates:

| Situation | Template |
|---|---|
| tiny noise / sparse or ternary secret → plain LWE | `scripts/templates/lwe_bkz.sage` (BKZ), `ctfkit.pqc.flatten_lwe` (small) |
| leaked bits of the ML-DSA mask `y`, faults, side-channel traces | `scripts/templates/ilwe_bp.sage` (belief propagation), `scripts/templates/lwe_hints.sage` (hint lattice) |
| NTRU public key `h = g/f` with small `f,g` | `scripts/templates/ntru.py`, `ctfkit.lattice.ntru_recover` |
| PQC challenge recognition / weakness scan | `scripts/templates/pqc_triage.py` |

## 7. 2026 attack directions (paper library)

The `pqc-implementation` direction in `assets/papers/` (25 papers) covers the
current research-grade attacks; use `scripts/papers/search.py --tag ML-DSA`,
`--tag ML-KEM`, `--tag HAWK`, etc. Highlights:

- **ML-DSA mask leakage** (`y` single bit / noisy bits / Hamming weight):
  2026/472, 2026/580, 2026/1712, 2026/2091 (ILWE + belief propagation),
  2026/1904 (horizontal fusion, 4 traces), 2026/056, 2026/2643.
- **ML-DSA faults / rejection sampling**: 2026/1344 (single-fault challenge
  sampling), 2026/1448 (randomized Dilithium), 2026/2567 (rejection-sampling
  fault evaluation).
- **ML-KEM oracles / implementation**: 2026/070 (DF oracle + LDPC),
  2026/1682 (incomplete FO comparison → linear key recovery), 2026/2069
  (comparison Booleanisation fault), 2026/820, 2026/2137, 2026/2448.
- **NTRU / Falcon**: 2026/582 (FrozenTRU cold boot), 2026/2124 (Falcon
  floating-point conversion leakage), 2026/2527 (NTRU+ module attacks).
- **Threshold signatures**: 2026/1386, 2026/1668 (nonce reuse),
  2026/2566 (fault-induced nonce repetition).
- **Structure / parameter evaluation**: 2026/279, 2026/366, 2026/1041,
  2026/2420.

Rule: the vulnerability tells you the **hint type** (perfect/approximate
coefficient, sign, noisy linear equation); map it to `lwe_hints.sage`
(construction) or `ilwe_bp.sage` (soft decoding) instead of attacking the
primitive directly.

## 8. Pitfalls

- **Do not treat Kyber/Dilithium as "just RSA/AES"**: the flag is usually
  encrypted with a derived symmetric key; recover the shared secret first.
- **Parameter mismatch:** a challenge may use a toy `N`/`q` that is not the
  standard; read the source.
- **Sage/fpylll needed:** large PQ lattices are not practical in pure Python.
  State the dependency and use Sage/BKZ when required.
- **FO oracle queries are limited:** plan the attack before connecting; a
  naive bit-by-bit attack may exceed the query budget.
