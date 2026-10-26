# Crypto Challenge Triage

The goal of triage is to turn a pile of files and a description into a ranked
list of attack hypotheses in a few minutes. Use three axes: primitive, shape,
symptom. The first strong match wins; confirm with a cheap computation.

## 0. First computations (do these before anything clever)

```python
# sizes
n.bit_length(), e.bit_length(), c.bit_length(), key.bit_length()
# relationships
p*q == n, (p-1)*(q-1) == phi, e*d % phi == 1
# modular sanity
c < n, m < n, pow(c, e, n) == c
# reuse
len(set(ns)) < len(ns), len(set(rs)) < len(rs), len(set(ivs)) < len(ivs)
# blocks
len(ct) % 16, duplicate 16-byte blocks, IV length
# signatures
gcd(n1, n2) for all pairs, repeated r
# curve
y^2 == x^3 + a*x + b mod p, discriminant 0, order smoothness
# PRNG
differences, gcd of difference determinants, output count (624?)
```

If any of these gives a clean hit, you have an attack path. If none do, read
the source again; the weakness is likely in the implementation.

## 1. Primitive identification

### RSA-shaped

Signals: `n, e, c`, `(n, e)` PEM key, `p, q`, `phi`, `d`, `dp`, `dq`, numbers
of 512–4096 bits with `e` a small odd number or a huge number.

Sub-signals and priors:

| Observation | First attack |
|---|---|
| `e = 3`, `c` small | exact cube root |
| `e = 3`, several `(n_i, c_i)` | Hastad broadcast |
| `e = 65537`, `n` reused with another `e` | common modulus |
| `e` close to `n` in size | Wiener (small `d`) |
| `p, q` close / `q - p` small | Fermat |
| `n` has small factor | trial division / rho / p-1 |
| `n_i` share a factor | pairwise gcd |
| `phi`, `d`, `dp`, `dq`, `qinv` | factor directly |
| high/low bits of `p` | Coppersmith partial factor |
| message prefix known | Coppersmith stereotyped message |
| two related messages | Franklin-Reiter / short-pad |
| `e = 2` | Rabin, four roots |
| signature + fault | CRT fault (gcd) |
| parity/LSB oracle | LSB oracle binary search |
| PKCS#1 v1.5 valid/invalid | Bleichenbacher |
| OAEP threshold/timing | Manger |

### ECC-shaped

Signals: `p, a, b`, `Gx, Gy`, point `(x, y)`, `n` (order), `r, s, z`/`h`
signatures, `Ed25519`, `X25519`, `secp256k1`.

| Observation | First attack |
|---|---|
| order has small factors | Pohlig-Hellman + CRT |
| point not validated | invalid curve |
| discriminant `4a^3+27b^2 == 0` | singular curve |
| `#E == p` | Smart's attack |
| small embedding degree | MOV/pairing |
| repeated `r` | ECDSA/DSA nonce reuse |
| nonce small/biased/partial | HNP lattice |
| fault in one signature | factor/recover from fault |
| X25519 low-order `u` | all-zero shared secret |

### DH-shaped

Signals: `p, g`, `A = g^a`, `B = g^b`, shared secret, KDF, MAC oracle.

| Observation | First attack |
|---|---|
| `g ∈ {0,1,p-1}` or peer in `{0,1,p-1,p}` | trivial shared secret |
| `p-1` smooth | Pohlig-Hellman |
| static key, `p-1` has small factors | small-subgroup/Lim-Lee |
| 512–768-bit `p` | Logjam/export-grade |
| X25519 low-order point | all-zero check |

### Symmetric-shaped

Signals: IV, nonce, 16/8-byte blocks, key, ciphertext, padding oracle,
encryption oracle, MAC.

| Observation | First attack |
|---|---|
| repeated blocks | ECB |
| selected-plaintext suffix | byte-at-a-time ECB |
| structured plaintext, block splicing | ECB cut-and-paste |
| controllable previous block/IV | CBC bit-flip |
| valid/invalid padding | CBC padding oracle |
| same nonce/keystream | CTR/stream reuse |
| GCM nonce reused | forbidden attack |
| CBC-MAC over `secret || msg` | length extension / block splicing |
| compressed-then-encrypted | CRIME/BREACH length oracle |

### Stream-shaped

Signals: XOR, keystream, LFSR, RC4, ChaCha, OTP, many ciphertexts.

| Observation | First attack |
|---|---|
| reused OTP/key | XOR ciphertexts, crib drag |
| LFSR, 2L bits known | Berlekamp-Massey |
| combined LFSR with bias | correlation attack |
| RC4 | second-byte bias / related-key |
| ChaCha20-Poly1305 nonce reuse | Poly1305 key recovery |

### PRNG-shaped

Signals: sequences, `random`, `rand`, `seed`, `LCG`, `MT`, `xorshift`, 624
outputs, timestamps.

| Observation | First attack |
|---|---|
| affine recurrence | LCG parameter recovery |
| only high/low bits | truncated LCG (brute force or lattice) |
| 624 × 32-bit | MT19937 clone |
| Python `random.random()` floats | MT float recovery |
| Java `Random` | 48-bit LCG, brute low 16 bits |
| V8 `Math.random()` | XorShift128+ state recovery (Z3) |
| C `srand(time())` | brute time window with ctypes/libc |
| small seed space | brute seed |

### Hash/MAC-shaped

Signals: digest, HMAC, `hash(secret || msg)`, CRC, length.

| Observation | First attack |
|---|---|
| `H(secret || msg)`, known secret length | length extension |
| `H(msg || secret)` | not length extension; look for collision/leak |
| HMAC | not length extension |
| CRC used as MAC | linear forgery |
| MD5/SHA-1 comparison of two messages | collision |
| sponge/SHA-3 | length extension does not apply |

### Lattice-shaped

Signals: modular linear equations with small unknowns, `A, b, q`, LWE,
knapsack, partial nonces, Coppersmith.

| Observation | First attack |
|---|---|
| `f(x) ≡ 0 mod N`, small `x` | Coppersmith univariate |
| known high bits of factor | partial-`p` Coppersmith |
| ECDSA partial/biased nonce | HNP |
| truncated LCG | HNP/truncated lattice |
| `b = A*s + e`, small `e` | LWE/CVP |
| subset sum | knapsack lattice |
| NTRU public key | NTRU lattice |
| small root of bivariate polynomial | bivariate Coppersmith (Sage) |

### ZKP/SSS-shaped

Signals: proofs, commitments, challenges, responses, shares, `verify`,
Fiat-Shamir, Groth16, graph coloring.

| Observation | First attack |
|---|---|
| challenge not bound to statement | replay/forge |
| nonce reused across proofs | recover witness |
| Shamir shares with reused coefficients | subtract shares |
| Groth16 `delta == gamma` | trivial forge |
| 3-coloring of impossible graph | hash collision / PRNG prediction |
| constraint system | Z3/OR-Tools |

### Exotic / PQ-shaped

Signals: Paillier, ElGamal, Goldwasser-Micali, Rabin, matrix/braid/tropical
groups, Kyber/ML-KEM, Dilithium/ML-DSA, Falcon, NTRU.

| Observation | First attack |
|---|---|
| Paillier encryption oracle | additive homomorphism, LSB oracle |
| ElGamal reused `k` | plaintext ratio |
| GM bit encryption | replicate ciphertext, force all-0/1 key |
| Rabin | four roots, parity oracle |
| matrix DH | linear algebra/Jordan form |
| braid DH | Alexander polynomial multiplicativity |
| tropical DH | residuation |
| Kyber/ML-KEM | FO failure oracle, NTT/representation bugs, tiny noise |
| Dilithium/Falcon | nonce leakage, weak randomness, implementation bugs |

## 2. Shape identification

### Output-only

Only `output.txt`/numbers. Parse named values, check relationships, then run
the RSA/ECC/PRNG decision tables. If everything looks random, check for a
hidden leak in the file (multiple values, comments, base64).

### Source-given

Read `challenge.py` line by line. Look for:

- `random` seeded with time / small seed,
- `pow(m, e, n)` without padding,
- reused nonce/IV/key,
- `assert` missing or wrong,
- `p = getPrime(256)` but `q = next_prime(p)`,
- `d` small or `e` huge,
- `flag` used as an integer without padding,
- a custom MAC/hash that is linear,
- a KDF that ignores the salt,
- a comparison that leaks timing,
- an oracle that returns more than yes/no.

### Service

Connect, capture the banner, identify the protocol (line/hex/base64/menu),
and count the queries you are allowed. Then map each interaction to an oracle
type in `references/remote.md`.

### Multi-stage

Many challenges combine two weaknesses:

- leak `p` high bits → Coppersmith → RSA decrypt → AES key,
- ECDSA nonce reuse → private key → AES-CBC decrypt,
- LCG prediction → XOR keystream → flag,
- padding oracle → plaintext → CBC bit-flip → admin token,
- HNP → private key → signature forgery.

If one attack gets you "almost" the flag, look for the second stage.

## 3. Symptom → attack priorities

1. **Small/weak parameter:** factor, small `e`, small `d`, small nonce, small
   seed, 512-bit DH, 8-bit key.
2. **Leak:** `phi/d/dp/dq`, high bits of `p`, nonce bits, PRNG state,
   intermediate hash state, server error messages.
3. **Reuse:** nonce, IV, keystream, modulus, prime, signature `r`, seed,
   padding oracle across messages.
4. **Missing validation:** point not on curve, `g` out of range, padding not
   checked, MAC not verified, length not checked, `e=1`, `n` user-supplied.
5. **Algebraic structure:** homomorphism, linearity, low-degree polynomial,
   small root, smooth order, singular curve.
6. **Implementation bug:** endianness, truncation, integer overflow, type
   confusion, timing, short-circuit evaluation, regex bypass.

## 4. Confidence and pivoting

- A hypothesis is **high confidence** when a cheap computation confirms its
  precondition (e.g., `gcd(n1,n2) > 1`, `p*q==n`, repeated block, smooth
  order, `p-1` smooth).
- **Medium** when the shape matches but the precondition needs a script.
- **Low** when it is a guess from the challenge name.

If two hypotheses are both plausible, run the cheaper one first. If it fails
in a way that contradicts its precondition, drop it and move on. Do not keep
retrying the same lattice with different parameters unless the bound analysis
says it should work.

Pivot to another category when:

- the files are mostly a binary/VM/obfuscated client → reverse,
- a pcap/disk/memory image must be carved first → forensics,
- the crypto is solved and only a network exploit remains → pwn/web,
- the challenge is an encoding/esoteric puzzle → misc.
