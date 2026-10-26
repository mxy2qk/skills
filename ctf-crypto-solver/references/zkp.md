# ZKP, Secret Sharing, and Constraint Solving

Crypto CTF ZKP tasks are rarely about breaking a sound proof system. They are
about a bad challenge, reused randomness, a broken setup, or a constraint
solver problem disguised as crypto.

## 1. Sigma protocols and Fiat-Shamir

A typical proof:

```
commit  t = g^r
challenge c = H(t, statement)        (Fiat-Shamir)
response s = r + c*x
verify  g^s == t * y^c
```

Attack surfaces:

- **Challenge not binding:** `c` does not include the statement or the
  session; replay a proof for a different statement.
- **Challenge predictable:** `c` comes from a weak PRNG or a timestamp;
  predict it and choose `t` accordingly.
- **Nonce reuse:** the same `r` in two proofs with different challenges leaks
  `x = (s1 - s2) / (c1 - c2)`. This is the Schnorr/ECDSA nonce-reuse attack.
- **Small challenge space:** brute-force `c` and solve for `x`.
- **Missing verification:** the verifier checks the equation but not the
  group membership or the range of the response.

```python
# Schnorr/Fiat-Shamir nonce reuse
from ctfkit import zkp
x = zkp.fiat_shamir_nonce_reuse(s1, s2, c1, c2, q)
```

## 2. Shamir secret sharing

Share `i` is `(i, f(i))` for a random polynomial `f` of degree `t-1` with
`f(0) = secret`.

Attacks:

- **Reused polynomial coefficients:** if the same random coefficients are used
  for every secret byte/share, subtracting two shares cancels the randomness
  and leaves plaintext differences.
- **Deterministic coefficients:** one share plus a seeded RNG may give a
  univariate equation in the secret.
- **Too many shares / low threshold:** interpolate directly with Lagrange.
- **Shares over a small field:** brute-force the missing share.
- **Share indices predictable:** if the dealer uses `i = 1,2,...` and the
  polynomial is low-degree, a few shares suffice.

```python
from ctfkit import zkp
secret = zkp.shamir_recover([(x1, y1), (x2, y2), (x3, y3)], p)
```

Manual Lagrange at 0 (if you prefer not to import the helper):

```python
def lagrange_zero(points, p):
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = num * (-xj) % p
            den = den * (xi - xj) % p
        secret = (secret + yi * num * pow(den, -1, p)) % p
    return secret
```

## 3. Groth16 and SNARK pitfalls

- **Broken setup (`delta == gamma`):** forge a proof trivially:
  `A = alpha`, `B = beta`, `C = -vk_x`. Always read the verifier constants.
- **Proof replay:** an unconstrained nullifier or no replay tracking lets you
  submit the same proof repeatedly.
- **Unconstrained inputs:** a public input not wired into the circuit can be
  chosen freely.
- **KZG/pairing oracle:** a pairing oracle that returns the pairing of
  attacker-chosen points can leak the trapdoor or let you forge.
- **DV-SNARG:** with verifier oracle access, learn the secret values from
  unconstrained pairs and cancel CRS entries.

## 4. Graph 3-coloring and combinatorial proofs

- A 3-coloring proof for an impossible graph (e.g. `K4`) is a red flag: the
  challenge is about cheating the protocol, not coloring the graph.
- Color with a greedy solver (`networkx.coloring.greedy_color` with
  `strategy="saturation_largest_first"`) to get a valid coloring for a
  colorable graph.
- If the protocol commits to colors with a hash, look for hash collisions or
  a predictable salt/nonce.
- If the verifier asks for one edge at a time, replay/record answers across
  sessions; a single committed coloring must satisfy every edge.

## 5. Garbled circuits

- Free-XOR garbling: XOR three truth-table entries to recover the global
  `Delta`.
- If the evaluator can choose input labels, evaluate both outputs and learn a
  wire value.
- If the same garbled circuit is reused with different inputs, labels may
  repeat and leak.

## 6. Constraint solving

When the "crypto" reduces to equations over bits/bytes, use:

- **Z3:** `BitVec` for bit-level ops, `Int` for arbitrary precision. Good for
  PRNG state recovery, VM/bytecode constraints, and small arithmetic ciphers.
- **OR-Tools CP-SAT:** good for combinatorial constraints (bigram
  substitution, scheduling, automata).
- **sympy:** polynomial equations, modular roots, linear algebra.
- **Guessing + propagation:** if the system is almost linear, solve the linear
  part and brute-force the small nonlinear part.

Z3 skeleton:

```python
from z3 import Solver, BitVec, sat

x = BitVec("x", 32)
s = Solver()
s.add(x * 0x1234567 + 0x9E3779B9 == 0xDEADBEEF)
if s.check() == sat:
    print(s.model()[x])
```

## 7. Pitfalls

- **Field vs. integer arithmetic:** proofs often use a prime field; do not
  mix in integer division.
- **Challenge derivation:** verify exactly what is hashed (statement,
  commitment, session ID, domain separator).
- **Transcript order:** a missing domain separator allows cross-protocol
  replay.
- **Randomness:** a "random" challenge from Python `random` is predictable;
  see `references/prng.md`.
- **Share encoding:** shares may be packed bytes, not field elements; unpack
  before interpolating.
