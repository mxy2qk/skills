---
name: ctf-crypto-solver
description: Solve CTF cryptography challenges end-to-end — inventory the challenge, classify the primitive and weakness, interact with nc/oracle services, write and run a solve script, and recover and validate the flag. Covers encoding/classical layers, RSA (small e, Wiener, Hastad, leaks, Coppersmith, Manger, LSB oracle), Diffie-Hellman, block and stream ciphers (ECB/CBC/CTR/GCM, padding oracles), PRNG (LCG/MT19937/Java/V8), ECC/ECDSA (invalid curve, singular, Pohlig-Hellman, nonce reuse, biased nonces), hash length extension, lattices/LWE/knapsack, ZKP/Shamir, exotic public-key schemes, and post-quantum weaknesses. Use this whenever the user gives a crypto CTF challenge, challenge files (challenge.py, output.txt, ciphertext, key, pcap), a host:port service with a crypto oracle, or asks to break/decrypt/crack a crypto task or write a solve script — even if they never say "CTF" or "crypto". Also use for follow-up questions on a challenge already in progress.
---

# CTF Crypto Solver

Solve the challenge, don't just describe it. The deliverable is a working
`solve.py`, the flag it prints, and a short explanation of the weakness.

Paths below are relative to this skill's directory. Read `references/triage.md`
first when the challenge type is not obvious.

## Operating principles

- **Cheap attacks first.** Factor small `n`, check small `e`, look for reused
  nonces/IVs, repeated blocks, leaked key material. Only then build lattices
  or custom algebra.
- **Keep a model, not a guess.** Write down: public parameters, secret,
  leak/oracle, constraints, message format, service protocol. Every attack is
  a statement about one of those fields.
- **One hypothesis at a time.** Verify it with a small computation before
  writing a long script.
- **Never fabricate a flag.** If the output is not printable, the attack did
  not work. Re-triage.
- **Timebox.** If an attack has not produced a verifiable intermediate result
  after a reasonable attempt, switch to the next hypothesis and say why.

## Phase 0 — Intake (first five minutes)

1. **Inventory the files.** Run the intake helper:
   ```bash
   "$PYTHON" scripts/intake.py <challenge-dir>
   ```
   It lists files, detects flag format, extracts named integers and bit
   lengths, finds `nc host port` / URLs, detects encodings, and ranks attack
   hypotheses. Use `--json` for machine-readable output.
2. **Read the source, don't execute it.** `challenge.py`, `server.py`,
   `task.sage`, and any helper module. The bug is usually visible as a missing
   check, a reused nonce, a short key, a leak, or a weak KDF. Use
   `references/source-audit.md` as the line-by-line checklist.
3. **Record the protocol.** For a service: how it greets, what it accepts
   (line / hex / base64 / binary), how many queries are allowed, whether it is
   stateful, and where the flag appears (decrypted plaintext, server response,
   signature, token).
4. **Detect the flag format.** `scripts/flagcheck.py` and
   `util.detect_flag_regex`. If the description says `flag{...}`, that is a
   free crib for XOR/Vigenère/AES-known-plaintext attacks.
5. **Write a short `analysis.md`** (3–8 bullets): primitive, public values,
   secret, leak, oracle, sizes, flag format, top three attack surfaces. This
   prevents circular reasoning later.

Run the environment probe and toolkit self-test once per session:
```bash
bash scripts/env.sh
"$PYTHON" scripts/selftest.py
```
If a check fails, fix the environment first; a broken helper costs more than
the check. No SageMath is assumed; `ctfkit.lattice` uses sympy's LLL when
available and a pure-Python fallback otherwise.

## Phase 1 — Classify

Use three axes. The first match usually wins; confirm with the triage details
in `references/triage.md`.

### By primitive

| Primitive | Signals | Reference |
|---|---|---|
| Classical / encoding | printable text, letter frequencies, base64/hex/Morse layers | `references/classical.md` |
| RSA | `n, e, c`, PEM key, `phi/d/dp/dq/p_high` | `references/rsa.md` |
| Diffie-Hellman | `p, g, A, B`, shared secret, `g^ab` | `references/dh.md` |
| ECC / ECDSA | `p, a, b, Gx, Gy, n`, points, `r, s, z` | `references/ecc.md` |
| ECDH MSB oracle / babyDH2 | x-coordinate MSBs of `a·P` for chosen `P`, shared secret needed | `references/ec-hnp.md` |
| Symmetric / modes | IV, nonce, ciphertext blocks, padding oracle | `references/symmetric.md` |
| Stream ciphers | keystream, LFSR, RC4, ChaCha, OTP reuse | `references/stream.md` |
| PRNG | sequence of numbers, `random`, `rand`, `MT`, `LCG` | `references/prng.md` |
| Hash / MAC | digest, HMAC, `secret || msg`, CRC | `references/hash.md` |
| Lattice / LWE | small unknowns, modular linear equations, `n, q, A, b` | `references/lattice.md` |
| ZKP / SSS | proofs, commitments, shares, Fiat-Shamir | `references/zkp.md` |
| Exotic public-key | Paillier, ElGamal, Goldwasser-Micali, Rabin | `references/exotic.md` |
| Post-quantum | Kyber/ML-KEM, Dilithium/ML-DSA, Falcon, NTRU | `references/post-quantum.md` |

### By challenge shape

| Shape | First move |
|---|---|
| Only `output.txt` with numbers | Parse named values, compute bit lengths, check `p*q==n`, factor if small |
| `challenge.py` given | Read it line by line; identify the exact operation and missed validation |
| Service `nc host port` | Connect, capture banner, solve PoW if any, map the menu/query format |
| Oracle returns valid/invalid | Padding oracle / MAC oracle / membership oracle; count queries and build the byte-by-byte attack |
| Oracle returns a bit | LSB/parity oracle, sign oracle, comparison oracle; binary search |
| Oracle encrypts attacker input | Chosen-plaintext: ECB byte-at-a-time, cut-and-paste, CBC bit-flip |
| Multiple keys/signatures | Common modulus, shared prime, nonce reuse, biased nonce |
| Leaked partial key | Coppersmith, HNP, partial-`p`, partial-`dp` |
| Text looks scrambled | Classical cipher or encoding layer; try layers first |

### By symptom

| Symptom | Attack |
|---|---|
| `e = 3/5/17`, short message | exact e-th root, `k*n` search, Hastad broadcast |
| `e` huge | Wiener (small `d`), or `gcd(e, phi)` issues |
| `n` reused, two exponents | common modulus |
| many `n_i`, same message | Hastad / CRT; shared factor via pairwise gcd |
| `p`, `q` close | Fermat / Coppersmith on `p-q` |
| `phi`, `d`, `dp`, `dq` leaked | factor directly; `gcd(a^(e*dp)-a, n)` |
| high bits of `p` known | Coppersmith partial factor |
| signature repeats `r` | ECDSA/DSA nonce reuse |
| nonce small/biased | HNP lattice |
| curve discriminant 0 | singular curve → additive/multiplicative group |
| curve order smooth | Pohlig-Hellman / small subgroup |
| `#E = p` | Smart's attack (Sage) |
| repeated ciphertext blocks | ECB |
| IV/previous block controllable | CBC bit-flip |
| padding valid/invalid oracle | CBC padding oracle |
| same nonce/keystream twice | CTR/stream XOR recovery |
| GCM nonce reused | forbidden attack (recover H, forge tag) |
| 624 consecutive 32-bit outputs | MT19937 clone |
| affine recurrence | LCG parameter recovery |
| digest + `secret || msg` | length extension |
| small unknowns in modular equations | LLL / Coppersmith / HNP / LWE |

## Phase 2 — Choose and run the attack

Order by cost:

1. Decode obvious layers (base64/hex/URL/Morse/ROT).
2. Check for leaked keys, tiny moduli, `p*q==n`, trivial DH values.
3. Factor with trial division, Fermat, Pollard rho, Pollard p-1.
4. Check small `e`, common modulus, Hastad, nonce reuse, repeated blocks.
5. Check PRNG state/parameter recovery.
6. Check padding/bit-flip/ECB oracles.
7. Use Coppersmith/HNP/LWE only when a small unknown is genuinely present.
8. Use custom algebra/exotic structures last.

Every attack has a precondition. State it, test it, then run it. If the
precondition fails, do not force the attack.

### Universal first checks

```python
n.bit_length(); e; c < n; pow(c, e, n) == c?
gcd(n1, n2) for all pairs; math.gcd(e, phi); p*q == n
ciphertext block count and duplicate blocks; IV length; key length
repeated r in signatures; nonce/IV reuse across messages
```

## Phase 3 — Remote and nc services

Read `references/remote.md` for the full playbook. Essentials:

- **Connect and capture the banner.** Use `util.connect(host, port,
  log_path=...)`; the transcript is invaluable when parsing fails.
- **Solve proof-of-work first.** `ctfkit.pow.parse_pow` /
  `parse_and_solve` / `remote.solve_pow_for_tube`. Common forms: leading zero
  hex chars, leading zero bits, hashcash-style prefix.
- **Map the protocol.** Line-based? Hex or base64 payload? Menu numbers? A
  fixed prompt? Binary length-prefixed? Send a harmless probe and observe.
- **Respect the query budget.** Padding oracles need ~4096 queries/block;
  LSB oracles ~`bit_length(n)`; byte-at-a-time ~256/byte. If the service
  limits queries, choose the attack that fits the budget.
- **Cache deterministic oracle answers.** Same input → same output; memoize.
- **Reconnect once on timeout.** Use `remote.retry`; do not silently spin.
- **Wrap the oracle in a function** so the same attack code works locally and
  remotely. For local servers use `remote.connect_process`.
- **Do not restart a service that is already running** unless the challenge
  says to; the target ciphertext/IV/state may change.

Oracle patterns and query shapes:

| Oracle | Query | Recover |
|---|---|---|
| CBC padding valid/invalid | crafted IV/ciphertext | plaintext block-by-block |
| ECB encryption of input+secret | chosen plaintext | secret byte-by-byte |
| RSA parity/LSB | `c * 2^(e*i) mod n` | plaintext via binary search |
| RSA PKCS#1 valid/invalid | chosen ciphertext | Bleichenbacher / Manger |
| ECDSA/DSA signature | chosen messages | nonce reuse / biased nonce |
| MAC valid/invalid | chosen messages | forgery / length extension |
| DH shared-secret check | small-subgroup elements | static key mod r, CRT |
| GCM encrypt with nonce | two messages | H and tag forgery |

## Phase 4 — Write the solve

- One `solve.py` in the challenge directory. Parameters at the top, attack,
  decode, then an explicit flag check.
- Print intermediates (factors, recovered key, plaintext) so a failed
  assumption is visible.
- Use integer arithmetic. Never `int(x ** (1/k))`; use `util.iroot` /
  `util.is_perfect_power`.
- Try both endiannesses when bytes look wrong; print hex.
- For remote solves, separate `--local` / `--remote` paths or a single
  `HOST/PORT` constant; keep the oracle callable small.
- Verify before declaring success:
  - RSA: `pow(m, e, n) == c`, `p*q == n`.
  - Symmetric: padding validates, plaintext is printable.
  - PRNG: predictions match held-out outputs.
  - Hash: forged digest equals a locally recomputed hash.
  - ECC: recovered `d` reproduces `r`, `s`.
  - Remote: the server accepts the forged value/flag.
- If the flag is not found, report what worked and what failed. Do not invent
  a flag.

## Phase 5 — Flag handling

Read `references/flag-formats.md`. Essentials:

- Common wrappers: `flag{...}`, `FLAG{...}`, `ctf{...}`, `picoCTF{...}`,
  `DASCTF{...}`, `NSSCTF{...}`, `HTB{...}`, `DUCTF{...}`, competition names,
  and any `name{...}` pattern. Some platforms accept raw 32/40/64 hex or a
  UUID; some require the wrapper.
- Detect the format from the description first; do not assume `flag{`.
- Use the known prefix as a crib: XOR/Vigenère/AES known-plaintext, or to
  score classical candidates.
- Normalize only whitespace/quotes; never lowercase or strip braces.
- Decoys exist. A source file may contain `flag{test}` or a placeholder.
  Submit only a value you derived by solving.
- If the plaintext contains multiple candidates, rank by common prefix and
  printable body; verify against the challenge format.

```bash
"$PYTHON" scripts/flagcheck.py plaintext.bin
"$PYTHON" scripts/flagcheck.py ciphertext.hex --prefix flag
```

## Phase 6 — Verify and report

- Recompute the ciphertext/signature/tag from the recovered secret.
- Check the flag against the expected regex and the challenge description.
- State the weakness in one or two sentences: what was reused, leaked,
  unpadded, too small, or not validated.
- Give the exact command to reproduce (`"$PYTHON" solve.py`).
- If part of the challenge is blocked (server down, missing file), finish
  everything else and state the gap.

## Attack catalog (quick reference)

### Classical and encoding

Caesar/ROT, affine, Atbash, Vigenère (IC + Kasiski + word-score refinement),
substitution (word-shape + annealing), rail fence, columnar transposition,
Playfair, Bacon, Morse, single-byte/repeating XOR, OTP reuse, homophonic,
Polybius, layered base64/hex/URL. See `references/classical.md`.

### RSA

Small `e` (exact root / `k*n` search), common modulus, Hastad broadcast,
Wiener, Boneh-Durfee, Fermat, Pollard rho/p-1, shared primes, `phi/d/dp/dq`
leaks, partial `p` (Coppersmith), stereotyped message, Franklin-Reiter,
short-pad, Rabin, multi-prime, `gcd(e, phi)>1`, LSB/parity oracle, Manger,
Bleichenbacher, CRT fault, homomorphic decryption oracle, signature forgeries.
See `references/rsa.md` and `references/rsa-crt-exponents.md`; runnable
templates `scripts/templates/boneh_durfee.sage`, `scripts/templates/crt_rsa_partial.sage`,
`scripts/templates/crt_rsa_small_dp.sage`.

### Diffie-Hellman

Trivial `g`/peer values, Pohlig-Hellman when `p-1` is smooth, small-subgroup
confinement / Lim-Lee, X25519 low-order points, Logjam/export-grade triage.
See `references/dh.md`.

### ECC / ECDSA / DSA

Small subgroup, invalid curve, singular curve (node/cusp), Smart's attack,
Pohlig-Hellman/BSGS, MOV/pairing, ECDSA/DSA nonce reuse, biased/partial nonce
HNP, fault injection, Ed25519 torsion. See `references/ecc.md`; runnable
templates `scripts/templates/smart_anomalous.sage`, `scripts/templates/mov_fr.sage`.

**ECDH x-coordinate MSB oracle (EC-HNP / babyDH2 lineage).** A service leaks
most significant bits of `x(a·P)` for points `P` you choose, and you must
recover the shared `x(a·B)` (or an AES key derived from it). This is *not* the
nonce HNP: the equations are quadratic and need the Asiacrypt-2022 lattice
`L(n,d,t)`. **Check feasibility first**: the number of pairs `n = (queries-1)/2`
is the binding constraint, and with `n=9` the reachable unknown bound is only
~2^209–2^215 regardless of `d`. Details, pitfalls, calibration case and a full
case study in `references/ec-hnp.md`; runnable template
`scripts/templates/ec_hnp.sage`.

### Symmetric / modes

ECB detection, cut-and-paste, byte-at-a-time ECB, CBC bit-flip, padding
oracle, IV reuse, CBC-MAC forgery, CTR bit-flip/reuse, GCM nonce reuse
(forbidden attack, multi-block), CFB/OFB state recovery, compression oracle.
See `references/symmetric.md`; multi-block GCM template
`scripts/templates/gcm_reuse.py`.

### Stream ciphers

OTP/many-time pad and crib dragging, LFSR/Berlekamp-Massey, correlation
attacks, RC4 biases, ChaCha20-Poly1305 nonce reuse. See `references/stream.md`.

### PRNG

LCG parameter recovery (known/unknown modulus), truncated LCG, MT19937
untemper/clone, float outputs, Java `Random`, V8 XorShift128+, C
`srand/rand`, time-based seeds, logistic map. See `references/prng.md`;
V8 recovery template `scripts/templates/v8_xorshift128plus.py` (needs z3).

### Hashes and MACs

Length extension (MD5/SHA-1/SHA-256), MD5/SHA-1 collisions, CRC32
linearity/forgery, HMAC pitfalls, sponge constructions. See
`references/hash.md`.

### Lattices

LLL/BKZ, Coppersmith (univariate, partial `p`, stereotyped message),
HNP/biased ECDSA nonces, truncated LCG, LWE/Ring-LWE/Module-LWE, subset
sum/knapsack, NTRU, orthogonal lattices. See `references/lattice.md` and
`references/lwe-hints.md`; runnable templates
`scripts/templates/coppersmith_multi.sage` (multivariate small roots),
`scripts/templates/lwe_bkz.sage` (embedding + Babai/BKZ),
`scripts/templates/lwe_hints.sage` (LWE with extra hints) and
`scripts/templates/lip_check.sage` (LIP detection, toy dims). For LIP / HAWK /
ideal lattices and dual/hybrid LWE parameter evaluation, see
`references/lip-hawk.md` and `references/lwe-dual.md`.

### ZKP / secret sharing

Fiat-Shamir/weak challenge, sigma protocol nonce reuse, Shamir SSS reused
coefficients, Groth16 broken setup/replay, graph 3-coloring, Z3/OR-Tools
constraint solving. See `references/zkp.md`.

### Exotic public-key

Paillier (additive homomorphism, LSB oracle), ElGamal (reused `k`, trivial
DLP), Goldwasser-Micali (bit replication), Rabin (four roots, parity oracle),
matrix/braid/tropical DH, isogeny notes. See `references/exotic.md`.

### Post-quantum

ML-KEM/Kyber, ML-DSA/Dilithium, Falcon, NTRU recognition; FO failure oracle;
NTT/representation bugs; lattice flattening. See `references/post-quantum.md`
and `references/pqc-faults.md` (side-channel/fault → key recovery flow;
runnable `scripts/templates/ilwe_bp.sage`). Start with
`scripts/templates/pqc_triage.py <dir>`; helpers in `ctfkit.pqc`
(`detect`, `negacyclic_matrix`, `flatten_lwe`).

## Optional external tools

The built-in toolkit handles the common cases without Sage. Reach for these
only when a reference says the pure-Python path is not enough:

| Tool | Use |
|---|---|
| `RsaCtfTool` | automated RSA attack sweep (small e, Wiener, Fermat, shared factors) |
| `crypto-attacks` (jvdsn) | Coppersmith, bivariate/HNP, LWE, ECDSA attacks in Sage |
| `fpylll` | BKZ / CVP for lattice dimensions where pure LLL is too weak |
| SageMath | Smart, MOV/FR, Boneh-Durfee, bivariate Coppersmith, BKZ; read `references/sage.md` and use `scripts/templates/smart_anomalous.sage`, `mov_fr.sage`, `boneh_durfee.sage`, `coppersmith_multi.sage`, `lwe_bkz.sage`, `lwe_hints.sage` |
| `nonce-disrespect` | multi-block AES-GCM forbidden attack |
| `hashpumpy` | hash length extension (alternative to `ctfkit.hashx`) |
| `z3-solver` | PRNG state recovery and constraint solving |
| `py_ecc` | pairings and curve helpers |

```bash
pip install fpylll z3-solver hashpumpy py-ecc
git clone https://github.com/jvdsn/crypto-attacks
git clone https://github.com/RsaCtfTool/RsaCtfTool
```

State the dependency if a solve uses one of these; do not silently assume it
is installed.

## Paper library (2026)

A curated, searchable index of 2026 IACR ePrint attacks relevant to lattice,
Sage, PQC and RSA challenges lives in `assets/papers/`:

- `assets/papers/index.md` — all 91 papers, grouped by direction, one line each
  (ID, date, title, CTF rating, challenge shape).
- `assets/papers/paper-map.md` — challenge-signal quick table plus, per
  direction, a "challenge shape → paper → template" table. Start here when a
  new challenge smells paper-based.
- `assets/papers/papers.json` — structured records with Chinese summaries,
  tags, `ctf_relevance` (1–5) and the matching template/tool.
- `assets/papers/<direction>.md` — six directions: `lattice-lwe-hints`,
  `pqc-implementation`, `sis-lip-ideal`, `coppersmith-rsa`,
  `hnp-signatures`, `ecc-pairing-isogeny`.

Use it when a challenge's parameters sit just past a classical bound, when a
new primitive name appears (ML-KEM/ML-DSA/HAWK/LIP/LtHash/Polar-KEM), or when
the task hands you extra "hints" (leaked bits, faults, side-channel traces).
`paper-map.md` is the quick lookup; `index.md` and the direction pages carry
the full summaries.

```bash
"$PYTHON" scripts/papers/search.py hint --min-rating 4
"$PYTHON" scripts/papers/search.py --direction coppersmith-rsa
"$PYTHON" scripts/papers/search.py --tag HAWK
```

The library is text-only and ships with the skill. Refreshing it is documented
in `assets/papers/README.md`; fetch/build scripts are in `scripts/papers/`.

## Toolkit

```python
import sys
sys.path.insert(0, r"<absolute path to this skill>/scripts")
from ctfkit import util, classical, rsa, lattice, prng, blockcipher, ecc, hashx, dh, stream, exotic, pow
```

**Library first for hard primitives.** For HNP/biased nonces, Coppersmith,
padding oracles, GCM nonce reuse, MT19937 cloning, and hash length extension,
call the tested helper before writing your own. These have subtle
scaling/offset details (HNP centering, padding-oracle truncation, GCM length
blocks) that are easy to get wrong. If you must reimplement, compare against
the helper on a synthetic instance first. Start from the closest file in
`scripts/templates/` and `references/recipes.md`.

| Module | Key functions |
|---|---|
| `util` | int/bytes, CRT, `iroot`, primality, English scoring, `find_flags`, `Tube`, `connect` |
| `classical` | Caesar/affine/Vigenère/substitution/rail/columnar/XOR/Morse/Playfair |
| `rsa` | small e, common modulus, Hastad, Wiener, Fermat, rho/p-1, leaks, Franklin-Reiter, Rabin, LSB oracle, Manger, Bleichenbacher, CRT fault, nth roots |
| `lattice` | `lll_reduce`, `coppersmith_univariate`, `factor_with_known_high_bits`, `hnp_solve`, `ecdsa_partial_nonce_recover`, `subset_sum_solve`, `lwe_cvp_solve`, `ntru_recover` |
| `prng` | LCG recovery/prediction, truncated LCG, MT19937 clone |
| `blockcipher` | ECB/CBC/CTR/GCM attacks, padding oracle, byte-at-a-time, GCM forgery |
| `ecc` | curve arithmetic, BSGS, Pohlig-Hellman, ECDSA/DSA nonce reuse, biased nonce, singular curve |
| `hashx` | MD5/SHA-1/SHA-256 length extension |
| `dh` | trivial `g`, smoothness, Pohlig-Hellman, subgroup recovery, X25519 low-order |
| `stream` | LFSR/Berlekamp-Massey, RC4, many-time pad, crib drag |
| `exotic` | Paillier, ElGamal, Goldwasser-Micali, Rabin helpers |
| `zkp` | Lagrange/Shamir recovery, Fiat-Shamir/Schnorr nonce reuse |
| `pow` | parse/solve PoW from a banner |
| `remote` | socket/subprocess tubes, PoW, menus, retry |

**Self-contained deliverable.** Prefer a single `solve.py` with no
`PYTHONPATH` tricks. Inline short attacks (copy the function from `ctfkit`);
they are written to be copy-pasteable. For large attacks (Coppersmith, HNP,
padding oracle, GCM), importing `ctfkit` is acceptable; state the dependency
and, for portability, copy `scripts/ctfkit/` next to the solve.

## Common failure modes

- **Endianness.** RSA/bytes are big-endian by default; MD5 state is
  little-endian. Print hex.
- **Block off-by-one.** Padding oracle truncates after the target block;
  byte-at-a-time aligns the secret to a block end.
- **Forgot padding.** Decrypted text often ends in `\x01`–`\x10`.
- **Parsed the wrong number.** `output.txt` may contain decoys; verify
  `p*q==n` and parameter sizes.
- **Assumed `flag{`.** Detect the format first.
- **Coppersmith bound.** The root must be below `N^(beta^2/d)`; check before
  building a large lattice.
- **HNP scaling.** Use the `(x_i - X/2)` centered embedding with `X/m`
  scaling; a naive `q^2` lattice returns trivial vectors.
- **PRNG alignment.** 624 outputs clone MT only at a block boundary; account
  for extra draws, `randint` rejection, and `random()` consuming two words.
- **Oracle budget.** Count queries before starting; a 4096-query attack will
  fail against a 500-query service.
- **Forcing a result.** Noise is not a flag.

## Reference index

- `references/triage.md` — full classification tree, archetypes, first checks
- `references/source-audit.md` — line-by-line audit checklist for challenge source
- `references/recipes.md` — copy-paste solve recipes for common advanced attacks
- `references/remote.md` — nc/oracle protocols, PoW, menus, budgets, logging
- `references/flag-formats.md` — flag formats, extraction, cribs, decoys
- `references/rsa.md` — RSA attacks and conditions
- `references/dh.md` — finite-field DH attacks
- `references/ecc.md` — ECC/ECDSA/DSA attacks
- `references/ec-hnp.md` — ECDH x-coordinate MSB oracle (EC-HNP / babyDH2): feasibility limits, L(n,d,t) lattice, flatter+msolve pipeline, toolchain pitfalls, literature map, case study
- `references/symmetric.md` — block cipher modes and oracles
- `references/stream.md` — stream ciphers and OTP
- `references/prng.md` — PRNG state recovery
- `references/hash.md` — length extension, collisions, CRC
- `references/lattice.md` — LLL, Coppersmith, HNP, LWE, knapsack
- `references/zkp.md` — ZKP, Shamir, constraint solving
- `references/exotic.md` — Paillier, ElGamal, GM, Rabin, exotic groups
- `references/post-quantum.md` — ML-KEM/ML-DSA/Falcon/NTRU notes
- `references/classical.md` — classical ciphers and simple XOR
- `references/workflow.md` — longer-form intake/verification checklist
