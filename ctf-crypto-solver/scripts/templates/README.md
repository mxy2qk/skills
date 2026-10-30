# Solve Templates

Copy the closest file into the challenge directory, adjust the paths/host/port,
and run it. These use the tested `ctfkit` helpers, so you do not have to
reimplement the error-prone parts.

| Template | Use when |
|---|---|
| `hnp_ecdsa.py` | ECDSA/DSA nonces are small, biased, or partially leaked |
| `padding_oracle.py` | CBC server answers valid/invalid for chosen ciphertext |
| `v8_xorshift128plus.py` | recover V8 `Math.random()` (XorShift128+) state from a few outputs and predict (needs `z3-solver`) |
| `pqc_triage.py` | scan a challenge dir for PQC fingerprints (moduli, ring, scheme names) and implementation-bug clues |
| `mt19937.py` | 624 consecutive 32-bit PRNG outputs + XORed ciphertext |
| `length_extension.py` | `H(secret || message)` MAC with known secret length |
| `gcm_reuse.py` | AES-GCM nonce reused across messages (single- or multi-block, AAD; JSON input; forges tags) |
| `dh_smooth.py` | finite-field DH with smooth `p-1` |
| `coppersmith_partial_p.py` | RSA with high bits of `p` known |
| `lwe_cvp.py` | small/ternary LWE instance in a JSON file |
| `ntru.py` | toy/weak-parameter NTRU public key in a JSON file |
| `ec_hnp.sage` | ECDH service leaks MSBs of `x(a·P)` (EC-HNP / babyDH2); needs Sage + flatter + msolve. Read `references/ec-hnp.md` first — check `n` and the bound before running |
| `smart_anomalous.sage` | elliptic curve with `#E == p` (anomalous); Smart's attack recovers the DLP in O(1) |
| `mov_fr.sage` | supersingular / low-embedding-degree curve; MOV (Weil) or Frey-Rück (Tate) transfers the ECDLP to `F_{p^k}` |
| `boneh_durfee.sage` | RSA with small private exponent `d < N^0.292` (Herrmann-May lattice) |
| `coppersmith_multi.sage` | small roots of a polynomial over `Zmod(N)` in several variables (HNP, partial `dp`, related messages) |
| `lwe_bkz.sage` | LWE `b = A·s + e` via the `[[q·I,0],[Aᵀ,I]]` embedding + Babai; LLL by default, BKZ with a block-size argument |
| `lwe_hints.sage` | LWE with extra linear hints `<v,s> = l` (perfect → elimination; approximate → appended rows). Read `references/lwe-hints.md` first |
| `crt_rsa_partial.sage` | CRT-RSA with partial `d_p`/`d_q` (MSB known → Coppersmith; LSB best-effort). Read `references/rsa-crt-exponents.md` first |
| `crt_rsa_small_dp.sage` | CRT-RSA with **unknown small** `d_p,d_q` (2026/2109 unravelled linearization; toy-scale validated). Read `references/rsa-crt-exponents.md` §2 |
| `ilwe_bp.sage` | Integer-LWE belief-propagation solver for PQC fault/leakage relations (`r = <a,s> + e`, small e). Read `references/pqc-faults.md` |
| `lip_check.sage` | Lattice-isomorphism check for toy dims (invariants + signed-permutation search). Read `references/lip-hawk.md` |

Usage:

```bash
PYTHON=/c/code/miniconda/python.exe   # or your interpreter from scripts/env.sh

"$PYTHON" scripts/templates/hnp_ecdsa.py --dir challenge/
"$PYTHON" scripts/templates/padding_oracle.py --port 40124 --prompt "answer> "
"$PYTHON" scripts/templates/mt19937.py --dir challenge/ --block-size 4 --endian big
"$PYTHON" scripts/templates/length_extension.py --port 40125 --append "&admin=1"
"$PYTHON" scripts/templates/dh_smooth.py --dir challenge/
"$PYTHON" scripts/templates/coppersmith_partial_p.py --dir challenge/
"$PYTHON" scripts/templates/lwe_cvp.py --file challenge/lwe.json
"$PYTHON" scripts/templates/ntru.py --file challenge/ntru.json
"$PYTHON" scripts/templates/gcm_reuse.py challenge/instance.json
"$PYTHON" scripts/templates/v8_xorshift128plus.py challenge/instance.json  # needs z3
"$PYTHON" scripts/templates/pqc_triage.py challenge/
# gcm_reuse.py is a fill-in template: edit the ciphertext/tag constants first.
```

`ec_hnp.sage` needs Sage and the `flatter`/`msolve` binaries instead of `ctfkit`:

```bash
sage scripts/templates/ec_hnp.sage challenge/instance.json 3 0
# optional: FLATTER=/path/to/flatter MSOLVE=/path/to/msolve sage ...
```

It prints `S.x` (the shared x-coordinate) and, if the instance JSON contains a
ciphertext, the AES plaintext. Read `references/ec-hnp.md` first: with only a
few pairs the lattice cannot reach the required unknown-bit bound, and flatter
at 900+ dimensions can exceed a 600 s service alarm.

The other five `.sage` templates read an `instance.json` sidecar and need only
plain Sage (no flatter/msolve):

```bash
sage scripts/templates/smart_anomalous.sage challenge/instance.json
sage scripts/templates/mov_fr.sage           challenge/instance.json [mov|fr]
sage scripts/templates/boneh_durfee.sage     challenge/instance.json
sage scripts/templates/coppersmith_multi.sage challenge/instance.json
sage scripts/templates/lwe_bkz.sage          challenge/instance.json [block_size]
sage scripts/templates/lwe_hints.sage        challenge/instance.json [block_size]
sage scripts/templates/crt_rsa_partial.sage  challenge/instance.json
sage scripts/templates/crt_rsa_small_dp.sage challenge/instance.json
sage scripts/templates/ilwe_bp.sage           challenge/instance.json
sage scripts/templates/lip_check.sage         challenge/instance.json
```

Instance formats are documented at the top of each file; integer fields may be
decimal or `0x`-hex strings. Run them through Docker with the `sagemath` image
and `TMPDIR` set to a writable mount — see `references/sage.md`. Each prints the
recovered value and, when a ciphertext is supplied, the flag.

The templates print the recovered plaintext and extract the first
`word{...}` flag. Adapt the key derivation and banner parsing to the
challenge; every challenge formats those differently.
