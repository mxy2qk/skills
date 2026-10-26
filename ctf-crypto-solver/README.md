# ctf-crypto-solver

A CTF cryptography skill for agents: intake the challenge, classify the
primitive/weakness, interact with `nc`/oracle services, write and run a solve
script, and recover/validate the flag.

## Layout

```
ctf-crypto-solver/
├── SKILL.md                 # the operating manual (read this first)
├── references/              # 18 deep-dive docs (triage, RSA, ECC, lattice, ...)
└── scripts/
    ├── env.sh               # find Python and optional packages
    ├── selftest.py          # 75 checks; run once per session
    ├── intake.py            # challenge inventory + ranked hypotheses
    ├── flagcheck.py         # flag extraction/ranking/normalization
    ├── templates/           # copy-paste solves (HNP, padding oracle, MT, ...)
    └── ctfkit/              # the attack library
        ├── util, classical, rsa, lattice, prng
        ├── blockcipher, ecc, hashx, dh, stream, exotic, zkp, pow
        └── data/            # English word-frequency table for scoring
```

## Quick start

```bash
# 1. find a Python with pycryptodome/sympy/gmpy2
bash scripts/env.sh
# -> PYTHON=/path/to/python

# 2. verify the toolkit
"$PYTHON" scripts/selftest.py

# 3. triage a challenge
"$PYTHON" scripts/intake.py /path/to/challenge/

# 4. (optional) extract/rank flags from a decrypted blob
"$PYTHON" scripts/flagcheck.py plaintext.bin --prefix flag
```

Then read `SKILL.md` and follow the phase workflow. The reference index at the
bottom of `SKILL.md` points to the relevant deep dive.

## Requirements

- Python 3.8+.
- `pycryptodome` for AES/RSA/GCM primitives.
- `sympy` strongly recommended (fast LLL, factorization, modular roots).
- `gmpy2` optional (faster big-int arithmetic).
- No SageMath required. Coppersmith/HNP/LLL use sympy's LLL, with a pure
  Python fallback. Large BKZ/bivariate/Smart attacks need Sage/fpylll; the
  references say so explicitly.

## Design notes

- The toolkit prefers tested helpers for error-prone attacks (HNP centering,
  padding-oracle truncation, GCM length blocks). `scripts/templates/` contains
  ready-to-adapt solves.
- `intake.py` never executes challenge code; it only reads text and inspects
  magic bytes.
- Flags are never fabricated. `flagcheck.py` ranks candidates and warns about
  placeholders/ decoys in source files.
- The skill assumes offline-first: connect to a service only when the
  challenge provides a host:port, and do not restart a running service.

## Reproducing the evaluation

`evals/` contains the synthetic challenges and grading scripts used during
development (classical, RSA, padding oracle, PRNG, ECDSA, DH, MT, length
extension, and a PoW-gated nc service). They are not part of the packaged
`.skill` file.
