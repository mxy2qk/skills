# Solve Templates

Copy the closest file into the challenge directory, adjust the paths/host/port,
and run it. These use the tested `ctfkit` helpers, so you do not have to
reimplement the error-prone parts.

| Template | Use when |
|---|---|
| `hnp_ecdsa.py` | ECDSA/DSA nonces are small, biased, or partially leaked |
| `padding_oracle.py` | CBC server answers valid/invalid for chosen ciphertext |
| `mt19937.py` | 624 consecutive 32-bit PRNG outputs + XORed ciphertext |
| `length_extension.py` | `H(secret || message)` MAC with known secret length |
| `gcm_reuse.py` | AES-GCM nonce reused across messages |
| `dh_smooth.py` | finite-field DH with smooth `p-1` |
| `coppersmith_partial_p.py` | RSA with high bits of `p` known |
| `lwe_cvp.py` | small/ternary LWE instance in a JSON file |
| `ntru.py` | toy/weak-parameter NTRU public key in a JSON file |
| `ec_hnp.sage` | ECDH service leaks MSBs of `x(a·P)` (EC-HNP / babyDH2); needs Sage + flatter + msolve. Read `references/ec-hnp.md` first — check `n` and the bound before running |

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

The templates print the recovered plaintext and extract the first
`word{...}` flag. Adapt the key derivation and banner parsing to the
challenge; every challenge formats those differently.
