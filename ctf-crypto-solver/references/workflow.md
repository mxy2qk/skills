# CTF Crypto Workflow

> Fast path: `SKILL.md` → `scripts/intake.py` → `references/triage.md`.
> Source audit: `references/source-audit.md`. Remote/nc: `references/remote.md`.
> Flags: `references/flag-formats.md`. Ready-made code: `references/recipes.md`
> and `scripts/templates/`. This file is the longer-form checklist.

## 1. Read the challenge, not just the files

Before touching math, answer:

- What is the flag format? Often stated (`flag{...}`, `CTF{...}`), sometimes
  implied by the platform.
- Is there a remote service? Host, port, protocol (line-based, menu, binary).
- What does the challenge name hint at? Names like "Wiener", "Copper",
  "ECB", "Three", "Broadcast", "Nonce" are usually direct hints.
- What is the expected difficulty? A 50-point challenge will not need a
  47-dimensional lattice.

Read `challenge.py`/`server.py` line by line. The bug is usually one of:

- a missing padding/validation check,
- a reused nonce/IV/seed,
- a key or prime that is too small,
- an oracle that leaks one bit,
- a leak of `phi`, `d`, `dp`, high bits of `p`,
- a hash used as `H(secret || message)`.

## 2. Extract parameters safely

`output.txt` often contains more numbers than you need, or numbers in an
order you did not expect.

```python
from ctfkit import util
text = util.read_text("output.txt")
named = util.parse_named_ints(text)   # {'n': [...], 'e': [...], 'c': [...]}
ints = util.parse_ints(text)
```

Sanity-check relationships before solving: `p*q == n`, `e*d % phi == 1`,
`c < n`, points on the curve, block lengths multiples of 16.

## 3. Try cheap hypotheses first

In rough order of cost:

1. Decode obvious layers: base64, hex, URL-encoding, Morse, ROT13/47.
2. Check for a leaked private key or a trivially small modulus.
3. Factor `n` with trial division, Fermat, Pollard rho, Pollard p-1.
4. Check small public exponent with an exact integer root.
5. Check reused nonces/IVs/keystreams.
6. Check repeated ciphertext blocks (ECB).
7. Check weak PRNG parameters.
8. Only then reach for lattices/Coppersmith or custom math.

Each hypothesis should be testable in a few lines. Do that before writing a
100-line solve.

## 4. Recognize combined weaknesses

Real challenges often stack two simple bugs:

- RSA with small `e` **and** a partially known message → Coppersmith.
- RSA with a leaked `dp` **and** a large `e` → factor from `dp`.
- CBC padding oracle **plus** a flag appended to the plaintext → decrypt
  backwards.
- LCG **plus** truncated outputs → lattice or low-bit brute force.
- ECDSA **plus** a biased nonce → lattice (Hidden Number Problem).
- Hash length extension **plus** an unknown secret length → try lengths
  0–64 and check which forged MAC the server accepts.

If one attack is "almost" working, look for the second weakness that closes
the gap.

## 5. Write a solve that proves itself

```python
# parameters
n = ...
e = ...
c = ...

# attack
p, q = factor(n)
assert p * q == n
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# decrypt
m = pow(c, d, n)
pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(pt)

# verify
assert pow(m, e, n) == c
flags = util.find_flags(pt)
assert flags, "no flag found"
print(flags[0])
```

Assertions turn a silent wrong answer into a visible failure. Use them.

## 6. Verify against a second source

- Recompute the ciphertext from the recovered plaintext.
- Predict a held-out PRNG output.
- Check that PKCS#7 padding is valid and the plaintext is printable.
- For remote challenges, confirm the flag with the server when possible.

## 7. Report honestly

If the attack failed, say what you tried, what the outputs were, and what
assumption seems wrong. A clear negative result is useful; a fabricated flag
is not. If part of the challenge is blocked (missing file, server down), solve
what you can and state the gap.
