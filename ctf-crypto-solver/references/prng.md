# PRNG Attacks

## 1. Linear congruential generators

```
x_{n+1} = (a * x_n + c) mod m
```

**Known modulus.** Three consecutive outputs determine `a` and `c`:

```
a = (x_2 - x_1) / (x_1 - x_0) mod m
c = x_1 - a*x_0 mod m
```

**Unknown modulus.** Differences `d_n = x_{n+1} - x_n` satisfy
`d_{n+1} = a*d_n mod m`, so `m` divides `d_{n+2}*d_n - d_{n+1}^2`. Take the
gcd of several such terms. The gcd may be a multiple of the true modulus;
the recovered recurrence still predicts correctly.

```python
from ctfkit import prng
m, a, c = prng.recover_lcg_parameters(outputs)
nxt = prng.predict_lcg(outputs, count=3)
```

**Truncated outputs.** If only the high `bits_kept` bits are leaked, brute
force the unknown low bits (small truncation) or use a lattice (large
truncation). `prng.crack_truncated_lcg` brute-forces the low bits.

**Small modulus / seed.** If `m` and the seed space are small, brute force
the seed and check the first outputs.

**Nonlinear or unknown generator.** Recover the state space: check whether
outputs are a permutation, whether the recurrence is affine, etc. If it is a
xorshift/PCG, try to invert the update from two outputs; otherwise treat it as
a black box and look for a seed leak.

## 2. Mersenne Twister (MT19937)

State: 624 32-bit words. Output: `temper(mt[index])`, where

```
y ^= y >> 11
y ^= (y << 7)  & 0x9d2c5680
y ^= (y << 15) & 0xefc60000
y ^= y >> 18
```

The transformation is invertible: `untemper` recovers a state word from an
output. With 624 consecutive outputs you reconstruct the full state and
predict all future outputs.

```python
from ctfkit import prng
pred = prng.mt19937_predict(outputs, count=5)
assert pred == held_out
```

**Alignment.** The 624 outputs must be consecutive and start at a block
boundary. If the challenge consumed extra draws before the leak (for example
`randint` rejection sampling, or `random.random()` uses 2 words per value),
align by finding the offset that makes predictions match. `MT19937.from_outputs`
assumes index 0 after the block; `from_state(state, index=...)` lets you set a
different position.

**Python `random` specifics.**

- `getrandbits(32)` returns one tempered 32-bit word.
- `random()` consumes two words: 27 + 26 bits.
- `randrange(n)` / `randint(a,b)` uses rejection sampling; the number of words
  consumed depends on `n` and the rejected draws.
- `shuffle` consumes multiple words per swap.
- `randbytes(n)` is `getrandbits(8*n)` in chunks.
- The seed is expanded with `init_by_array`, not the classic
  `init_genrand(seed)`; don't assume `MT19937(seed)` reproduces Python's
  `Random(seed)` unless you reimplement Python's seeding.

If the challenge prints full 32-bit `getrandbits(32)` outputs, cloning is
direct. If it prints `randint(0, 255)` values, reconstructing the state needs
more care: each value reveals 8 bits of a tempered word with rejection, and
you may need a constraint solver or many outputs.

## 3. Java `Random`

48-bit LCG: `seed = (seed * 0x5DEECE66D + 0xB) mod 2^48`, high 32 bits used.
Two consecutive `nextInt()` outputs (or one `nextLong`) are enough to brute
force the low 16 bits and recover the state. If seeded with
`System.currentTimeMillis()`, brute force a time window around the challenge.

## 4. Other generators

- **xorshift/PCG:** invert the update if the parameters are known; otherwise
  use observed outputs to solve for the state bits.
- **LFSR:** Berlekamp-Massey from 2L bits; predict the rest.
- **AES-CTR as PRNG:** a reused key/nonce reduces to keystream recovery.
- **Hash chains:** if outputs are `H(seed || counter)`, look for a length
  extension or a leaked seed.

## 4b. Other common PRNGs

### Java `Random`

48-bit LCG: `seed = (seed * 0x5DEECE66D + 0xB) mod 2^48`; outputs are the high
32 bits. Two consecutive `nextInt()` outputs (or one `nextLong`) are enough to
brute-force the low 16 bits and recover the state.

- `nextInt(bound)` uses rejection; the number of draws varies.
- `new Random()` seeded with `System.currentTimeMillis()`: brute-force a
  window around the challenge time.
- `Random(seed)` with a known/small seed: reproduce the sequence directly.

```python
from ctfkit import prng
pred = prng.java_random_predict(outputs[:2], count=10)  # predicts after out2
```

### V8 `Math.random()` (XorShift128+)

V8 uses XorShift128+ over two 64-bit words; `Math.random()` returns the top 53
bits of each 64-bit step divided by `2^53`. Given a few consecutive outputs,
recover the two state words with a Z3 `QF_BV` solver, then predict.

```python
from ctfkit import prng
g = prng.XorShift128Plus(state0, state1)   # reference implementation
g.next64(); g.next_double()
prng.v8_double_to_int(0.123)                # invert Math.random() to 53 bits
```

Runnable template: `scripts/templates/v8_xorshift128plus.py` (needs
`pip install z3-solver`; takes JSON `outputs`, and predicts from the recovered
state). Note that V8 caches values LIFO in some call sites; reverse the order
if the sequence looks shuffled. Tools: `d0nutptr/v8_rand_buster`.

### C `srand`/`rand`

A binary may use `srand(time(NULL))` and `rand()` for keys/XOR masks. Python's
`random` is a different PRNG. Call libc directly:

```python
import ctypes, time
libc = ctypes.CDLL("libc.so.6")  # or msvcrt on Windows
libc.srand(int(time.time()))
[libc.rand() for _ in range(10)]
```

Brute-force a time window if the exact second is unknown. On Windows, the
MSVCRT `rand` algorithm differs; use the challenge's own libc if possible.

### MT19937 from floats

`random.random()` exposes 53 bits per call (two words), but a float only
reveals ~8 usable bits per output in many challenge formats. With ~3360
outputs, a GF(2) linear system (the `not_random` matrix) recovers the full
state. This is slower and more specialized than the integer case; use the
`not_random` library or build the matrix offline.

### Logistic map / chaotic PRNG

`x = r*x*(1-x)` with `r ≈ 3.99–4.0`; keystream often
`struct.pack("<f", x)`. Recover the seed by brute-forcing high-precision
decimals or by matching the first keystream floats. Small parameter/seed
spaces are the intended weakness.

### Truncated LCG as a lattice

If `x_{i+1} = a*x_i + b mod m` and only the high bits `y_i = x_i >> t` are
leaked, write `x_i = y_i*2^t + z_i` with small `z_i`. The recurrence becomes

```
z_{i+1} - a*z_i ≡ a*y_i*2^t + b - y_{i+1}*2^t (mod m)
```

Build the lattice with `m` on the diagonal, the right-hand sides in the last
row, and `2^t` in the corner; LLL exposes the small residuals. For small `t`,
`prng.crack_truncated_lcg` brute-forces the low bits instead.

### Middle-square, xorshift, custom recurrences

- **Middle-square:** invert the square and search the middle digits.
- **xorshift:** invert the shifts/XORs if the parameters are known; otherwise
  recover the state with Z3 from enough outputs.
- **Custom affine/quadratic recurrences:** write the recurrence, solve for the
  parameters from outputs, verify on held-out values.

## 5. Pitfalls

- **Modulus multiples.** The recovered `m` may be `k*m_true`; predictions still
  work, but don't compare `m` to the challenge's stated modulus blindly.
- **Output truncation.** `x >> k` loses the low bits; solve for them rather
  than assuming the outputs are full state.
- **Byte order.** LCG outputs may be serialized little-endian; try both.
- **Warm-up draws.** Many generators discard initial outputs; if predictions
  are off by a constant offset, try shifting the observed sequence.
- **Rejection sampling.** `randint`/`randrange` do not consume a fixed number
  of words; a state clone from raw outputs is safer than from `randint`.
