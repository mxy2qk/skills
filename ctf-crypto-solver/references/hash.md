# Hash Attacks

## 1. Merkle-Damgard and length extension

MD5, SHA-1, and SHA-256 process the message in 64-byte blocks, carrying a
chaining state. The digest is the final state. Given `H(secret || message)`
and the length of `secret || message`, you can continue hashing from that
state without knowing the secret.

The attack:

1. Parse the digest into the internal state.
2. Append the padding that the original hash applied:
   `0x80`, zeros, then the 64-bit bit-length of `secret || message` (little-
   endian for MD5, big-endian for SHA-1/SHA-256).
3. Append your extension and hash it with the parsed state as the starting
   value, using the new total length for the final padding.

```python
from ctfkit import hashx

tail, forged = hashx.length_extension(
    "sha256",
    original_digest,          # bytes
    len(secret) + len(message),
    b"&admin=1",
)
forged_message = message + tail
# send forged_message and forged to the server
```

If the server compares hex, use `forged.hex()`.

**Unknown secret length.** Try every length from 0 to ~64 (or the plausible
range); the forged message differs because the glue padding encodes the
length. Submit each until one is accepted.

## 2. Algorithm specifics

| Algorithm | Block | Digest | State words | Length field | Word endian |
|---|---|---|---|---|---|
| MD5 | 64 | 16 | 4 × 32-bit | little-endian | little |
| SHA-1 | 64 | 20 | 5 × 32-bit | big-endian | big |
| SHA-256 | 64 | 32 | 8 × 32-bit | big-endian | big |

`ctfkit.hashx` implements all three and exposes `hash_bytes` for self-checks.

## 3. When length extension does not work

- **HMAC.** `HMAC(K, m) = H(K xor opad || H(K xor ipad || m))`. The outer hash
  rejects extensions; length extension does not apply.
- **Truncated digests.** If the server keeps only the first `k` bytes, you can
  still extend, but the truncated state is incomplete; you need the full
  internal state, which a truncated digest does not give. Brute force or find
  another bug.
- **Different construction.** SHA-3/Keccak, BLAKE2, and sponge constructions
  are not Merkle-Damgard; length extension does not apply.
- **Secret appended** (`H(message || secret)`). The secret is at the end;
  length extension does not help. Look for a different attack (e.g. hash
  collision, or the secret is recoverable).

## 4. Collisions

- **MD5:** practical chosen-prefix collisions exist. If the challenge checks
  two different messages with the same MD5, generate a collision pair offline
  (tools: `hashclash`, `fastcoll`).
- **SHA-1:** SHAttered collision for two specific PDFs; chosen-prefix
  collisions are expensive but feasible.
- **SHA-256:** no practical collision; look for length extension, a weak
  comparison, or a different bug.

Collision attacks are usually not the intended path in CTF unless the
challenge explicitly checks `md5(a) == md5(b)` for distinct `a, b`.

## 5. Other hash-based pitfalls

- **`==` vs `hmac.compare_digest`.** Timing attacks on byte comparisons are
  possible but usually need many remote queries.
- **Type confusion.** `hashlib.md5(x)` vs `hashlib.md5(x.encode())`; bytes vs
  str mismatches can change the input.
- **Null bytes.** Some parsers truncate at `\x00`; a MAC over the truncated
  string may validate.
- **CRC/checksums.** CRC is linear; forge it by solving a small linear system
  over GF(2), not by brute force.
- **Hash as a PRNG / key derivation.** If `key = H(seed)` and the seed is
  small, brute force the seed.

## 6. CRC, HMAC, and collision pitfalls

### CRC is linear

CRC is an affine function over GF(2). If a challenge uses `CRC32(msg ||
secret)` as a MAC, append 4 chosen bytes to force any target CRC without the
secret. Solve the 32-bit linear system, or use a CRC-forging script.

- **ZIP CRC brute force:** ZIP local headers store the CRC32 of each file
  unencrypted. For small files (≤ 6 printable bytes), brute-force the content
  against the stored CRC.
- **Introspective CRC:** find an ASCII string whose CRC equals itself; this is
  a linear system over GF(2) with free variables chosen for printable output.

### HMAC is not length-extendable

`HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m))`. The outer hash blocks
extensions. Do not apply length extension to HMAC.

Other HMAC pitfalls:

- **HMAC-CRC linearity:** if the "HMAC" is actually a CRC-based construction,
  the key may be recoverable from one message-MAC pair.
- **Flawed HMAC:** `H((key xor msg) + msg)` can leak key bits: query `msg=0`
  to get `H(key)`, then `msg=2^i` to test bit `i`.
- **Key length:** HMAC pre-hashes keys longer than the block size; a login
  that hashes the password differently may bypass the check.

### MD5/SHA-1 collisions

- **MD5:** practical chosen-prefix collisions (`fastcoll`, `hashclash`). Useful
  when the challenge compares `md5(a) == md5(b)` for distinct messages, or
  when a nonce is derived from `MD5(prefix || counter)`.
- **SHA-1:** SHAttered collision for specific PDFs; chosen-prefix collisions
  are expensive but feasible.
- **SHA-256:** no practical collision; look for length extension, a weak
  comparison, or a different bug.

### Truncated and non-standard digests

- A truncated digest does not expose the full internal state, so length
  extension does not directly work. If the server keeps only the first `k`
  bytes, you may still extend if you can brute-force the missing state bytes
  for small `k`.
- SHA-3/Keccak, BLAKE2, and sponge constructions are not Merkle-Damgard;
  length extension does not apply. Look for state recovery, rate/capacity
  issues, or a collision in a reduced-round variant.
- A custom iterative hash may leak intermediate states; if the state update
  is invertible, isolate per-block values and brute-force small blocks.

## 7. Verification

After forging, recompute locally:

```python
import hashlib
assert hashlib.sha256(secret + forged_message).digest() == forged
```

If you do not know the secret, verify the structure: the glue padding must put
the total length at a multiple of 64, and the final length field must equal the
new total.
