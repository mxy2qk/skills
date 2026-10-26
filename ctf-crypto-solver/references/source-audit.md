# Source Audit Checklist

When `challenge.py`/`server.py` is provided, the intended bug is almost
always visible. Read it once for structure, then audit these areas.

## 1. Key generation

- Which primes? `getPrime(bits)`, `next_prime`, `random.getrandbits`, a
  hardcoded list?
- Are `p` and `q` independent? Check for `q = next_prime(p)`, `q = p + small`,
  `q = p`, reused primes across keys.
- Is `e` standard? `3`, `5`, `17`, `65537`, `1`, or random?
- Is `d` small? Is `n` reused?
- Are curve parameters standard? Is the generator on the curve? Is the order
  checked?
- Is the seed for a PRNG time-based, small, or reused?
- Is the key derived from a password with a weak KDF (MD5/SHA1, no salt)?

## 2. Encryption / signature

- Is padding used? `pow(m, e, n)` without padding is a red flag.
- Which mode? ECB (deterministic), CBC (IV handling), CTR (nonce reuse),
  GCM (nonce reuse), CFB/OFB (state recovery).
- How is the IV/nonce generated? Random, fixed, counter, reused across
  messages, prepended to the ciphertext?
- Is the key derived from public data? `SHA256(public_key) xor seed` is
  recoverable.
- Is the MAC computed before or after encryption? Encrypt-then-MAC vs
  MAC-then-encrypt vs MAC-and-encrypt.
- Is the MAC over `secret || message` (length extension) or `message ||
  secret` (not length extension)?
- Are signatures deterministic? Is `k` reused, small, biased, or derived from
  a weak PRNG?
- Is `r` validated? Is `s` canonical? Is the message hash truncated?

## 3. Randomness

- `random.seed(...)`: what is the seed? Time, PID, small integer, fixed?
- `os.urandom` vs `random`: the latter is predictable.
- `getrandbits`, `randint`, `randrange`, `shuffle`: how many words per call?
- Are nonces/IVs/keys generated once and reused?
- Is a "random" challenge value derived from a counter or hash of public data?

## 4. Oracle and interface

- What exactly does the service return? Plaintext, ciphertext, a bit, a
  boolean, a timing difference, an error message?
- How many queries are allowed? Is there a rate limit?
- Is the service stateful? Does it rotate keys per connection?
- Can you choose the key, IV, nonce, modulus, generator, or curve?
- Can you submit malformed lengths/points and observe the error?
- Does the service leak decrypted bytes in an error message?
- Does it compare strings with `==` (timing) or a constant-time function?

## 5. Validation and bounds

- Are points checked to be on the curve? Is the subgroup checked?
- Is `g` checked to be in `[2, p-2]`? Is the peer public value checked?
- Is the padding checked? Is the MAC checked before decryption?
- Is the length checked? Can you truncate/extend a ciphertext?
- Is the exponent/prime size checked? Can you pass `e = 1` or a composite `n`?
- Are user-supplied parameters used directly in `pow`, inverse, or CRT?

## 6. Flag handling

- Where is the flag? In the source, in an environment variable, in a file, in
  the server's plaintext?
- Is it encrypted with a derived key? Which KDF and mode?
- Is it printed only after a successful oracle/forge?
- Is there a decoy flag in the source? Do not submit it.

## 7. Common anti-patterns → attack

| Code pattern | Attack |
|---|---|
| `pow(m, e, n)` with small `e` | small-e root / Hastad |
| `d = getPrime(128)` | Wiener / Boneh-Durfee |
| `q = next_prime(p)` | Fermat / Coppersmith |
| `p = getPrime(256); q = getPrime(256)` reused | shared factor |
| `phi`, `dp`, `dq` printed | direct factor |
| `AES.MODE_ECB` | cut-and-paste / byte-at-a-time |
| fixed IV | CBC bit-flip / IV reuse |
| `nonce = random.getrandbits(64)` reused | CTR/GCM nonce reuse |
| `k = random.randrange(1, 2**32)` | ECDSA/DSA nonce bias/HNP |
| `random.seed(time.time())` | brute time window |
| `random.seed(seed)` with small seed | brute seed |
| `hash(secret + msg)` | length extension |
| `CRC32(msg + secret)` | CRC linear forgery |
| `g = 1` / no range check | trivial DH secret |
| `E.order()` smooth | Pohlig-Hellman |
| point not validated | invalid curve |
| `assert` missing on verifier | forge/replay |
| `A = 0` accepted in DH/SRP | zero shared secret |
| `pickle`/`eval` on user data | RCE (pivot to pwn) |

## 8. Efficient reading

1. Skim imports and constants: which libraries, which parameters?
2. Find the `main`/handler: what does the user send, what comes back?
3. Find the flag path: how is it read and printed?
4. Find the crypto calls: `pow`, `AES`, `hashlib`, `random`, `inverse`,
   `EllipticCurve`, `Matrix`.
5. Work backward from the flag to the key and from the key to the weakness.
6. Check every `if`/`assert` for what it *does not* validate.

## 9. Ask these questions

- What is the secret, and what would let me compute it?
- What is the smallest unknown? (A small root, a short nonce, a small seed.)
- What is reused? (Nonce, IV, modulus, prime, key, signature `r`.)
- What is leaked? (Bits of `p`/`d`/`k`, `phi`, a decrypted block, an error.)
- What can I choose? (Plaintext, ciphertext, key, IV, point, generator.)
- What does the oracle return, and how many bits per query?
- What is the intended attack's query/compute budget?

If the answer to one of these is "nothing", the bug is likely in a place you
have not read yet: a helper module, a Dockerfile, a requirements pin, or the
challenge description itself.
