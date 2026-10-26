# Copy-Paste Solve Recipes

These are the attacks where small implementation details decide success. Use
the tested helper, then adapt only the parsing and key derivation.

## 1. ECDSA biased / partial nonce (HNP)

Input: signatures `(r_i, s_i, h_i)` and the known high part of each nonce
`leaked_i`, with `t` unknown low bits (`k_i = leaked_i*2^t + delta_i`).

```python
import re, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ctfkit import util, lattice

text = util.read_text("output.txt")
v = util.parse_named_ints(text)
q = v["n"][0]
t = v["unknown_low_bits"][0]
count = len([k for k in v if k.startswith("r")])

rs = [v[f"r{i}"][0] for i in range(count)]
ss = [v[f"s{i}"][0] for i in range(count)]
hs = [v[f"h{i}"][0] for i in range(count)]
leaked = [v[f"k_msb{i}"][0] for i in range(count)]

for d in lattice.ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, t):
    key = hashlib.sha256(str(d).encode()).digest()[:32]
    iv = bytes.fromhex(text.split("iv = ")[1].split()[0])
    ct = bytes.fromhex(text.split("ciphertext = ")[1].split()[0])
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    except ValueError:
        continue
    if b"flag{" in pt:
        print(pt)
        break
```

Notes:

- Need roughly `q.bit_length() / t` signatures.
- The helper returns `d` and `-d mod q`; verify by recomputing `r`.
- If only low bits are known, transform the equations (multiply by the inverse
  shift) or use the extended HNP; do not feed them to the MSB wrapper.

## 2. CBC padding oracle

Local or remote. The server must answer "valid/invalid padding" for a
ciphertext you choose.

```python
import re, socket
from ctfkit import blockcipher as bc, pow as powkit, util

tube = util.connect("127.0.0.1", 40124, timeout=10)
banner = tube.recvuntil(b"answer> ")
if b"proof of work" in banner.lower():
    prefix = re.search(rb"prefix=([0-9a-fA-F]+)", banner).group(1).decode()
    answer, _ = powkit.solve_pow(prefix=prefix, zeros=3)
    tube.sendline(answer)

head = tube.recvuntil(b"Send hex")
tube.recvline()  # drain the rest of the banner line
iv = bytes.fromhex(re.search(rb"IV=([0-9a-f]+)", head).group(1).decode())
ct = bytes.fromhex(re.search(rb"CT=([0-9a-f]+)", head).group(1).decode())

def oracle(msg: bytes) -> bool:
    tube.sendline(msg.hex())
    return tube.recvline().strip() == b"valid"

pt = bc.padding_oracle_attack(oracle, iv + ct, 16)
tube.close()
print(pt)
```

Notes:

- `iv + ct` is correct when the server decrypts the IV as the first block.
- Drain the banner tail before the first query; otherwise the first response
  is a leftover banner line.
- Compare the whole `valid`/`invalid` token, not a substring.
- The helper truncates after the target block; if the server rejects truncated
  ciphertext, attack only the last block.

## 3. MT19937 clone

Input: 624 consecutive `getrandbits(32)` outputs; ciphertext XORed with the
next outputs.

```python
from ctfkit import prng, util

obs = [int(x) for x in util.read_text("outputs.txt").split()]
ct = bytes.fromhex(util.read_text("ciphertext.hex").strip())
words = prng.mt19937_predict(obs, (len(ct) + 3) // 4)
ks = b"".join(w.to_bytes(4, "big") for w in words)
pt = bytes(a ^ b for a, b in zip(ct, ks))
print(pt)
```

Notes:

- 624 outputs clone MT only at a block boundary. If the challenge consumed
  extra draws, try shifting the alignment or recover the index.
- `random()` floats need a different attack (see `references/prng.md`).
- `randint`/`randrange` use rejection sampling; a raw-output clone is safer.

## 4. Hash length extension

Input: `md5(secret || message)`, the message, and the secret length. Target:
append data and compute a valid MAC without the secret.

```python
import re
from ctfkit import hashx, util

tube = util.connect("127.0.0.1", 40125, timeout=10)
banner = tube.recvuntil(b"Send:")
tube.recvline()  # drain banner tail
msg = re.search(rb"message=([^\r\n]+)", banner).group(1)
mac_hex = re.search(rb"mac=([0-9a-fA-F]+)", banner).group(1).decode()
secret_len = int(re.search(rb"secret_length=(\d+)", banner).group(1))

tail, new_mac = hashx.length_extension(
    "md5", bytes.fromhex(mac_hex), secret_len + len(msg), b"&admin=1"
)
forged = msg + tail
tube.sendline(forged.hex() + " " + new_mac.hex())
print(tube.recvline())
tube.close()
```

Notes:

- `length_extension` returns the bytes to append **and** the new digest.
- If the secret length is unknown, try 0..64 and submit each.
- HMAC and SHA-3/sponge constructions are not vulnerable this way.

## 5. AES-GCM nonce reuse

Two equal-length one-block messages, same nonce/key, empty AAD. Recover the
keystream (CTR) and optionally H/tag forgery.

```python
from ctfkit import blockcipher as bc

# c1, c2, t1, t2, known_p1 from the challenge
keystream = bc.xor_bytes(c1, known_p1)
p_other = bc.xor_bytes(c2, keystream)
print(p_other)

h, j0 = bc.gcm_nonce_reuse_forge(c1, t1, c2, t2)
new_tag = bc.gcm_forge_tag(h, j0, b"", new_ct)
```

Notes:

- The one-block helper recovers `H` from `T1^T2 = (C1^C2)*H^2`.
- Multi-block messages need polynomial factoring over `GF(2^128)`; use
  `nonce-disrespect` or a dedicated solver.
- The CTR keystream reuse always works, even if tag recovery is hard.

## 6. DH with smooth order

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ctfkit import util, ecc

text = util.read_text("output.txt")
v = util.parse_named_ints(text)
p, g, A, B = v["p"][0], v["g"][0], v["A"][0], v["B"][0]
a = ecc.dlog_prime_field(g, A, p)  # reduces to ord(g), then Pohlig-Hellman
assert pow(g, a, p) == A
S = pow(B, a, p)
key = hashlib.sha256(str(S).encode()).digest()[:32]
iv = bytes.fromhex(text.split("iv = ")[1].split()[0])
ct = bytes.fromhex(text.split("ciphertext = ")[1].split()[0])
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16))
```

Notes:

- `p-1` must be smooth; factor it first.
- `g` is often not a generator; the helper reduces to its actual order.
- Try `SHA256(S)`, `MD5(S)`, and raw `S` bytes if the KDF is unspecified.

## 7. Coppersmith partial `p`

Input: `n`, `p_high`, `shift` (unknown low bits `x`), `p = p_high*2^shift + x`.

```python
from ctfkit import util, lattice, rsa

v = util.parse_named_ints(util.read_text("output.txt"))
n, e, c = v["n"][0], v["e"][0], v["c"][0]
p_high, shift = v["p_high"][0], v["unknown_low_bits"][0]

got = lattice.factor_with_known_high_bits(n, p_high, shift)
assert got and got[0] * got[1] == n
p, q = got
d = pow(e, -1, (p - 1) * (q - 1))
print(rsa.decrypt_bytes(c, d, n))
```

Notes:

- The unknown part must be below roughly `N^(0.25)` for `beta=0.5`.
- If the lattice is too large, reduce `m`; if it is still slow, use Sage.

## 8. RSA LSB / parity oracle

```python
import re
from ctfkit import rsa, util, blockcipher as bc

# oracle(ct) -> LSB of Dec(ct)
def oracle(ct):
    tube.sendline(str(ct))
    return int(tube.recvline().strip())

m = rsa.lsb_oracle_attack(oracle, c, e, n, verify=lambda x: check_flag(x))
```

Notes:

- The estimate can be off by a few units; pass a strong `verify` (full flag
  pattern or a valid recomputation).
- Query count ≈ `n.bit_length()`.
- For a noisy oracle, use the standard attack then correct the last few bits
  by checking the plaintext.

## 9. Byte-at-a-time ECB

```python
from ctfkit import blockcipher as bc

def oracle(data: bytes) -> bytes:
    tube.sendline(data.hex())
    return bytes.fromhex(tube.recvline().strip().decode())

pt = bc.byte_at_a_time_ecb_decrypt(oracle, block_size=16)
print(pt)
```

Notes:

- The oracle must encrypt `attacker_input || secret`.
- Align the next secret byte to the end of a block with `block_size-1-len%block_size`
  filler bytes.
- If there is a fixed prefix, find its length and pass `prefix_len`.

## 10. Common parsing and flag extraction

```python
import re
from ctfkit import util

text = util.read_text("output.txt")
v = util.parse_named_ints(text)       # {'n': [...], 'e': [...], ...}
numbers = util.parse_ints(text)
fmt = util.detect_flag_regex(text)
flags = util.find_flags(plaintext)
```

For a decrypted binary or a server response:

```bash
"$PYTHON" scripts/flagcheck.py plaintext.bin --prefix flag
```

Notes:

- `parse_named_ints` ignores hex values (e.g. `iv = 6a...`) thanks to a
  boundary check; parse those separately with `bytes.fromhex`.
- A flag may be base64/hex encoded; `flagcheck` tries one layer.
- Do not lowercase or strip braces; submit exactly what you derived.

## 11. LWE via CVP/Babai

Input: `A` (m x n), `b = A*s + e mod q`, small `s`/`e`.

```python
from ctfkit import lattice

s, e = lattice.lwe_cvp_solve(A, b, q)
print("secret:", s)
# verify
assert all((sum(A[i][j]*s[j] for j in range(len(s))) + e[i]) % q == b[i] % q
           for i in range(len(A)))
```

For toy/weak CTF parameters this is enough. Larger dimensions need fpylll/BKZ
with the same `[[qI,0],[A^T,I]]` embedding. Map near-zero values to the
expected `{-1,0,1}`/binary range and try both vector conventions.

## 12. NTRU (toy/weak parameters)

Input: `h` (length N), `q`, ring `x^N +/- 1`, small `f, g`.

```python
from ctfkit import lattice

for f, g in lattice.ntru_recover(h, q, negacyclic=True, max_coeff=2):
    assert lattice.ntru_mul(h, f, q, True) == [x % q for x in g]
    print("f:", f)
    print("g:", g)
```

Pure LLL for small/sparse parameters; realistic NTRU needs BKZ
(fpylll/Sage). Recovered vectors may be rotations/signs of the original.

## 13. Manger / Bleichenbacher RSA oracles

```python
from ctfkit import rsa

# Manger: oracle True iff Dec(ct) < B = 2^(8*(k-1))
m = rsa.manger_attack(oracle, n, e, c, oracle_returns_valid=True,
                      max_queries=10000)

# Bleichenbacher: oracle True iff PKCS#1 v1.5 padding is valid
m = rsa.bleichenbacher_attack(oracle, n, e, c, max_queries=200_000)
```

Manger is ~`2*bit_length(n)` queries for typical OAEP blocks. Bleichenbacher
is data-dependent (tens of thousands); always set `max_queries` for a remote
service and log the transcript.

## 14. Shamir secret sharing / Fiat-Shamir nonce reuse

```python
from ctfkit import zkp

secret = zkp.shamir_recover([(x1, y1), (x2, y2), (x3, y3)], p)

# Schnorr/Fiat-Shamir: s_i = r + c_i*x with the same nonce r
x = zkp.fiat_shamir_nonce_reuse(s1, s2, c1, c2, q)
```

Check whether the challenge reuses polynomial coefficients/shares; if so,
subtract shares before interpolating.
