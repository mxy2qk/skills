# Symmetric Ciphers and Modes

## 0. Identify the mode from the challenge

| Clue | Mode |
|---|---|
| Repeated 16-byte blocks in ciphertext | ECB |
| Oracle: "your input" encryption, repeated blocks | ECB |
| Ciphertext length multiple of block size, IV provided, no repeats | CBC |
| XOR with a keystream, same plaintext encrypts identically across messages | CTR/stream |
| Oracle returns padding valid/invalid | CBC padding oracle |
| MAC over `secret || msg` | CBC-MAC / length extension |
| Nonce reused with GCM | GCM forbidden attack |

## 1. PKCS#7

Pad to a multiple of the block size by appending `k` bytes of value `k`
(always adds a full block if already aligned). Remove padding only after
validating all `k` bytes.

```python
from ctfkit import blockcipher as bc
padded = bc.pkcs7_pad(pt)
pt = bc.pkcs7_unpad(decrypted)
```

## 2. ECB

**Detection.** For 16-byte blocks, count duplicates. ECB leaks equality of
plaintext blocks.

```python
bc.detect_ecb(ciphertext, 16)
```

**Cut and paste.** If the oracle builds a structured plaintext (e.g.
`email=...&uid=...&role=user`) and returns ECB ciphertext, reorder blocks so a
block containing `admin` is used as the `role` block. You usually need to
arrange input lengths so the target block is byte-aligned.

**Byte-at-a-time decryption.** Oracle encrypts `attacker_input || secret` in
ECB. Feed `block_size - 1 - (len(known) % block_size)` bytes so the next
secret byte is the last byte of a block; build a dictionary of that block for
each guess.

```python
pt = bc.byte_at_a_time_ecb_decrypt(oracle, block_size=16)
```

- `oracle(data) -> ciphertext` must include the secret and padding.
- If the oracle prepends a fixed prefix, find the prefix length by looking for
  the input length at which blocks become attacker-controlled, then pass
  `prefix_len` (or align manually).
- Stop using the ciphertext length: the padded secret length is constant.

## 3. CBC

Encryption: `C_i = E(P_i xor C_{i-1})`, `C_0 = IV`.
Decryption: `P_i = D(C_i) xor C_{i-1}`.

**Bit flipping.** If you control `C_{i-1}` (or the IV), changing it by
`delta` changes `P_i` by the same `delta`, while garbling `P_{i-1}`:

```python
new_prev = bc.cbc_bitflip(orig_prev, known_plain, target_plain)
```

Typical target: change `admin=0` to `admin=1`, or `role=user` to `role=admin`
(pad with extra bytes if the strings differ in length).

**Padding oracle.** The server tells you whether the decrypted plaintext has
valid padding. To recover block `i`, truncate the ciphertext after block `i`,
then for padding value `k = 1..16`:

- Set the last `k-1` bytes of the previous block so they decrypt to `k`.
- Guess the byte at position `16-k`; the oracle says valid when
  `intermediate_byte = guess xor k`.
- Recover `P_i[j] = intermediate[j] xor C_{i-1}[j]`.

The false positive for `k=1` is handled by flipping the previous byte: real
`0x01` padding stays valid, longer padding becomes invalid.

```python
pt = bc.padding_oracle_attack(oracle, ciphertext, block_size=16, iv=iv)
```

The helper truncates after each target block. If the server refuses truncated
ciphertext, attack only the last block, or keep later blocks fixed and adjust
the oracle logic.

**IV reuse / fixed IV.** Same plaintext prefixes encrypt identically in the
first block; XOR of two ciphertexts reveals XOR of plaintexts.

## 4. CTR and stream ciphers

`C_i = P_i xor KS_i`. Reusing the nonce reuses the keystream:

```python
p2 = bc.ctr_reuse_recover(c1, p1, c2)     # p2 = c2 xor (c1 xor p1)
ks = bc.recover_keystream(c, known_plaintext)
```

If only part of one plaintext is known, recover the keystream there and use it
to decrypt the other message at those positions. If the counter is predictable,
you can generate future keystream once the key is recovered.

## 5. CBC-MAC and GCM

**CBC-MAC length extension.** MAC = last CBC block of the message under the
key, IV = 0. Given a valid `(message, tag)`, append `message_pad || extension`
and use the old tag as the IV; you need to query the MAC oracle on the
extension with that IV (or the oracle only exposes the standard MAC, in which
case this is not directly forgeable). The classic exploit is bypassing a
length check by appending blocks.

**GCM nonce reuse.** Two messages with the same nonce leak the XOR of
plaintexts and the authentication key `H`. Recover `H` from the relation
between ciphertexts, tags, and lengths; then forge tags. Use two messages of
equal length for the simplest algebra.

## 6. Stream ciphers

- Reused keystream: XOR ciphertexts.
- Known plaintext: recover keystream.
- LFSR: Berlekamp-Massey recovers the recurrence from 2L bits; then predict.
- RC4 biases: first bytes are biased; use many ciphertexts.

## 7. Advanced mode attacks

### AES-GCM nonce reuse (forbidden attack)

Reusing a nonce with the same key reuses the CTR keystream **and** the
Poly1305/GHASH authentication key. Two messages:

```
C1 xor C2 = P1 xor P2
T1 xor T2 = (C1 xor C2) * H^2        (equal-length, one-block, empty AAD)
```

Recover `H`, then `E_K(J0) = T1 xor GHASH_H(C1)`, and forge tags for any
ciphertext under the same nonce.

```python
from ctfkit import blockcipher as bc
h, j0 = bc.gcm_nonce_reuse_forge(c1, t1, c2, t2)
tag = bc.gcm_forge_tag(h, j0, b"", new_ct)
```

The one-block helper is exact. Multi-block messages require factoring a
polynomial over `GF(2^128)`; use `nonce-disrespect` or a dedicated GHASH
solver. The plaintext recovery part (`C1 xor C2`) always works.

### CBC-MAC forgery

CBC-MAC with IV=0 is secure only for fixed-length messages:

- **Length extension / block splicing:** append blocks and use the old tag as
  the IV; if the verifier accepts variable lengths, forge.
- **MAC over `secret || msg`:** if the construction is a plain hash, use
  length extension (`references/hash.md`).
- **Truncated MAC:** brute-force the missing bytes if short enough.
- **Different-length collision:** find two messages with the same CBC-MAC by
  solving for a block.

### CFB / OFB

- **CFB:** `C_i = P_i xor E(C_{i-1})`. A known plaintext block recovers
  `E(C_{i-1})`, so you can forge the next block or flip bits.
- **CFB-8:** with a static IV and 8-bit feedback, 16 known bytes reconstruct
  the state.
- **OFB:** `KS_i = E(KS_{i-1})`; if the state transition is invertible and you
  know any plaintext block, run the state backward to decrypt earlier blocks.

### Compression oracle (CRIME/BREACH)

Compress-then-encrypt leaks plaintext through ciphertext length. Send chosen
inputs; when a guess matches the secret, the compressed length drops. Recover
byte-by-byte with a length oracle. The same idea applies to any
length-revealing oracle (e.g. token length in a response).

### AEAD partitioning oracle

If the server accepts multiple keys or a key-committing AEAD is missing, craft
ciphertexts that decrypt under many candidate keys and use the success/failure
oracle to partition the key space. Look for multi-key APIs, `try` loops over
keys, or non-committing AEAD constructions.

## 8. Pitfalls

- **Block size.** Try 8 (DES/Blowfish) as well as 16.
- **Padding stripping.** A plaintext ending in `\x01` may be data, not
  padding; validate the full pad.
- **IV placement.** Some APIs prepend the IV to the ciphertext; split it off
  before block attacks.
- **Oracle framing.** Padding oracles often expect hex/base64; encode
  correctly and account for line endings.
- **Truncation.** If the server rejects shortened ciphertexts, your padding
  oracle helper needs the untruncated variant (only the last block is
  attackable).
- **Rate limits.** Remote oracles may throttle; batch and retry.
