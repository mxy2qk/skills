# Stream Cipher Attacks

Stream ciphers XOR plaintext with a keystream. The attacks are about
recovering, reusing, or predicting that keystream.

## 1. One-time pad and keystream reuse

If the same keystream is used twice:

```
C1 xor C2 = P1 xor P2
```

With a known plaintext in one message:

```python
from ctfkit import stream
p2 = stream.xor_bytes(stream.xor_bytes(c1, p1), c2)
```

With no known plaintext, use **crib dragging**: guess a word, slide it over
one ciphertext, and check whether the other side is printable.

```python
hits = stream.crib_drag([c1, c2], b"flag{")
for i, j, pos, candidate in hits:
    print(pos, candidate)
```

The flag prefix is a strong crib: `flag{`, `CTF{`, `picoCTF{`, etc. Try
several offsets and encodings.

## 2. XOR key recovery from file headers

If a file claims to be PNG/PDF/ZIP but `file` reports "data", the plaintext
header is known:

```python
known = png_header + b"\x00" * ...
keystream = stream.xor_bytes(ciphertext[:len(known)], known)
```

Then extend the key using repeated structures (`IEND`, `%%EOF`, ZIP local
headers). If the keystream repeats, XOR it out; if it is a PRNG, recover the
state (see `references/prng.md`).

## 3. LFSR and Berlekamp-Massey

A binary LFSR satisfies a linear recurrence:

```
s[n] = c[1]*s[n-1] xor ... xor c[L]*s[n-L]
```

Berlekamp-Massey recovers the connection polynomial from `2L` bits:

```python
from ctfkit import stream
C = stream.berlekamp_massey(bits)
next_bits = stream.lfsr_predict(bits, 64)
```

Conventions vary:

- **Fibonacci:** the new bit is a XOR of selected previous bits.
- **Galois:** the state shifts and taps XOR into positions; the output bit is
  usually the LSB.
- Bit order may be MSB-first or LSB-first; try both.
- The observed bits may be the keystream, not the state. Recover the
  recurrence, then generate the keystream.

**Correlation attack.** When several LFSRs are combined by a biased function
(e.g. majority), each LFSR correlates with the output. Recover one LFSR at a
time by checking candidate initial states against the output, then extend.

## 4. RC4

RC4 is a byte-oriented stream cipher. CTF attacks:

- **Second-byte bias:** `KS[1]` is biased toward `0x00` (about 1/128 vs
  1/256). With ~2048 samples, distinguish RC4 from random.
- **Related keys / IV weakness:** WEP-style `IV || key`; the first keystream
  bytes leak key bytes.
- **Known keystream:** XOR with known plaintext; no key recovery needed.

```python
from ctfkit import stream
ks = stream.rc4_keystream(key, length)
pt = stream.xor_bytes(ciphertext, ks)
```

## 5. ChaCha20-Poly1305 nonce reuse

Same nonce + key ⇒ same ChaCha20 keystream and the same Poly1305 one-time key
`r, s`. Two messages:

```
C1 xor C2 = P1 xor P2
```

With a known plaintext, recover the other. For authentication, the Poly1305
key is derived from the first ChaCha20 block; nonce reuse lets you recover the
one-time key and forge tags. The algebra is polynomial evaluation modulo
`2^130 - 5`.

## 6. AES-CTR / OFB / CFB

- **CTR:** keystream reuse; flipping ciphertext bits flips plaintext bits.
  `blockcipher.ctr_bitflip` does this.
- **OFB:** keystream is the repeated encryption of the previous block; if the
  state transition is invertible and you know any plaintext block, you can run
  the state backward and decrypt earlier blocks.
- **CFB:** the previous ciphertext block is encrypted to produce the
  keystream; a known plaintext block recovers that keystream and lets you
  forge the next block. CFB-8 with a static IV leaks state after 16 known
  bytes.

## 7. Other stream constructions

- **A5/1, Grain, Trivium:** LFSR-based; look for reduced-round variants,
  known IV/key reuse, or correlation attacks.
- **Hash-based keystream:** `KS = H(seed || counter)`. If the hash is
  Merkle-Damgard and the seed is a prefix, length extension may apply; if the
  counter is reused, XOR messages.
- **Custom xorshift/LCG keystream:** recover the PRNG state (see
  `references/prng.md`).

## 8. Pitfalls

- **Endianness:** keystream words may be packed little-endian.
- **Bit vs byte:** LFSR outputs may be packed 8 bits per byte in either order.
- **Warm-up:** some generators discard the first N outputs; account for it.
- **Truncation:** the keystream may be truncated to a few bits per output.
- **Nonce reuse is not always obvious:** check IV/nonce fields across
  messages, and whether the server reuses a counter.
