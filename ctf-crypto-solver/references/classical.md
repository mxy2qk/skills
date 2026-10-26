# Classical Ciphers and Simple XOR

## 0. Identification

| Property | Likely cipher |
|---|---|
| Same letter-frequency shape as English, shifted | Caesar / ROT |
| Frequency shape preserved, each letter mapped consistently | Substitution / affine |
| Flat frequency, long text | Vigenère / polyalphabetic |
| Same letters, scrambled order, spaces preserved | Transposition |
| Spaces removed, letter frequencies normal | Route / columnar / rail fence |
| Digraphs, no `j`, 25-letter grid | Playfair |
| Only `.` `-` `/` | Morse |
| Groups of 5 bits / A-B | Bacon |
| Arbitrary bytes, high entropy | XOR / modern cipher |

Always try layers first: base64 → hex → ROT47 → Morse → classical. A "classical
cipher" challenge often hides the real text behind one encoding.

## 1. Monoalphabetic

**Caesar / ROT-n.** Brute force all 26 shifts and score English:

```python
from ctfkit import classical as cl
best = cl.caesar_bruteforce(ciphertext)[0]   # (score, shift, plaintext)
```

**Affine.** `E(x) = a*x + b mod 26`, `gcd(a, 26) = 1`. Brute force the 12 valid
`a` values and 26 `b` values:

```python
cl.affine_bruteforce(ciphertext)
```

**Atbash.** `a <-> z`; one line:

```python
cl.atbash(ciphertext)
```

**Substitution.** Preserves word boundaries (usually). Two-stage solve:

1. Match word shapes against a dictionary: `"qxnoy"` and `"quick"` share the
   pattern `(0,1,2,3,4)`; backtracking enforces a consistent letter mapping.
2. Refine with simulated annealing on word/trigram score.

```python
results = cl.substitution_hillclimb(ciphertext)
plaintext = results[0][2]
```

If the ciphertext has no spaces, word-shape matching is unavailable; the
annealer still works but needs a longer text. A short flag-only ciphertext may
need a crib (guess a known word, derive letters, propagate).

## 2. Polyalphabetic

**Vigenère.** Key repeated over the letters. Detection: index of coincidence
(IC) of columns. English IC ≈ 0.066; random ≈ 0.038.

- Find key length: average the IC of each column for candidate lengths; the
  correct length has columns close to English IC. Kasiski examination (repeated
  trigrams and their distance gcds) corroborates.
- Recover each key letter by trying 26 shifts per column and choosing the one
  whose letter distribution is closest to English (chi-squared).
- Refine the whole key with word-level scoring to fix isolated column errors.

```python
cl.vigenere_bruteforce(ciphertext, max_keylen=20)
```

**Autokey / Beaufort / Gronsfeld.** Variants of the same idea; read the
challenge code for the exact recurrence.

## 3. Transposition

**Rail fence.** Write the text in a zigzag over `r` rails, read rows. Brute
force `r` and score:

```python
cl.rail_fence_bruteforce(ciphertext)
```

**Columnar.** Write plaintext in rows under a keyword, read columns in
alphabetical key order. Brute force permutations for small widths:

```python
cl.columnar_bruteforce(ciphertext, max_cols=7)
```

For larger widths, use simulated annealing over column permutations and
English n-gram score. Watch for padding characters (`X`, spaces) that must be
stripped before scoring.

**Route / scytale.** Read the text in a grid along a path; try grid dimensions
that divide the length and both reading orders.

## 4. Other classical ciphers

- **Playfair:** digraph substitution on a 5×5 grid (I/J combined). If the key
  is unknown, brute force short keys or use a crib; `cl.playfair_decrypt`.
- **Bacon:** 5-bit groups, A/B or 0/1; `cl.bacon_decode`.
- **Morse:** `cl.morse_decode`; separators vary (`/`, spaces, newlines).
- **Hill cipher:** matrix multiplication mod 26; recover the matrix from known
  plaintext/ciphertext pairs, or brute force small dimensions.
- **Bifid/Trifid:** fractionation; usually a crib/known-key challenge.

## 5. XOR

**Single byte.** Brute force 256 keys and score:

```python
cl.single_byte_xor_bruteforce(data)
```

**Repeating key.** Find the key length by normalized Hamming distance between
chunks, then solve each column as a single-byte XOR. The toolkit evaluates
every candidate length and ranks the full plaintext, which is more reliable on
short texts:

```python
cl.repeating_xor_bruteforce(data, max_keylen=40)
```

If the plaintext is not English (e.g. a flag or a binary format), score with a
crib instead: XOR the ciphertext with a guessed phrase at each offset and look
for a repeating key.

## 6. One-time pad, layers, and other encodings

### OTP reuse / many-time pad

If the same keystream encrypts two messages:

```
C1 xor C2 = P1 xor P2
```

With a known plaintext, recover the other; without one, use crib dragging (try
`flag{`, common words, and the challenge name at every offset).

```python
from ctfkit import stream
candidates = stream.crib_drag([c1, c2], b"flag{")
```

The flag prefix is the best crib. If the keystream repeats with a period,
XOR the ciphertext with itself shifted by the period to expose the plaintext.

### XOR with a known file header

If a file is XOR-encrypted and claims to be PNG/PDF/ZIP, the header is known:

- PNG: `89 50 4E 47 0D 0A 1A 0A`
- PDF: `%PDF-`
- ZIP: `PK\x03\x04`
- ELF: `\x7fELF`

XOR the first bytes to recover the key prefix, then extend using trailer
headers (`IEND`, `%%EOF`, ZIP central directory).

### Homophonic and fractionating ciphers

- **Homophonic:** common letters map to multiple symbols; letter frequencies
  flatten. Group symbols by frequency, solve as a monoalphabetic cipher, then
  use the flag format as a crib.
- **Polybius:** coordinates `(row, col)` in a 5×5 square; try both `1-5` and
  `0-4` indexing.
- **Bacon:** 5-bit groups; A/B or 0/1; try both alphabet offsets.
- **Book cipher:** `(page, line, word)` or `(chapter, verse, letter)`; the
  challenge must provide the book or a link. Try 0/1-based indexing.

### Layered encodings

Try in this order, re-checking after each layer:

1. URL decode (`%xx`).
2. Base64 (standard, URL-safe, missing padding).
3. Base32/Base85.
4. Hex.
5. ROT13/ROT47/Atbash.
6. Morse (`.`/`-`, separators vary).
7. Binary (8-bit groups).
8. Decimal/octal ASCII.
9. Reverse the string / reverse line order.

Do not blindly decode more than 2–3 layers; each layer can destroy a valid
flag. Save the output after each step.

### Image/audio side channels

Some "classical" challenges encode text in pixel rows/columns (Caesar shifts
per strip), audio spectrograms, or file metadata. If the text solver fails,
inspect the file with `strings`, `xxd`, `binwalk`, and an image viewer. This
borders on stego; pivot to a stego workflow if the bytes are not text.

## 7. Scoring and pitfalls

- **English score is a heuristic.** Inspect the top 5 candidates, not only the
  first. A flag may appear in a lower-ranked candidate.
- **Preserve case and punctuation** when evaluating; stripping them loses
  information (especially for transposition).
- **Short texts are ambiguous.** A 20-letter ciphertext may have several
  plausible keys; use the flag format as a crib.
- **Layers.** Decode base64/hex/URL first; a classical solver on base64 text
  produces noise.
- **Padding.** Transposition ciphers often pad to a rectangle; try stripping
  trailing `X`, spaces, or nulls.
- **Direction.** Encryption and decryption shifts are inverses; if a solver's
  "shift 7" looks like "shift 19", the sign convention is flipped.
