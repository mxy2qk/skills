# Flag Formats and Extraction

The flag is the deliverable. Getting the math right and then submitting the
wrong bytes is a common way to lose a challenge.

## 1. Common formats

| Format | Typical platform |
|---|---|
| `flag{...}` | most CTFs, picoCTF variants |
| `FLAG{...}` | some competitions; case-sensitive |
| `ctf{...}` / `CTF{...}` | generic |
| `picoCTF{...}` | picoCTF |
| `HTB{...}` | Hack The Box |
| `DASCTF{...}`, `NSSCTF{...}`, `BUUCTF{...}` | Chinese platforms |
| `DUCTF{...}`, `idek{...}`, `corctf{...}`, `maple{...}` | event-specific |
| `name{...}` | many events use the event name as prefix |
| raw 32/40/64/96/128 hex | some platforms accept the bare digest |
| UUID | rare, often wrapped |

Some challenges use a **custom prefix** stated only in the description, e.g.
`hitcon{...}`. Always detect before assuming.

## 2. Detect the format

```python
from ctfkit.util import detect_flag_regex, find_flags
fmt = detect_flag_regex(description)
```

The detector prefers common prefixes, so a ciphertext fragment like
`htpn{...}` does not override an explicit `flag{...}` hint. If the description
says "flag format: `XXX{...}`", use `XXX` as the crib.

## 3. Extract from output

```bash
"$PYTHON" scripts/flagcheck.py plaintext.bin
"$PYTHON" scripts/flagcheck.py response.txt --prefix flag
```

`flagcheck` searches:

- wrapped `\w+{...}` candidates, ranked by common prefix and printable body,
- one or two layers of hex/base64 decoding,
- raw 32/40/64/96/128 hex strings,
- UUID-shaped values.

For a binary decrypted plaintext, write it to a file and run the checker; do
not rely on terminal rendering of non-ASCII bytes.

## 4. Normalize correctly

- Strip surrounding whitespace and quotes, not internal characters.
- Keep case exactly as recovered; do not lowercase.
- Keep the braces and underscores.
- Do not strip a trailing `!`, `.`, or digits that are part of the flag.
- If the platform expects a raw hex value, do not wrap it; if it expects
  `flag{...}`, do not unwrap it. The description decides.

## 5. Use the prefix as a crib

A known prefix is the most valuable known plaintext in the challenge:

- **XOR:** `keystream = ciphertext xor b"flag{"` at the correct offset.
- **Vigenère:** subtract the crib from the ciphertext to derive key letters.
- **AES-CBC/ECB known plaintext:** use the first block to recover keystream or
  validate a key guess.
- **Substitution:** map the crib letters and propagate.
- **Hash length extension:** the prefix is not the secret, but the flag format
  tells you what the plaintext should look like.
- **RSA:** if the flag is small and starts with `flag{`, use it as a
  stereotyped-message Coppersmith crib.

## 6. Decoys and multiple candidates

- Source files may contain `flag{test}`, `flag{redacted}`, or a placeholder
  read from an environment variable. They are not the answer.
- A decrypted blob may contain several `word{...}` strings. Rank by:
  1. the expected prefix from the description,
  2. a fully printable body,
  3. plausible length,
  4. semantic sense.
- If two candidates both look valid, check which one the server accepts (for
  remote challenges) or recompute the encryption/signature from each.

## 7. Remote responses

The flag may arrive as:

- the plaintext returned by a decrypt oracle,
- a line printed after a successful forge,
- a token in a JSON/HTTP response,
- a filename or header field,
- an error message containing decrypted bytes.

Parse the whole response, not just the first line. If it is JSON, load it and
search all string values recursively. If it is binary, save it and run
`flagcheck`.

## 8. Encoding layers

The flag may be base64/hex/URL-encoded after decryption:

```python
import base64, urllib.parse
for decode in (lambda b: b, base64.b64decode, bytes.fromhex,
               lambda b: urllib.parse.unquote_to_bytes(b)):
    try:
        candidate = decode(data)
    except Exception:
        continue
    print(find_flags(candidate))
```

Do not decode more than a couple of layers blindly; each layer changes the
byte length and can destroy a valid flag.

## 9. Submission checklist

- Does the value match the detected format exactly?
- Is it printable and free of whitespace/newlines?
- Did you derive it by solving, not by reading a decoy?
- Does recomputing the ciphertext/signature/tag from the recovered secret
  succeed?
- If remote, did the server accept it?
