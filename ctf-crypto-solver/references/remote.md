# Remote and nc Crypto Challenges

Most "hard" crypto CTFs are a small protocol wrapped around one oracle. The
cryptanalysis is usually standard; the difficulty is speaking the protocol
correctly and staying within the query budget.

## 1. First contact checklist

```bash
nc host port
```

Capture:

- the banner (may contain IV, CT, public key, PoW, menu),
- the prompt character/string,
- whether input is line-based, hex, base64, or binary,
- whether the connection is stateful (same key/ciphertext across queries),
- the query limit (often stated or enforced by disconnecting),
- where the flag appears (decrypted plaintext, server response, token).

Use `ctfkit.util.connect(host, port, log_path="transcript.log")`. The
transcript makes protocol bugs obvious.

```python
from ctfkit.util import connect
tube = connect("host", 12345, timeout=10, log_path="remote.log")
banner = tube.recvuntil(b"> ")
print(banner)
```

If the service is local, run it as a subprocess:

```python
from ctfkit.remote import connect_process
tube = connect_process(["python", "server.py"], cwd="challenge/")
banner = tube.recvuntil(b"> ")
```

## 2. Proof of work

Many services gate the real protocol behind a PoW:

```
sha256(prefix + answer) must start with 4 zeros
Give me a string such that md5(answer) begins with 00000
proof of work: sha1('AAA' + suffix) has 12 leading zero bits
```

Use the parser/solver:

```python
from ctfkit import pow
info = pow.parse_pow(banner.decode())
answer, digest = pow.parse_and_solve(banner.decode())
tube.sendline(answer)
```

or, in one call:

```python
from ctfkit.remote import solve_pow_for_tube
solve_pow_for_tube(tube, banner)
```

If parsing fails, call `pow.solve_pow` directly:

```python
pow.solve_pow(prefix="abc", zeros=4, algo="sha256", position="prefix")
pow.solve_pow(prefix="AAA", zeros=12, unit="bits", algo="sha1")
pow.solve_pow(literal="deadbeef", algo="sha256", time_limit=60)
```

Tips:

- The answer is usually a decimal string; some services want hex, a fixed
  length, or an alphanumeric string. Pass `encoding`/`length`.
- Leading-zero counts are usually hex characters, not bits. `0000` = 16 bits.
- If the difficulty is too high for pure Python, use `hashcat`/C or ask the
  service for a new instance. Do not wait silently.
- Some services give a nonce and ask for a hash with a named prefix; treat it
  as `unit="literal"`.

## 3. Protocol mapping

### Line-based text

```python
tube.sendlineafter(b"option: ", b"1")
line = tube.recvline()
```

- Read the prompt, not a fixed number of bytes.
- Normalize `\r\n` vs `\n`.
- If the server echoes input, account for the echo.

### Hex-encoded bytes

```python
tube.sendline(ciphertext.hex().encode())
resp = tube.recvline().strip()
```

- Some services want uppercase hex, `0x` prefix, or no prefix. Probe once.
- If the response is `valid`/`invalid`, compare the **whole token**, not a
  substring: `b"valid" in b"invalid"` is a classic false positive.

### Base64

```python
import base64
tube.sendline(base64.b64encode(data))
```

- Watch for URL-safe base64 and padding removal.
- Some services accept both; some reject newlines inside the payload.

### Menu-driven

```python
from ctfkit.remote import read_menu, choose
menu = read_menu(tube, prompt=b"> ")
choose(tube, 1, prompt=b"> ")
```

- Menu numbers/letters may change between connections; parse them from the
  menu text, don't hardcode.
- A menu may hide a debug/verify option that is the real oracle.

### Binary / length-prefixed

- Read exact lengths with `tube.recv(n)`; do not use `recvuntil` unless there
  is a delimiter.
- For 4/8-byte length prefixes, parse both endiannesses.
- If the service sends a fixed-size header, read it first, then the body.

## 4. Query budgets

Estimate before you start. A service that disconnects after 500 queries will
not tolerate a 4096-query padding oracle.

| Attack | Queries |
|---|---|
| CBC padding oracle | ~128–256 per byte × block size ≈ 2k–4k per block |
| ECB byte-at-a-time | 256 per byte (plus alignment) |
| RSA LSB/parity oracle | ~`n.bit_length()` (≈1024 for RSA-1024) |
| Bleichenbacher | ~10k for RSA-2048 (highly variable) |
| Manger | ~`n.bit_length()` for the simple threshold oracle |
| DH small subgroup | `r` per factor `r` of `p-1` |
| GCM nonce reuse | 2 encryptions + local forging |
| Hash length extension | 1 verification per guessed secret length |
| PRNG state recovery | 624 MT outputs (or enough floats) |
| Signature nonce reuse | 2 signatures |
| HNP | `n` signatures depending on leaked bits; often 20–60 |

If the budget is tight:

- Use a **batch** endpoint if one exists.
- Reuse connections; do not reconnect per query.
- Cache deterministic answers.
- For padding oracles, attack only the block containing the flag if the
  plaintext structure is known.
- For LSB oracles, stop once the recovered bytes contain the flag; you do not
  need the full integer.

## 5. Oracle wrapper pattern

Write the attack against a callable, then plug in local or remote:

```python
def make_oracle(tube):
    def oracle(payload: bytes) -> bool:
        tube.sendline(payload.hex())
        resp = tube.recvline().strip()
        return resp == b"valid"
    return oracle

# local test
def local_oracle(payload):
    return server.check_padding(payload)

attack(local_oracle)      # validate logic first
attack(make_oracle(tube)) # then run remotely
```

For deterministic oracles, memoize:

```python
from functools import lru_cache

@lru_cache(maxsize=None)
def oracle(ct_hex: str) -> bool:
    tube.sendline(ct_hex.encode())
    return tube.recvline().strip() == b"valid"
```

## 6. Reliability

- **Timeouts:** set 5–15s; a hung read is usually a wrong delimiter.
- **Reconnect:** `remote.retry(lambda: connect(...), attempts=3)`.
- **Rate limits:** add small sleeps if the server drops connections; prefer
  fewer, larger queries.
- **State:** some services rotate keys per connection. If the ciphertext
  changes, your attack must finish within one session.
- **Restart policy:** do not restart a challenge server that is already
  running; you may lose the target state. If you must restart, note the new
  IV/CT/key.
- **Logging:** keep `remote.log`; when parsing fails, read the raw bytes.
- **Binary safety:** avoid `print(bytes)` for binary payloads; use `.hex()`.

## 7. Common protocol bugs

- **Substring match:** `b"valid" in resp` also matches `b"invalid"`. Compare
  the exact token.
- **Leftover banner:** reading until a prompt may leave text in the buffer;
  clear it before the first oracle query.
- **Echo:** the server may echo your input; skip the echoed line.
- **Newline conventions:** some services require `\r\n`, others `\n`.
- **Encoding:** a hex oracle may expect lowercase, uppercase, or `0x`.
- **Length checks:** the server may reject ciphertexts that are not a
  multiple of the block size, or may pad them silently.
- **Menu drift:** option numbers can change after an error; re-read the menu.
- **Disconnect on invalid input:** a wrong query may kill the connection; use
  a fresh connection per batch if necessary.

## 8. Remote solve skeleton

```python
from ctfkit.util import connect
from ctfkit import blockcipher as bc
import re

HOST, PORT = "127.0.0.1", 40123

def run():
    tube = connect(HOST, PORT, timeout=10, log_path="remote.log")
    banner = tube.recvuntil(b"Send hex")
    iv = bytes.fromhex(re.search(rb"IV=([0-9a-f]+)", banner).group(1).decode())
    ct = bytes.fromhex(re.search(rb"CT=([0-9a-f]+)", banner).group(1).decode())

    def oracle(payload: bytes) -> bool:
        tube.sendline(payload.hex())
        return tube.recvline().strip() == b"valid"

    pt = bc.padding_oracle_attack(oracle, iv + ct, 16)
    tube.close()
    print(pt)
    m = re.search(rb"flag\{[^}]+\}", pt)
    return m.group(0).decode() if m else None

print(run())
```

The same structure works for any yes/no oracle: parse the challenge data from
the banner, wrap the query, run the attack, extract the flag, close.
