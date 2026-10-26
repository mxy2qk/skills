"""Generate the eval challenges deterministically.

Run: python build_challenges.py
Creates evals/challenges/<name>/ and evals/expected.json.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.join(HERE, "challenges")


def ensure(path):
    os.makedirs(path, exist_ok=True)
    return path


def write(path, text, mode="w"):
    with open(path, mode, encoding=None if "b" in mode else "utf-8", newline=None if "b" in mode else "\n") as fh:
        fh.write(text)


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits, rng, offset=0):
    x = (1 << (bits - 1)) + rng.randrange(1 << (bits - 2)) + (offset << (bits - 2))
    x |= 1
    while not is_prime(x):
        x += 2
    return x


def rsa_encrypt(m, e, n):
    return pow(m, e, n)


def make_classical():
    d = ensure(os.path.join(CHAL, "classical-vigenere"))
    flag = "flag{vigenere_is_not_secure}"
    plain = (
        "The intercepted transmission reads as follows. Analysts believe the message "
        "was protected with a repeating key cipher, and the key length is at most eight. "
        "Recover the plaintext and report the hidden token. "
        f"The token is {flag}. End of transmission."
    )
    key = "cipher"
    ct = []
    j = 0
    for c in plain:
        if c.isalpha():
            k = ord(key[j % len(key)]) - 97
            base = 97 if c.islower() else 65
            ct.append(chr((ord(c) - base + k) % 26 + base))
            j += 1
        else:
            ct.append(c)
    write(os.path.join(d, "ciphertext.txt"), "".join(ct))
    write(
        os.path.join(d, "hint.txt"),
        "We intercepted a message that looks like it used a repeating-key cipher.\n"
        "The key is a common English word and is at most 8 letters long.\n"
        "Recover the full plaintext and extract the flag (format: flag{...}).\n",
    )
    return flag


def make_wiener():
    d = ensure(os.path.join(CHAL, "rsa-wiener"))
    rng = random.Random(1001)
    flag = "flag{wiener_says_your_d_is_too_small}"
    p = prime(512, rng)
    q = prime(512, rng, offset=1)
    n = p * q
    phi = (p - 1) * (q - 1)
    dd = prime(120, rng)
    while math.gcd(dd, phi) != 1:
        dd = prime(120, rng)
    e = pow(dd, -1, phi)
    m = int.from_bytes(flag.encode(), "big")
    c = rsa_encrypt(m, e, n)
    write(
        os.path.join(d, "output.txt"),
        f"n = {n}\ne = {e}\nc = {c}\n",
    )
    write(
        os.path.join(d, "hint.txt"),
        "A textbook RSA implementation reused a poorly chosen private exponent.\n"
        "The public exponent is unusually large. Recover the flag (flag{...}).\n",
    )
    return flag


def make_partial_p():
    d = ensure(os.path.join(CHAL, "rsa-partial-p"))
    rng = random.Random(2002)
    flag = "flag{coppersmith_finds_small_roots}"
    p = prime(256, rng)
    q = prime(256, rng, offset=1)
    n = p * q
    e = 65537
    m = int.from_bytes(flag.encode(), "big")
    c = rsa_encrypt(m, e, n)
    shift = 40
    p_high = p >> shift
    write(
        os.path.join(d, "output.txt"),
        f"n = {n}\ne = {e}\nc = {c}\np_high = {p_high}\nunknown_low_bits = {shift}\n",
    )
    write(
        os.path.join(d, "hint.txt"),
        "A memory corruption bug leaked the high bits of p but wiped the low "
        f"{shift} bits. Recover the flag (flag{{...}}).\n",
    )
    return flag


def make_lcg():
    d = ensure(os.path.join(CHAL, "prng-lcg"))
    rng = random.Random(3003)
    flag = "flag{linear_congruential_generators_are_predictable}"
    m = 2**64 - 59  # largest prime below 2^64
    a = rng.randrange(1, m)
    c = rng.randrange(1, m)
    seed = rng.randrange(1, m)
    state = seed
    outputs = []
    for _ in range(12):
        state = (a * state + c) % m
        outputs.append(state)
    plain = (
        "The beacon output was encrypted with a stream derived from a linear "
        f"congruential generator. {flag}. That is all."
    ).encode()
    # crypto stream: each 8-byte block XORed with the next LCG output
    blocks = [plain[i : i + 8] for i in range(0, len(plain), 8)]
    stream = []
    for _ in blocks:
        state = (a * state + c) % m
        stream.append(state.to_bytes(8, "big"))
    ct = bytes(x ^ y for x, y in zip(plain, b"".join(stream)))
    write(os.path.join(d, "outputs.txt"), "\n".join(str(x) for x in outputs) + "\n")
    write(os.path.join(d, "ciphertext.hex"), ct.hex() + "\n")
    write(
        os.path.join(d, "hint.txt"),
        "The server printed 12 consecutive LCG outputs before encrypting a message.\n"
        "The ciphertext is XORed with the next LCG outputs, 8 bytes per block,\n"
        "big-endian. Recover the flag (flag{...}). The LCG parameters are unknown.\n",
    )
    return flag


def make_ecdsa():
    d = ensure(os.path.join(CHAL, "ecc-ecdsa"))
    rng = random.Random(4004)
    flag = "flag{ecdsa_nonce_reuse_breaks_the_key}"
    # secp256k1
    p = 2**256 - 2**32 - 977
    a, b = 0, 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(k, P):
        R = None
        while k:
            if k & 1:
                R = add(R, P)
            P = add(P, P)
            k >>= 1
        return R

    G = (Gx, Gy)
    priv = rng.randrange(2, n)
    k = rng.randrange(2, n)
    z1 = rng.randrange(2, n)
    z2 = rng.randrange(2, n)
    r = mul(k, G)[0] % n
    s1 = pow(k, -1, n) * (z1 + r * priv) % n
    s2 = pow(k, -1, n) * (z2 + r * priv) % n

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    key = hashlib.sha256(str(priv).encode()).digest()[:32]
    iv = bytes(rng.randrange(256) for _ in range(16))
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag.encode(), 16))

    write(
        os.path.join(d, "output.txt"),
        "\n".join(
            [
                f"p = {p}",
                f"a = {a}",
                f"b = {b}",
                f"Gx = {Gx}",
                f"Gy = {Gy}",
                f"n = {n}",
                f"r = {r}",
                f"s1 = {s1}",
                f"s2 = {s2}",
                f"z1 = {z1}",
                f"z2 = {z2}",
                f"iv = {iv.hex()}",
                f"ciphertext = {ct.hex()}",
            ]
        )
        + "\n",
    )
    write(
        os.path.join(d, "hint.txt"),
        "Two ECDSA signatures were produced by a buggy signer on secp256k1.\n"
        "The flag was encrypted with AES-256-CBC using\n"
        "key = SHA256(str(private_key_as_decimal))[:32], with the IV below.\n"
        "Recover the flag (flag{...}).\n",
    )
    return flag


SERVER_PY = r'''#!/usr/bin/env python3
"""Padding-oracle service.

The flag is read from the CTF_FLAG environment variable; it is never written
to disk. The service prints IV and CT on connect, then accepts one hex-encoded
message per line (IV || ciphertext) and answers "valid" or "invalid".
"""

import os
import socketserver
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get("CTF_FLAG", "flag{missing_flag_env}")
KEY = os.urandom(16)
IV = os.urandom(16)
PLAIN = (
    b"A padding oracle reveals the plaintext one byte at a time. "
    + FLAG.encode()
    + b" The key never leaves this process."
)
CT = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(PLAIN, 16))


def valid_padding(data: bytes) -> bool:
    if not data or len(data) % 16:
        return False
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, data[:16])
        pt = cipher.decrypt(data[16:])
        p = pt[-1]
        return 1 <= p <= 16 and pt[-p:] == bytes([p]) * p
    except Exception:
        return False


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(f"IV={IV.hex()}\nCT={CT.hex()}\n".encode())
        self.wfile.write(b"Send hex(IV||CT), one per line. Type 'quit' to exit.\n")
        self.wfile.flush()
        for line in self.rfile:
            raw = line.strip()
            if raw.lower() == b"quit":
                break
            try:
                data = bytes.fromhex(raw.decode())
            except Exception:
                self.wfile.write(b"invalid\n")
                self.wfile.flush()
                continue
            self.wfile.write(b"valid\n" if valid_padding(data) else b"invalid\n")
            self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 40123
    with Server(("127.0.0.1", port), Handler) as server:
        print(f"listening on 127.0.0.1:{port}", flush=True)
        server.serve_forever()
'''


def make_padding_oracle():
    d = ensure(os.path.join(CHAL, "aes-padding-oracle"))
    write(os.path.join(d, "server.py"), SERVER_PY)
    write(
        os.path.join(d, "hint.txt"),
        "A CBC padding oracle is running at 127.0.0.1:40123.\n"
        "It prints IV and CT on connect and answers valid/invalid for hex(IV||CT).\n"
        "If it is not running, start it with:\n"
        "  CTF_FLAG='<the real flag>' python server.py 40123\n"
        "Decrypt the plaintext and recover the flag (flag{...}).\n",
    )
    return "flag{padding_oracles_leak_plaintext}"


def main():
    ensure(CHAL)
    expected = {}
    expected["classical-vigenere"] = make_classical()
    expected["rsa-wiener"] = make_wiener()
    expected["rsa-partial-p"] = make_partial_p()
    expected["prng-lcg"] = make_lcg()
    expected["ecc-ecdsa"] = make_ecdsa()
    expected["aes-padding-oracle"] = make_padding_oracle()
    write(os.path.join(HERE, "expected.json"), json.dumps(expected, indent=2) + "\n")
    print("built challenges:")
    for name, flag in expected.items():
        print(f"  {name}: {flag}")


if __name__ == "__main__":
    main()
