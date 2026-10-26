"""Generate the hard eval set used to validate the advanced attacks.

Run: python build_hard_challenges.py
Creates evals/hard_challenges/<name>/ and evals/hard_expected.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = os.path.join(HERE, "hard_challenges")


def ensure(path):
    os.makedirs(path, exist_ok=True)
    return path


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def is_prime(n: int) -> bool:
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


def make_ecdsa_biased():
    d = ensure(os.path.join(CHAL, "ecdsa-biased-nonce"))
    rng = random.Random(7001)
    flag = "flag{ecdsa_biased_nonce_hnp_works}"
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
    t = 8
    W = 1 << t
    sign = []
    for _ in range(40):
        delta = rng.randrange(W)
        leaked = rng.randrange(1, (n - delta) // W)
        k = leaked * W + delta
        R = mul(k, G)
        r = R[0] % n
        h = rng.randrange(1, n)
        s = pow(k, -1, n) * (h + r * priv) % n
        sign.append((r, s, h, leaked))
    key = hashlib.sha256(str(priv).encode()).digest()[:32]
    iv = bytes(rng.randrange(256) for _ in range(16))
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag.encode(), 16))

    out = [
        f"p = {p}", f"a = {a}", f"b = {b}", f"Gx = {Gx}", f"Gy = {Gy}",
        f"n = {n}", f"unknown_low_bits = {t}",
    ]
    for i, (r, s, h, leaked) in enumerate(sign):
        out.append(f"r{i} = {r}")
        out.append(f"s{i} = {s}")
        out.append(f"h{i} = {h}")
        out.append(f"k_msb{i} = {leaked}")
    out += [f"iv = {iv.hex()}", f"ciphertext = {ct.hex()}"]
    write(os.path.join(d, "output.txt"), "\n".join(out) + "\n")
    write(
        os.path.join(d, "hint.txt"),
        "A buggy ECDSA signer on secp256k1 generated 40 signatures. Each nonce's\n"
        f"top bits were leaked (k_msb), but the low {t} bits are unknown.\n"
        "Flag key = SHA256(str(private_key_as_decimal))[:32], AES-256-CBC.\n"
        "Recover the flag (flag{...}).\n",
    )
    return flag


def make_mt():
    d = ensure(os.path.join(CHAL, "prng-mt19937"))
    rng = random.Random(7002)
    flag = "flag{mt19937_state_recovery_works}"
    obs = [rng.getrandbits(32) for _ in range(624)]
    plain = (
        "The beacon used a Mersenne Twister stream. "
        f"{flag}. End of transmission."
    ).encode()
    blocks = [plain[i : i + 4] for i in range(0, len(plain), 4)]
    stream = [rng.getrandbits(32).to_bytes(4, "big") for _ in blocks]
    ct = bytes(x ^ y for x, y in zip(plain, b"".join(stream)))
    write(os.path.join(d, "outputs.txt"), "\n".join(str(x) for x in obs) + "\n")
    write(os.path.join(d, "ciphertext.hex"), ct.hex() + "\n")
    write(
        os.path.join(d, "hint.txt"),
        "624 consecutive 32-bit outputs are given, followed by a ciphertext.\n"
        "The ciphertext is XORed with the next 32-bit outputs, 4 bytes per block,\n"
        "big-endian. Recover the flag (flag{...}).\n",
    )
    return flag


def make_length_extension():
    d = ensure(os.path.join(CHAL, "hash-length-extension"))
    flag = "flag{length_extension_still_works}"
    server = '''#!/usr/bin/env python3
"""Length-extension verifier.

The secret is read from CTF_SECRET and never written to disk. A client sends
one line: hex(message) hex(mac). The server accepts if the MAC is correct and
the message contains admin=1, then prints the flag.
"""

import hashlib
import os
import socketserver
import sys

SECRET = os.environ.get("CTF_SECRET", "0123456789abcdef").encode()
FLAG = os.environ.get("CTF_FLAG", "flag{missing_env}")
MESSAGE = b"user=guest&role=user"
MAC = hashlib.md5(SECRET + MESSAGE).hexdigest().encode()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            b"message=" + MESSAGE + b"\\n"
            + b"mac=" + MAC + b"\\n"
            + f"secret_length={len(SECRET)}\\n".encode()
            + b"Send: hex(message) hex(mac)\\n"
        )
        self.wfile.flush()
        line = self.rfile.readline().strip()
        try:
            msg_hex, mac_hex = line.split()
            msg = bytes.fromhex(msg_hex.decode())
            mac = mac_hex.decode().lower()
        except Exception:
            self.wfile.write(b"bad format\\n")
            return
        if b"admin=1" in msg and hashlib.md5(SECRET + msg).hexdigest() == mac:
            self.wfile.write(b"accepted " + FLAG.encode() + b"\\n")
        else:
            self.wfile.write(b"rejected\\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 40125
    with Server(("127.0.0.1", port), Handler) as s:
        print(f"listening on {port}", flush=True)
        s.serve_forever()
'''
    write(os.path.join(d, "server.py"), server)
    write(
        os.path.join(d, "hint.txt"),
        "A verifier is running at 127.0.0.1:40125. It authenticates\n"
        "message = user=guest&role=user with md5(secret || message), where the\n"
        "secret is 16 bytes. Make it accept a message containing admin=1, then\n"
        "it prints the flag. If the service is not running, start it with\n"
        "  CTF_SECRET=<16 bytes> CTF_FLAG='<the real flag>' python server.py 40125\n",
    )
    return flag


def make_dh_smooth():
    d = ensure(os.path.join(CHAL, "dh-smooth-order"))
    rng = random.Random(7004)
    flag = "flag{dh_smooth_order_falls_to_pohlig_hellman}"
    # Build a ~256-bit prime p with p-1 smooth.
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    M = 1
    while M.bit_length() < 245:
        M *= rng.choice(small)
    p = None
    for k in range(1, 20000):
        cand = k * M + 1
        if cand.bit_length() >= 240 and is_prime(cand):
            p = cand
            break
    if p is None:
        raise RuntimeError("could not build smooth prime")
    g = 2
    while pow(g, (p - 1) // 2, p) == 1:
        g += 1
    a = rng.randrange(2, p - 1)
    b = rng.randrange(2, p - 1)
    A = pow(g, a, p)
    B = pow(g, b, p)
    S = pow(g, a * b, p)
    key = hashlib.sha256(str(S).encode()).digest()[:32]
    iv = bytes(rng.randrange(256) for _ in range(16))
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag.encode(), 16))
    write(
        os.path.join(d, "output.txt"),
        "\n".join(
            [
                f"p = {p}", f"g = {g}", f"A = {A}", f"B = {B}",
                f"iv = {iv.hex()}", f"ciphertext = {ct.hex()}",
            ]
        )
        + "\n",
    )
    write(
        os.path.join(d, "hint.txt"),
        "A Diffie-Hellman exchange used a weak prime. The flag key is\n"
        "SHA256(str(shared_secret))[:32], AES-256-CBC.\n"
        "Recover the flag (flag{...}).\n",
    )
    return flag


POW_PADDING_SERVER = r'''#!/usr/bin/env python3
"""PoW-gated CBC padding oracle.

Connect, solve the proof of work, then receive IV/CT and query the oracle.
The flag is read from CTF_FLAG and never written to disk.
"""

import hashlib
import os
import re
import socketserver
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get("CTF_FLAG", "flag{missing_env}")
KEY = os.urandom(16)
IV = os.urandom(16)
PLAIN = b"A padding oracle behind a proof of work. " + FLAG.encode() + b" Done."
CT = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(PLAIN, 16))
PREFIX = os.urandom(4).hex()
DIFFICULTY = 3


def valid_padding(data: bytes) -> bool:
    if not data or len(data) % 16:
        return False
    try:
        pt = AES.new(KEY, AES.MODE_CBC, data[:16]).decrypt(data[16:])
        p = pt[-1]
        return 1 <= p <= 16 and pt[-p:] == bytes([p]) * p
    except Exception:
        return False


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(
            f"proof of work: sha256(prefix + answer) starts with {DIFFICULTY} zeros\n"
            f"prefix={PREFIX}\nanswer> ".encode()
        )
        self.wfile.flush()
        ans = self.rfile.readline().strip().decode(errors="replace")
        if not hashlib.sha256((PREFIX + ans).encode()).hexdigest().startswith("0" * DIFFICULTY):
            self.wfile.write(b"bad pow\n")
            return
        self.wfile.write(f"IV={IV.hex()}\nCT={CT.hex()}\n".encode())
        self.wfile.write(b"Send hex(IV||CT), one per line.\n")
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 40124
    with Server(("127.0.0.1", port), Handler) as s:
        print(f"listening on {port}", flush=True)
        s.serve_forever()
'''


def make_pow_padding():
    d = ensure(os.path.join(CHAL, "nc-pow-padding"))
    write(os.path.join(d, "server.py"), POW_PADDING_SERVER)
    write(
        os.path.join(d, "hint.txt"),
        "A CBC padding oracle is running at 127.0.0.1:40124, behind a\n"
        "proof of work: sha256(prefix + answer) must start with 3 hex zeros.\n"
        "After solving it, the server prints IV and CT and answers valid/invalid\n"
        "for hex(IV||CT). Recover the flag (flag{...}).\n",
    )
    return "flag{pow_then_padding_oracle}"


def main():
    ensure(CHAL)
    expected = {}
    expected["ecdsa-biased-nonce"] = make_ecdsa_biased()
    expected["prng-mt19937"] = make_mt()
    expected["hash-length-extension"] = make_length_extension()
    expected["dh-smooth-order"] = make_dh_smooth()
    expected["nc-pow-padding"] = make_pow_padding()
    write(os.path.join(HERE, "hard_expected.json"), json.dumps(expected, indent=2) + "\n")
    print("built hard challenges:")
    for k, v in expected.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
