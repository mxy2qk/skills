#!/usr/bin/env python3
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
