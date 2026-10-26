#!/usr/bin/env python3
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
