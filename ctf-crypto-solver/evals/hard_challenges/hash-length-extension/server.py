#!/usr/bin/env python3
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
            b"message=" + MESSAGE + b"\n"
            + b"mac=" + MAC + b"\n"
            + f"secret_length={len(SECRET)}\n".encode()
            + b"Send: hex(message) hex(mac)\n"
        )
        self.wfile.flush()
        line = self.rfile.readline().strip()
        try:
            msg_hex, mac_hex = line.split()
            msg = bytes.fromhex(msg_hex.decode())
            mac = mac_hex.decode().lower()
        except Exception:
            self.wfile.write(b"bad format\n")
            return
        if b"admin=1" in msg and hashlib.md5(SECRET + msg).hexdigest() == mac:
            self.wfile.write(b"accepted " + FLAG.encode() + b"\n")
        else:
            self.wfile.write(b"rejected\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 40125
    with Server(("127.0.0.1", port), Handler) as s:
        print(f"listening on {port}", flush=True)
        s.serve_forever()
