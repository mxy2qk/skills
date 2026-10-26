#!/usr/bin/env python3
"""Template: hash length extension against H(secret || message).

The verifier should expose the message, MAC, and secret length, then accept
one line containing hex(message) and hex(mac). Adapt --send-format if needed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import hashx, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--algo", default="md5", choices=["md5", "sha1", "sha256"])
    ap.add_argument("--append", default="&admin=1")
    ap.add_argument("--send-format", default="{msg_hex} {mac_hex}")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    tube = util.connect(args.host, args.port, timeout=args.timeout, log_path="length_extension.log")
    banner = b""
    for _ in range(20):
        banner += tube.recvuntil(b"\n")
        if all(k in banner for k in (b"message=", b"mac=", b"secret_length=")):
            break
    # Drain a possible prompt line ("Send: ...").
    try:
        tube.recvline()
    except Exception:
        pass

    msg_m = re.search(rb"message=([^\r\n]+)", banner)
    mac_m = re.search(rb"mac=([0-9a-fA-F]+)", banner)
    len_m = re.search(rb"secret_length=(\d+)", banner)
    if not (msg_m and mac_m and len_m):
        raise SystemExit(f"could not parse banner: {banner[:300]!r}")

    msg = msg_m.group(1)
    mac = bytes.fromhex(mac_m.group(1).decode())
    secret_len = int(len_m.group(1))
    total = secret_len + len(msg)

    tail, new_mac = hashx.length_extension(args.algo, mac, total, args.append.encode())
    forged = msg + tail
    print(f"[*] secret_len={secret_len}, total={total}, forged={len(forged)} bytes")

    line = args.send_format.format(msg_hex=forged.hex(), mac_hex=new_mac.hex())
    tube.sendline(line)
    print(tube.recvuntil(b"\n"))
    tube.close()


if __name__ == "__main__":
    main()
