#!/usr/bin/env python3
"""Template: CBC padding oracle, local or remote, optional PoW.

The server should print IV and CT and a marker line (default "Send") before
accepting queries. If it uses a different prompt, set --prompt/--marker.

Examples:
    python padding_oracle.py --port 40124 --prompt "answer> "
    python padding_oracle.py --host 1.2.3.4 --port 1337 --prompt "" --marker ">"
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import blockcipher as bc, pow as powkit, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--prompt", default="answer> ", help="initial prompt; empty to skip")
    ap.add_argument("--marker", default="Send", help="line that precedes oracle queries")
    ap.add_argument("--block-size", type=int, default=16)
    ap.add_argument("--pow-zeros", type=int, default=3)
    args = ap.parse_args()

    tube = util.connect(args.host, args.port, timeout=10, log_path="oracle.log")
    banner = tube.recvuntil(args.prompt.encode()) if args.prompt else b""

    if b"proof of work" in banner.lower() or b"prefix=" in banner.lower():
        prefix = re.search(rb"prefix=([^\s]+)", banner)
        result = powkit.parse_and_solve(banner.decode("latin-1"))
        answer = result[0] if result else None
        if answer is None and prefix:
            solved = powkit.solve_pow(
                prefix=prefix.group(1).decode(), zeros=args.pow_zeros
            )
            answer = solved[0] if solved else None
        if answer is None:
            raise SystemExit("could not parse/solve the proof of work")
        print(f"[*] PoW answer: {answer}")
        tube.sendline(answer)

    head = tube.recvuntil(args.marker.encode())
    if b"IV=" not in head and b"IV=" in banner:
        head = banner + head
    try:
        tube.recvline()  # drain the rest of the marker line
    except Exception:
        pass

    iv_m = re.search(rb"IV=([0-9a-fA-F]+)", head)
    ct_m = re.search(rb"CT=([0-9a-fA-F]+)", head)
    if not iv_m or not ct_m:
        raise SystemExit(f"could not parse IV/CT; banner was: {head[:300]!r}")
    iv = bytes.fromhex(iv_m.group(1).decode())
    ct = bytes.fromhex(ct_m.group(1).decode())

    def oracle(msg: bytes) -> bool:
        tube.sendline(msg.hex())
        return tube.recvline().strip() == b"valid"

    pt = bc.padding_oracle_attack(oracle, iv + ct, args.block_size)
    tube.close()
    print(pt)
    m = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", pt)
    if m:
        print("FLAG:", m.group(0).decode())


if __name__ == "__main__":
    main()
