#!/usr/bin/env python3
"""Template: MT19937 clone from 624 consecutive 32-bit outputs.

Adapt `block_size`/`endianness` to the challenge's keystream packing.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import prng, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--outputs", default="outputs.txt")
    ap.add_argument("--ciphertext", default="ciphertext.hex")
    ap.add_argument("--block-size", type=int, default=4)
    ap.add_argument("--endian", choices=["big", "little"], default="big")
    args = ap.parse_args()

    obs = [int(x) for x in util.read_text(os.path.join(args.dir, args.outputs)).split()]
    ct = bytes.fromhex(util.read_text(os.path.join(args.dir, args.ciphertext)).strip())
    if len(obs) < 624:
        raise SystemExit(f"need 624 outputs, got {len(obs)}")

    blocks = (len(ct) + args.block_size - 1) // args.block_size
    words = prng.mt19937_predict(obs, blocks)
    ks = b"".join(w.to_bytes(args.block_size, args.endian) for w in words)
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    print(pt)
    m = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", pt)
    if m:
        print("FLAG:", m.group(0).decode())


if __name__ == "__main__":
    main()
