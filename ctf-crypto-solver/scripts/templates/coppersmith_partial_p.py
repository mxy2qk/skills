#!/usr/bin/env python3
"""Template: Coppersmith partial-p RSA.

Expects output.txt with n, e, c, p_high, unknown_low_bits (or similar names).
Adapt the field names to the challenge.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import lattice, rsa, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--file", default="output.txt")
    args = ap.parse_args()

    text = util.read_text(os.path.join(args.dir, args.file))
    v = util.parse_named_ints(text)
    n, e, c = v["n"][0], v["e"][0], v["c"][0]

    # Accept a few common names for the leaked high bits and shift.
    p_high = next(
        (v[k][0] for k in ("p_high", "ph", "p_msb", "known_msb", "p_known") if k in v),
        None,
    )
    shift = next(
        (v[k][0] for k in ("unknown_low_bits", "shift", "low_bits", "unknown_bits") if k in v),
        None,
    )
    if p_high is None or shift is None:
        # Try to infer shift from p_high's bit length and n's size.
        if p_high is None:
            raise SystemExit("could not find p_high in output.txt")
        shift = max(0, n.bit_length() // 2 - p_high.bit_length())
        print(f"[!] inferred shift={shift}")

    got = lattice.factor_with_known_high_bits(n, p_high, shift)
    if not got:
        raise SystemExit("Coppersmith failed; check the bound/window")
    p, q = got
    assert p * q == n
    d = pow(e, -1, (p - 1) * (q - 1))
    pt = rsa.decrypt_bytes(c, d, n)
    print(f"[*] p={p}\n[*] q={q}")
    print(pt)
    m = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", pt)
    if m:
        print("FLAG:", m.group(0).decode())


if __name__ == "__main__":
    main()
