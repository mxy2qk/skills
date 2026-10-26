#!/usr/bin/env python3
"""Template: toy/weak-parameter NTRU key recovery.

Input JSON (default challenge/ntru.json):
    {"q": 97, "h": [ ... ], "negacyclic": true}
where h = g * f^{-1} mod (x^N +/- 1) and f, g are small.

Uses pure LLL; realistic NTRU needs BKZ (fpylll/Sage). The recovered (f, g)
may be a rotation/sign of the original; verify by multiplication.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import lattice  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="challenge/ntru.json")
    ap.add_argument("--max-coeff", type=int, default=2)
    args = ap.parse_args()

    with open(args.file, encoding="utf-8") as fh:
        data = json.load(fh)
    h, q = data["h"], data["q"]
    negacyclic = data.get("negacyclic", True)

    cands = lattice.ntru_recover(h, q, negacyclic, max_coeff=args.max_coeff)
    print(f"[*] candidates: {len(cands)}")
    for f, g in cands:
        ok = lattice.ntru_mul(h, f, q, negacyclic) == [x % q for x in g]
        print(f"f={f}\ng={g}\nverified={ok}\n")


if __name__ == "__main__":
    main()
