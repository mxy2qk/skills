#!/usr/bin/env python3
"""Template: LWE via CVP/Babai.

Input JSON (default challenge/lwe.json):
    {"q": 97, "A": [[...], ...], "b": [ ... ]}
where b = A*s + e (mod q) and s/e are small.

For larger dimensions use fpylll/BKZ with the same embedding; this helper is
for toy/weak CTF parameters.
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
    ap.add_argument("--file", default="challenge/lwe.json")
    ap.add_argument("--binary", action="store_true", help="s is binary, not ternary")
    args = ap.parse_args()

    with open(args.file, encoding="utf-8") as fh:
        data = json.load(fh)
    A, b, q = data["A"], data["b"], data["q"]

    s, e = lattice.lwe_cvp_solve(A, b, q)
    if args.binary:
        s = [1 if x else 0 for x in s]
    print("[*] secret:", s)
    print("[*] error: ", e)

    # Verify: A*s + e == b (mod q)
    m = len(A)
    ok = all(
        (sum(A[i][j] * s[j] for j in range(len(s))) + e[i]) % q == b[i] % q
        for i in range(m)
    )
    print("[*] verified:", ok)


if __name__ == "__main__":
    main()
