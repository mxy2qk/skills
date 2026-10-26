#!/usr/bin/env python3
"""Template: smooth-order finite-field Diffie-Hellman.

Expects output.txt with p, g, A, B, iv, ciphertext. Tries common KDFs.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import ecc, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--file", default="output.txt")
    args = ap.parse_args()

    text = util.read_text(os.path.join(args.dir, args.file))
    v = util.parse_named_ints(text)
    p, g, A, B = v["p"][0], v["g"][0], v["A"][0], v["B"][0]

    a = ecc.dlog_prime_field(g, A, p)
    if a is None:
        raise SystemExit("DLP failed; is p-1 smooth?")
    assert pow(g, a, p) == A
    S = pow(B, a, p)
    print(f"[*] a={a}\n[*] shared={S}")

    iv_m = re.search(r"iv\s*=\s*([0-9a-fA-F]+)", text)
    ct_m = re.search(r"ciphertext\s*=\s*([0-9a-fA-F]+)", text)
    if not iv_m or not ct_m:
        print("[!] no AES iv/ciphertext; printing the shared secret only")
        return

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        raise SystemExit("pycryptodome required for AES: pip install pycryptodome")

    iv = bytes.fromhex(iv_m.group(1))
    ct = bytes.fromhex(ct_m.group(1))
    keys = [
        ("sha256(str(S))", hashlib.sha256(str(S).encode()).digest()[:32]),
        ("sha256(S.to_bytes)", hashlib.sha256(S.to_bytes((S.bit_length() + 7) // 8, "big")).digest()[:32]),
        ("md5(str(S))", hashlib.md5(str(S).encode()).digest()),
        ("sha256(S bytes LE)", hashlib.sha256(S.to_bytes((S.bit_length() + 7) // 8, "little")).digest()[:32]),
    ]
    for name, key in keys:
        try:
            pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        except ValueError:
            continue
        print(f"[*] KDF={name}")
        print(pt)
        if b"flag{" in pt or b"CTF{" in pt:
            return


if __name__ == "__main__":
    main()
