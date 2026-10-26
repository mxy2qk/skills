#!/usr/bin/env python3
"""Template: ECDSA biased/partial nonce (HNP).

Expects output.txt with lines like:
    n = ...
    unknown_low_bits = 8
    r0 = ...  s0 = ...  h0 = ...  k_msb0 = ...
    iv = ...
    ciphertext = ...

Adapt the key derivation (SHA256(str(d)) here) to the challenge.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import lattice, util  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--file", default="output.txt")
    ap.add_argument("--unknown-bits", type=int, default=None)
    args = ap.parse_args()

    text = util.read_text(os.path.join(args.dir, args.file))
    v = util.parse_named_ints(text)
    q = v["n"][0]
    t = args.unknown_bits if args.unknown_bits is not None else v.get("unknown_low_bits", [8])[0]

    idx = sorted(
        int(re.fullmatch(r"r(\d+)", k).group(1)) for k in v if re.fullmatch(r"r\d+", k)
    )
    if not idx:
        raise SystemExit("no r0, r1, ... values found")
    rs = [v[f"r{i}"][0] for i in idx]
    ss = [v[f"s{i}"][0] for i in idx]
    hs = [v[f"h{i}"][0] for i in idx]
    leaked = [v[f"k_msb{i}"][0] for i in idx]

    print(f"[*] {len(idx)} signatures, {t} unknown bits per nonce")
    cands = lattice.ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, t)
    print("[*] candidates:", cands)
    if not cands:
        raise SystemExit("no private-key candidate; check the leak direction/bound")

    iv_m = re.search(r"iv\s*=\s*([0-9a-fA-F]+)", text)
    ct_m = re.search(r"ciphertext\s*=\s*([0-9a-fA-F]+)", text)
    if not iv_m or not ct_m:
        print("[!] no AES iv/ciphertext found; printing candidates only")
        return

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError:
        raise SystemExit("pycryptodome required for AES: pip install pycryptodome")

    iv = bytes.fromhex(iv_m.group(1))
    ct = bytes.fromhex(ct_m.group(1))
    for d in cands:
        for name, key in (
            ("sha256(str(d))", hashlib.sha256(str(d).encode()).digest()[:32]),
            ("sha256(d.to_bytes(32))", hashlib.sha256(d.to_bytes(32, "big")).digest()[:32]),
        ):
            try:
                pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
            except ValueError:
                continue
            print(f"[*] KDF={name} d={d}")
            print(pt)
            if b"flag{" in pt or b"CTF{" in pt:
                return


if __name__ == "__main__":
    main()
