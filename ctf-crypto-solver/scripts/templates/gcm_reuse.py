#!/usr/bin/env python3
"""Template: AES-GCM nonce reuse / forbidden attack (single- and multi-block).

Two messages encrypted with the SAME nonce and key share H and E_K(J0). The tag
difference gives a polynomial in H; its roots over GF(2^128) include the real H.
Once H and E_K(J0) are known you can forge tags for arbitrary ciphertexts with
that nonce (and decrypt via the CTR keystream if you know any plaintext).

Usage:
    python gcm_reuse.py [instance.json]

instance.json (hex strings; aad optional):
    {
      "c1": "...", "t1": "...", "aad1": "",
      "c2": "...", "t2": "...", "aad2": "",
      "known_p1": "...",              # optional: enables keystream decrypt
      "target_ct": "...",             # optional: same-nonce ciphertext
      "target_tag": "...",            # optional: its true tag -> disambiguates H
      "target_aad": "",
      "forge_ct": "...", "forge_aad": ""   # optional: tag to forge
    }
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import blockcipher as bc  # noqa: E402


def hx(v):
    if v is None:
        return b""
    v = v.strip()
    return bytes.fromhex(v[2:] if v.lower().startswith("0x") else v)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "instance.json"
    inst = json.load(open(path))

    c1, t1 = hx(inst["c1"]), hx(inst["t1"])
    c2, t2 = hx(inst["c2"]), hx(inst["t2"])
    aad1, aad2 = hx(inst.get("aad1")), hx(inst.get("aad2"))

    cands = bc.gcm_nonce_reuse_forge_multi(c1, t1, c2, t2, aad1, aad2)
    print(f"[*] H candidates: {len(cands)}")

    # disambiguate with a known target tag, if provided
    chosen = None
    if inst.get("target_tag"):
        tct, ttag, taad = hx(inst["target_ct"]), hx(inst["target_tag"]), hx(inst.get("target_aad"))
        for h, mask in cands:
            if bc.gcm_forge_tag(h, mask, taad, tct) == ttag:
                chosen = (h, mask)
                break
        if chosen is None:
            print("[!] no candidate matches the target tag")
    if chosen is None and len(cands) == 1:
        chosen = cands[0]

    for h, mask in (cands if chosen is None else [chosen]):
        print(f"[*] H = {h:032x}  E_K(J0) = {mask:032x}")

    if inst.get("known_p1"):
        ks = bc.xor_bytes(c1, hx(inst["known_p1"]))
        if inst.get("target_ct"):
            print("[*] target plaintext:", bc.xor_bytes(hx(inst["target_ct"]), ks))

    if chosen is not None and inst.get("forge_ct"):
        tag = bc.gcm_forge_tag(chosen[0], chosen[1], hx(inst.get("forge_aad")), hx(inst["forge_ct"]))
        print("[*] forged tag:", tag.hex())
    elif chosen is None:
        print("[!] ambiguous H: supply a known (target_ct, target_tag) to disambiguate")


if __name__ == "__main__":
    main()
