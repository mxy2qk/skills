#!/usr/bin/env python3
"""Template: AES-GCM nonce reuse.

Fill in the two one-block ciphertext/tag pairs (same nonce/key) and one known
plaintext. The CTR keystream lets you decrypt another ciphertext under the
same nonce; the helper also recovers H and forges tags for the one-block case.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import blockcipher as bc  # noqa: E402

# ---- fill these from the challenge ----
C1 = bytes.fromhex("00" * 16)
T1 = bytes.fromhex("00" * 16)
C2 = bytes.fromhex("00" * 16)
T2 = bytes.fromhex("00" * 16)
KNOWN_P1 = b"known plaintext"  # exactly 16 bytes for the one-block helper
TARGET_CT = bytes.fromhex("00" * 16)  # another ciphertext with the same nonce
NEW_CT = bytes.fromhex("00" * 16)  # if you want to forge a tag


def main():
    if len(KNOWN_P1) != 16:
        raise SystemExit("KNOWN_P1 must be 16 bytes for the one-block helper")

    keystream = bc.xor_bytes(C1, KNOWN_P1)
    print("[*] decrypted target:", bc.xor_bytes(TARGET_CT, keystream))

    h, j0 = bc.gcm_nonce_reuse_forge(C1, T1, C2, T2)
    if h:
        print(f"[*] recovered H={h:032x}")
        tag = bc.gcm_forge_tag(h, j0, b"", NEW_CT)
        print("[*] forged tag:", tag.hex())
    else:
        print("[!] could not recover H (check lengths/nonce/AAD)")


if __name__ == "__main__":
    main()
