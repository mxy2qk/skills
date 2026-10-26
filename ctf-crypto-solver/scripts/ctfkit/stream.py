"""Stream cipher helpers: LFSR, RC4, many-time pad, XOR keystreams."""

from __future__ import annotations

import string

PRINTABLE = set(bytes(string.printable, "ascii"))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def recover_keystream(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    return xor_bytes(ciphertext, known_plaintext)


def many_time_pad_xor(ciphertexts: list[bytes]) -> bytes:
    """XOR of all messages: C1^C2^... = P1^P2^..."""
    if not ciphertexts:
        return b""
    out = bytearray(ciphertexts[0])
    for c in ciphertexts[1:]:
        for i, b in enumerate(c):
            out[i] ^= b
    return bytes(out)


def crib_drag(
    ciphertexts: list[bytes], crib: bytes, printable_ratio: float = 0.9
) -> list[tuple[int, int, int, bytes]]:
    """Slide a guessed plaintext across pairs of reused-keystream messages.

    Returns (i, j, position, candidate_plaintext_for_j) candidates.
    """
    out = []
    for i in range(len(ciphertexts)):
        for j in range(i + 1, len(ciphertexts)):
            c1, c2 = ciphertexts[i], ciphertexts[j]
            limit = min(len(c1), len(c2)) - len(crib) + 1
            for pos in range(max(0, limit)):
                ks = xor_bytes(c1[pos : pos + len(crib)], crib)
                cand = xor_bytes(c2[pos : pos + len(crib)], ks)
                if not cand:
                    continue
                ratio = sum(1 for b in cand if b in PRINTABLE) / len(cand)
                if ratio >= printable_ratio:
                    out.append((i, j, pos, cand))
    return out


# --------------------------------------------------------------------------
# LFSR / Berlekamp-Massey
# --------------------------------------------------------------------------


def berlekamp_massey(bits: list[int]) -> list[int]:
    """Return the connection polynomial C with C[0]=1 for a binary sequence.

    Recurrence: s[n] = XOR_{i=1..L} C[i] * s[n-i].
    """
    n = len(bits)
    C = [1]
    B = [1]
    L = 0
    m = 1
    for N in range(n):
        d = bits[N]
        for i in range(1, L + 1):
            if i < len(C):
                d ^= C[i] & bits[N - i]
        if d == 1:
            T = C[:]
            need = len(B) + m
            if len(C) < need:
                C += [0] * (need - len(C))
            for j in range(len(B)):
                C[j + m] ^= B[j]
            if 2 * L <= N:
                L = N + 1 - L
                B = T
                m = 1
            else:
                m += 1
        else:
            m += 1
    return C[: L + 1]


def lfsr_next(bits: list[int], C: list[int]) -> int:
    acc = 0
    for i in range(1, len(C)):
        acc ^= C[i] & bits[-i]
    return acc & 1


def lfsr_predict(bits: list[int], count: int) -> list[int]:
    """Predict the next `count` bits from 2L observed bits."""
    C = berlekamp_massey(bits)
    out = list(bits)
    for _ in range(count):
        out.append(lfsr_next(out, C))
    return out[len(bits) :]


def lfsr_connection_polynomial(bits: list[int]) -> list[int]:
    return berlekamp_massey(bits)


# --------------------------------------------------------------------------
# RC4
# --------------------------------------------------------------------------


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rc4_keystream(key: bytes, length: int) -> bytes:
    return rc4(key, b"\x00" * length)


def rc4_prga(key: bytes, length: int) -> bytes:
    return rc4_keystream(key, length)
