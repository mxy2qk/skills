"""Classic public-key schemes that show up in CTF "exotic crypto" tasks.

Paillier (additively homomorphic), ElGamal, Goldwasser-Micali (bitwise), and
small helpers for the attacks that follow from their algebra.
"""

from __future__ import annotations

import math

from .util import invmod


# --------------------------------------------------------------------------
# Paillier
# --------------------------------------------------------------------------


def paillier_keygen(p: int, q: int) -> tuple[int, int, int, int]:
    """Return (n, g, lambda, mu) for the common g = n+1 variant."""
    n = p * q
    g = n + 1
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    n2 = n * n
    l_val = (pow(g, lam, n2) - 1) // n
    mu = invmod(l_val, n)
    return n, g, lam, mu


def paillier_encrypt(m: int, n: int, g: int | None = None, r: int = 1) -> int:
    g = g or (n + 1)
    return pow(g, m, n * n) * pow(r, n, n * n) % (n * n)


def paillier_decrypt(c: int, n: int, lam: int, mu: int, g: int | None = None) -> int:
    g = g or (n + 1)
    n2 = n * n
    l_val = (pow(c, lam, n2) - 1) // n
    return l_val * mu % n


def paillier_add(c1: int, c2: int, n: int) -> int:
    """Enc(m1) * Enc(m2) = Enc(m1 + m2)."""
    return c1 * c2 % (n * n)


def paillier_mul_const(c: int, k: int, n: int) -> int:
    """Enc(m)^k = Enc(k*m)."""
    return pow(c, k, n * n)


def paillier_negate(c: int, n: int) -> int:
    """Enc(-m mod n) = Enc(m)^(-1)."""
    return invmod(c, n * n)


# --------------------------------------------------------------------------
# ElGamal
# --------------------------------------------------------------------------


def elgamal_encrypt(m: int, p: int, g: int, h: int, k: int) -> tuple[int, int]:
    return pow(g, k, p), m * pow(h, k, p) % p


def elgamal_decrypt(c1: int, c2: int, x: int, p: int) -> int:
    return c2 * invmod(pow(c1, x, p), p) % p


def elgamal_reuse_known_plaintext(
    c1: int, c2_known: int, known_m: int, c2_target: int, p: int
) -> int:
    """Same ephemeral k: recover the other plaintext from one known one."""
    # c2 = m * h^k; ratio cancels h^k and k.
    return c2_target * invmod(c2_known, p) % p * known_m % p


def elgamal_trivial_h(h: int, p: int) -> list[int]:
    """Public keys that make the shared secret a known constant."""
    out = []
    if h % p == 1:
        out.append(1)
    if h % p == p - 1:
        out.append(p - 1)
    return out


# --------------------------------------------------------------------------
# Goldwasser-Micali
# --------------------------------------------------------------------------


def _is_qr(a: int, p: int) -> bool:
    a %= p
    if a == 0:
        return True
    return pow(a, (p - 1) // 2, p) == 1


def gm_decrypt_bit(c: int, p: int, q: int) -> int:
    """0 if c is a quadratic residue mod both primes, else 1."""
    return 0 if (_is_qr(c, p) and _is_qr(c, q)) else 1


def gm_decrypt(ciphertexts: list[int], p: int, q: int) -> list[int]:
    return [gm_decrypt_bit(c, p, q) for c in ciphertexts]


def gm_bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)


# --------------------------------------------------------------------------
# Rabin (helpers beyond ctfkit.rsa.rabin_roots)
# --------------------------------------------------------------------------


def rabin_encrypt(m: int, n: int) -> int:
    return m * m % n


def rabin_candidates(c: int, p: int, q: int) -> list[int]:
    from .rsa import rabin_roots

    return rabin_roots(c, p, q)
