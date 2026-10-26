"""Classic finite-field Diffie-Hellman attacks.

Pattern: public `p, g`, peer values `A = g^a`, `B = g^b`, shared `S = g^ab`.
The oracle is usually "does this derived key decrypt/verify?".
"""

from __future__ import annotations

import math

from .ecc import _factorint, dlog_prime_field
from .util import crt


def trivial_shared_secrets(p: int) -> list[int]:
    """Secrets forced by unvalidated g / peer values."""
    return [0, 1, p - 1, p]


def is_trivial_generator(g: int, p: int) -> bool:
    return g % p in (0, 1, p - 1)


def subgroup_element(g: int, p: int, r: int) -> int:
    """An element of exact order r, when r divides p-1."""
    if (p - 1) % r:
        raise ValueError("r does not divide p-1")
    h = pow(g, (p - 1) // r, p)
    if h == 1:
        raise ValueError("g has too small an order for this r")
    return h


def smoothness(p: int, max_bits: int = 40) -> tuple[dict[int, int], int, bool]:
    """Factor p-1 and report the largest prime factor.

    Returns (factorization, largest_prime, is_smooth).
    """
    factors = _factorint(p - 1)
    largest = max(factors) if factors else 1
    return factors, largest, largest.bit_length() <= max_bits


def pohlig_hellman_fp(g: int, h: int, p: int, order: int | None = None):
    """Solve g^x = h mod p when the order is smooth."""
    return dlog_prime_field(g, h, p, order or (p - 1))


def recover_secret_mod_r(base: int, r: int, p: int, check) -> int | None:
    """Brute-force b mod r using an oracle `check(S_candidate) -> bool`.

    `base` is the small-order element sent to the server; the server raises it
    to its static secret b, so `base**j mod p` is the candidate shared secret
    for b = j (mod r).
    """
    for j in range(r):
        if check(pow(base, j, p)):
            return j
    return None


recover_secret_mod_r_modp = recover_secret_mod_r


def crt_recover_secret(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """Combine b mod r_i into b mod product(r_i)."""
    return crt(residues, moduli)


def shared_secret(g: int, a: int, b: int, p: int) -> int:
    return pow(g, a * b, p)


def x25519_low_order_u() -> list[int]:
    """Known low-order u-coordinates for X25519 (probe, then check all-zero)."""
    # 0, 1 and the small-order points from RFC 7748 discussions. The first
    # two cover the common "missing all-zero check" bug.
    return [0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504]


def factor_p_minus_1_bits(p: int) -> dict:
    factors, largest, smooth = smoothness(p)
    return {
        "factors": factors,
        "largest_prime": largest,
        "largest_bits": largest.bit_length(),
        "smooth_40": smooth,
    }
