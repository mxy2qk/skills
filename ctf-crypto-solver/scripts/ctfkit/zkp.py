"""Small ZKP / secret-sharing helpers.

These cover the algebraic cores that CTF ZKP tasks usually reduce to. The
protocol-specific parts (verifier equations, transcript hashing) still need to
be read from the challenge source.
"""

from __future__ import annotations

from .util import invmod


def lagrange_interpolate(points: list[tuple[int, int]], p: int, x: int = 0) -> int:
    """Evaluate the interpolating polynomial through `points` at `x` mod p."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        num = den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = num * (x - xj) % p
            den = den * (xi - xj) % p
        total = (total + yi * num * invmod(den, p)) % p
    return total


def shamir_recover(shares: list[tuple[int, int]], p: int) -> int:
    """Recover f(0) from Shamir shares (x_i, f(x_i))."""
    return lagrange_interpolate(shares, p, 0)


def fiat_shamir_nonce_reuse(s1: int, s2: int, c1: int, c2: int, q: int) -> int:
    """Recover the witness from a Schnorr/Fiat-Shamir nonce reuse.

    Responses s_i = r + c_i*x with the same nonce r:
        x = (s1 - s2) / (c1 - c2) mod q
    """
    return (s1 - s2) * invmod((c1 - c2) % q, q) % q


def schnorr_recover(s1: int, s2: int, c1: int, c2: int, q: int) -> int:
    return fiat_shamir_nonce_reuse(s1, s2, c1, c2, q)


def schnorr_verify(g, y, t, c, s, q, mul=None, add=None):
    """Verify g^s == t * y^c in a group.

    Pass `mul(base, exponent)` / `add(P, Q)` for a custom group; defaults to
    modular multiplication in F_p (pass p as q).
    """
    if mul is None:
        mul = pow
        left = pow(g, s, q)
        right = t * pow(y, c, q) % q
        return left == right
    left = mul(g, s)
    right = add(t, mul(y, c))
    return left == right


def groth16_broken_setup_forge(alpha, beta, vk_x):
    """Trivial forgery when the setup has delta == gamma (pairing groups).

    Returns the (A, B, C) values to submit; the caller supplies group objects
    and performs the pairing check. This is only a reminder of the shape.
    """
    return alpha, beta, -vk_x
