"""Elliptic curve helpers and common CTF ECC attacks.

Points are (x, y) tuples; the point at infinity is None.
Curves are short Weierstrass: y^2 = x^3 + a*x + b over F_p.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .rsa import tonelli_shanks
from .util import crt, invmod, isqrt_exact


@dataclass
class Curve:
    p: int
    a: int
    b: int

    def __post_init__(self):
        self.a %= self.p
        self.b %= self.p

    def is_on(self, P) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def neg(self, P):
        if P is None:
            return None
        return (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            if y1 == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * invmod(2 * y1, p) % p
        else:
            lam = (y2 - y1) * invmod((x2 - x1) % p, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def double(self, P):
        return self.add(P, P)

    def mul(self, k: int, P):
        if k == 0 or P is None:
            return None
        if k < 0:
            return self.mul(-k, self.neg(P))
        result = None
        addend = P
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def discriminant(self) -> int:
        return (4 * self.a**3 + 27 * self.b**2) % self.p


# --------------------------------------------------------------------------
# discrete logs
# --------------------------------------------------------------------------


def bsgs(curve: Curve, G, Q, order: int, max_steps: int | None = None):
    """Baby-step giant-step: find k with k*G = Q in a group of known order."""
    if Q is None:
        return 0
    m = math.isqrt(order) + 1
    if max_steps is not None:
        m = min(m, max_steps)
    table = {}
    cur = None
    for j in range(m):
        table.setdefault(cur, j)
        cur = curve.add(cur, G)
    # giant steps: Q - i*m*G
    step = curve.mul(-m, G)
    gamma = Q
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = curve.add(gamma, step)
    return None


def _factorint(n: int) -> dict[int, int]:
    try:
        import sympy as sp

        return {int(q): int(e) for q, e in sp.factorint(n).items()}
    except Exception:
        pass
    from .rsa import pollard_rho

    factors: dict[int, int] = {}
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        while n % q == 0:
            factors[q] = factors.get(q, 0) + 1
            n //= q
    while n > 1:
        got = pollard_rho(n)
        if not got:
            factors[n] = factors.get(n, 0) + 1
            break
        q = got[0]
        while n % q == 0:
            factors[q] = factors.get(q, 0) + 1
            n //= q
    return factors


def pohlig_hellman(curve: Curve, G, Q, order: int, factors: dict[int, int] | None = None):
    """Solve k*G = Q when the group order is smooth."""
    if factors is None:
        factors = _factorint(order)
    residues, moduli = [], []
    for q, e in factors.items():
        qe = q**e
        cofactor = order // qe
        Gq = curve.mul(cofactor, G)
        Qq = curve.mul(cofactor, Q)
        g = curve.mul(q ** (e - 1), Gq)  # order q
        x = 0
        for k in range(e):
            t = curve.add(Qq, curve.mul(-x, Gq))
            h = curve.mul(q ** (e - 1 - k), t)
            dk = bsgs(curve, g, h, q)
            if dk is None:
                return None
            x += dk * (q**k)
        residues.append(x % qe)
        moduli.append(qe)
    try:
        sol, _ = crt(residues, moduli)
    except ValueError:
        return None
    return sol % order


# --------------------------------------------------------------------------
# DLP in the multiplicative group (used by singular-curve attacks)
# --------------------------------------------------------------------------


def bsgs_int(g: int, h: int, order: int, p: int):
    """Baby-step giant-step in F_p^*."""
    m = math.isqrt(order) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor = pow(g, -m, p)
    gamma = h % p
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def dlog_prime_field(g: int, h: int, p: int, order: int | None = None):
    """Discrete log in F_p^* via Pohlig-Hellman.

    The order defaults to p-1, but g is often not a generator. Reduce to the
    actual order of g first; otherwise prime factors outside g's subgroup
    produce a base of 1 and the attack fails.
    """
    g %= p
    h %= p
    if order is None:
        order = p - 1
    # Reduce `order` to the multiplicative order of g.
    for q in list(_factorint(order)):
        while order % q == 0 and pow(g, order // q, p) == 1:
            order //= q
    if order <= 1:
        return 0
    factors = _factorint(order)
    residues, moduli = [], []
    for q, e in factors.items():
        qe = q**e
        cofactor = order // qe
        gamma = pow(g, cofactor, p)
        hh = pow(h, cofactor, p)
        base = pow(gamma, q ** (e - 1), p)  # order q
        x = 0
        for k in range(e):
            exp = q ** (e - 1 - k)
            t = pow(hh * pow(pow(g, -x, p), cofactor, p) % p, exp, p)
            dk = bsgs_int(base, t, q, p)
            if dk is None:
                return None
            x += dk * (q**k)
        residues.append(x % qe)
        moduli.append(qe)
    sol, _ = crt(residues, moduli)
    return sol % order


# --------------------------------------------------------------------------
# singular curves
# --------------------------------------------------------------------------


def _cubic_root_mod_p(a: int, b: int, p: int) -> int | None:
    """Find a root of x^3 + a*x + b over F_p."""
    for r in range(0, 1000):
        if (r**3 + a * r + b) % p == 0:
            return r
    try:
        import sympy as sp

        x = sp.Symbol("x")
        poly = sp.Poly(x**3 + a * x + b, x, modulus=p)
        for root in poly.ground_roots():
            if root.is_integer:
                return int(root) % p
    except Exception:
        pass
    return None


def singular_curve_dlog(curve: Curve, G, Q, order: int | None = None):
    """Discrete log on a singular curve.

    A singular curve is isomorphic either to the additive group (cusp) or to
    F_p^* / a norm-one subgroup (node). This handles the split-node and cusp
    cases, which are the usual CTF setups.
    """
    p = curve.p
    if curve.discriminant() != 0:
        raise ValueError("curve is not singular")
    if G is None or Q is None:
        return None
    r = _cubic_root_mod_p(curve.a, curve.b, p)
    if r is None:
        raise ValueError("could not find the singular point")
    # translate so the singular point is at the origin
    u1, v1 = (G[0] - r) % p, G[1] % p
    u2, v2 = (Q[0] - r) % p, Q[1] % p
    c = (3 * r) % p

    if c == 0:
        # cusp: y^2 = x^3, group is additive via t = u/v
        if v1 % p == 0 or v2 % p == 0:
            return None
        t1 = u1 * invmod(v1, p) % p
        t2 = u2 * invmod(v2, p) % p
        if t1 == 0:
            return None
        return t2 * invmod(t1, p) % p

    s = tonelli_shanks(c, p)
    if s is None:
        raise ValueError(
            "non-split node: the curve maps into the norm-one subgroup of "
            "F_{p^2}; solve that DLP in an extension field"
        )
    # split node: y^2 = x^2 (x + c), map to F_p^* via t = (v + s*u)/(v - s*u)
    def to_multiplicative(u, v):
        num = (v + s * u) % p
        den = (v - s * u) % p
        if den % p == 0:
            return None
        return num * invmod(den, p) % p

    t1 = to_multiplicative(u1, v1)
    t2 = to_multiplicative(u2, v2)
    if t1 is None or t2 is None or t1 == 0:
        return None
    group_order = order if order is not None else p - 1
    return dlog_prime_field(t1, t2, p, group_order)


# --------------------------------------------------------------------------
# ECDSA
# --------------------------------------------------------------------------


def ecdsa_recover_private_key(
    r: int, s1: int, s2: int, z1: int, z2: int, n: int
) -> tuple[int, int]:
    """Recover (nonce k, private key d) when two signatures share a nonce."""
    denom = (s1 - s2) % n
    k = (z1 - z2) % n * invmod(denom, n) % n
    d = (s1 * k - z1) % n * invmod(r, n) % n
    return k, d


def ecdsa_nonce_reuse(*args, **kwargs):
    return ecdsa_recover_private_key(*args, **kwargs)


def dsa_recover_private_key(r: int, s1: int, s2: int, z1: int, z2: int, n: int):
    """DSA uses the same nonce-reuse formula as ECDSA."""
    return ecdsa_recover_private_key(r, s1, s2, z1, z2, n)


def ecdsa_biased_nonce_recover(
    q: int,
    rs: list[int],
    ss: list[int],
    hs: list[int],
    unknown_bits: int,
    known_msb: list[int] | None = None,
    max_dim: int = 60,
) -> list[int]:
    """Recover d from ECDSA signatures with small/partial nonces (HNP)."""
    from .lattice import ecdsa_partial_nonce_recover

    n = len(rs)
    leaked = [0] * n if known_msb is None else list(known_msb)
    return ecdsa_partial_nonce_recover(
        q, rs, ss, hs, leaked, unknown_bits, max_dim=max_dim
    )


def ecdsa_recover_key_from_signatures(
    sigs: list[tuple[int, int, int]], n: int
) -> int | None:
    """Given [(r, s, z), ...], find a reused nonce and recover the key."""
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            ri, si, zi = sigs[i]
            rj, sj, zj = sigs[j]
            if ri != rj:
                continue
            try:
                _, d = ecdsa_recover_private_key(ri, si, sj, zi, zj, n)
                return d
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------
# curve construction helpers
# --------------------------------------------------------------------------


def curve_from_params(p: int, a: int, b: int, Gx: int, Gy: int, n: int) -> tuple[Curve, tuple[int, int], int]:
    curve = Curve(p, a, b)
    G = (Gx % p, Gy % p)
    if not curve.is_on(G):
        raise ValueError("generator is not on the curve")
    return curve, G, n


def point_from_text(text: str):
    """Parse '(x, y)' or 'x,y' from challenge output."""
    import re

    nums = [int(v) for v in re.findall(r"-?\d+", text)]
    if len(nums) < 2:
        return None
    return (nums[0], nums[1])
