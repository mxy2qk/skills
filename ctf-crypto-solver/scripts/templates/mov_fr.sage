#!/usr/bin/env sage
# MOV / Frey-Rück attack: solve an ECDLP by transferring it to a finite field
# F_{q^k} via pairings, when the embedding degree k is small (supersingular /
# low-embedding curves).
#
# Usage:
#   sage mov_fr.sage instance.json [mov|fr]
#
# instance.json:
#   {
#     "p": "0x...", "a": "-1", "b": "0x...",
#     "P": ["0x...", "0x..."],          # base point, order n
#     "Q": ["0x...", "0x..."],          # target, Q = l*P
#     "order": "0x..."  or null,        # n (optional; computed if omitted)
#     "max_k": 6                        # optional: max embedding degree to try
#   }
#
# Second argv-selector: "mov" (Weil pairing, default) or "fr" (Tate pairing).
# Both transfer the DLP to F_{q^k} and call Sage's finite-field log(), which
# internally uses index calculus / Pohlig-Hellman — fast only when n's largest
# prime factor is not cryptographically large.
#
# Adapted from jvdsn/crypto-attacks (MIT): get_embedding_degree inlined;
# mov_attack / frey_ruck_attack rebalanced to throw-on-failure semantics.

import json, sys
from math import gcd
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def embedding_degree(q, n, max_k):
    """Smallest k with q^k == 1 (mod n), or None."""
    for k in range(1, max_k + 1):
        if q**k % n == 1:
            return k
    return None

def _pin_log(alpha, beta, P, R, n):
    """Recover l with l*P == R from beta = alpha^l.

    The finite-field log gives l only modulo ord(alpha). If n has small
    factors (or the point has composite order), ord(alpha) can be a proper
    divisor of n, so enumerate the coset l + t*ord(alpha) and keep the value
    that actually maps P to R.
    """
    l = ZZ(beta.log(alpha))
    oa = ZZ(alpha.multiplicative_order())
    if oa == 0:
        return None
    for t in range(ZZ(n) // oa):
        cand = l + t * oa
        if cand * P == R:
            return int(cand)
    return None

def mov_attack(P, R, max_k=6, max_tries=10):
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "gcd(n, q) must be 1"
    k = embedding_degree(q, n, max_k)
    if k is None:
        return None
    print("embedding degree k =", k)
    Ek = E.base_extend(GF(q**k))
    Pk = Ek(P); Rk = Ek(R)
    for _ in range(max_tries):
        Q_ = Ek.random_point()
        m = Q_.order()
        d = gcd(m, n)
        Q = (m // d) * Q_
        if Q.order() != n:
            continue
        alpha = Pk.weil_pairing(Q, n)
        if alpha == 1:
            continue
        beta = Rk.weil_pairing(Q, n)
        print("finite-field DLP in F_{%s^%s}, ord(alpha)=%s ..."
              % (q, k, alpha.multiplicative_order()))
        l = _pin_log(alpha, beta, P, R, n)
        if l is not None:
            return l
    return None

def fr_attack(P, R, max_k=6, max_tries=10):
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "gcd(n, q) must be 1"
    k = embedding_degree(q, n, max_k)
    if k is None:
        return None
    print("embedding degree k =", k)
    Ek = E.base_extend(GF(q**k))
    Pk = Ek(P); Rk = Ek(R)
    for _ in range(max_tries):
        S = Ek.random_point()
        T = Ek.random_point()
        gamma = Pk.tate_pairing(S, n, k) / Pk.tate_pairing(T, n, k)
        if gamma == 1:
            continue
        delta = Rk.tate_pairing(S, n, k) / Rk.tate_pairing(T, n, k)
        print("finite-field DLP in F_{%s^%s}, ord(gamma)=%s ..."
              % (q, k, gamma.multiplicative_order()))
        l = _pin_log(gamma, delta, P, R, n)
        if l is not None:
            return l
    return None

# ------------------------------------------------------------------- main ----
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage mov_fr.sage instance.json [mov|fr]")
    inst = json.load(open(sys.argv[1]))
    mode = sys.argv[2] if len(sys.argv) > 2 else "mov"
    p = zz(inst["p"]); a = zz(inst["a"]); b = zz(inst["b"])
    Px, Py = zz(inst["P"][0]), zz(inst["P"][1])
    Qx, Qy = zz(inst["Q"][0]), zz(inst["Q"][1])
    max_k = int(inst.get("max_k", 6))

    E = EllipticCurve(GF(p), [a, b])
    P = E(Px, Py)
    Q = E(Qx, Qy)
    if not E.is_on_curve(Px, Py) or not E.is_on_curve(Qx, Qy):
        print("WARNING: a point is not on the claimed curve")

    if inst.get("order") is not None:
        _n = zz(inst["order"])
        if _n * P != E(0):
            print("WARNING: n*P != infinity; double-check n")
        P.set_order(_n)   # avoids the expensive order computation

    if mode == "fr":
        l = fr_attack(P, Q, max_k=max_k)
    else:
        l = mov_attack(P, Q, max_k=max_k)

    if l is None:
        print("NO_SOLUTION — embedding degree not small (or DLP intractable)")
        sys.exit(2)

    if l * P != Q:
        print("WARNING: recovered l does not satisfy l*P == Q")
    print("l =", l)

if __name__ == "__main__":
    main()