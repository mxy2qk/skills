#!/usr/bin/env sage
# CRT-RSA partial CRT exponent factoring ("Approximate Divisor Multiples").
#
# Usage:
#   sage crt_rsa_partial.sage instance.json
#
# instance.json:
#   {
#     "N": "0x...", "e": "0x...",
#     "dp": {"known_msb": "0x...", "unknown_lsb": 240},    # MSB case
#     "dq": {"known_msb": "0x...", "unknown_lsb": 240},
#     # or the LSB case:
#     "dp": {"known_lsb": "0x...", "known_lsb_bits": 256, "unknown_msb": 256},
#     "dq": { ...same shape... },
#     "m": 4, "t": 4      # optional Coppersmith params (defaults from the paper)
#   }
#
# Recovers (p, q) and prints them. Requires dp/dq of EQUAL bit length, and the
# unknown fraction within the bound
#   delta = log(max unknown bits, N) < min(1/4 + alpha, 1/2 - 2*alpha)
# where alpha = log(e, N) (base 2).
#
# Based on jvdsn/crypto-attacks known_crt_exponents.py (MIT) and the paper
# "Approximate Divisor Multiples - Factoring with Only a Third of the Secret
# CRT-Exponents". Read references/rsa-crt-exponents.md first.

import json, sys
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage crt_rsa_partial.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    N = zz(inst["N"]); e = zz(inst["e"])
    dp = inst["dp"]; dq = inst["dq"]
    m = int(inst.get("m", 4)); t = int(inst.get("t", 4))

    factors = attack_partial(N, e, dp, dq, m, t)
    if factors is None:
        print("NO_FACTORS — check the known-bits fraction against the bound")
        sys.exit(2)
    p, q = factors
    print("p =", p)
    print("q =", q)
    print("p*q == N:", p * q == N)

# ------------------------------------------------------------------ attack ----
def _univariate_small_roots(f, Nmod, X, m, t):
    """Roots of f (over Zmod(Nmod)) with |root| < X, via Sage's small_roots.

    The root is only guaranteed modulo a factor (beta=0.5): here dp is a root
    mod p, not mod the whole kN.
    """
    if not hasattr(f, "small_roots"):
        R = Zmod(Nmod)["x"]
        f = f.change_ring(R)
    return [int(r) for r in f.small_roots(X, m=m, t=t, beta=0.5)]

def _factor_msb(N, e, dpM, unknown_lsb, k, m, t):
    g = gcd(e, k * N)
    inv_mod = k // g * N
    x = Zmod(k * N)["x"].gen()
    f = x + (e * dpM * (1 << unknown_lsb) + k - 1) * pow(e, -1, inv_mod)
    X = 1 << unknown_lsb
    for x0 in _univariate_small_roots(f, k * N, X, m, t):
        dp = int(f(x0))
        p = gcd(dp, N)
        if 1 < p < N and N % p == 0:
            return p, N // p
    return None

def _factor_lsb(N, e, dpL, dpL_bits, unknown_msb, k, m, t):
    g = gcd((1 << dpL_bits) * e, k * N)
    inv_mod = k // g * N
    x = Zmod(k * N)["x"].gen()
    f = x + (e * dpL + k - 1) * pow((1 << dpL_bits) * e, -1, inv_mod)
    X = 1 << unknown_msb
    for x0 in _univariate_small_roots(f, k * N, X, m, t):
        dp = int(f(x0))
        p = gcd(dp, N)
        if 1 < p < N and N % p == 0:
            return p, N // p
    return None

def _bivariate_small_roots(g, Nmod, X, Y, m):
    # reuse the validated multivariate small_roots from coppersmith_multi.sage.
    # It normalizes by the constant term, so it needs an invertible constant —
    # for the LSB case that often fails (constant even mod 2^i*e); if so we
    # report and give up (the MSB formulation is the robust path).
    import os
    tpl_dir = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(tpl_dir, "coppersmith_multi.sage")).read()
    ns = {"__name__": "coppersmith_multi", "__builtins__": __builtins__}
    exec(compile(preparse(src), "coppersmith_multi.sage", "exec"), ns)
    try:
        return ns["small_roots"](g, (X, Y), m=m)
    except ValueError as ex:
        print("LSB bivariate lattice skipped:", ex)
        return []

def _lg2(x):
    return float(RR(x).log(2))

def attack_partial(N, e, dp, dq, m=None, t=None):
    """Factor N given partial MSB/LSB knowledge of dp and dq."""
    alpha = _lg2(e) / _lg2(N)
    m = int(m) if m else 4
    t = int(t) if t else 4

    if "known_msb" in dp and "known_msb" in dq:
        u = int(dp["unknown_lsb"]); v = int(dq["unknown_lsb"])
        dpM = zz(dp["known_msb"]); dqM = zz(dq["known_msb"])
        delta = max(_lg2(1 << u), _lg2(1 << v)) / _lg2(N)
        bound = min(1 / 4 + alpha, 1 / 2 - 2 * alpha)
        print("MSB case: delta=%.4f < %.4f ? %s" % (delta, float(bound), delta < bound))
        A_ = (1 << (u + v)) * e**2 * dpM * dqM
        A_ = (A_ + N - 1) // N          # ceil
        x = Zmod(e)["x"].gen()
        for poly in (x**2 - (1 - A_ * (N - 1)) * x + A_,
                     x**2 + (1 - A_ * (N - 1) + e) * x + A_):
            for k, _ in poly.roots():
                if k == 0:
                    continue
                k = int(k)
                f = _factor_msb(N, e, dpM, u, k, m, t)
                if f:
                    return f
                f = _factor_msb(N, e, dqM, v, k, m, t)
                if f:
                    return f
        return None

    if "known_lsb" in dp and "known_lsb" in dq:
        i = int(dp["known_lsb_bits"]); j = int(dq["known_lsb_bits"])
        assert i == j, "dp/dq LSB should have equal length"
        dpL = zz(dp["known_lsb"]); dqL = zz(dq["known_lsb"])
        u = int(dp["unknown_msb"]); v = int(dq["unknown_msb"])
        delta = max(_lg2(1 << u), _lg2(1 << v)) / _lg2(N)
        bound = min(1 / 4 + alpha, 1 / 2 - 2 * alpha)
        print("LSB case: delta=%.4f < %.4f ? %s" % (delta, float(bound), delta < bound))
        pr = Zmod((1 << i) * e)["x, y"]
        x, y = pr.gens()
        A = -e**2 * dpL * dqL + e * dpL + e * dqL - 1
        f = (N - 1) * x * y - (e * dqL - 1) * x - (e * dpL - 1) * y + A
        g = f * pow((N - 1) // gcd(N - 1, e * (1 << i)), -1, (1 << i) * e)
        sm = _bivariate_small_roots(g, (1 << i) * e, e, e, m=2)
        for k, l in sm:
            if k == 0 or l == 0:
                continue
            f2 = _factor_lsb(N, e, dpL, i, u, int(k), m, t)
            if f2:
                return f2
            f2 = _factor_lsb(N, e, dqL, i, v, int(l), m, t)
            if f2:
                return f2
        return None

    raise SystemExit("provide known_msb+unknown_lsb OR known_lsb+known_lsb_bits+unknown_msb for BOTH dp and dq")

if __name__ == "__main__":
    main()
