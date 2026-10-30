#!/usr/bin/env sage
# CRT-RSA with small (UNKNOWN) CRT exponents — 2026/2109 unravelled
# linearization attack. Recovers p, q from N, e when d_p = d mod (p-1) and
# d_q = d mod (q-1) are both small (d_p, d_q < N^delta, delta < 0.122 for
# full-size e).
#
# Usage:
#   sage crt_rsa_small_dp.sage instance.json
#
# instance.json:
#   {
#     "N": "0x...", "e": "0x...",
#     "delta": 0.1,          # optional: assumed bound d_p,d_q < N^delta
#     "m_list": [6, 8],      # optional: even lattice parameters to try
#     "recover_timeout": 60  # optional: seconds per Groebner attempt
#   }
#
# Based on ePrint 2026/2109 (Ding et al., unravelled linearization) — a
# half-dimension formulation of the TLP attack (ePrint 2017/092). See
# references/rsa-crt-exponents.md §2. Validated on toy parameters (80-bit N,
# d_p,d_q ~ few bits); production parameters need larger m and more time.

import json, sys, signal
from sage.all import *

TRUE_ROOT = None   # optional debug hook: (A,B,C,T,L) tuple to report vanishing

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

# ------------------------------------------------ polynomial dict helpers ----
# monomial = (a,b,c,t,l)  for  A^a B^b C^c T^t L^l
def _mul(m1, m2):
    return tuple(x + y for x, y in zip(m1, m2))

def _pmul(p1, p2):
    out = {}
    for k1, v1 in p1.items():
        for k2, v2 in p2.items():
            kk = _mul(k1, k2)
            out[kk] = out.get(kk, 0) + v1 * v2
    return {k: v for k, v in out.items() if v}

def _ppow(p, n):
    r = {(0, 0, 0, 0, 0): 1}
    for _ in range(n):
        r = _pmul(r, p)
    return r

def trans(F, N):
    """Unravelled linearization: repeatedly apply R1 (AL->T-B-C) and
    R2 (ALT->...) until no monomial has both A and L."""
    work = dict(F)
    for _ in range(200000):
        target = next((m for m in work if m[0] > 0 and m[4] > 0), None)
        if target is None:
            return {k: v for k, v in work.items() if v}
        a, b, c, t, l = target
        coeff = work.pop(target)
        if t == 0:
            base = (a - 1, b, c, 0, l - 1)
            for m2, co in (((0, 0, 0, 1, 0), coeff),
                           ((0, 1, 0, 0, 0), -coeff),
                           ((0, 0, 1, 0, 0), -coeff)):
                mm = _mul(base, m2); work[mm] = work.get(mm, 0) + co
        else:
            base = (a - 1, b, c, t - 1, l - 1)
            for m2, co in (((0, 1, 0, 1, 1), coeff),
                           ((0, 1, 0, 0, 1), coeff),
                           ((0, 0, 1, 0, 1), coeff),
                           ((0, 2, 0, 0, 0), -N * coeff),
                           ((0, 1, 0, 0, 0), -2 * N * coeff),
                           ((0, 0, 0, 0, 0), -N * coeff),
                           ((1, 0, 0, 0, 0), 4 * N * coeff),
                           ((0, 1, 0, 1, 0), -coeff),
                           ((0, 0, 1, 1, 0), -coeff)):
                mm = _mul(base, m2); work[mm] = work.get(mm, 0) + co
        work = {k: v for k, v in work.items() if v}
    raise RuntimeError("trans did not terminate")

def monomial_set(m):
    n = m // 2
    S = set()
    for t in (0, 1):
        for a in range(n + 1):
            for b in range(n + 1):
                for c in range(n + 1):
                    if 1 <= a + b + c <= n - t and m - t - b - 2 * c >= 0:
                        S.add((a, b, c, t, 0))
        for b in range(n + 1):
            for c in range(n + 1):
                if 1 <= b + c <= n - t and m - t - b - 2 * c >= 0:
                    for gam in range(1, b + c):
                        S.add((0, b, c, t, gam))
    return sorted(S)

# ------------------------------------------------------------------ attack ----
def attack(N, e, m, delta, rtimeout):
    lnN2 = float(RR(N).log(2))
    alpha = float(RR(e).log(2)) / lnN2

    def powN(coef):
        return ZZ(2) ** max(1, int(round(coef * lnN2)))

    bounds = [powN(2 * delta + 2 * alpha - 1),
              powN(alpha + delta - 0.5),
              powN(2 * delta + 2 * alpha - 0.5),
              powN(alpha + delta),
              powN(0.5)]
    Mset = monomial_set(m)
    if not Mset:
        return None
    f = {(0, 1, 0, 0, 0): 1, (1, 0, 0, 0, 0): (N - 1)}
    g = {(0, 0, 1, 0, 0): 1, (1, 0, 0, 0, 0): (N + 1)}
    h = {(0, 0, 0, 1, 0): 1, (0, 1, 0, 0, 0): -1, (0, 0, 0, 0, 0): 1}
    idx = {mz: i for i, mz in enumerate(Mset)}
    D = len(Mset)
    Bmat = matrix(ZZ, D, D)
    for (a, b, c, t, l) in Mset:
        ee = m - t - b - 2 * c
        F = {(0, 0, 0, 0, 0): e**ee}
        if t: F = _pmul(F, _ppow(h, t))
        if a: F = _pmul(F, _ppow({(1, 0, 0, 0, 0): 1}, a))
        if l: F = _pmul(F, _ppow({(0, 0, 0, 0, 1): 1}, l))
        if b: F = _pmul(F, _ppow(f, b))
        if c: F = _pmul(F, _ppow(g, c))
        Ft = trans(F, N)
        ri = idx[(a, b, c, t, l)]
        for mz, co in Ft.items():
            if mz in idx:
                Bmat[ri, idx[mz]] = co
    for j, (a, b, c, t, l) in enumerate(Mset):
        sc = bounds[0]**a * bounds[1]**b * bounds[2]**c * bounds[3]**t * bounds[4]**l
        Bmat.rescale_col(j, sc)
    if Bmat.det() == 0:
        print("  singular lattice at m=%d" % m)
        return None
    print("  lattice %dx%d, LLL..." % (D, D), flush=True)
    Bmat = Bmat.LLL()
    # Howgrave-Graham selection: keep rows short enough to vanish over ZZ
    thr = RR(e) ** m / RR(sqrt(D))
    sel = [i for i in range(D)
           if sum(ZZ(Bmat[i, j]) ** 2 for j in range(D)) <= thr * thr]
    print("  short vectors below HG threshold: %d/%d" % (len(sel), D), flush=True)
    if len(sel) < 3:
        # fall back to the shortest third of the rows
        norms = [sum(ZZ(Bmat[i, j]) ** 2 for j in range(D)) for i in range(D)]
        order = sorted(range(D), key=lambda i: norms[i])
        sel = order[:max(3, D // 3)]
    BB = Bmat.change_ring(QQ)
    for j, (a, b, c, t, l) in enumerate(Mset):
        sc = bounds[0]**a * bounds[1]**b * bounds[2]**c * bounds[3]**t * bounds[4]**l
        BB.rescale_col(j, 1 / sc)
    return recover(BB, Mset, N, rtimeout, sel)

def _poly_from_row(row, Mset):
    P = PolynomialRing(QQ, names=("A", "B", "C", "T", "L"))
    gens = P.gens()
    res = P(0)
    for co, mz in zip(row, Mset):
        term = QQ(co)
        for g_, e_ in zip(gens, mz):
            term *= g_ ** e_
        res += term
    return res

def _alarm(sig, frm):
    raise TimeoutError("groebner timeout")

def recover(BB, Mset, N, rtimeout, sel=None):
    P = PolynomialRing(QQ, names=("A", "B", "C", "T", "L"))
    A, Bv, C, T, L = P.gens()
    polys = []
    idxs = sel if sel is not None else range(BB.nrows())
    for i in idxs:
        row = [BB[i, j] for j in range(BB.ncols())]
        if not all(x == 0 for x in row):
            polys.append(_poly_from_row(row, Mset))
    rel1 = A * L + Bv + C - T
    rel2 = Bv * L * T + (Bv + C) * L - N * (Bv + 1)**2 + 4 * N * A - T**2
    if TRUE_ROOT is not None:
        A0, B0, C0, T0, L0 = TRUE_ROOT
        van = sum(1 for pol in polys if pol(A0, B0, C0, T0, L0) == 0)
        print("  [debug] %d/%d LLL polys vanish at true root" % (van, len(polys)),
              flush=True)
    n = len(polys)
    for k in (8, 12, 16, 20, 24, n, 10, 14, 18):
        if k >= 3 and k <= n:
            subset = polys[:k] + [rel1, rel2]
            try:
                signal.signal(signal.SIGALRM, _alarm)
                signal.alarm(int(rtimeout))
                I = P.ideal(subset)
                dim = I.dimension()
                if TRUE_ROOT is not None:
                    print("  [debug] k=%d dim=%s" % (k, dim), flush=True)
                if dim != 0:
                    signal.alarm(0)
                    continue
                V = I.variety(ring=ZZ)
                signal.alarm(0)
            except TimeoutError:
                if TRUE_ROOT is not None:
                    print("  [debug] k=%d timeout" % k, flush=True)
                continue
            except Exception:
                try:
                    signal.alarm(0)
                except Exception:
                    pass
                continue
            for sol in V:
                try:
                    A0 = ZZ(sol["A"]); B0 = ZZ(sol["B"]); C0 = ZZ(sol["C"])
                except Exception:
                    continue
                fac = factor_from_ABC(N, A0, B0, C0)
                if fac:
                    return fac
    return None

def factor_from_ABC(N, A0, B0, C0):
    disc = (B0 + 1)**2 - 4 * A0
    if disc < 0:
        return None
    s = isqrt(disc)
    if s * s != disc:
        return None
    for k1, k2 in [((B0 + 1 + s) // 2, (B0 + 1 - s) // 2)]:
        if k1 <= 0 or k2 <= 0:
            continue
        aa = k1 - A0; bb = -(C0 + B0); cc = (k2 - A0) * N
        if aa == 0:
            continue
        d2 = bb * bb - 4 * aa * cc
        if d2 < 0:
            continue
        s2 = isqrt(d2)
        if s2 * s2 != d2:
            continue
        for num in (-bb + s2, -bb - s2):
            if num % (2 * aa) != 0:
                continue
            p = ZZ(num // (2 * aa))
            if 1 < p and N % p == 0:
                return (p, N // p)
    return None

# -------------------------------------------------------------------- main ----
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage crt_rsa_small_dp.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    N = zz(inst["N"]); e = zz(inst["e"])
    delta = float(inst.get("delta", 0.1))
    m_list = inst.get("m_list", [6, 8])
    rtimeout = int(inst.get("recover_timeout", 60))
    print("N bits=%d e bits=%d delta=%.3f" % (N.nbits(), e.nbits(), delta))
    for m in m_list:
        if m % 2:
            continue
        print("m=%d" % m, flush=True)
        try:
            r = attack(N, e, m, delta, rtimeout)
        except Exception as ex:
            print("  error:", type(ex).__name__, ex, flush=True)
            continue
        if r:
            p, q = r
            print("p =", p)
            print("q =", q)
            print("p*q == N:", p * q == N)
            return
    print("FAILED — try a larger m_list, a larger delta, or check parameters")
    sys.exit(2)

if __name__ == "__main__":
    main()
