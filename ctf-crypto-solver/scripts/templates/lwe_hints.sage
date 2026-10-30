#!/usr/bin/env sage
# LWE with hints template — recover s from b = A*s + e (mod q) plus linear
# hints <v_i, s> = l_i (mod q) about the secret.
#
# Usage:
#   sage lwe_hints.sage instance.json [block_size]
#
# instance.json:
#   {
#     "q": "0x...",                     # prime modulus
#     "A": [[...], ...],                # m x n
#     "b": [ ... ],                     # length m, b = A*s + e (mod q)
#     "hints": [
#       {"v": [...], "l": "0x...", "type": "perfect"},
#       {"v": [...], "l": "0x...", "type": "approx", "e": 3}
#     ]
#   }
#   hint types:
#     perfect  — <v, s> = l (mod q) exactly
#     approx   — <v, s> = l + e' (mod q) with |e'| <= e
#     (coordinate hint = perfect with v = e_j, l = c)
#
# Optional BLOCK_SIZE as argv[2] forces BKZ instead of plain LLL.
#
# Method (see references/lwe-hints.md): eliminate the hinted coordinates via
# mod-q row reduction to get a lower-dimensional plain LWE, solve it with the
# [[q*I,0],[A^T,I]] embedding + Babai, then back-substitute. Requires q prime.

import json, sys
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage lwe_hints.sage instance.json [block_size]")
    inst = json.load(open(sys.argv[1]))
    q = zz(inst["q"])
    A = [[zz(x) for x in row] for row in inst["A"]]
    b = [zz(x) for x in inst["b"]]
    hints = inst.get("hints", [])
    block = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    s = solve_lwe_hints(A, b, q, hints, block)
    print("s =", s)
    print("verified:", verify(A, b, q, s, hints))

# ---------------------------------------------------------------- helpers ----
def solve_lwe_hints(A, b, q, hints, block=0):
    """Two strategies:

    - all hints perfect  -> eliminate hinted coordinates (reduces dimension),
      solve the reduced plain LWE, back-substitute.
    - any approximate hint -> append every hint as an extra noisy LWE row
      (<v,s> = l + e' is exactly the shape of an LWE sample). Naive
      elimination amplifies the hint noise through V_P^{-1} to ~q/2, so do
      not use it for approximate hints.
    """
    n = len(A[0]) if A else 0
    if not hints or not n:
        return solve_plain(A, b, q, block)

    all_perfect = all(h.get("type", "perfect") == "perfect" for h in hints)
    if not all_perfect:
        A2 = A + [[zz(x) for x in h["v"]] for h in hints]
        b2 = b + [zz(h["l"]) for h in hints]
        print("hints appended as noisy rows (%d extra)" % len(hints))
        return solve_plain(A2, b2, q, block)

    # ---------------- perfect hints: elimination ----------------

    # ---- build V (h x n), l ----
    V = matrix(ZZ, len(hints), n)
    ell = vector(ZZ, len(hints))
    for k, h in enumerate(hints):
        V[k, :] = vector(ZZ, [zz(x) for x in h["v"]])
        ell[k] = zz(h["l"]) % q
    Vq = V.change_ring(GF(q))

    # ---- independent hints + pivot columns (mod-q RREF) ----
    pivcols, used_rows = [], []
    rows = [list(Vq.row(i)) for i in range(Vq.nrows())]
    r = 0
    for c in range(n):
        piv = next((i for i in range(r, len(rows)) if rows[i][c] != 0), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        inv = ~rows[r][c]
        rows[r] = [x * inv for x in rows[r]]
        for i in range(len(rows)):
            if i != r and rows[i][c] != 0:
                f = rows[i][c]
                rows[i] = [(x - f * y) % q for x, y in zip(rows[i], rows[r])]
        pivcols.append(c)
        used_rows.append(r)
        r += 1
        if r == len(rows):
            break
    hp = len(pivcols)
    print("independent hints:", hp, "of", len(hints), "| pivots:", pivcols)

    Vp = V[used_rows, :]
    lp = vector([ell[used_rows[i]] for i in range(hp)])
    P = pivcols
    N = [j for j in range(n) if j not in P]
    V_P = Vp.matrix_from_columns(P)      # hp x hp
    V_N = Vp.matrix_from_columns(N)      # hp x (n-hp)

    K = GF(q)
    V_P_inv = V_P.change_ring(K).inverse()

    A_P = matrix(ZZ, [[A[i][j] for j in P] for i in range(len(A))])
    A_N = matrix(ZZ, [[A[i][j] for j in N] for i in range(len(A))])
    bvec = vector(ZZ, b)

    # reduced LWE over non-pivot coordinates (all arithmetic mod q)
    T = A_P.change_ring(K) * V_P_inv
    M = (A_N.change_ring(K) - T * V_N.change_ring(K))
    bp = (bvec.change_ring(K) - T * lp.change_ring(K))
    Mc = matrix(ZZ, [[int((M[i][j] + q // 2) % q) - q // 2
                      for j in range(M.ncols())] for i in range(M.nrows())])
    bc = [int((bp[i] + q // 2) % q) - q // 2 for i in range(len(bp))]

    if N:
        sN = solve_plain(Mc, bc, q, block)
    else:
        sN = []  # all coordinates pinned by hints

    # ---- back-substitute the pivot coordinates ----
    l_eff = (lp - V_N * vector(ZZ, sN)) % q
    res = V_P_inv * vector([int(l_eff[i]) for i in range(hp)])
    sP = [int((res[i] + q // 2) % q) - q // 2 for i in range(hp)]

    s = [0] * n
    for j, v in zip(P, sP):
        s[j] = v
    for j, v in zip(N, sN):
        s[j] = v
    return s

# --------------------------------------------------- plain LWE (no hints) ----
def solve_plain(A, b, q, block=0):
    """Solve b = A*s + e (mod q) with the [[q*I,0],[A^T,I]] embedding + Babai."""
    if hasattr(A, "nrows"):            # accept a Sage matrix too
        A = [[int(A[i, j]) for j in range(A.ncols())] for i in range(A.nrows())]
    m, n = len(A), (len(A[0]) if A else 0)
    dim = m + n
    rows = matrix(ZZ, dim, dim)
    for i in range(m):
        rows[i, i] = q
    for j in range(n):
        for i in range(m):
            rows[m + j, i] = A[i][j] % q
        rows[m + j, m + j] = 1
    if block > 0:
        try:
            rows = rows.BKZ(block_size=block, proof=False)
        except Exception:
            rows = rows.LLL()
    else:
        rows = rows.LLL()
    target = [x % q for x in b] + [0] * n
    closest, _ = babai(list(rows.rows()), target)
    half = q // 2
    return [int(((closest[m + j] + half) % q) - half) for j in range(n)]

def babai(B, target):
    from sage.all import matrix, QQ
    n = len(target)
    Bm = matrix(QQ, [list(row) for row in B])[:n]
    G, _ = Bm.gram_schmidt()
    w = vector(QQ, target)
    coeffs = [0] * len(Bm.rows())
    for i in range(len(Bm.rows()) - 1, -1, -1):
        gi = G.row(i)
        den = gi * gi
        if den == 0:
            continue
        c = round((w * gi) / den)
        coeffs[i] = c
        if c:
            w = w - c * Bm.row(i)
    closest = sum(coeffs[i] * Bm.row(i) for i in range(len(Bm.rows())))
    return closest, coeffs

# ---------------------------------------------------------------- verify ----
def verify(A, b, q, s, hints):
    m = len(A)
    err = [((b[i] - sum(A[i][j] * s[j] for j in range(len(s))) + q // 2) % q) - q // 2
           for i in range(m)]
    mx = max((abs(e) for e in err), default=0)
    hint_ok = True
    for h in hints:
        v = [zz(x) for x in h["v"]]
        r = ((sum(vi * sj for vi, sj in zip(v, s)) - zz(h["l"])) + q // 2) % q - q // 2
        tol = 0 if h.get("type", "perfect") == "perfect" else zz(h.get("e", 1))
        if abs(r) > tol:
            hint_ok = False
    return "A*s == b (max|e|=%d) | hints ok=%s" % (mx, hint_ok)

if __name__ == "__main__":
    main()
