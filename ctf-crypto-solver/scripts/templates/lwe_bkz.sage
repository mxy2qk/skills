#!/usr/bin/env sage
# LWE solve via lattice embedding + BKZ/LLL + Babai nearest plane.
#
# Usage:
#   sage lwe_bkz.sage instance.json [block_size]
#
# instance.json:
#   {
#     "q": 0x...,
#     "A": [[...], ...],      # m x n  (A)
#     "b": [ ... ]            # length m, b = A*s + e (mod q)
#   }
#
# Optional: pass a BLOCK_SIZE as the second argument to force BKZ (e.g. 40)
# instead of plain LLL — needed once m+n is large or the secret is not tiny.
#
# The script reproduces the [[q*I, 0], [A^T, I]] embedding used by
# ctfkit.lattice.lwe_cvp_solve but reduces the embedding with Sage's lattice
# tools, so it scales past the pure-Python LLL dimension limit. Output: s, e
# centered in [-q/2, q/2), plus verification.

import json, sys
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def babai_nearest_plane(B_reduced, target):
    """Babai's nearest plane on a reduced basis (rows).

    Each reduced row already has length len(target) (the embedding is square),
    so the algorithm just walks all of them top-down via Gram-Schmidt.
    """
    from sage.all import matrix, QQ
    n = len(target)
    B = matrix(QQ, [list(row) for row in B_reduced])
    G, _mu = B.gram_schmidt()
    w = vector(QQ, target)
    coeffs = [0] * len(B.rows())
    for i in range(len(B.rows()) - 1, -1, -1):
        gi = G.row(i)
        den = gi * gi
        if den == 0:
            continue
        c = round((w * gi) / den)
        coeffs[i] = c
        if c:
            w = w - c * B.row(i)
    closest = sum(coeffs[i] * B.row(i) for i in range(len(B.rows())))
    return closest, coeffs

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage lwe_bkz.sage instance.json [block_size]")
    inst = json.load(open(sys.argv[1]))
    q = zz(inst["q"])
    A = [[zz(x) for x in row] for row in inst["A"]]
    b = [zz(x) for x in inst["b"]]
    block = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    m = len(A)
    n = len(A[0]) if m else 0
    print("m=%d n=%d q=%d block=%d" % (m, n, q, block))

    # embedding [[q*I, 0], [A^T, I]] -- dim = m + n
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
            Bred = rows.BKZ(block_size=block, proof=False)
            print("BKZ block=%d done" % block)
        except Exception as ex:
            print("BKZ failed (%s) — falling back to LLL" % type(ex).__name__)
            Bred = rows.LLL()
    else:
        Bred = rows.LLL()

    target = [x % q for x in b] + [0] * n
    closest, _ = babai_nearest_plane(list(Bred.rows()), target)
    half = q // 2
    s = [int(((closest[m + j] + half) % q) - half) for j in range(n)]
    e = [int(((b[i] - closest[i] + half) % q) - half) for i in range(m)]

    print("s =", s)
    print("e =", e)

    # verify: b == A*s + e (mod q)
    ok = all(
        (sum(A[i][j] * s[j] for j in range(n)) + e[i] - b[i]) % q == 0
        for i in range(m)
    )
    print("verified:", ok)

if __name__ == "__main__":
    main()