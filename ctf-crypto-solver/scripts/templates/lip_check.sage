#!/usr/bin/env sage
# Generic LIP (Lattice Isomorphism Problem) tooling for toy dimensions.
#
# Usage:
#   sage lip_check.sage instance.json
#
# instance.json:
#   {
#     "basis1": [[...], ...],   # integer d x d (rows = basis of L1)
#     "basis2": [[...], ...],   # integer d x d (rows = basis of L2)
#   }
#
# Checks whether L1 and L2 are isometric (L2 = O·L1 for an orthogonal O):
#   1. invariants: |det(G1)| == |det(G2)|, LLL norm-profile match
#   2. for d <= 7, brute-force signed permutations O with O·L1 == L2
#      (in the standard inner product, an integer orthogonal map IS a signed
#       permutation; the check verifies a unimodular change of basis U with
#       O·B1·U = B2)
# Outputs: isomorphic? and (one) O + U. Non-canonical / high-dim lattices that
# pass the invariants but fail the search are reported as needing the paper
# route (SVP-based reductions: ePrint 2026/1593, 1560, 2198, 2381).

import json, sys, itertools
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage lip_check.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    B1 = matrix(ZZ, [[zz(x) for x in row] for row in inst["basis1"]])
    B2 = matrix(ZZ, [[zz(x) for x in row] for row in inst["basis2"]])
    d1, d2 = B1.dimensions(), B2.dimensions()
    if d1 != d2:
        raise SystemExit("dimension mismatch: %s vs %s" % (d1, d2))
    d = d1[0]
    if d1[1] != d or d2[1] != d or B1.det() == 0 or B2.det() == 0:
        raise SystemExit("bases must be square, full-rank integer matrices")

    print("dimension:", d)
    # ---- invariants ----
    G1 = B1 * B1.T; G2 = B2 * B2.T
    det1 = abs(ZZ(G1.det())); det2 = abs(ZZ(G2.det()))
    print("|det(G1)| == |det(G2)|:", det1 == det2)
    if det1 != det2:
        print("NO_ISOMORPHISM (determinant differs)")
        sys.exit(2)

    # LLL-reduced Gram-Schmidt squared norms (informational only — the exact
    # decision is the signed-permutation search below)
    def profile(M):
        Mred = M.LLL()
        G, _ = matrix(QQ, Mred).gram_schmidt()
        return sorted([round(float(QQ(G[i] * G[i])), 6) for i in range(d)])
    p1, p2 = profile(B1), profile(B2)
    print("LLL profile L1:", p1)
    print("LLL profile L2:", p2)

    # ---- signed-permutation search ----
    if d <= 7:
        for sigma in itertools.permutations(range(d)):
            for signs in itertools.product([1, -1], repeat=d):
                O = matrix(ZZ, d, d)
                for r in range(d):
                    O[r, sigma[r]] = signs[r]
                # does O·B1 generate the same lattice as B2?
                M = B2.inverse() * (O * B1)      # want M unimodular (M^T as change of basis)
                if M.det() == 0:
                    continue
                if all(M[i, j].denominator() == 1 for i in range(d) for j in range(d)):
                    if abs(ZZ(M.det())) == 1:
                        print("ISOMORPHIC")
                        print("O =")
                        print(O)
                        print("U (unimodular, B2 = O·B1·U) =")
                        print(M.T)
                        return
        print("passes invariants but no signed-permutation map found —",
              "needs SVP-based / paper route (2026/1593, 1560, 2198, 2381)")
        sys.exit(3)
    else:
        print("dimension > 7: invariant checks only — no exhaustive search")
        print("invariants match; conclude NOTHING (need SVP-based route)")
        sys.exit(3)

if __name__ == "__main__":
    main()
