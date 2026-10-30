#!/usr/bin/env sage
# Multivariate Coppersmith (Hovgrave-Graham 'small_roots').
#
# Usage:
#   sage coppersmith_multi.sage instance.json
#
# instance.json — the polynomial is described as a sparse list of terms over
# Zmod(N), with per-variable bounds:
#   {
#     "N": "0x...",            # modulus
#     "m": 1,                  # optional: lattice power (default 1)
#     "terms": [ [[2, 1], "0x...a353"], [[0, 1], "0x...1234"], ... ]
#                              # each term = [exponents, coefficient];
#                              # len(exponents) must agree across terms
#     "bounds": ["0x...", "0x..."]   # per-variable root bound X_i
#   }
#
# The script builds f(x0, x1, ...) = sum(c * prod(xi^ei)) over Zmod(N), then
# finds all small roots (|xi| < bounds[i]) and verifies each against f == 0
# mod N. Common patterns to encode here: HNP (f = a*x + y - b), partial-dp /
# small-CRT-exponent (bivariate), related messages, known-high-bits + unknown
# x (stereotyped/partial-p, usually univariate).
#
# Implementation is a from-scratch re-build of the well-known Sage small_roots
# (defund/coppersmith, GPL-derived): same shift lattice, but the matrix is
# constructed manually because Sage 10 removed Sequence.coefficient_matrix().

import itertools, json, sys
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

def small_roots(f, bounds, m=1, d=None):
    """Find small integer roots of a polynomial f over Zmod(N).

    f   — polynomial over Zmod(N); constant term nonzero and invertible.
    bounds — per-variable root bound (list or tuple).
    m   — lattice power (default 1); raise to enlarge the achievable region.
    d   — bound on shift degree (default: f.degree()).
    Returns a list of root tuples (length = number of variables).
    """
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    # make the constant coefficient 1 (or as close as possible)
    coeffs = f.coefficients()          # missing zeros are absent
    const = f.constant_coefficient()
    if const == 0:
        raise ValueError("constant term is 0; shift the polynomial first")
    if gcd(ZZ(const), N) != 1:
        raise ValueError("constant term is not invertible mod N (try gcd -> factor?)")
    f = f * (1 / const)       # normalize the constant coefficient to 1 mod N
    f = f.change_ring(ZZ)

    # build shift polynomials: N^(m-i) * f^i * (monomial shift of deg < d)
    G = []
    for i in range(m + 1):
        base = N**(m - i) * f**i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base
            for var, sh in zip(f.variables(), shifts):
                g *= var**sh
            G.append(g)

    # collect the monomial basis over ZZ manually (Sage 10 note above)
    mons = set()
    for g in G:
        mons.update(g.monomials())
    mons = sorted(mons, key=lambda mo: (mo.degree(), tuple(mo.exponents()[0])))
    mid = {mo: k for k, mo in enumerate(mons)}
    ncols = len(mons)

    B = matrix(ZZ, len(G), ncols)
    for r, g in enumerate(G):
        for mo, c in zip(g.monomials(), g.coefficients()):
            B[r, mid[mo]] = c

    # column scaling by the root bounds
    factors = [monomial(*bounds) for monomial in mons]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)

    # read the short rows back into polynomials; a 0-dim ideal pins the roots
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, [sum(B[i, j] * mons[j] for j in range(ncols))
                           for i in range(B.nrows())]):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                roots.append(tuple(R(root[var]) for var in f.variables()))
            return roots
    return []

# ------------------------------------------------------------------- main ----
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage coppersmith_multi.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    N = zz(inst["N"])
    m = int(inst.get("m", 1))
    terms = inst["terms"]
    bounds = [zz(x) for x in inst["bounds"]]
    varn = len(terms[0][0])

    P = PolynomialRing(Zmod(N), "x", varn)
    gens_ = P.gens()
    f = sum(zz(c) * prod(gens_[i]**e for i, e in enumerate(exps))
            for exps, c in terms)
    print("f =", f)
    print("variables:", varn, "| m:", m, "| bounds:", bounds)

    roots = small_roots(f, tuple(bounds), m=m)
    if not roots:
        print("NO_ROOTS — enlarge m, or check the terms / bounds description")
        sys.exit(1)
    for root in roots:
        ok = all((sum(zz(c) * prod(root[i]**e for i, e in enumerate(exps))
                      for exps, c in terms) % N) == 0 for _ in [0])
        print("root:", root, "| f(root) mod N:", int(f(root)) % N, "| zero:", ok)

    import re
    # dump each coordinate as bytes in case one is a flag-bearing message
    for root in roots:
        for xi in root:
            if int(xi) > 0:
                try:
                    bs = int(xi).to_bytes((int(xi).bit_length() + 7) // 8, "big")
                    mh = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", bs)
                    if mh:
                        print("FLAG:", mh.group(0).decode())
                except Exception:
                    pass

if __name__ == "__main__":
    main()