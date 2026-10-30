#!/usr/bin/env sage
# Boneh-Durfee attack (Herrmann-May) for small private decryption exponents.
#
# Usage:
#   sage boneh_durfee.sage instance.json
#
# instance.json:
#   {
#     "n": "0x...", "e": "0x...",
#     "c": "0x..." ,              # optional RSA ciphertext to decrypt
#     "delta": 0.18,             # optional: guess d < n^delta (max ~0.292)
#     "m": 4,                    # optional: lattice size (bigger = stronger/slower)
#     "t": null,                 # optional: int((1-2*delta)*m) if omitted
#     "_len": null               # optional: bytes length of the plaintext
#   }
#
# Recovers d, prints it, and if c is given prints the decrypted plaintext /
# extracted flag. If the printed message is garbage, lower delta or raise m and
# rerun; Boneh-Durfee is *not* a one-shot guarantee.
#
# Ported/trimmed from David Wong's public boneh_durfee.sage (mimoo/
# RSA-and-LLL-attacks, MIT). The core lattice routine is unchanged.

import json, sys, time
from sage.all import *

def zz(v):
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

# ---------------------------------------------------------------- config ----
debug = False
strict = False
helpful_only = True
dimension_min = 7  # stop removing rows if the lattice reaches this dimension

# --------------------------------------------------------- helpers (mimoo) ----
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii, ii] >= modulus:
            nothelpful += 1
    print(nothelpful, "/", BB.dimensions()[0], "vectors are not helpful")

def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = "%02d " % ii
        for jj in range(BB.dimensions()[1]):
            a += "0" if BB[ii, jj] == 0 else "X"
        if BB.dimensions()[0] < 60 and BB[ii, ii] >= bound:
            a += "~"
        print(a)

def remove_unhelpful(BB, monomials, bound, current):
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB
    for ii in range(current, -1, -1):
        if BB[ii, ii] >= bound:
            affected_vectors, affected_vector_index = 0, 0
            for jj in range(ii + 1, BB.dimensions()[0]):
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj
            if affected_vectors == 0:
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                return remove_unhelpful(BB, monomials, bound, ii - 1)
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                if (affected_deeper
                        and abs(bound - BB[affected_vector_index, affected_vector_index])
                        < abs(bound - BB[ii, ii])):
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    return remove_unhelpful(BB, monomials, bound, ii - 1)
    return BB

# --------------------------------------------------------- core (from mimoo) ----
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """Find (x0, y0) with |x0| < XX, |y0| < YY and pol(x0, y0) == 0.

    Boneh-Durfee, revisited by Herrmann & May. Solvable whenever
    d < N^delta, delta < 1 - sqrt(2)/2 ~= 0.292.
    """
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x * y + 1 - u)   # u = x*y + 1
    polZ = Q(pol).lift()

    UU = XX * YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x**ii * modulus**(mm - kk) * polZ(u, x, y)**kk
            gg.append(xshift)
    gg.sort()

    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()

    # y-shifts (Herrmann & May selection)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            yshift = y**jj * polZ(u, x, y)**kk * modulus**(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm / tt) * jj, mm + 1):
            monomials.append(u**kk * y**jj)

    # build lattice
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = (gg[ii].monomial_coefficient(monomials[jj])
                              * monomials[jj](UU, XX, YY))

    # prune unhelpful rows
    if helpful_only:
        BB = remove_unhelpful(BB, monomials, modulus**mm, nn - 1)
        nn = BB.dimensions()[0]
        if nn == 0:
            return 0, 0
    if debug:
        helpful_vectors(BB, modulus**mm)

    # determinant bound check (informational unless strict)
    det = BB.det()
    bound = modulus**(mm * nn)
    if det >= bound:
        print("det(L) >= e^(m*n): solution may not be found; try higher m / lower delta")
        if strict:
            return -1, -1

    if debug:
        matrix_overview(BB, modulus**mm)
    BB = BB.LLL()
    if debug:
        print("LLL done; %dx%d" % (BB.dimensions()[0], BB.dimensions()[1]))

    # find two independent short vectors, take resultant
    found = False
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            PR.<w, z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w * z + 1, w, z) * BB[pol1_idx, jj] / monomials[jj](UU, XX, YY)
                pol2 += monomials[jj](w * z + 1, w, z) * BB[pol2_idx, jj] / monomials[jj](UU, XX, YY)
            rr = pol1.resultant(pol2)
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            found = True
            break
        if found:
            break
    # found? then recover the algebraic root from the resultant
    if not found:
        return 0, 0

    # rr is the resultant of the two bivariate polys; its parent is still the
    # (w, z) ring, so substituting (q, q) collapses it to one variable.
    PR.<q> = PolynomialRing(ZZ)
    rr = rr(q, q)
    soly = rr.roots()
    if len(soly) == 0:
        return 0, 0
    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]
    return solx, soly

# ------------------------------------------------------------------- main ----
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage boneh_durfee.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    t_start = time.time()

    N = zz(inst["n"]); e = zz(inst["e"])
    delta = float(inst.get("delta", 0.18))
    mm = int(inst.get("m", 4))
    tt = inst.get("t")
    tt = int(zz(tt)) if tt is not None else int((1 - 2 * delta) * mm)

    X = 2 * floor(N**delta)      # d < N^delta  =>  |x| = |k| < 2 N^delta
    Y = floor(N**(1 / 2))        # p, q ~= sqrt(N)
    print("N bits:", N.nbits(), "| e bits:", e.nbits())
    print("delta:", delta, "| m:", mm, "| t:", tt)

    P.<x, y> = PolynomialRing(ZZ)
    A = (N + 1) // 2
    pol = 1 + x * (A + y)
    solx, soly = boneh_durfee(pol, e, mm, tt, X, Y)

    if solx <= 0:
        raise SystemExit("no solution found — lower delta (%.3f) or raise m" % delta)
    d = int(pol(solx, soly) / e)

    # sanity check that d really is a private exponent
    if pow(2, e * d, N) != 2:
        print("WARNING: recovered (solx,soly) did not give a working d")
    print("d =", d)
    print("(%.1fs)" % (time.time() - t_start))

    if inst.get("c") is not None:
        c = zz(inst["c"])
        pt_int = pow(c, d, N)
        blen = inst.get("_len")
        if blen is None:
            blen = (pt_int.bit_length() + 7) // 8
        pt = int(pt_int).to_bytes(int(blen), "big").lstrip(b"\x00")
        print("plaintext bytes:", pt[:160])
        import re
        m = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", pt)
        if m:
            print("FLAG:", m.group(0).decode())

if __name__ == "__main__":
    main()