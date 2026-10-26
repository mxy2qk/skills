#!/usr/bin/env sage
# EC-HNP template (partial x-coordinate leak of an ECDH shared point).
#
# Covers the babyDH2 / AliyunCTF lineage, i.e. the lattice L(n,d,t) of
# Xu-Sarkar-Wang-Hu, Asiacrypt 2022, eprint 2022/1239.
#
# Usage:
#   sage ec_hnp.sage instance.json [d] [t]
#
# instance.json (ASCII/hex ints are fine):
#   {
#     "K": 235,                 # unknown low bits per leak
#     "p": "...", "a": -3, "b": "...",   # optional, NIST521p defaults
#     "A_x": "...", "B_x": "...",        # public x-coordinates (A = a*G, B = b*G)
#     "leaks": {"0": "...", "1": "...", "-1": "...", ...},
#     "ciphertext": "...",      # optional: hex AES-ECB of a token keyed by
#                               #           sha256(str(S.x).encode())
#     "_debug": {...}           # optional ground truth for calibration
#   }
#
# !!! READ references/ec-hnp.md FIRST !!!
# Check the sample count and the bound before running this: with n pairs fixed,
# the reachable unknown-bit bound is limited. d=3 means w=906 and flatter can
# already take ~30 min; a service alarm of 600 s will not wait.
#
# The script needs `flatter` in PATH (or FLATTER=/path/to/flatter) and
# `msolve` for the final solve (or set MSOLVE=/path/to/msolve).

import json, os, re, subprocess, sys, time
from fractions import Fraction
from hashlib import sha256
from sage.all import *

FLATTER = os.environ.get("FLATTER") or "flatter"
MSOLVE = os.environ.get("MSOLVE") or "msolve"

def log(*a):
    print("[%7.1fs] " % (time.time() - T0), *a, flush=True)
T0 = time.time()

# ---------------------------------------------------------------- input ----
inst = json.load(open(sys.argv[1]))
d = int(sys.argv[2]) if len(sys.argv) > 2 else 2
t = int(sys.argv[3]) if len(sys.argv) > 3 else 0
K = int(inst["K"])
p = ZZ(inst.get("p", 2**521 - 1))
a = ZZ(inst.get("a", -3))
b = ZZ(inst.get("b", 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00))
leaks = {int(k): int(v) for k, v in inst["leaks"].items()}
NQ = len([m for m in leaks if m > 0])
h0 = ZZ(leaks[0]) << K
E = EllipticCurve(GF(p), [a, b])
A = E.lift_x(GF(p)(inst["A_x"]))
Qxs = [ZZ((i * A)[0]) for i in range(1, NQ + 1)]
log("NQ=%d d=%d t=%d K=%d pbits=%d" % (NQ, d, t, K, p.nbits()))

# ------------------------------------------------------------- helpers ----
def sym(v):
    v = ZZ(v) % p
    return v - p if v > p // 2 else v

def Coe(H, Qx, h0, a, b, p):
    A_ = H * (h0 - Qx)**2 - 2 * h0**2 * Qx - 2 * (a + Qx**2) * h0 - 2 * a * Qx - 4 * b
    B_ = 2 * (H * (h0 - Qx) - 2 * h0 * Qx - a - Qx**2)
    C_ = H - 2 * Qx
    D_ = (h0 - Qx)**2
    E_ = 2 * (h0 - Qx)
    return A_ % p, B_ % p, C_ % p, D_ % p, E_ % p

def build_ff(p, d, t, NQ, Fs, x0, ys, As, Bs, Cs, Ds, Es):
    """Paper L(n,d,t) shifts. Verified to reproduce the public DH2.sage list."""
    Exp_res = [[int(c) for c in bin(mask)[2:].zfill(NQ)] for mask in range(2**NQ)]

    def get_row1(k, js):
        r = 1
        for u in range(len(js)):
            if u != k:
                r *= x0**2 + Es[js[u] - 1] * x0 + Ds[js[u] - 1]
        return r

    def get_row2(k, js):
        return x0 * get_row1(k, js)

    def get_M(js):
        l = len(js)
        polys = [get_row1(k, js) for k in range(l)] + [get_row2(k, js) for k in range(l)]
        M = Matrix(ZZ, 2 * l, 2 * l)
        for r, poly in enumerate(polys):
            for e, c in poly.dict().items():
                M[r, int(e[0])] = c
        return M

    def Get_js(exps):
        return [exps[i] * (i + 1) for i in range(len(exps)) if exps[i]]

    def prod_pow(exps, vars_):
        r = 1
        for e, v in zip(exps, vars_):
            if e:
                r *= v
        return r

    def Get_prodF(u, js):
        r = ys[js[u - 1] - 1]
        for i in range(len(js)):
            if i != u - 1:
                r *= Fs[js[i] - 1]
        return r

    ff = []
    for i0 in range(2 * d):
        for l in range(d + 1):
            f_temp = None
            if 1 <= l <= d and 0 <= i0 <= 2 * l - 1:
                f_temp = p**(d + 1 - l)
            if 0 <= l <= d and 2 * l <= i0 <= 2 * d:
                f_temp = p**(d - l)
            if l == 0 and 0 <= i0 <= 2 * d:
                ff.append(f_temp * x0**i0)
            if l == 1 and 0 <= i0 <= 1:
                for exps in Exp_res:
                    if sum(exps) == l:
                        ff.append(f_temp * x0**i0 * prod_pow(exps, ys))
            if 1 <= l <= d and 2 * l <= i0 <= 2 * d:
                for exps in Exp_res:
                    if sum(exps) == l:
                        ff.append(f_temp * x0**(i0 - 2 * l) * prod_pow(exps, Fs))
            if 2 <= l <= d and 0 <= i0 <= 2 * l - 1:
                for exps in Exp_res:
                    if sum(exps) == l:
                        ft = 0
                        js = Get_js(exps)
                        M = get_M(js).change_ring(Zmod(p**(l - 1)))
                        W = M.inverse().change_ring(ZZ)
                        for u in range(1, l + 1):
                            for v in range(2):
                                ft += W[i0, u + l * v - 1] * x0**v * Get_prodF(u, js)
                        ff.append(f_temp * (ft % p**(l - 1)))
    for i0 in range(t + 1):
        l = d + 1
        def Get_H(u, js):
            r = ys[js[u - 1] - 1]
            for i in range(len(js)):
                if i != u - 1:
                    r *= Fs[js[i] - 1]
            return r
        def Get_J(u, js):
            r = Cs[js[u - 1] - 1]
            for i in range(len(js)):
                if i != u - 1:
                    r *= Fs[js[i] - 1]
            return r
        def Get_K(u, js):
            r = Bs[js[u - 1] - 1] - Cs[js[u - 1] - 1] * Es[js[u - 1] - 1]
            for i in range(len(js)):
                if i != u - 1:
                    r *= Fs[js[i] - 1]
            return r
        for exps in Exp_res:
            if sum(exps) == l:
                js = Get_js(exps)
                M = get_M(js).change_ring(Zmod(p**(l - 1)))
                W = M.inverse().change_ring(ZZ)
                Hp = Jp = Kp = 0
                for u in range(1, l + 1):
                    for v in range(2):
                        Hp += W[i0, u + l * v - 1] * x0**v * Get_H(u, js)
                        Jp += W[i0, u + l * v - 1] * x0**v * Get_J(u, js)
                for u in range(1, l + 1):
                    Kp += W[i0, u + l - 1] * Get_K(u, js)
                ff.append((Hp + Jp + Kp) % p**d)
    return ff

# ---------------------------------------------------------- lattice ----
PR, x0, ys, Fs, co = None, None, None, None, None
names = ["x0"] + ["y%d" % (i + 1) for i in range(NQ)]
PR = PolynomialRing(ZZ, names=names)
x0 = PR.gen(0); ys = list(PR.gens()[1:])
As, Bs, Cs, Ds, Es = [], [], [], [], []
for i in range(NQ):
    m = i + 1
    H = (leaks[m] + leaks[-m]) << K
    Ai, Bi, Ci, Di, Ei = Coe(ZZ(H), Qxs[i], ZZ(h0), ZZ(a), ZZ(b), ZZ(p))
    As.append(ZZ(Ai)); Bs.append(ZZ(Bi)); Cs.append(ZZ(Ci))
    Ds.append(ZZ(Di)); Es.append(ZZ(Ei))
Fs = [As[i] + Bs[i] * x0 + Cs[i] * x0**2 + Ds[i] * ys[i]
      + Es[i] * x0 * ys[i] + x0**2 * ys[i] for i in range(NQ)]
ff = build_ff(p, d, t, NQ, Fs, x0, ys, As, Bs, Cs, Ds, Es)
log("polynomials:", len(ff))

# CRITICAL: columns are scaled by monomial bounds BEFORE reduction.
bounds = [2**K] + [2**(K + 1)] * NQ
mons = set()
for f in ff:
    mons.update(f.dict().keys())
mons = sorted(tuple(e) for e in mons)
mid = {e: i for i, e in enumerate(mons)}
Mat = Matrix(ZZ, len(ff), len(mons))
for r, f in enumerate(ff):
    for e, c in f.dict().items():
        Mat[r, mid[tuple(e)]] = c
factors = []
for e in mons:
    v = 1
    for ei, bi in zip(e, bounds):
        v *= bi**ei
    factors.append(v)
for j, f in enumerate(factors):
    Mat.rescale_col(j, f)
w, ncols = Mat.nrows(), Mat.ncols()
log("lattice %dx%d" % (w, ncols))

# ------------------------------------------------------- reduction ----
txt = "[[" + "]\n[".join(" ".join(map(str, row)) for row in Mat) + "]]"
t0 = time.time()
rr = subprocess.run([FLATTER], input=txt.encode(), capture_output=True)
Bred = matrix(ZZ, w, ncols, map(int, re.findall(rb"-?\d+", rr.stdout)))
log("flatter %.1fs" % (time.time() - t0))

# ------------------------------------------------------- selection ----
pd = p**d
thr = RR(pd) / RR(sqrt(ncols))
norms = []
for i in range(w):
    l2 = sum(ZZ(Bred[i, j])**2 for j in range(ncols))
    norms.append(RR(sqrt(RR(l2))))
order = sorted(range(w), key=lambda i: norms[i])
cert = [i for i in order if norms[i] < thr]
log("certified rows:", len(cert), "| shortest norm bits %.1f vs threshold %.1f"
    % (float(log(norms[order[0]], 2)), float(log(thr, 2))))

Br = Bred.change_ring(QQ)
for j, f in enumerate(factors):
    Br.rescale_col(j, 1 / f)
QQR = PolynomialRing(QQ, names=names)

def poly_of(i):
    g = sum((Br[i, j] * QQR.monomial(*e) for j, e in enumerate(mons)), QQR(0))
    den = 1
    for c in g.dict().values():
        den = lcm(den, QQ(c).denominator())
    return g * den

def verify_Sx(Sx):
    if not (0 <= Sx < p):
        return False
    try:
        S0 = E.lift_x(GF(p)(Sx))
    except Exception:
        return False
    for ss in (S0, -S0):
        for As_ in (A, -A):
            ok = True
            for t_ in range(-NQ, NQ + 1):
                if (ZZ((ss + t_ * As_)[0]) >> K) != leaks[t_]:
                    ok = False; break
            if ok:
                return True
    return False

def try_solve(idx, timeout=240):
    polys = [poly_of(i) for i in idx]
    with open("ec_hnp_tmp.ms", "w") as f:
        f.write(",".join(names) + "\n0\n" + ",\n".join(str(g) for g in polys) + "\n")
    try:
        subprocess.run([MSOLVE, "-f", "ec_hnp_tmp.ms", "-o", "ec_hnp_tmp.out", "-t", "8"],
                       timeout=timeout, capture_output=True)
        txt = open("ec_hnp_tmp.out").read()
    except subprocess.TimeoutExpired:
        return None
    sols = []
    try:
        s2 = re.sub(r"(\d+)/(\d+)", r"Fraction(\1,\2)", txt.strip().rstrip(":").strip())
        data = eval(s2, {"Fraction": Fraction, "__builtins__": {}}, {})
        if isinstance(data, list) and data and data[0] == 0:
            sols = [it[0] for it in data[1][1]]
    except Exception:
        return None
    for sol in sols:
        if len(sol) == NQ + 1 and all(isinstance(c, int) for c in sol) and 0 <= sol[0] < 2**K:
            Sx = h0 + sol[0]
            if verify_Sx(Sx):
                return Sx
    return None

found = None
if len(cert) >= NQ + 1:
    found = try_solve(cert[:max(NQ + 1, 2 * (NQ + 1))])
    log("certified solve ->", found is not None)
if found is None:
    import random
    random.seed(1)
    top = order[:60]
    trials = [top[s:s + NQ + 3] for s in range(0, 30)]
    trials += [random.sample(top, NQ + 3) for _ in range(8)]
    for k, idx in enumerate(trials):
        found = try_solve(idx, timeout=60)
        if found is not None:
            log("heuristic trial", k, "solved"); break

if found is None:
    print("NO_SOLUTION — check references/ec-hnp.md section 0 (feasibility) and 5")
    sys.exit(2)

print("S.x =", int(found))
if inst.get("ciphertext"):
    try:
        from Crypto.Cipher import AES
        pt = AES.new(sha256(str(int(found)).encode()).digest(),
                     AES.MODE_ECB).decrypt(bytes.fromhex(inst["ciphertext"]))
        print("plaintext:", pt[:120])
    except Exception as ex:
        print("AES step skipped:", type(ex).__name__)
