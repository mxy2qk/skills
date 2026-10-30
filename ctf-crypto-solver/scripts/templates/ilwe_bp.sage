#!/usr/bin/env sage
# ILWE belief-propagation solver — recover a small integer secret from noisy
# linear relations (Integer-LWE), the "keep track of your errors" route for
# ML-DSA / PQC fault & side-channel leakage (ePrint 2026/2091, 2026/2448).
#
# Usage:
#   sage ilwe_bp.sage instance.json
#
# instance.json:
#   {
#     "support": [-1, 0, 1],            # per-coordinate secret values
#     "noise": 2,                       # |error_j| <= noise per relation
#     "relations": [ [ [[i, a_ij], ...], r_j ], ... ],   # sparse: (index, coeff) + r
#     "iterations": 40,                 # optional
#     "max_degree": 10                   # optional: exact-BP factor degree cap
#   }
#
# The relation is r_j = sum_i a_ij * s_i + e_j  (over the integers, NO modulus),
# with s_i in `support` and |e_j| <= noise. Loopy belief propagation on the
# factor graph recovers s; factors above max_degree fall back to an
# expected-value approximation. Output: s, max |e_j|, recovered-if-within-bound.

import json, sys, itertools
from sage.all import *

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage ilwe_bp.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    support = inst["support"]
    B = int(inst["noise"])
    rel = inst["relations"]            # list of [ [(i,a),...], r ]
    iters = int(inst.get("iterations", 40))
    maxdeg = int(inst.get("max_degree", 10))

    n = max((i for r in rel for i, _ in r[0]), default=-1) + 1
    print("variables:", n, "| support:", support, "| noise<=%d" % B,
          "| relations:", len(rel), "| iters:", iters)

    # normalize factors to integer lists
    factors = []
    for nbrs, r in rel:
        factors.append(([(int(i), int(a)) for i, a in nbrs], int(r)))

    s = bp_solve(support, B, factors, n, iters, maxdeg)
    print("s =", s)

    # verify
    mx = 0
    for nbrs, r in factors:
        res = r - sum(a * s[i] for i, a in nbrs)
        mx = max(mx, abs(res))
    ok = mx <= B
    print("max|error| =", mx, "| within bound:", ok)

# ---------------------------------------------------------------- solver ----
def bp_solve(support, B, factors, n, iters, maxdeg):
    D = len(support)
    sup = list(support)
    # incoming belief from each variable to each factor (init uniform)
    # msg_fv[j][i] = dict value->prob (from factor j to variable i)
    msg_fv = [{} for _ in factors]
    msg_vf = [{} for _ in range(n)]   # per variable: dict factor_idx -> {value:prob}
    for v in range(n):
        msg_vf[v] = {j: {val: 1.0 / D for val in sup}
                     for j in range(len(factors)) if any(i == v for i, _ in factors[j][0])}

    for _ in range(iters):
        # factor -> variable messages
        for j, (nbrs, r) in enumerate(factors):
            idxs = [i for i, _ in nbrs]
            for t, (i, a) in enumerate(nbrs):
                others = nbrs[:t] + nbrs[t + 1:]
                msg = {}
                for v in sup:
                    if len(others) <= maxdeg:
                        acc = 0.0
                        for combo in itertools.product(sup, repeat=len(others)):
                            contrib = sum(a_k * u for (_, a_k), u in zip(others, combo))
                            e = r - a * v - contrib
                            pr = 1.0 if abs(e) <= B else 1e-9
                            for (ok_, _), u in zip(others, combo):
                                pr *= msg_vf[ok_].get(j, {u: 1.0}).get(u, 1e-9)
                            acc += pr
                        msg[v] = acc
                    else:
                        # large factor: approximate others by their means
                        e = r - a * v - sum(a_k * mean_of(msg_vf[k].get(j))
                                            for k, a_k in others)
                        msg[v] = 1.0 if abs(e) <= B else 1e-9
                tot = sum(msg.values()) or 1e-12
                msg_fv[j][i] = {v: p / tot for v, p in msg.items()}
        # variable -> factor messages
        for v in range(n):
            for j in msg_vf[v]:
                prod = {}
                for val in sup:
                    p = 1.0
                    for jj in msg_vf[v]:
                        if jj != j:
                            p *= msg_fv[jj].get(v, {}).get(val, 1.0)
                    prod[val] = p
                tot = sum(prod.values()) or 1e-12
                msg_vf[v][j] = {val: p / tot for val, p in prod.items()}

    # beliefs = product of all incoming factor messages
    out = []
    for v in range(n):
        post = {}
        for val in sup:
            p = 1.0
            for j in msg_vf[v]:
                p *= msg_fv[j].get(v, {}).get(val, 1.0)
            post[val] = p
        tot = sum(post.values()) or 1e-12
        out.append(max(sup, key=lambda val: post[val] / tot))
    return out

def mean_of(d):
    if not d:
        return 0.0
    return sum(val * p for val, p in d.items())

if __name__ == "__main__":
    main()
