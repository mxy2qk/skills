#!/usr/bin/env sage
# Smart's attack on an anomalous (trace-one) elliptic curve, #E == p.
#
# Usage:
#   sage smart_anomalous.sage instance.json
#
# instance.json:
#   {
#     "p": "0x...", "a": "-3", "b": "0x...",
#     "G": {"x": "...", "y": "..."},   # base point on the curve
#     "Q": {"x": "...", "y": "..."},   # target, Q = k*G
#     "_k": 12345                      # optional ground truth (calibration only)
#   }
#   Points may also be given as [x, y] lists.
#
# Precondition: E = EllipticCurve(GF(p), [a,b]) with E.order() == p (i.e.
# trace of Frobenius == 1). The script asserts this. If it fails, this is not
# an anomalous curve: look for smooth order (Pohlig-Hellman), a small
# embedding degree (mov_fr.sage), or a singular curve instead.
#
# References:
#   Smart N. P., "The Discrete Logarithm Problem on Elliptic Curves of Trace
#   One" (adapted from jvdsn/crypto-attacks, MIT license). The F_p-adic lift
#   and formal-group step below match that implementation.

import json, sys
from sage.all import *

def zz(v):
    """Read a JSON integer that may be a Python int, decimal str or 0x-hex str."""
    if isinstance(v, int):
        return ZZ(v)
    s = str(v).strip()
    return ZZ(int(s, 16)) if s[:2].lower() == "0x" else ZZ(s)

# ---------------------------------------------------------------- input ----
def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: sage smart_anomalous.sage instance.json")
    inst = json.load(open(sys.argv[1]))
    p = zz(inst["p"]); a = zz(inst["a"]); b = zz(inst["b"])
    pv = inst["G"]; qv = inst["Q"]
    Gx = zz(pv["x"] if isinstance(pv, dict) else pv[0])
    Gy = zz(pv["y"] if isinstance(pv, dict) else pv[1])
    Qx = zz(qv["x"] if isinstance(qv, dict) else qv[0])
    Qy = zz(qv["y"] if isinstance(qv, dict) else qv[1])

    K = GF(p)
    E = EllipticCurve(K, [a, b])
    G = E(Gx, Gy)
    Q = E(Qx, Qy)
    if E.trace_of_frobenius() != 1:
        raise SystemExit("curve is NOT anomalous (trace of Frobenius != 1); "
                         "check the problem, or use a different attack")
    print("E.order() =", E.order(), "(= p =", p, "ok)")

    k = smart_attack_retry(G, Q)

    print("k =", k)
    if k * G != Q:
        raise SystemExit("Smart's attack gave a wrong k (should not happen after "
                         "the internal precision retry)")
    if "_k" in inst and int(k) != zz(inst["_k"]):
        print("WARNING: ground truth _k =", inst["_k"], "mismatch")

# ----------------------------------------------------------------- attack ----
def _gf_to_qq(n, qq, x):
    """Base-field element -> p-adic number (F_p is embedded as ZZ)."""
    return ZZ(x) if n == 1 else qq(list(map(int, x.polynomial())))

def _lift(Ep, p, Px, Py):
    """Lift a point (given as p-adic coords reducing to Px,Py mod p) to Ep."""
    for P in Ep.lift_x(Px, all=True):
        if (P.xy()[1] % p) == Py:
            return P

def smart_attack(G, P, prec=20):
    """Recover l with P == l*G for an anomalous curve (trace of Frobenius 1).

    Adapted from jvdsn/crypto-attacks (MIT). Handles both F_p (n == 1) and
    extension fields GF(p^n) (n > 1, Section 6.2 of Hoffmann's survey).
    `prec` is the p-adic working precision; raise it if the lift miscarries.
    """
    E = G.curve()
    assert E.trace_of_frobenius() == 1, "curve must have trace of Frobenius 1"

    F = E.base_ring()
    p = F.characteristic()
    q = F.order()
    n = F.degree()
    qq = Qq(q, prec=prec, names="g")

    # Random lift of the curve coefficients to qq; the q * lift makes the
    # points land in the formal group so the DLP becomes additive.
    Ep = EllipticCurve(qq, [_gf_to_qq(n, qq, ai) + q * ZZ.random_element(1, q)
                            for ai in E.a_invariants()])
    Gx, Gy = _gf_to_qq(n, qq, G.xy()[0]), _gf_to_qq(n, qq, G.xy()[1])
    Gx, Gy = (q * _lift(Ep, p, Gx, Gy)).xy()
    Px, Py = _gf_to_qq(n, qq, P.xy()[0]), _gf_to_qq(n, qq, P.xy()[1])
    Px, Py = (q * _lift(Ep, p, Px, Py)).xy()
    l = ZZ(((Px / Py) / (Gx / Gy)) % p)

    if n > 1:
        # Iteratively correct l modulo p, p^2, ..., p^n.
        G0 = p ** (n - 1) * G
        G0x, G0y = _gf_to_qq(n, qq, G0.xy()[0]), _gf_to_qq(n, qq, G0.xy()[1])
        G0x, G0y = (q * _lift(Ep, p, G0x, G0y)).xy()
        for i in range(1, n):
            Pi = p ** (n - i - 1) * (P - l * G)
            if Pi.is_zero():
                continue
            Pix, Piy = _gf_to_qq(n, qq, Pi.xy()[0]), _gf_to_qq(n, qq, Pi.xy()[1])
            Pix, Piy = (q * _lift(Ep, p, Pix, Piy)).xy()
            l += p ** i * ZZ(((Pix / Piy) / (G0x / G0y)) % p)

    return int(l)

def smart_attack_retry(G, P, start_prec=2, max_prec=48):
    """Smart's attack with automatic precision retry — small primes may need a
    bigger working precision for the formal-group division to be exact."""
    cur = start_prec
    while cur <= max_prec:
        try:
            l = smart_attack(G, P, prec=cur)
            if l * G == P:
                return l
        except Exception:
            pass
        cur *= 2
    raise RuntimeError("Smart's attack failed at all precisions up to %d" % max_prec)

if __name__ == "__main__":
    main()