#!/usr/bin/env python3
"""Recover V8 `Math.random()` state (XorShift128+) from observed outputs.

V8 uses XorShift128+ over two 64-bit words; `Math.random()` returns the top 53
bits of each 64-bit step divided by 2^53. Given a few consecutive outputs, the
128-bit state is recovered with an SMT solver (z3), then future values are
predicted.

Dependency: z3-solver (pip install z3-solver). Pure-Python prediction (given the
state) is in `ctfkit.prng.XorShift128Plus`.

Usage:
    python v8_xorshift128plus.py instance.json

instance.json:
    {
      "outputs": [0.123, 0.456, ...],   # Math.random() doubles (use >= 3)
      "kind": "double",                 # or "raw64" for full 64-bit outputs
      "count": 5                        # optional: how many to predict
    }
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import prng  # noqa: E402

MASK64 = (1 << 64) - 1
MASK53 = (1 << 53) - 1


def recover_state(outputs, kind="double"):
    try:
        import z3
    except ImportError:
        raise SystemExit("this template needs z3-solver (pip install z3-solver)")

    s0 = z3.BitVec("s0", 64)
    s1 = z3.BitVec("s1", 64)
    a, b = s0, s1
    sol = z3.Solver()
    for v in outputs:
        x = a                      # s1 = state0
        y = b                      # s0 = state1
        ns1 = x
        ns1 = ns1 ^ (ns1 << 23)
        ns1 = ns1 ^ z3.LShR(ns1, 17)
        ns1 = ns1 ^ y
        ns1 = ns1 ^ z3.LShR(y, 26)
        out = ns1 + y
        a, b = y, ns1
        if kind == "double":
            obs = v if isinstance(v, int) else prng.v8_double_to_int(float(v))
            sol.add(z3.LShR(out, 11) == z3.BitVecVal(obs & MASK53, 64))
        else:
            sol.add(out == z3.BitVecVal(int(v) & MASK64, 64))
    if sol.check() != z3.sat:
        return None
    m = sol.model()
    return int(m[s0].as_long()), int(m[s1].as_long())


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "instance.json"
    inst = json.load(open(path))
    outputs = inst["outputs"]
    kind = inst.get("kind", "double")
    count = int(inst.get("count", 5))

    # 3 outputs (159 bits of constraints) are usually enough; extra help
    use = outputs[: max(3, len(outputs))]
    st = recover_state(use, kind)
    if st is None:
        raise SystemExit("no state satisfies the outputs (need more/additional outputs)")
    s0, s1 = st
    print("state0 = 0x%016x" % s0)
    print("state1 = 0x%016x" % s1)

    gen = prng.XorShift128Plus(s0, s1)
    # advance past the observed outputs, then predict what comes next
    for _ in outputs:
        if kind == "double":
            gen.next_double()
        else:
            gen.next64()
    if kind == "double":
        pred = [gen.next_double() for _ in range(count)]
        print("next doubles:", pred)
    else:
        pred = [gen.next64() for _ in range(count)]
        print("next 64-bit:", ["0x%016x" % x for x in pred])


if __name__ == "__main__":
    main()
