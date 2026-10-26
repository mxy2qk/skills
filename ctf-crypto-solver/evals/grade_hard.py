"""Grade the hard validation set (with-skill only, or any config present).

Usage:
    python grade_hard.py <iteration-dir>
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

KEYWORDS = {
    "ecdsa-biased-nonce": ["hnp", "hidden number", "biased nonce", "partial nonce", "lattice"],
    "prng-mt19937": ["mt19937", "mersenne", "untemper", "clone", "state recovery"],
    "hash-length-extension": ["length extension", "md5", "glue", "merkle"],
    "dh-smooth-order": ["pohlig", "smooth", "discrete log", "diffie"],
    "nc-pow-padding": ["proof of work", "pow", "padding oracle", "cbc"],
}


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def grade(run_dir, flag, keywords):
    out = os.path.join(run_dir, "outputs")
    flag_text = read(os.path.join(out, "flag.txt")).strip()
    solve_text = read(os.path.join(out, "solve.py"))
    notes_text = read(os.path.join(out, "notes.md"))
    combined = (solve_text + "\n" + notes_text).lower()

    exp = []
    exp.append(
        {
            "text": f"flag.txt contains {flag}",
            "passed": flag in flag_text,
            "evidence": f"flag.txt={flag_text[:120]!r}",
        }
    )
    exp.append(
        {
            "text": "solve.py exists and is non-empty",
            "passed": bool(solve_text.strip()),
            "evidence": f"solve.py is {len(solve_text)} bytes",
        }
    )
    exp.append(
        {
            "text": "solve.py does not hardcode the expected flag",
            "passed": flag not in solve_text,
            "evidence": "flag literal found" if flag in solve_text else "no flag literal",
        }
    )
    hit = next((k for k in keywords if k in combined), None)
    exp.append(
        {
            "text": f"solve.py/notes.md references the intended attack ({keywords[0]})",
            "passed": hit is not None,
            "evidence": f"found {hit!r}" if hit else "no technique keyword",
        }
    )
    passed = sum(1 for e in exp if e["passed"])
    return {
        "expectations": exp,
        "summary": {
            "passed": passed,
            "failed": len(exp) - passed,
            "total": len(exp),
            "pass_rate": round(passed / len(exp), 4),
        },
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    iteration = sys.argv[1]
    expected = json.load(open(os.path.join(HERE, "hard_expected.json"), encoding="utf-8"))
    total = 0
    ok = 0
    for name, flag in expected.items():
        for config in ("with_skill", "without_skill"):
            run_dir = os.path.join(iteration, f"eval-{list(expected).index(name)}-{name}", config)
            out = os.path.join(run_dir, "outputs")
            if not os.path.isdir(out):
                continue
            if not os.path.exists(os.path.join(out, "flag.txt")) and not os.path.exists(
                os.path.join(out, "notes.md")
            ):
                # Incomplete run (e.g. the agent was interrupted); do not grade.
                continue
            res = grade(run_dir, flag, KEYWORDS.get(name, []))
            res["eval_name"] = name
            res["configuration"] = config
            with open(os.path.join(run_dir, "grading.json"), "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=2)
                fh.write("\n")
            total += 1
            ok += 1 if res["summary"]["pass_rate"] == 1.0 else 0
            print(f"{name:24s} {config:14s} {res['summary']['passed']}/{res['summary']['total']}")
    print(f"\n{ok}/{total} runs fully passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
