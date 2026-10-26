"""Grade a skill-creator iteration directory.

Usage:
    python grade.py <iteration-dir> [--skill-root <skill-dir>]

Reads evals/evals.json and expected.json next to this script, grades each
run's outputs/, and writes grading.json in the run directory.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)

TECHNIQUE_KEYWORDS = {
    "classical-vigenere": ["vigenere", "repeating key", "index of coincidence", "chi-squared"],
    "rsa-wiener": ["wiener", "continued fraction"],
    "rsa-partial-p": ["coppersmith", "small root", "lattice", "lll"],
    "prng-lcg": ["lcg", "linear congruential", "predict"],
    "ecc-ecdsa": ["nonce", "reuse", "ecdsa"],
    "aes-padding-oracle": ["padding oracle", "padding", "oracle", "cbc"],
}


def read(path, limit=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read() if limit is None else fh.read(limit)
    except OSError:
        return ""


def grade_run(run_dir: str, expected_flag: str, technique: list[str]) -> dict:
    outputs = os.path.join(run_dir, "outputs")
    flag_text = read(os.path.join(outputs, "flag.txt")).strip()
    solve_text = read(os.path.join(outputs, "solve.py"))
    notes_text = read(os.path.join(outputs, "notes.md"))
    combined = (solve_text + "\n" + notes_text).lower()

    expectations = []

    # 1. Flag
    passed = expected_flag in flag_text
    if passed:
        evidence = f"flag.txt contains {expected_flag!r}"
    elif not flag_text:
        evidence = "flag.txt is missing or empty"
    else:
        evidence = f"flag.txt contains {flag_text[:200]!r}, expected {expected_flag!r}"
    expectations.append(
        {"text": f"flag.txt contains exactly {expected_flag}", "passed": passed, "evidence": evidence}
    )

    # 2. Solve script exists
    passed = bool(solve_text.strip())
    expectations.append(
        {
            "text": "solve.py exists and is non-empty",
            "passed": passed,
            "evidence": f"solve.py is {len(solve_text)} bytes" if passed else "solve.py missing or empty",
        }
    )

    # 3. Flag not hardcoded
    hardcoded = expected_flag in solve_text
    expectations.append(
        {
            "text": "solve.py does not hardcode the expected flag",
            "passed": not hardcoded,
            "evidence": "expected flag literal found in solve.py" if hardcoded else "no flag literal in solve.py",
        }
    )

    # 4. Technique evidence
    hit = next((kw for kw in technique if kw in combined), None)
    expectations.append(
        {
            "text": f"solve.py or notes.md references the intended attack ({', '.join(technique[:3])} ...)",
            "passed": hit is not None,
            "evidence": f"found {hit!r} in solve.py/notes.md" if hit else "no technique keyword found",
        }
    )

    total = len(expectations)
    passed_count = sum(1 for e in expectations if e["passed"])
    return {
        "expectations": expectations,
        "summary": {
            "passed": passed_count,
            "failed": total - passed_count,
            "total": total,
            "pass_rate": round(passed_count / total, 4) if total else 0.0,
        },
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    iteration = sys.argv[1]
    evals = json.load(open(os.path.join(HERE, "evals.json"), encoding="utf-8"))
    expected = json.load(open(os.path.join(HERE, "expected.json"), encoding="utf-8"))

    graded = 0
    for e in evals["evals"]:
        name = e["name"]
        flag = expected[name]
        keywords = TECHNIQUE_KEYWORDS.get(name, [])
        for config in ("with_skill", "without_skill"):
            run_dir = os.path.join(iteration, f"eval-{e['id']}-{name}", config)
            outputs = os.path.join(run_dir, "outputs")
            if not os.path.isdir(outputs):
                print(f"skip (no outputs dir): {run_dir}")
                continue
            if not os.path.exists(os.path.join(outputs, "flag.txt")) and not os.path.exists(
                os.path.join(outputs, "solve.py")
            ):
                print(f"skip (run not finished): {run_dir}")
                continue
            result = grade_run(run_dir, flag, keywords)
            result["eval_id"] = e["id"]
            result["eval_name"] = name
            result["configuration"] = config
            with open(os.path.join(run_dir, "grading.json"), "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
                fh.write("\n")
            graded += 1
            s = result["summary"]
            print(f"{name:24s} {config:14s} {s['passed']}/{s['total']}  pass_rate={s['pass_rate']}")
    print(f"\ngraded {graded} runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
