"""Aggregate grading.json + timing.json into benchmark.json / benchmark.md.

The stock skill-creator aggregator expects config/run-1/ subdirectories; this
workspace keeps outputs directly under config/, so this script adapts the
same schema to that layout.
"""

from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def stats(values: list[float]) -> dict:
    if not values:
        return {"mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0}
    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    return {
        "mean": round(mean, 4),
        "stddev": round(math.sqrt(variance), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
    }


def fmt_delta(a: float, b: float, digits: int = 2, sign: bool = True) -> str:
    diff = a - b
    s = f"{diff:+.{digits}f}" if sign else f"{diff:.{digits}f}"
    return s


def main():
    if len(sys.argv) < 2:
        print("usage: python aggregate.py <iteration-dir> [--skill-name NAME]")
        return 2
    iteration = sys.argv[1]
    skill_name = "ctf-crypto-solver"
    if "--skill-name" in sys.argv:
        skill_name = sys.argv[sys.argv.index("--skill-name") + 1]

    evals = json.load(open(os.path.join(HERE, "evals.json"), encoding="utf-8"))
    runs = []
    per_config: dict[str, list] = {"with_skill": [], "without_skill": []}

    for e in evals["evals"]:
        for config in ("with_skill", "without_skill"):
            run_dir = os.path.join(iteration, f"eval-{e['id']}-{e['name']}", config)
            grading_path = os.path.join(run_dir, "grading.json")
            if not os.path.exists(grading_path):
                continue
            grading = json.load(open(grading_path, encoding="utf-8"))
            timing = {}
            timing_path = os.path.join(run_dir, "timing.json")
            if os.path.exists(timing_path):
                timing = json.load(open(timing_path, encoding="utf-8"))
            summary = grading["summary"]
            result = {
                "pass_rate": summary["pass_rate"],
                "passed": summary["passed"],
                "failed": summary["failed"],
                "total": summary["total"],
                "time_seconds": float(
                    timing.get("total_duration_seconds", timing.get("duration_ms", 0) / 1000)
                ),
                "tokens": int(timing.get("total_tokens", 0)),
                "tool_calls": int(timing.get("tool_calls", 0)),
                "errors": 0,
            }
            runs.append(
                {
                    "eval_id": e["id"],
                    "eval_name": e["name"],
                    "configuration": config,
                    "run_number": 1,
                    "result": result,
                    "expectations": grading["expectations"],
                }
            )
            per_config[config].append(result)

    if not runs:
        print("no graded runs found")
        return 1

    run_summary = {}
    for config, items in per_config.items():
        run_summary[config] = {
            "pass_rate": stats([r["pass_rate"] for r in items]),
            "time_seconds": stats([r["time_seconds"] for r in items]),
            "tokens": stats([float(r["tokens"]) for r in items]),
        }

    delta = {
        "pass_rate": fmt_delta(
            run_summary["with_skill"]["pass_rate"]["mean"],
            run_summary["without_skill"]["pass_rate"]["mean"],
        ),
        "time_seconds": fmt_delta(
            run_summary["with_skill"]["time_seconds"]["mean"],
            run_summary["without_skill"]["time_seconds"]["mean"],
            digits=1,
        ),
        "tokens": f"{run_summary['with_skill']['tokens']['mean'] - run_summary['without_skill']['tokens']['mean']:+.0f}",
    }

    # Per-assertion pass rates, to surface non-discriminating checks.
    notes = []
    texts = sorted({exp["text"] for r in runs for exp in r["expectations"]})
    for text in texts:
        w = [exp for r in runs if r["configuration"] == "with_skill" for exp in r["expectations"] if exp["text"] == text]
        b = [exp for r in runs if r["configuration"] == "without_skill" for exp in r["expectations"] if exp["text"] == text]
        wr = sum(1 for x in w if x["passed"]) / len(w) if w else 0
        br = sum(1 for x in b if x["passed"]) / len(b) if b else 0
        if w and b and wr == br == 1.0:
            notes.append(f"Assertion always passes in both configs: {text!r}")

    with_skill_mean = run_summary["with_skill"]["pass_rate"]["mean"]
    without_mean = run_summary["without_skill"]["pass_rate"]["mean"]
    notes.append(
        f"Mean pass rate: with_skill={with_skill_mean:.3f}, without_skill={without_mean:.3f}, delta={delta['pass_rate']}"
    )
    notes.append(
        f"Mean tokens: with_skill={run_summary['with_skill']['tokens']['mean']:.0f}, "
        f"without_skill={run_summary['without_skill']['tokens']['mean']:.0f}"
    )

    benchmark = {
        "metadata": {
            "skill_name": skill_name,
            "skill_path": os.path.dirname(HERE),
            "executor_model": "inherited",
            "analyzer_model": "inline",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evals_run": [e["id"] for e in evals["evals"]],
            "runs_per_configuration": 1,
        },
        "runs": runs,
        "run_summary": run_summary,
        "delta": delta,
        "notes": notes,
    }

    out_json = os.path.join(iteration, "benchmark.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(benchmark, fh, indent=2)
        fh.write("\n")

    lines = [
        f"# Benchmark — {skill_name}",
        "",
        "| Config | Pass rate | Time (s) | Tokens |",
        "|---|---|---|---|",
    ]
    for config in ("with_skill", "without_skill"):
        s = run_summary[config]
        lines.append(
            f"| {config} | {s['pass_rate']['mean']:.2f} ± {s['pass_rate']['stddev']:.2f} "
            f"| {s['time_seconds']['mean']:.1f} | {s['tokens']['mean']:.0f} |"
        )
    lines += ["", f"Delta: pass_rate {delta['pass_rate']}, time {delta['time_seconds']}s, tokens {delta['tokens']}", "", "## Per-eval"]
    lines += ["", "| Eval | Config | Passed | Time (s) | Tokens |", "|---|---|---|---|---|"]
    for r in runs:
        res = r["result"]
        lines.append(
            f"| {r['eval_name']} | {r['configuration']} | {res['passed']}/{res['total']} "
            f"| {res['time_seconds']:.1f} | {res['tokens']} |"
        )
    lines += ["", "## Notes"] + [f"- {n}" for n in notes]
    with open(os.path.join(iteration, "benchmark.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"wrote {out_json}")
    print("\n".join(lines[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
