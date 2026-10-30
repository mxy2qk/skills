#!/usr/bin/env python3
"""Search the curated 2026 paper library.

Usage:
    python search.py <keyword> [--direction D] [--tag T] [--min-rating N]
    python search.py --list-dirs
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "..", "assets", "papers", "papers.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keyword", nargs="?", default="")
    ap.add_argument("--direction")
    ap.add_argument("--tag")
    ap.add_argument("--min-rating", type=int, default=0)
    ap.add_argument("--list-dirs", action="store_true")
    args = ap.parse_args()

    data = json.load(open(LIB, encoding="utf-8"))
    if args.list_dirs:
        from collections import Counter
        for d, n in Counter(x["direction"] for x in data).items():
            print("%-24s %d" % (d, n))
        return

    kw = args.keyword.lower()
    hits = []
    for r in data:
        blob = " ".join([r["title"], r["summary"], " ".join(r["tags"]),
                         r["ctf_note"], r["mapped"]]).lower()
        if kw and kw not in blob:
            continue
        if args.direction and r["direction"] != args.direction:
            continue
        if args.tag and args.tag.lower() not in " ".join(r["tags"]).lower():
            continue
        if r["ctf_relevance"] < args.min_rating:
            continue
        hits.append(r)

    hits.sort(key=lambda r: (-r["ctf_relevance"], -int(r["id"].split("/")[1])))
    for r in hits:
        print("[%d] %s  %s  (%s)" % (r["ctf_relevance"], r["id"], r["title"], r["date"]))
        print("     tags: %s" % ", ".join(r["tags"]))
        print("     %s" % r["summary"])
        print("     -> %s | %s" % (r["ctf_note"], r["url"]))
        print()
    print("%d match(es)" % len(hits), file=sys.stderr)


if __name__ == "__main__":
    main()
