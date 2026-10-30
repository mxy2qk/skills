#!/usr/bin/env python3
"""Fetch full abstracts for the selected papers.

Input : selected.json
Output: selected_full.json (adds "abstract_full")

Usage: python fetch_abstracts.py [--limit N]
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.request

UA = "Mozilla/5.0 (compatible; ctf-crypto-research/1.0)"
ABS_RE = re.compile(
    r'<h5 class="mt-3">Abstract</h5>\s*<p style="white-space: pre-wrap;">(.*?)</p>',
    re.S,
)


def clean(s: str) -> str:
    s = re.sub(r"<br\s*/?>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", default="selected.json")
    ap.add_argument("--out", default="selected_full.json")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    data = json.load(open(args.inp, encoding="utf-8"))
    if args.limit:
        data = data[: args.limit]
    ok = 0
    for i, rec in enumerate(data, 1):
        try:
            page = fetch(rec["url"])
            m = ABS_RE.search(page)
            rec["abstract_full"] = clean(m.group(1)) if m else rec.get("abstract", "")
            if m:
                ok += 1
        except Exception as ex:
            rec["abstract_full"] = rec.get("abstract", "")
            print("WARN %s: %s" % (rec["id"], ex), file=sys.stderr)
        print("%3d/%3d %s" % (i, len(data), rec["id"]), flush=True)
        time.sleep(0.5)

    json.dump(data, open(args.out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("fetched %d/%d abstracts -> %s" % (ok, len(data), args.out))


if __name__ == "__main__":
    main()
