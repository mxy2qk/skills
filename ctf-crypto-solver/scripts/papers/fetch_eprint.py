#!/usr/bin/env python3
"""Fetch 2026 IACR ePrint papers relevant to lattice/Sage CTF directions.

Writes raw, de-duplicated metadata to eprint_raw.json (title, authors, date,
category, truncated abstract, url). Full abstracts are fetched separately for
the shortlist.

Usage:
    python fetch_eprint.py --out eprint_raw.json [--pages 1]
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://eprint.iacr.org/search?q="
UA = "Mozilla/5.0 (compatible; ctf-crypto-research/1.0)"

# one query per direction / sub-topic; keep them specific so page 1 is enough
QUERIES = [
    "lattice attack",
    "Coppersmith",
    "hidden number problem",
    "LWE attack",
    "learning with errors hints",
    "NTRU cryptanalysis",
    "module-LWE attack",
    "ML-KEM attack",
    "Kyber attack",
    "ML-DSA attack",
    "Dilithium attack",
    "HAWK cryptanalysis",
    "SIS attack",
    "lattice isomorphism",
    "isogeny cryptanalysis",
    "pairing attack",
    "elliptic curve discrete logarithm",
    "subset sum cryptanalysis",
    "RSA partial key exposure",
    "Wiener attack RSA",
    "truncated LCG",
    "multivariate Coppersmith",
    "Groebner lattice",
    "fault attack lattice",
    "side-channel lattice",
    "dual attack LWE",
    "signature nonce leakage",
    "ECDLP",
    "knapsack cryptosystem",
    "polynomial congruential generator",
]

ENTRY_RE = re.compile(
    r'<a title="(2026/\d+)" class="paperlink" href="/(2026/\d+)">.*?'
    r'Last updated: (\d{4}-\d{2}-\d{2}).*?'
    r'<strong>(.*?)</strong>.*?'
    r'<span class="fst-italic">(.*?)</span>.*?'
    r'<small class="badge category[^"]*">(.*?)</small>.*?'
    r'<p class="mb-0 mt-1 search-abstract">(.*?)</p>',
    re.S,
)


def clean(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def parse(page: str):
    out = []
    for m in ENTRY_RE.finditer(page):
        pid, _, date, title, authors, cat, abstract = m.groups()
        out.append({
            "id": pid,
            "date": date,
            "title": clean(title),
            "authors": clean(authors),
            "category": clean(cat),
            "abstract": clean(abstract),
            "url": "https://eprint.iacr.org/" + pid,
        })
    return out


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="eprint_raw.json")
    ap.add_argument("--pages", type=int, default=1)
    args = ap.parse_args()

    seen = {}
    for q in QUERIES:
        for p in range(1, args.pages + 1):
            url = BASE + urllib.parse.quote(q) + "&page=%d" % p
            try:
                page = fetch(url)
            except Exception as ex:
                print("WARN fetch failed %r p%d: %s" % (q, p, ex), file=sys.stderr)
                time.sleep(1.5)
                continue
            items = parse(page)
            new = 0
            for it in items:
                if it["id"] not in seen:
                    it["query"] = q
                    seen[it["id"]] = it
                    new += 1
            print("%-38s p%d: %2d results, %2d new (total %d)"
                  % (q, p, len(items), new, len(seen)), flush=True)
            time.sleep(0.8)

    items = sorted(seen.values(), key=lambda x: int(x["id"].split("/")[1]), reverse=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    print("wrote %d papers -> %s" % (len(items), args.out))


if __name__ == "__main__":
    main()
