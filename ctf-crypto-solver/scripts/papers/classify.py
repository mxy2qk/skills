#!/usr/bin/env python3
"""Classify the fetched 2026 ePrint candidates into CTF-relevant directions.

Input : eprint_raw.json (from fetch_eprint.py)
Output: selected.json    (id, direction, tags, metadata, truncated abstract)
"""
import json

DIRS = {
    "lattice-lwe-hints": [
        "2026/279", "2026/366", "2026/421", "2026/612", "2026/614", "2026/630",
        "2026/688", "2026/1041", "2026/1048", "2026/1060", "2026/1081",
        "2026/1326", "2026/1400", "2026/1720", "2026/2117", "2026/2166",
        "2026/2186", "2026/2565", "2026/2638", "2026/2654", "2026/177",
    ],
    "pqc-implementation": [
        "2026/064", "2026/070", "2026/472", "2026/528", "2026/580",
        "2026/582", "2026/820", "2026/981", "2026/1344", "2026/1386",
        "2026/1448", "2026/1668", "2026/1682", "2026/1712", "2026/1904",
        "2026/2091", "2026/2124", "2026/2258", "2026/2643", "2026/056",
        "2026/2069", "2026/2137", "2026/2211", "2026/2448", "2026/2567",
    ],
    "sis-lip-ideal": [
        "2026/699", "2026/890", "2026/1298", "2026/1318", "2026/1349",
        "2026/1377", "2026/1554", "2026/1560", "2026/1593", "2026/1705",
        "2026/1755", "2026/2042", "2026/2083", "2026/2198", "2026/2225",
        "2026/2281", "2026/2325", "2026/2381", "2026/2420", "2026/2527",
        "2026/2543", "2026/722", "2026/1642",
    ],
    "coppersmith-rsa": [
        "2026/244", "2026/519", "2026/1027", "2026/1295", "2026/1357",
        "2026/1529", "2026/2109", "2026/2620", "2026/1137", "2026/1908",
        "2026/1969",
    ],
    "hnp-signatures": [
        "2026/423", "2026/1366", "2026/1808", "2026/2566",
    ],
    "ecc-pairing-isogeny": [
        "2026/1002", "2026/1486", "2026/1575", "2026/1623", "2026/1776",
        "2026/1823", "2026/2560",
    ],
}


def main():
    raw = {x["id"]: x for x in json.load(open("eprint_raw.json", encoding="utf-8"))}
    out, missing = [], []
    for direction, ids in DIRS.items():
        for pid in ids:
            it = raw.get(pid)
            if it is None:
                missing.append(pid)
                continue
            rec = dict(it)
            rec["direction"] = direction
            out.append(rec)
    if missing:
        print("MISSING from raw (need extra fetch):", missing)
    out.sort(key=lambda x: (x["direction"], int(x["id"].split("/")[1])))
    json.dump(out, open("selected.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("selected:", len(out))
    from collections import Counter
    for k, v in Counter(x["direction"] for x in out).items():
        print("  %-24s %d" % (k, v))


if __name__ == "__main__":
    main()
