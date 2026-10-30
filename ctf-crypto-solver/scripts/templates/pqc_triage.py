#!/usr/bin/env python3
"""Template: PQC challenge triage.

Scans a challenge directory for post-quantum fingerprints (moduli, ring
degrees, scheme names) and implementation-bug clues, then points at the
relevant reference sections, paper-library direction, and templates.

Usage:
    python pqc_triage.py <challenge-dir>
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from ctfkit import pqc  # noqa: E402

Q_VALUES = {3329: "ML-KEM/Kyber", 8380417: "ML-DSA/Dilithium", 12289: "Falcon",
            8192: "Saber", 4591: "NTRU Prime", 7681: "Kyber toy", 2048: "NTRU"}
NAME_RE = re.compile(r"kyber|ml[-_]?kem|dilithium|ml[-_]?dsa|falcon|ntru|saber|"
                     r"hqc|bike|sntrup|ntt|ntruprime", re.I)
N_RE = re.compile(r"\bN\s*=\s*(256|512|761|1024)\b")
CLUES = {
    "FO/oracle": r"oracle|re-?encrypt|fo[-_ ]?fail|decaps",
    "rejection sampling": r"reject|rejection|abort",
    "nonce/seed reuse": r"nonce|seed|deterministic",
    "NTT/representation": r"\bntt\b|bit[-_ ]?revers|montgomery|twiddle",
    "compression": r"compress|decompress|\bdu\b|\bdv\b",
    "leak/hint": r"leak|hint|hamming|side[-_ ]?channel|fault",
    "tiny noise": r"tiny|small (error|noise)|eta",
}


def read_all(d):
    chunks = []
    for base, _dirs, files in os.walk(d):
        for fn in files:
            p = os.path.join(base, fn)
            if os.path.getsize(p) > 2_000_000:
                continue
            try:
                chunks.append((fn, open(p, "r", encoding="utf-8", errors="replace").read()))
            except OSError:
                continue
    return chunks


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: python pqc_triage.py <challenge-dir>")
    d = sys.argv[1]
    chunks = read_all(d)
    blob = "\n".join(t for _n, t in chunks)

    found_q = set()
    for qv in Q_VALUES:
        if re.search(r"\b%d\b" % qv, blob):
            found_q.add(qv)

    schemes = set()
    for qv in found_q:
        for s in pqc.detect(q=qv):
            schemes.add(s)
    for m in NAME_RE.findall(blob):
        for s in pqc.detect():
            if m.lower().replace("_", "-") in s.lower().replace("/", "-"):
                schemes.add(s)

    print("== PQC triage: %s ==" % d)
    print("files:", ", ".join(n for n, _ in chunks[:12]),
          "..." if len(chunks) > 12 else "")
    print("moduli seen:", sorted(found_q) or "none")
    print("scheme candidates:", sorted(schemes) or "none")
    print()
    hits = []
    for label, pat in CLUES.items():
        if re.search(pat, blob, re.I):
            hits.append(label)
    print("likely weakness clues:", ", ".join(hits) or "none found")
    print()
    print("next steps:")
    if hits:
        for h in hits:
            if h == "FO/oracle":
                print("  - FO/PC oracle: chosen-ciphertext attack; see references/post-quantum.md §2, "
                      "references/pqc-faults.md")
            elif h == "rejection sampling":
                print("  - rejection-sampling bug/fault: see references/pqc-faults.md; "
                      "papers 2026/1344, 2026/2567")
            elif h == "nonce/seed reuse":
                print("  - nonce/seed reuse: XOR ciphertexts; papers 2026/1668, 2026/2566")
            elif h == "NTT/representation":
                print("  - NTT/representation bug: compare against KAT; references/post-quantum.md §4")
            elif h == "compression":
                print("  - compression bug: high bits of u/v leak; references/post-quantum.md §2")
            elif h == "leak/hint":
                print("  - leakage/hint: scripts/templates/ilwe_bp.sage or lwe_hints.sage; "
                      "references/pqc-faults.md")
            elif h == "tiny noise":
                print("  - tiny noise: flatten to LWE with scripts/templates/lwe_bkz.sage")
    if schemes:
        print("  - scheme identified: open references/post-quantum.md and "
              "assets/papers/paper-map.md (direction pqc-implementation)")
    if not hits and not schemes:
        print("  - no PQ fingerprint found; run scripts/intake.py for a general triage")


if __name__ == "__main__":
    main()
