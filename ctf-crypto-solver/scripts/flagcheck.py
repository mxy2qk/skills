"""Find, rank, and normalize flags in text or binary output.

Usage:
    python flagcheck.py <file-or-text> [--prefix flag] [--json]

Why a scoring pass: decrypted output often contains several `word{...}`
strings (ciphertext artifacts, hash-like blobs, decoys). The common prefixes
and printable content are what separate the real flag from noise.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ctfkit.util import COMMON_FLAG_PREFIXES, detect_flag_regex  # noqa: E402

GENERIC_RE = re.compile(r"[A-Za-z0-9_]{1,40}\{[^}\r\n]{1,300}\}")
RAW_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _decode_layers(data: bytes) -> bytes:
    """Try one or two common wrappers (hex/base64) before searching."""
    out = data
    for _ in range(2):
        stripped = out.strip()
        try:
            if re.fullmatch(rb"[0-9a-fA-F\s]+", stripped) and len(stripped.replace(b" ", b"").replace(b"\n", b"")) % 2 == 0:
                candidate = bytes.fromhex(re.sub(rb"\s+", b"", stripped).decode())
                if any(32 <= b < 127 or b in (9, 10, 13) for b in candidate[:200]):
                    out = candidate
                    continue
        except Exception:
            pass
        try:
            candidate = base64.b64decode(stripped, validate=True)
            if candidate and sum(1 for b in candidate[:200] if 32 <= b < 127) > len(candidate[:200]) * 0.8:
                out = candidate
                continue
        except Exception:
            pass
        break
    return out


def _is_printable_inside(s: str) -> bool:
    return all(32 <= ord(c) < 127 or c in "\t" for c in s)


def extract_flags(data: bytes | str, prefix: str | None = None) -> list[dict]:
    """Return ranked flag candidates as dicts with value/score/why."""
    if isinstance(data, bytes):
        raw = data
    else:
        raw = data.encode("latin-1", errors="replace")
    original_text = raw.decode("latin-1", errors="replace")
    decoded = _decode_layers(raw)
    decoded_text = decoded.decode("latin-1", errors="replace")
    # Search both the literal text and any decoded layer: a raw hex flag is
    # valid on some platforms, while a base64 wrapper hides a normal one.
    text = original_text if decoded_text == original_text else original_text + "\n" + decoded_text

    candidates: dict[str, dict] = {}

    def add(value: str, score: int, why: str):
        value = normalize_flag(value)
        if not value or "{" not in value or "}" not in value:
            return
        body = value.split("{", 1)[1].rsplit("}", 1)[0]
        if not body or len(body) > 300:
            return
        if not _is_printable_inside(body):
            return
        entry = candidates.setdefault(value, {"value": value, "score": 0, "why": []})
        entry["score"] += score
        if why not in entry["why"]:
            entry["why"].append(why)

    for m in GENERIC_RE.finditer(text):
        value = m.group(0)
        head = value.split("{", 1)[0]
        if prefix and head != prefix:
            # still keep it, but far below the requested prefix
            add(value, 5, f"generic wrapper {head}{{...}} (prefix mismatch)")
            continue
        if head in COMMON_FLAG_PREFIXES:
            add(value, 100, f"common flag prefix {head}{{")
        elif prefix and head == prefix:
            add(value, 120, f"expected flag prefix {head}{{")
        else:
            add(value, 20, f"generic wrapper {head}{{...}}")

    # Raw hex / UUID: some platforms accept the bare value.
    if not candidates:
        for m in RAW_HEX_RE.finditer(text):
            v = m.group(0)
            if len(v) in (32, 40, 64, 96, 128):
                candidates[v] = {"value": v, "score": 30, "why": [f"raw {len(v)}-hex string"]}
        for m in UUID_RE.finditer(text):
            v = m.group(0)
            candidates[v] = {"value": v, "score": 30, "why": ["UUID-shaped value"]}

    ranked = sorted(candidates.values(), key=lambda c: (-c["score"], len(c["value"])))
    return ranked


def normalize_flag(value: str) -> str:
    """Strip common wrappers/punctuation without changing the flag body."""
    s = value.strip()
    s = s.strip("`'\"")
    s = s.strip()
    # Remove trailing sentence punctuation only outside a closing brace.
    if s.endswith("}") is False:
        s = s.rstrip(".,;:")
    return s


def flag_crib(data: bytes | str, prefix: str | None = None) -> bytes | None:
    """Return the known flag prefix (e.g. b'flag{') for known-plaintext attacks."""
    if prefix is None:
        if isinstance(data, bytes):
            text = data.decode("latin-1", errors="replace")
        else:
            text = data
        fmt = detect_flag_regex(text)
        if fmt:
            prefix = fmt.split("\\", 1)[0]
        else:
            ranked = extract_flags(text)
            if ranked and "{" in ranked[0]["value"]:
                prefix = ranked[0]["value"].split("{", 1)[0]
    if not prefix:
        return None
    return (prefix + "{").encode()


def detect_format(data: bytes | str) -> str | None:
    return detect_flag_regex(data)


def main():
    ap = argparse.ArgumentParser(description="Extract and rank CTF flags")
    ap.add_argument("source", help="file path, or '-' to read stdin")
    ap.add_argument("--prefix", default=None, help="expected flag prefix, e.g. flag")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.source == "-":
        raw = sys.stdin.buffer.read()
    elif os.path.exists(args.source):
        with open(args.source, "rb") as fh:
            raw = fh.read()
    else:
        raw = args.source.encode()

    ranked = extract_flags(raw, args.prefix)
    if args.json:
        print(json.dumps({"format": detect_format(raw), "candidates": ranked}, indent=2))
        return 0

    print(f"Detected format: {detect_format(raw) or 'unknown'}")
    if not ranked:
        print("No flag candidates found.")
        print("Tried: wrapped \\w+{...}, raw 32/40/64/128 hex, UUID, and one hex/base64 decode layer.")
        return 1
    print(f"Found {len(ranked)} candidate(s):")
    for i, c in enumerate(ranked[:10], 1):
        print(f"  {i}. {c['value']}  (score {c['score']}: {'; '.join(c['why'])})")
    print(f"\nBest: {ranked[0]['value']}")
    crib = flag_crib(raw, args.prefix)
    if crib:
        print(f"Crib for known-plaintext attacks: {crib!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
