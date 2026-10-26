"""Proof-of-work helpers for remote CTF services.

Many `nc` challenges open with a hashcash-style gate before the real protocol:

    sha256(prefix + answer) must start with 4 hex zeros
    Give me a string so that md5(answer) begins with 00000

The parser is deliberately forgiving; when it cannot find a pattern, call
`solve_pow` directly with the parameters you read from the banner.
"""

from __future__ import annotations

import hashlib
import itertools
import re
import string
import time

ALGOS = {"md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"}


def format_answer(n: int, encoding: str = "decimal", length: int | None = None) -> str:
    """Render a counter as the answer string."""
    if encoding == "hex":
        s = format(n, "x")
    elif encoding == "HEX":
        s = format(n, "X")
    elif encoding in ("alnum", "base36"):
        alphabet = string.digits + string.ascii_lowercase
        if n == 0:
            s = "0"
        else:
            out = []
            while n:
                n, r = divmod(n, len(alphabet))
                out.append(alphabet[r])
            s = "".join(reversed(out))
    else:  # decimal / string
        s = str(n)
    if length is not None:
        s = s.rjust(length, "0")
    return s


def _leading_zero_bits(digest_hex: str, bits: int) -> bool:
    value = int(digest_hex, 16)
    return value >> (len(digest_hex) * 4 - bits) == 0 if bits > 0 else True


def solve_pow(
    prefix: str = "",
    zeros: int = 4,
    algo: str = "sha256",
    position: str = "prefix",
    unit: str = "hex",
    encoding: str = "decimal",
    length: int | None = None,
    literal: str | None = None,
    max_iter: int = 1 << 32,
    time_limit: float | None = 60.0,
) -> tuple[str, str] | None:
    """Find an answer satisfying the proof-of-work.

    Args:
        prefix: fixed string from the service.
        zeros: number of leading zero hex characters (or bits if unit="bits").
        algo: hash name accepted by hashlib.
        position: "prefix" for `prefix + answer`, "suffix" for `answer + prefix`.
        unit: "hex" (zero hex chars), "bits" (zero bits), or "literal".
        encoding: how to render the answer ("decimal", "hex", "alnum").
        length: zero-pad the answer to this length.
        literal: required digest prefix when unit="literal".
        max_iter: safety cap.

    Returns (answer, digest_hex) or None.
    """
    algo = algo.lower().replace("-", "")
    if algo not in ALGOS:
        # allow any hashlib name
        try:
            hashlib.new(algo)
        except Exception:
            raise ValueError(f"unknown hash algorithm {algo!r}")

    if literal is not None:
        unit = "literal"
        literal = literal.lower()

    start = time.monotonic()
    for i in range(max_iter):
        if time_limit is not None and (i & 0xFFFF) == 0 and time.monotonic() - start > time_limit:
            return None
        answer = format_answer(i, encoding, length)
        data = (prefix + answer) if position == "prefix" else (answer + prefix)
        digest = hashlib.new(algo, data.encode()).hexdigest()
        if unit == "literal":
            ok = digest.startswith(literal)
        elif unit == "bits":
            ok = _leading_zero_bits(digest, zeros)
        else:
            ok = digest.startswith("0" * zeros)
        if ok:
            return answer, digest
    return None


def parse_pow(text: str) -> dict:
    """Best-effort extraction of PoW parameters from a banner.

    Returns a dict with keys: prefix, zeros, algo, position, unit, encoding,
    length, literal, found. Missing values get sensible defaults.
    """
    low = text.lower()
    info: dict = {
        "prefix": "",
        "zeros": 4,
        "algo": "sha256",
        "position": "prefix",
        "unit": "hex",
        "encoding": "decimal",
        "length": None,
        "literal": None,
        "found": False,
    }

    for algo in ("sha512", "sha256", "sha1", "md5", "sha3_256", "blake2b"):
        if algo in low:
            info["algo"] = algo
            break

    placeholder = re.compile(
        r"^(?:prefix|suffix|answer|secret|nonce|token|string|number|input|x{2,}|\?{2,})$",
        re.I,
    )

    # 1. Explicit assignment: "prefix = 'xyz'", "prefix is abc".
    m = re.search(
        r"\bprefix\b\s*(?:=|is|:)\s*['\"]?([A-Za-z0-9_+/=.:-]{1,64})['\"]?", text, re.I
    )
    if m and not placeholder.match(m.group(1)):
        info["prefix"] = m.group(1)
    else:
        # 2. sha256('abc' + answer) / sha256(abc + answer).
        m = re.search(
            r"(?:sha256|sha1|md5|sha512|sha3_256)\s*\(\s*['\"]?"
            r"([A-Za-z0-9_+/=.:-]{1,64})['\"]?\s*\+",
            text,
            re.I,
        )
        if m and not placeholder.match(m.group(1)):
            info["prefix"] = m.group(1)

    # 3. A required digest prefix: "starts with abc" / "begins with 0000".
    #    All-zero values are a difficulty, not a salt.
    m = re.search(
        r"(?:starts?|begins?|beginning|prefixed)\s+(?:with|by)\s+['\"]?([A-Za-z0-9_+/=.:-]{2,64})['\"]?",
        text,
        re.I,
    )
    if m:
        val = m.group(1)
        if set(val) <= {"0"}:
            info["zeros"] = len(val)
            info["unit"] = "literal"
            info["literal"] = val
        elif not placeholder.match(val):
            info["unit"] = "literal"
            info["literal"] = val

    # suffix orientation
    if re.search(r"answer\s*\+\s*(?:prefix|suffix|secret)|suffix\s*\+", text, re.I):
        info["position"] = "suffix"

    # leading zeros / difficulty
    m = re.search(r"(\d+)\s*(?:leading\s*)?(?:hex\s*)?zeros?", text, re.I)
    if m:
        if info["unit"] != "literal":
            info["zeros"] = int(m.group(1))
    else:
        m = re.search(r"difficulty\s*[:=]?\s*(\d+)", text, re.I)
        if m and info["unit"] != "literal":
            info["zeros"] = int(m.group(1))

    if re.search(r"\bbits?\b", low) and "zero" in low:
        info["unit"] = "bits"

    if re.search(r"\bhex(?:adecimal)?\b", low):
        info["encoding"] = "hex"
    if re.search(r"\b(?:decimal|number|integer)\b", low):
        info["encoding"] = "decimal"

    m = re.search(
        r"(?:length|exactly)\s*(?:of\s*)?(\d+)\s*(?:chars?|characters?|bytes?)", text, re.I
    )
    if m:
        info["length"] = int(m.group(1))

    info["found"] = bool(info["prefix"] or info["literal"] or info["zeros"] != 4)
    return info


def parse_and_solve(text: str, **overrides) -> tuple[str, str] | None:
    """Parse a PoW banner and solve it. Overrides win over parsed values."""
    info = parse_pow(text)
    params = {k: v for k, v in info.items() if k != "found" and v is not None}
    params.update(overrides)
    if params.get("literal"):
        params["unit"] = "literal"
    return solve_pow(**params)


if __name__ == "__main__":
    import sys

    banner = " ".join(sys.argv[1:]) or "Give me a string such that sha256('abc' + answer) starts with 4 zeros"
    result = parse_and_solve(banner)
    print("parsed:", parse_pow(banner))
    print("answer:", result[0] if result else None)
    print("digest:", result[1] if result else None)
