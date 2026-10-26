"""Shared helpers for CTF crypto work.

Everything here is stdlib-only so a solve script stays runnable anywhere.
Optional packages (sympy/gmpy2/pycryptodome) are used by other modules when
present, never required by this one.
"""

from __future__ import annotations

import importlib.util
import math
import os
import re
import socket
import string
import sys
from functools import lru_cache

# --------------------------------------------------------------------------
# bytes <-> ints
# --------------------------------------------------------------------------


def b2i(data: bytes) -> int:
    """Big-endian bytes to int."""
    return int.from_bytes(data, "big")


def i2b(n: int, length: int | None = None) -> bytes:
    """Big-endian int to bytes. Pads to `length` when given."""
    if n < 0:
        raise ValueError("negative integers do not have a big-endian byte form")
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def i2b_le(n: int, length: int | None = None) -> bytes:
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "little")


def b2i_le(data: bytes) -> int:
    return int.from_bytes(data, "little")


def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings, cycling the shorter one if lengths differ."""
    if not a or not b:
        return b""
    if len(a) < len(b):
        a, b = b, a
    n = len(b)
    return bytes(x ^ b[i % n] for i, x in enumerate(a))


def xor_single(data: bytes, key: int) -> bytes:
    return bytes(c ^ key for c in data)


def hamming(a: bytes, b: bytes) -> int:
    """Bit difference between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("hamming needs equal lengths")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# --------------------------------------------------------------------------
# number theory
# --------------------------------------------------------------------------


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_r < 0:
        old_r, old_s, old_t = -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def invmod(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (gcd={g})")
    return x % m


def crt(remainders: list[int], moduli: list[int]) -> tuple[int, int]:
    """Chinese remainder theorem for pairwise-coprime moduli.

    Returns (solution, product_of_moduli) with solution in [0, product).
    """
    if len(remainders) != len(moduli):
        raise ValueError("remainders and moduli must have the same length")
    x, m = 0, 1
    for r, n in zip(remainders, moduli):
        g, p, _ = egcd(m, n)
        if (r - x) % g:
            raise ValueError("system is inconsistent: moduli are not coprime")
        # combine x mod m and r mod n
        lcm = m // g * n
        t = ((r - x) // g) % (n // g) * p % (n // g)
        x = (x + m * t) % lcm
        m = lcm
    return x % m, m


def isqrt_exact(n: int) -> int | None:
    """Return sqrt(n) if n is a perfect square, else None."""
    if n < 0:
        return None
    r = math.isqrt(n)
    return r if r * r == n else None


def iroot(n: int, k: int) -> int:
    """Floor of the k-th root of n, exactly (no floating point)."""
    if n < 0:
        raise ValueError("iroot needs a non-negative n")
    if k <= 0:
        raise ValueError("root degree must be positive")
    if n in (0, 1) or k == 1:
        return n
    if k == 2:
        return math.isqrt(n)
    # Newton iteration seeded above the true root
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def is_perfect_power(n: int, k: int) -> int | None:
    """Return m if n == m**k exactly, else None."""
    if n < 0:
        return None
    r = iroot(n, k)
    return r if r**k == n else None


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin. Deterministic for n < 3.3e24, else probabilistic."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True
    if any(n % p == 0 for p in small):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    if n < 3317044064679887385961981:
        bases = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)
        if n < 3215031751:
            bases = (2, 3, 5, 7, 11, 13, 17)
        if n < 341550071728321:
            bases = (2, 3, 5, 7, 11, 13, 17, 19, 23)
        for a in bases:
            if a % n == 0:
                continue
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True
    # random rounds for huge n
    import random

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def primes_upto(limit: int) -> list[int]:
    """Sieve of Eratosthenes."""
    if limit < 2:
        return []
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i : limit + 1 : i] = b"\x00" * (((limit - i * i) // i) + 1)
    return [i for i, v in enumerate(sieve) if v]


def factor_small(n: int, limit: int = 100_000) -> tuple[dict[int, int], int]:
    """Trial-divide by primes up to `limit`.

    Returns (factorisation dict, remaining unfactored cofactor).
    """
    factors: dict[int, int] = {}
    for p in primes_upto(limit):
        if p * p > n:
            break
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p
    return factors, n


def gcd_list(values) -> int:
    g = 0
    for v in values:
        g = math.gcd(g, v)
        if g == 1:
            break
    return g


def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b


# --------------------------------------------------------------------------
# English scoring (for classical ciphers and xor keys)
# --------------------------------------------------------------------------

# Letter frequencies in percent.
ENGLISH_LETTER_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

# Common bigrams in percent of letter pairs.
ENGLISH_BIGRAMS = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99, "re": 1.85,
    "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35, "ti": 1.34, "es": 1.34,
    "or": 1.28, "te": 1.20, "of": 1.17, "ed": 1.17, "is": 1.13, "it": 1.12,
    "al": 1.09, "ar": 1.07, "st": 1.05, "to": 1.05, "nt": 1.04, "ng": 0.95,
    "se": 0.93, "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76, "ri": 0.73,
    "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69, "ra": 0.69, "ce": 0.65,
    "li": 0.62, "ch": 0.60, "ll": 0.58, "be": 0.58, "ma": 0.57, "si": 0.55,
    "om": 0.55, "ur": 0.54, "ca": 0.53, "el": 0.53, "ta": 0.53, "la": 0.53,
    "ns": 0.51, "di": 0.50, "fo": 0.50, "ho": 0.49, "pe": 0.49, "ec": 0.48,
    "pr": 0.48, "no": 0.47, "ct": 0.46, "us": 0.46, "ac": 0.46, "ot": 0.45,
    "il": 0.45, "tr": 0.44, "ly": 0.44, "nc": 0.44, "et": 0.43, "ut": 0.43,
    "ss": 0.42, "so": 0.42, "rs": 0.42, "un": 0.41, "lo": 0.41, "wa": 0.40,
    "ge": 0.40, "ie": 0.40, "wh": 0.39, "ee": 0.39, "wi": 0.38, "em": 0.38,
    "ad": 0.38, "ol": 0.37, "rt": 0.37, "po": 0.36, "we": 0.36, "na": 0.36,
    "ul": 0.35, "ni": 0.35, "ts": 0.35, "mo": 0.35, "ow": 0.35, "pa": 0.34,
    "im": 0.34, "mi": 0.34, "ai": 0.34, "sh": 0.33, "ir": 0.33, "su": 0.33,
    "id": 0.33, "os": 0.32, "iv": 0.32, "ia": 0.32, "am": 0.32, "fi": 0.32,
    "ci": 0.31, "vi": 0.31, "pl": 0.31, "ig": 0.30, "tu": 0.30, "ev": 0.30,
    "ld": 0.30, "ry": 0.30, "mp": 0.29, "fe": 0.29, "bl": 0.29, "ab": 0.29,
    "gh": 0.29, "ty": 0.28, "op": 0.28, "wo": 0.28, "sa": 0.27, "ay": 0.27,
    "ex": 0.27, "ke": 0.27, "fr": 0.27, "oo": 0.27, "av": 0.26, "ag": 0.26,
    "if": 0.26, "ap": 0.26, "gr": 0.26, "od": 0.26, "bo": 0.25, "sp": 0.25,
    "rd": 0.25, "do": 0.25, "uc": 0.25, "bu": 0.24, "ei": 0.24, "ov": 0.24,
    "by": 0.24, "rm": 0.24, "ep": 0.24, "tt": 0.24, "oc": 0.24, "fa": 0.23,
    "ef": 0.23, "cu": 0.23, "rn": 0.23, "sc": 0.23, "gi": 0.22, "da": 0.22,
    "yo": 0.22, "cr": 0.22, "cl": 0.22, "du": 0.22, "ga": 0.22, "qu": 0.21,
    "ue": 0.21, "ff": 0.21, "ba": 0.21, "ey": 0.21, "ls": 0.21, "va": 0.21,
    "um": 0.21, "pp": 0.21, "ua": 0.20, "up": 0.20, "lu": 0.20, "go": 0.20,
    "ht": 0.20, "ru": 0.20, "ug": 0.20, "ds": 0.20, "lt": 0.20, "pi": 0.20,
    "rc": 0.20, "rr": 0.20, "eg": 0.19, "au": 0.19, "ck": 0.19, "ew": 0.19,
    "mu": 0.19, "br": 0.19, "bi": 0.19, "pt": 0.19, "ak": 0.19, "pu": 0.18,
    "ui": 0.18, "rg": 0.18, "ib": 0.18, "tl": 0.18, "ny": 0.18, "ki": 0.18,
    "rk": 0.18, "ys": 0.18, "ob": 0.18, "mm": 0.18, "fu": 0.18, "ph": 0.18,
    "og": 0.17, "ms": 0.17, "ye": 0.17, "ud": 0.17, "mb": 0.17, "ip": 0.17,
    "ub": 0.17, "oi": 0.17, "rl": 0.17, "gu": 0.17, "dr": 0.17, "hr": 0.17,
}

COMMON_WORDS = {
    "the": 7.0, "be": 4.0, "to": 4.0, "of": 4.0, "and": 3.5, "a": 3.0,
    "in": 3.0, "that": 3.0, "have": 2.5, "i": 2.5, "it": 2.5, "for": 2.5,
    "not": 2.5, "on": 2.0, "with": 2.0, "he": 2.0, "as": 2.0, "you": 2.0,
    "do": 2.0, "at": 2.0, "this": 2.0, "but": 2.0, "his": 2.0, "by": 2.0,
    "from": 2.0, "they": 2.0, "we": 2.0, "say": 1.5, "her": 1.5, "she": 1.5,
    "or": 1.5, "an": 1.5, "will": 1.5, "my": 1.5, "one": 1.5, "all": 1.5,
    "would": 1.5, "there": 1.5, "their": 1.5, "what": 1.5, "so": 1.5,
    "up": 1.5, "out": 1.5, "if": 1.5, "about": 1.5, "who": 1.5, "get": 1.5,
    "which": 1.5, "go": 1.5, "me": 1.5, "when": 1.5, "make": 1.5, "can": 1.5,
    "like": 1.5, "time": 1.5, "no": 1.5, "just": 1.5, "him": 1.5, "know": 1.5,
    "take": 1.5, "people": 1.5, "into": 1.5, "year": 1.5, "your": 1.5,
    "good": 1.5, "some": 1.5, "could": 1.5, "them": 1.5, "see": 1.5,
    "other": 1.5, "than": 1.5, "then": 1.5, "now": 1.5, "look": 1.5,
    "only": 1.5, "come": 1.5, "its": 1.5, "over": 1.5, "think": 1.5,
    "also": 1.5, "back": 1.5, "after": 1.5, "use": 1.5, "two": 1.5,
    "how": 1.5, "our": 1.5, "work": 1.5, "first": 1.5, "well": 1.5,
    "way": 1.5, "even": 1.5, "new": 1.5, "want": 1.5, "because": 1.5,
    "any": 1.5, "these": 1.5, "give": 1.5, "day": 1.5, "most": 1.5,
    "us": 1.5, "is": 2.5, "are": 2.5, "was": 2.5, "were": 2.5, "been": 2.5,
    "has": 2.5, "had": 2.5, "did": 2.0, "does": 2.0, "said": 2.0,
    "flag": 2.0, "ctf": 2.0, "key": 1.5, "secret": 1.5, "message": 1.5,
    "cipher": 1.5, "crypto": 1.5, "text": 1.0, "plain": 1.0,
    "attack": 1.0, "found": 1.0, "here": 1.5, "where": 1.5, "very": 1.5,
    "should": 1.5, "much": 1.5, "more": 1.5, "many": 1.5, "such": 1.5,
    "through": 1.5, "between": 1.5, "under": 1.5, "before": 1.5,
    "never": 1.5, "always": 1.5, "still": 1.5, "again": 1.5,
    "hello": 1.0, "world": 1.0, "the": 7.0,
}


def _logp(freq_percent: float, total: float = 100.0) -> float:
    return math.log(freq_percent / total + 1e-9)


_LETTER_LOG = {c: _logp(v) for c, v in ENGLISH_LETTER_FREQ.items()}
_BIGRAM_LOG = {b: _logp(v) for b, v in ENGLISH_BIGRAMS.items()}
_BIGRAM_DEFAULT = math.log(0.01 / 100.0)
_WORD_BONUS = {w: math.log(v) for w, v in COMMON_WORDS.items()}

_OOV_LOG = -9.0


@lru_cache(maxsize=1)
def _word_vocab() -> dict[str, float]:
    """Word -> log-likelihood, from the bundled frequency-ranked list."""
    path = os.path.join(os.path.dirname(__file__), "data", "english_10k.txt")
    vocab: dict[str, float] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for rank, line in enumerate(fh):
                w = line.strip().lower()
                if w:
                    vocab[w] = -math.log(rank + 10.0)
    except OSError:
        return {}
    return vocab


def word_score(data: bytes | str) -> float:
    """Average log-likelihood that the tokens are English words.

    Word-level evidence is much stronger than letter frequencies for
    substitution ciphers, where word boundaries survive encryption.
    """
    if isinstance(data, bytes):
        text = data.decode("latin-1")
    else:
        text = data
    words = re.findall(r"[a-z]+", text.lower())
    if not words:
        return _OOV_LOG
    vocab = _word_vocab()
    if not vocab:
        return sum(_WORD_BONUS.get(w, _OOV_LOG) for w in words) / len(words)
    return sum(vocab.get(w, _OOV_LOG) for w in words) / len(words)


def word_list() -> list[str]:
    """Dictionary words in frequency order (commonest first)."""
    return list(_word_vocab().keys())


def _letter_avg_score(text: str) -> float:
    letters = [c for c in text.lower() if c in _LETTER_LOG]
    if not letters:
        return -1e9
    return sum(_LETTER_LOG[c] for c in letters) / len(letters)


def _bigram_avg_score(text: str) -> float:
    low = text.lower()
    bigrams = [low[i : i + 2] for i in range(len(low) - 1)]
    if not bigrams:
        return _BIGRAM_DEFAULT
    return sum(_BIGRAM_LOG.get(b, _BIGRAM_DEFAULT) for b in bigrams) / len(bigrams)


@lru_cache(maxsize=1)
def _trigram_log() -> dict[str, float]:
    """Trigram log-likelihoods derived from the bundled word frequency list.

    Generated at runtime so the bundled data stays small. Word boundaries are
    marked with ^ and $, which keeps cross-word trigrams from polluting the
    statistics.
    """
    vocab = _word_vocab()
    if not vocab:
        return {}
    counts: dict[str, float] = {}
    total = 0.0
    # vocab values are -log(rank+10); recover a rank-like weight from them
    for word, logp in vocab.items():
        weight = math.exp(logp)  # 1/(rank+10)
        padded = "^" + word + "$"
        for i in range(len(padded) - 2):
            tri = padded[i : i + 3]
            counts[tri] = counts.get(tri, 0.0) + weight
            total += weight
    if total <= 0:
        return {}
    return {t: math.log(c / total + 1e-12) for t, c in counts.items()}


def trigram_score(data: bytes | str) -> float:
    if isinstance(data, bytes):
        text = data.decode("latin-1")
    else:
        text = data
    table = _trigram_log()
    if not table:
        return _OOV_LOG
    vals = []
    for word in re.findall(r"[a-z]+", text.lower()):
        padded = "^" + word + "$"
        for i in range(len(padded) - 2):
            vals.append(table.get(padded[i : i + 3], _OOV_LOG))
    if not vals:
        return _OOV_LOG
    return sum(vals) / len(vals)


def english_score(data: bytes | str) -> float:
    """Rough log-likelihood that `data` is English text.

    Higher is better. Averages over characters so long and short samples
    compare fairly, then adds word-level and printable-ratio evidence.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("latin-1")
        except Exception:
            return -1e9
    else:
        text = data
    if not text:
        return -1e9
    letters = [c for c in text.lower() if c in _LETTER_LOG]
    if not letters:
        return -1e9
    score = 0.45 * _letter_avg_score(text)
    score += 0.25 * _bigram_avg_score(text)
    score += 0.35 * word_score(text)
    printable = sum(1 for c in text if c in string.printable or c in " \n\t")
    score += 0.15 * (printable / len(text))
    return score


def substitution_score(data: bytes | str) -> float:
    """Scoring tuned for substitution ciphers.

    Word-level evidence is the strongest signal once a key is nearly right,
    but trigrams give the hill climber a smoother path to that region.
    """
    if isinstance(data, bytes):
        text = data.decode("latin-1")
    else:
        text = data
    if not text:
        return -1e9
    score = 0.22 * _letter_avg_score(text)
    score += 0.18 * _bigram_avg_score(text)
    score += 0.30 * trigram_score(text)
    score += 0.30 * word_score(text)
    if re.search(r"\b(flag|ctf)\{", text, re.I):
        score += 1.5
    return score


def chi_squared_english(data: bytes | str) -> float:
    """Chi-squared distance from English letter frequencies (lower is better)."""
    if isinstance(data, bytes):
        text = data.decode("latin-1")
    else:
        text = data
    low = [c for c in text.lower() if "a" <= c <= "z"]
    if not low:
        return float("inf")
    n = len(low)
    counts = {c: 0 for c in ENGLISH_LETTER_FREQ}
    for c in low:
        counts[c] = counts.get(c, 0) + 1
    total = 0.0
    for c, freq in ENGLISH_LETTER_FREQ.items():
        expected = n * freq / 100.0
        total += (counts[c] - expected) ** 2 / expected
    return total


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

FLAG_RE = re.compile(r"[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,300}\}")


def find_flags(text: bytes | str) -> list[str]:
    """Find anything that looks like a CTF flag."""
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return FLAG_RE.findall(text)


COMMON_FLAG_PREFIXES = [
    "flag", "FLAG", "ctf", "CTF", "picoCTF", "PICOCTF", "DASCTF", "NSSCTF",
    "HTB", "DUCTF", "idek", "SCTF", "N1CTF", "0CTF", "TCTF", "HITCON",
    "Balsn", "midnight", "ictf", "grey", "uiuctf", "corctf", "maple",
]


def detect_flag_regex(text: bytes | str) -> str | None:
    """Detect the challenge's flag format from its description.

    Common prefixes are checked first, so a ciphertext that happens to
    contain `xxxx{...}` does not override an explicit `flag{...}` hint.
    """
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    for prefix in COMMON_FLAG_PREFIXES:
        if re.search(re.escape(prefix) + r"\{[^}\r\n]{1,60}\}", text):
            return prefix + r"\{[^}]+\}"
    m = re.search(
        r"(?:flag\s+(?:format|is|starts?\s+with)|format)\s*[:=]?\s*"
        r"([A-Za-z0-9_]{2,32})\{",
        text,
        re.I,
    )
    if m:
        return m.group(1) + r"\{[^}]+\}"
    m = re.search(r"([A-Za-z0-9_]{1,32})\{[^{}\r\n]{1,60}\}", text)
    if m and m.group(1).lower() not in {"http", "https"}:
        return m.group(1) + r"\{[^}]+\}"
    return None


# --------------------------------------------------------------------------
# parsing challenge text
# --------------------------------------------------------------------------

_INT_RE = re.compile(r"-?\d+")
_NAME_INT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(-?\d+)(?![0-9A-Za-z_])")


def parse_ints(text: str) -> list[int]:
    return [int(x) for x in _INT_RE.findall(text)]


def parse_named_ints(text: str) -> dict[str, list[int]]:
    """Parse lines like `n = 12345` into {'n': [12345]}."""
    out: dict[str, list[int]] = {}
    for name, value in _NAME_INT_RE.findall(text):
        out.setdefault(name, []).append(int(value))
    return out


def parse_bytes_literal(text: str) -> bytes | None:
    """Parse b'...' or b"..." literals commonly found in output.txt."""
    m = re.search(r"b(['\"])(.*?)\1", text, re.S)
    if not m:
        return None
    body = m.group(2)
    try:
        return body.encode("latin-1").decode("unicode_escape").encode("latin-1")
    except Exception:
        return body.encode("latin-1")


def read_text(path) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# environment detection
# --------------------------------------------------------------------------


def have(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def env_report() -> dict:
    mods = [
        "Crypto", "Cryptodome", "sympy", "gmpy2", "numpy", "z3",
        "pwn", "pwnlib", "ecdsa", "sageall",
    ]
    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "has_sage": bool(__import__("shutil").which("sage")),
        "packages": {m: have(m) for m in mods},
    }


# --------------------------------------------------------------------------
# remote helpers (no pwntools dependency)
# --------------------------------------------------------------------------


class Tube:
    """Minimal pwntools-like wrapper around a socket.

    Pass `log_path` to append a transcript; oracle debugging is much easier
    when you can read exactly what was sent and received.
    """

    def __init__(self, sock: socket.socket, timeout: float | None = None, log_path: str | None = None):
        self.sock = sock
        self.buf = b""
        self.log_path = log_path
        self._log_fh = open(log_path, "ab") if log_path else None
        if timeout is not None:
            self.sock.settimeout(timeout)

    def _log(self, tag: bytes, data: bytes):
        if self._log_fh:
            self._log_fh.write(tag + data + b"\n")
            self._log_fh.flush()

    def recv(self, n: int = 4096) -> bytes:
        data = self.sock.recv(n)
        self._log(b"<< ", data)
        return data

    def recvuntil(self, delim: bytes, drop: bool = True) -> bytes:
        """Read through `delim`; return everything before it (or including)."""
        while delim not in self.buf:
            chunk = self.recv(4096)
            if not chunk:
                data, self.buf = self.buf, b""
                return data
            self.buf += chunk
        idx = self.buf.index(delim)
        end = idx + len(delim)
        data, self.buf = self.buf[:end], self.buf[end:]
        return data[:-len(delim)] if drop else data

    def recvuntil_any(self, delims: list[bytes], drop: bool = True) -> tuple[bytes, bytes | None]:
        """Read until any delimiter; return (data, matched_delimiter)."""
        while True:
            for d in delims:
                if d in self.buf:
                    idx = self.buf.index(d)
                    end = idx + len(d)
                    data, self.buf = self.buf[:end], self.buf[end:]
                    return (data[:-len(d)] if drop else data), d
            chunk = self.recv(4096)
            if not chunk:
                data, self.buf = self.buf, b""
                return data, None

    def recvline(self) -> bytes:
        return self.recvuntil(b"\n", drop=True)

    def recvall(self) -> bytes:
        chunks = [self.buf]
        self.buf = b""
        while True:
            chunk = self.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def send(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode()
        self._log(b">> ", data)
        self.sock.sendall(data)

    def sendline(self, data: bytes | str = b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def sendhex(self, data: bytes, newline: bool = True):
        payload = data.hex().encode()
        self.sendline(payload) if newline else self.send(payload)

    def sendb64(self, data: bytes, newline: bool = True):
        import base64

        payload = base64.b64encode(data)
        self.sendline(payload) if newline else self.send(payload)

    def sendafter(self, delim: bytes, data: bytes | str):
        self.recvuntil(delim)
        self.send(data)

    def sendlineafter(self, delim: bytes, data: bytes | str):
        self.recvuntil(delim)
        self.sendline(data)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        if self._log_fh:
            try:
                self._log_fh.close()
            except Exception:
                pass
            self._log_fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def connect(
    host: str,
    port: int,
    timeout: float = 10.0,
    tls: bool = False,
    log_path: str | None = None,
) -> Tube:
    if tls:
        import ssl

        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return Tube(ctx.wrap_socket(raw), timeout, log_path=log_path)
    sock = socket.create_connection((host, port), timeout=timeout)
    return Tube(sock, timeout, log_path=log_path)
