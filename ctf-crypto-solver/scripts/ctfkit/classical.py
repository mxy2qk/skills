"""Classical cipher and simple-XOR solvers.

Functions take/return `str` for letter ciphers and `bytes` for XOR, except
where noted. "Bruteforce" helpers return candidates sorted best-first as
tuples you can inspect; they do not guess silently.
"""

from __future__ import annotations

import itertools
import math
import random
import re
import string
import time
from functools import lru_cache

from .util import (
    ENGLISH_LETTER_FREQ,
    chi_squared_english,
    english_score,
    find_flags,
    hamming,
    substitution_score,
    word_list,
)

ALPHABET = string.ascii_lowercase


# --------------------------------------------------------------------------
# monoalphabetic
# --------------------------------------------------------------------------


def _shift_char(c: str, k: int) -> str:
    if c.islower():
        return chr((ord(c) - 97 + k) % 26 + 97)
    if c.isupper():
        return chr((ord(c) - 65 + k) % 26 + 65)
    return c


def caesar(data: str, k: int, decrypt: bool = True) -> str:
    """Shift by k. decrypt=True shifts backwards."""
    if decrypt:
        k = -k
    return "".join(_shift_char(c, k) for c in data)


def caesar_encrypt(data: str, k: int) -> str:
    return caesar(data, k, decrypt=False)


def caesar_decrypt(data: str, k: int) -> str:
    return caesar(data, k, decrypt=True)


def caesar_bruteforce(data: str) -> list[tuple[float, int, str]]:
    out = []
    for k in range(26):
        text = caesar(data, k)
        out.append((english_score(text), k, text))
    return sorted(out, reverse=True)


def affine_decrypt(data: str, a: int, b: int) -> str:
    inv = pow(a, -1, 26)
    out = []
    for c in data:
        if c.islower():
            out.append(chr((inv * (ord(c) - 97 - b)) % 26 + 97))
        elif c.isupper():
            out.append(chr((inv * (ord(c) - 65 - b)) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def affine_bruteforce(data: str) -> list[tuple[float, int, int, str]]:
    out = []
    for a in range(26):
        if math.gcd(a, 26) != 1:
            continue
        for b in range(26):
            text = affine_decrypt(data, a, b)
            out.append((english_score(text), a, b, text))
    return sorted(out, reverse=True)


def atbash(data: str) -> str:
    out = []
    for c in data:
        if c.islower():
            out.append(chr(122 - (ord(c) - 97)))
        elif c.isupper():
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    return "".join(out)


def rot13(data: str) -> str:
    return caesar(data, 13)


def rot47(data: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in data)


# --------------------------------------------------------------------------
# polyalphabetic
# --------------------------------------------------------------------------


def vigenere(data: str, key: str, decrypt: bool = True) -> str:
    key_ints = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key_ints:
        return data
    out = []
    j = 0
    sign = -1 if decrypt else 1
    for c in data:
        if c.isalpha():
            k = key_ints[j % len(key_ints)]
            out.append(_shift_char(c, sign * k))
            j += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_encrypt(data: str, key: str) -> str:
    return vigenere(data, key, decrypt=False)


def index_of_coincidence(data: str) -> float:
    letters = [c.lower() for c in data if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {c: letters.count(c) for c in set(letters)}
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _columns(data: str, width: int) -> list[str]:
    letters = [c for c in data if c.isalpha()]
    return ["".join(letters[i::width]) for i in range(width)]


def kasiski(data: str, ngram: int = 3, limit: int = 12) -> list[int]:
    """Candidate key lengths from repeated n-grams."""
    text = "".join(c.lower() for c in data if c.isalpha())
    positions: dict[str, list[int]] = {}
    for i in range(len(text) - ngram + 1):
        positions.setdefault(text[i : i + ngram], []).append(i)
    distances = []
    for pos in positions.values():
        if len(pos) > 1:
            for a, b in itertools.combinations(pos, 2):
                distances.append(b - a)
    if not distances:
        return []
    g = 0
    for d in distances:
        g = math.gcd(g, d)
    # score key lengths by how many distances are divisible by them
    scores = {}
    for cand in range(2, limit + 1):
        scores[cand] = sum(1 for d in distances if d % cand == 0)
    return sorted(scores, key=lambda c: (-scores[c], c))


def _recover_vigenere_key(data: str, keylen: int) -> str:
    key = []
    for col in _columns(data, keylen):
        best_shift, best_chi = 0, float("inf")
        for shift in range(26):
            shifted = "".join(_shift_char(c, -shift) for c in col)
            chi = chi_squared_english(shifted)
            if chi < best_chi:
                best_chi, best_shift = chi, shift
        key.append(ALPHABET[best_shift])
    return "".join(key)


def _refine_vigenere_key(data: str, key: str, passes: int = 3) -> tuple[str, float]:
    """Fix isolated column errors using full-plaintext word scoring."""
    key = list(key)
    best = english_score(vigenere(data, "".join(key)))
    for _ in range(passes):
        improved = False
        for i in range(len(key)):
            best_c = key[i]
            for cand in ALPHABET:
                if cand == key[i]:
                    continue
                trial = list(key)
                trial[i] = cand
                score = english_score(vigenere(data, "".join(trial)))
                if score > best:
                    best, best_c = score, cand
            if best_c != key[i]:
                key[i] = best_c
                improved = True
        if not improved:
            break
    return "".join(key), best


def _minimal_period(key: str) -> str:
    n = len(key)
    for p in range(1, n + 1):
        if n % p == 0 and key == key[:p] * (n // p):
            return key[:p]
    return key


def vigenere_bruteforce(data: str, max_keylen: int = 20) -> list[tuple[float, str, str]]:
    """Return (score, key, plaintext) candidates, best first."""
    raw = []
    for keylen in range(1, max_keylen + 1):
        key = _recover_vigenere_key(data, keylen)
        raw.append((english_score(vigenere(data, key)), key))
    raw.sort(reverse=True)
    results = []
    # Refine the most promising few with word-level scoring, which catches a
    # single column whose chi-squared minimum was off by a few shifts.
    for _, key in raw[:3]:
        rkey, score = _refine_vigenere_key(data, key)
        results.append((score, rkey, vigenere(data, rkey)))
    for score, key in raw[3:]:
        results.append((score, key, vigenere(data, key)))
    # Collapse repeated keys (lemonlemon -> lemon) so the shortest period wins.
    best_by_key: dict[str, tuple[float, str, str]] = {}
    for score, key, text in results:
        short = _minimal_period(key)
        if short not in best_by_key or score > best_by_key[short][0]:
            best_by_key[short] = (score, short, text)
    return sorted(best_by_key.values(), reverse=True)


# --------------------------------------------------------------------------
# transposition
# --------------------------------------------------------------------------


def rail_fence_pattern(length: int, rails: int) -> list[int]:
    if rails <= 1:
        return [0] * length
    cycle = list(range(rails)) + list(range(rails - 2, 0, -1))
    return [cycle[i % len(cycle)] for i in range(length)]


def rail_fence_decrypt(data: str, rails: int) -> str:
    pattern = rail_fence_pattern(len(data), rails)
    counts = [pattern.count(r) for r in range(rails)]
    chunks, idx = [], 0
    for c in counts:
        chunks.append(list(data[idx : idx + c]))
        idx += c
    pos = [0] * rails
    out = []
    for r in pattern:
        out.append(chunks[r][pos[r]])
        pos[r] += 1
    return "".join(out)


def rail_fence_encrypt(data: str, rails: int) -> str:
    pattern = rail_fence_pattern(len(data), rails)
    return "".join(data[i] for rail in range(rails) for i, r in enumerate(pattern) if r == rail)


def rail_fence_bruteforce(data: str, max_rails: int = 12) -> list[tuple[float, int, str]]:
    out = []
    for rails in range(2, max_rails + 1):
        text = rail_fence_decrypt(data, rails)
        out.append((english_score(text), rails, text))
    return sorted(out, reverse=True)


def columnar_decrypt(data: str, key: str | list[int], pad: str | None = None) -> str:
    """Decrypt a columnar transposition with a keyword or explicit column order.

    With a string key, columns are read in alphabetical order of the keyword.
    With a list, it gives the order in which columns were read (0-indexed).
    """
    ncols = len(key)
    if isinstance(key, str):
        order = sorted(range(ncols), key=lambda i: (key[i].lower(), i))
    else:
        order = list(key)
    n = len(data)
    nrows = (n + ncols - 1) // ncols
    remainder = n % ncols
    if remainder == 0:
        lengths = [nrows] * ncols
    else:
        lengths = [nrows if i < remainder else nrows - 1 for i in range(ncols)]
    cols = {}
    idx = 0
    for col in order:
        L = lengths[col]
        cols[col] = data[idx : idx + L]
        idx += L
    out = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                out.append(cols[c][r])
    text = "".join(out)
    if pad:
        text = text.rstrip(pad)
    return text


def columnar_encrypt(data: str, key: str, pad: str | None = None) -> str:
    ncols = len(key)
    if pad:
        while len(data) % ncols:
            data += pad
    nrows = (len(data) + ncols - 1) // ncols
    padded = data.ljust(nrows * ncols)
    order = sorted(range(ncols), key=lambda i: (key[i].lower(), i))
    return "".join(padded[r * ncols + c] for c in order for r in range(nrows))


def columnar_bruteforce(
    data: str, max_cols: int = 7, pad: str | None = None
) -> list[tuple[float, tuple[int, ...], str]]:
    """Try every column permutation for small widths."""
    out = []
    for ncols in range(2, max_cols + 1):
        if math.factorial(ncols) > 5040:
            break
        for perm in itertools.permutations(range(ncols)):
            # perm[c] is the original column placed at read-position c
            text = columnar_decrypt(data, list(perm), pad=pad)
            out.append((english_score(text), perm, text))
    return sorted(out, key=lambda t: t[0], reverse=True)


# --------------------------------------------------------------------------
# substitution (hill climbing)
# --------------------------------------------------------------------------


def substitution_decrypt(data: str, key: str | dict[str, str]) -> str:
    """key maps ciphertext letter -> plaintext letter."""
    if isinstance(key, str):
        key = {c: p for c, p in zip(ALPHABET, key.lower())}
    out = []
    for c in data:
        if c.islower():
            out.append(key.get(c, c))
        elif c.isupper():
            out.append(key.get(c.lower(), c.lower()).upper())
        else:
            out.append(c)
    return "".join(out)


def _word_pattern(word: str) -> tuple[int, ...]:
    """Letter-repetition pattern, e.g. really -> (0,1,2,2,3,4)."""
    seen: dict[str, int] = {}
    out = []
    for c in word:
        if c not in seen:
            seen[c] = len(seen)
        out.append(seen[c])
    return tuple(out)


@lru_cache(maxsize=1)
def _pattern_index() -> dict[tuple[int, ...], list[str]]:
    index: dict[tuple[int, ...], list[str]] = {}
    for w in word_list():
        if 2 <= len(w) <= 18 and w.isalpha():
            index.setdefault(_word_pattern(w), []).append(w)
    return index


def _candidate_words(cw: str, mapping, used, index) -> list[str]:
    out = []
    for pw in index.get(_word_pattern(cw), ()):
        ok = True
        for c, p in zip(cw, pw):
            if mapping.get(c, p) != p or used.get(p, c) != c:
                ok = False
                break
        if ok:
            out.append(pw)
    return out


def substitution_pattern_solve(
    data: str, max_solutions: int = 200, time_limit: float = 5.0
) -> list[dict[str, str]]:
    """Solve a substitution cipher by matching word shapes to a dictionary.

    Words of the same length and repetition pattern are interchangeable
    candidates; backtracking enforces a consistent letter mapping. Unknown
    words (names, the flag body, technical terms) are left unconstrained
    instead of failing the search, because the surrounding common words
    usually pin the mapping down.
    """
    words = re.findall(r"[a-z]+", data.lower())
    if not words:
        return []
    unique = list(dict.fromkeys(words))
    unique.sort(key=lambda w: (-len(w), w))  # long, distinctive words first
    index = _pattern_index()
    solutions: list[dict[str, str]] = []
    start = time.time()

    def rec(mapping: dict[str, str], used: dict[str, str], pending: list[str]):
        if len(solutions) >= max_solutions or time.time() - start > time_limit:
            return
        best_word, best_cands = None, None
        still: list[str] = []
        for cw in pending:
            cands = _candidate_words(cw, mapping, used, index)
            if not cands:
                continue  # no consistent dictionary word: leave it alone
            still.append(cw)
            if best_cands is None or len(cands) < len(best_cands):
                best_word, best_cands = cw, cands
        if best_word is None:
            solutions.append(dict(mapping))
            return
        rest = [w for w in still if w != best_word]
        for pw in best_cands:
            m2, u2 = dict(mapping), dict(used)
            ok = True
            for c, p in zip(best_word, pw):
                if m2.get(c, p) != p or u2.get(p, c) != c:
                    ok = False
                    break
                m2[c] = p
                u2[p] = c
            if ok:
                rec(m2, u2, rest)
                if len(solutions) >= max_solutions or time.time() - start > time_limit:
                    return

    rec({}, {}, unique)
    return solutions


def _frequency_key(data: str) -> str:
    """Initial key from letter frequency, mapping commonest cipher -> etaion..."""
    counts = {c: 0 for c in ALPHABET}
    for c in data.lower():
        if c in counts:
            counts[c] += 1
    order = sorted(ALPHABET, key=lambda c: counts[c], reverse=True)
    english = "etaoinshrdlucmfwypvbgkjqxz"
    return "".join(english[order.index(c)] for c in ALPHABET)


def _refine_key(
    data: str, key: str, rng: random.Random, iterations: int, temp0: float, cooling: float
) -> tuple[float, str]:
    current = substitution_score(substitution_decrypt(data, key))
    best_score, best_key = current, key
    temp = temp0
    for _ in range(iterations):
        i, j = rng.randrange(26), rng.randrange(26)
        if i == j:
            continue
        cand = list(key)
        cand[i], cand[j] = cand[j], cand[i]
        cand_key = "".join(cand)
        score = substitution_score(substitution_decrypt(data, cand_key))
        if score >= current or rng.random() < math.exp((score - current) / max(temp, 1e-9)):
            key, current = cand_key, score
            if score > best_score:
                best_score, best_key = score, cand_key
        temp *= cooling
    return best_score, best_key


def substitution_hillclimb(
    data: str,
    restarts: int = 8,
    iterations: int = 4000,
    seed: int | None = None,
    temp0: float = 0.5,
    cooling: float = 0.9997,
) -> list[tuple[float, str, str]]:
    """Solve a substitution cipher: dictionary shapes first, then refine.

    The pattern solver usually snaps most of the key into place on English
    text with preserved word boundaries; annealing fills in letters that no
    dictionary word constrains. Returns (score, key, plaintext) best first.
    """
    rng = random.Random(seed)
    data_l = data.lower()
    seeds: list[str] = []
    for mapping in substitution_pattern_solve(data_l, max_solutions=restarts * 8, time_limit=4.0):
        seeds.append("".join(mapping.get(c, c) for c in ALPHABET))
    seeds.append(_frequency_key(data_l))
    for _ in range(2):
        perm = list(ALPHABET)
        rng.shuffle(perm)
        seeds.append("".join(perm))
    # keep the most promising distinct seeds
    scored = sorted(
        ((substitution_score(substitution_decrypt(data_l, k)), k) for k in set(seeds)),
        reverse=True,
    )
    results = []
    for _, key in scored[:restarts]:
        best_score, best_key = _refine_key(data_l, key, rng, iterations, temp0, cooling)
        results.append((best_score, best_key, substitution_decrypt(data, best_key)))
    return sorted(results, reverse=True)


# --------------------------------------------------------------------------
# single-byte / repeating-key XOR
# --------------------------------------------------------------------------


def single_byte_xor_bruteforce(data: bytes) -> list[tuple[float, int, bytes]]:
    out = []
    for k in range(256):
        pt = bytes(c ^ k for c in data)
        out.append((english_score(pt), k, pt))
    return sorted(out, reverse=True)


# Fast per-byte unigram score, used when evaluating thousands of keys.
_BYTE_LOG: list[float] = []
for _b in range(256):
    _ch = chr(_b).lower()
    if _ch in ENGLISH_LETTER_FREQ:
        _BYTE_LOG.append(math.log(ENGLISH_LETTER_FREQ[_ch] / 100.0 + 1e-12))
    elif _ch == " ":
        _BYTE_LOG.append(math.log(0.17))
    elif _ch in "\n\r\t":
        _BYTE_LOG.append(math.log(0.02))
    elif 32 <= _b < 127:
        _BYTE_LOG.append(math.log(0.002))
    else:
        _BYTE_LOG.append(math.log(1e-6))


def _fast_byte_score(data: bytes) -> float:
    if not data:
        return -1e9
    return sum(_BYTE_LOG[b] for b in data) / len(data)


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def _xor_keylen_score(data: bytes, keylen: int) -> float:
    chunks = [data[i : i + keylen] for i in range(0, len(data), keylen)]
    chunks = [c for c in chunks if len(c) == keylen]
    if len(chunks) < 2:
        return float("inf")
    pairs = list(itertools.combinations(chunks[:8], 2))
    return sum(hamming(a, b) / keylen for a, b in pairs) / len(pairs)


def repeating_xor_bruteforce(
    data: bytes, max_keylen: int = 40
) -> list[tuple[float, bytes, bytes]]:
    """Try every key length and rank the resulting plaintexts.

    Every length is evaluated (not just the Hamming-distance favourites)
    because short texts make the key-length statistic noisy; the full
    plaintext score is the reliable signal. A small per-byte penalty prefers
    the shortest key when a multiple of it decrypts identically.
    """
    out = []
    for keylen in range(1, max_keylen + 1):
        key = bytearray()
        for col in range(keylen):
            column = data[col::keylen]
            best_k, best_score = 0, -1e18
            for k in range(256):
                score = _fast_byte_score(bytes(c ^ k for c in column))
                if score > best_score:
                    best_score, best_k = score, k
            key.append(best_k)
        key_b = bytes(key)
        pt = repeating_key_xor(data, key_b)
        out.append((english_score(pt) - 0.02 * keylen, key_b, pt))
    return sorted(out, reverse=True)


# --------------------------------------------------------------------------
# encodings often wrapped around classical puzzles
# --------------------------------------------------------------------------

MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-..-.": "/", "-....-": "-", ".--.-.": "@",
}


def morse_decode(data: str, sep: str = " ", wordsep: str = "/") -> str:
    words = data.strip().replace(wordsep, "|").split("|")
    out = []
    for word in words:
        letters = [MORSE.get(code, "?") for code in word.split(sep) if code]
        out.append("".join(letters))
    return " ".join(out)


def bacon_decode(data: str, variant: str = "ab") -> str:
    text = "".join(c.lower() for c in data if c.isalpha())
    if variant == "ab":
        groups = [text[i : i + 5] for i in range(0, len(text) - 4, 5)]
        out = []
        for g in groups:
            bits = "".join("0" if c == "a" else "1" for c in g)
            out.append(chr(int(bits, 2) + 65))
        return "".join(out)
    # 0/1 variant
    bits = "".join("0" if c == "0" else "1" for c in data if c in "01")
    return "".join(chr(int(bits[i : i + 5], 2) + 65) for i in range(0, len(bits) - 4, 5))


def playfair_decrypt(data: str, key: str) -> str:
    """Decrypt a Playfair cipher (I/J combined, no padding removal)."""
    seen = []
    for c in re.sub(r"[^a-z]", "", key.lower().replace("j", "i")):
        if c not in seen:
            seen.append(c)
    for c in "abcdefghiklmnopqrstuvwxyz":
        if c not in seen:
            seen.append(c)
    grid = [seen[i : i + 5] for i in range(0, 25, 5)]
    pos = {c: (r, c_) for r, row in enumerate(grid) for c_, c in enumerate(row)}

    def decrypt_pair(a: str, b: str) -> str:
        if a not in pos:
            a = "i" if a == "j" else a
        if b not in pos:
            b = "i" if b == "j" else b
        if a not in pos or b not in pos:
            return a + b
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            return grid[ra][(ca - 1) % 5] + grid[rb][(cb - 1) % 5]
        if ca == cb:
            return grid[(ra - 1) % 5][ca] + grid[(rb - 1) % 5][cb]
        return grid[ra][cb] + grid[rb][ca]

    letters = re.sub(r"[^a-z]", "", data.lower().replace("j", "i"))
    out = []
    for i in range(0, len(letters) - 1, 2):
        out.append(decrypt_pair(letters[i], letters[i + 1]))
    return "".join(out)


# --------------------------------------------------------------------------
# convenience: try everything and surface flags
# --------------------------------------------------------------------------

def try_classical(data: str) -> list[tuple[str, str]]:
    """Run the common letter-cipher solvers and return (attack, plaintext)."""
    out = []
    for score, shift, text in caesar_bruteforce(data)[:2]:
        out.append((f"caesar shift {shift}", text))
    for score, a, b, text in affine_bruteforce(data)[:2]:
        out.append((f"affine a={a} b={b}", text))
    for score, key, text in vigenere_bruteforce(data, max_keylen=12)[:3]:
        out.append((f"vigenere key={key}", text))
    for score, rails, text in rail_fence_bruteforce(data)[:2]:
        out.append((f"rail fence rails={rails}", text))
    for score, key, text in substitution_hillclimb(data, restarts=4, iterations=2000)[:2]:
        out.append((f"substitution key={key}", text))
    for score, perm, text in columnar_bruteforce(data, max_cols=6)[:2]:
        out.append((f"columnar perm={perm}", text))
    out.append(("atbash", atbash(data)))
    out.append(("rot47", rot47(data)))
    if data.strip().startswith((".", "-")) or "-" in data:
        out.append(("morse", morse_decode(data)))
    out.append(("bacon", bacon_decode(data)))
    return out


def find_all_flags(candidates: list[tuple[str, str]]) -> list[tuple[str, str, list[str]]]:
    out = []
    for name, text in candidates:
        flags = find_flags(text)
        if flags:
            out.append((name, text, flags))
    return out
