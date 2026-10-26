"""Challenge intake: inventory files, extract signals, rank attack hypotheses.

Usage:
    python intake.py <challenge-dir-or-file> [--json] [--max-bytes N]

This is deliberately heuristic. Its job is to make the first five minutes of
a crypto challenge mechanical: what files exist, what numbers are given, what
the flag format is, whether there is a service, which primitives are visible,
and which attack families deserve attention first. It never executes challenge
code.
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

from ctfkit.util import (  # noqa: E402
    detect_flag_regex,
    find_flags,
    parse_named_ints,
)

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode"}
TEXT_EXT = {
    ".txt", ".py", ".sage", ".md", ".json", ".yaml", ".yml", ".csv", ".log",
    ".pem", ".pub", ".key", ".crt", ".ini", ".cfg", ".toml", ".html", ".js",
    ".sh", ".bat", ".ps1", ".tex", ".rst",
}
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE executable"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"SQLite format 3", "SQLite database"),
    (b"-----BEGIN", "PEM key/certificate"),
    (b"\x00asm", "WebAssembly"),
]

HINT_MAP = {
    "rsa": ["rsa", "modulus", "public exponent", "private exponent"],
    "wiener": ["wiener", "small d", "continued fraction"],
    "hastad": ["hastad", "håstad", "broadcast", "same message"],
    "coppersmith": ["coppersmith", "small root", "known high bits", "partial p", "stereotyped"],
    "fermat": ["fermat", "close primes", "consecutive primes"],
    "common modulus": ["common modulus"],
    "common factor": ["common factor", "shared prime", "batch gcd"],
    "oracle": ["oracle", "padding valid", "valid padding", "query"],
    "lsb": ["lsb", "parity", "least significant bit", "even/odd"],
    "pkcs": ["pkcs", "v1.5", "bleichenbacher", "manger", "oaep"],
    "fault": ["fault", "faulty", "crt fault"],
    "ecb": ["ecb", "electronic codebook"],
    "cbc": ["cbc", "cipher block chaining"],
    "ctr": ["ctr", "counter mode"],
    "gcm": ["gcm", "ghash", "aead"],
    "padding": ["padding", "pkcs#7", "pkcs7"],
    "nonce": ["nonce reuse", "iv reuse", "same nonce", "reused nonce", "nonce is reused"],
    "ecdsa": ["ecdsa", "signature", "signing", "nonce reuse"],
    "dsa": ["dsa", "digital signature"],
    "ecc": ["elliptic", "curve", "ecc", "secp", "ed25519", "x25519"],
    "singular": ["singular", "discriminant", "smart", "anomalous"],
    "pohlig": ["pohlig", "smooth order", "small subgroup", "bsgs"],
    "dh": ["diffie", "dh ", "key exchange", "shared secret", "smooth", "pohlig", "subgroup"],
    "hnp": ["hnp", "hidden number", "biased nonce", "partial nonce", "leaked nonce", "known msb", "known lsb", "nonce bits"],
    "lattice": ["lattice", "lll", "bkz", "cvp", "svp", "coppersmith"],
    "lwe": ["lwe", "ring-lwe", "module-lwe", "ntru", "kyber", "ml-kem"],
    "pq": ["dilithium", "ml-dsa", "falcon", "post-quantum", "kyber", "ml-kem"],
    "prng": ["prng", "pseudo-random", "pseudorandom", "mersenne", "mt19937", "lcg", "xorshift", "seed", "randcrack"],
    "lcg": ["lcg", "linear congruential", "congruential"],
    "mt": ["mt19937", "mersenne", "twister", "randcrack"],
    "java": ["java.util.random", "java random", "nextint", "nextlong", "new random("],
    "v8": ["v8", "xorshift128", "math.random"],
    "crand": ["srand", "rand()", "glibc rand", "msvcrt rand"],
    "hash": ["hash", "digest", "sha256", "sha1", "md5", "mac", "hmac"],
    "length extension": ["length extension", "secret ||", "secret + "],
    "classical": [
        "caesar", "vigenere", "vigenère", "substitution", "transposition",
        "rail fence", "xor", "repeating key", "repeating-key", "polyalphabetic",
        "kasiski", "key length", "monoalphabetic", "playfair", "bacon",
        "morse", "rot13", "atbash", "columnar",
    ],
    "zkp": ["zkp", "zero-knowledge", "zero knowledge", "commitment", "fiat-shamir", "sigma protocol", "groth16", "secret sharing"],
    "shamir": ["shamir", "secret sharing"],
    "paillier": ["paillier", "homomorphic"],
    "elgamal": ["elgamal", "el gamal"],
    "goldwasser": ["goldwasser", "micali"],
    "rabin": ["rabin"],
    "lfsr": ["lfsr", "linear feedback", "berlekamp"],
    "rc4": ["rc4", "arc4"],
    "chacha": ["chacha", "poly1305"],
    "xor": ["xor", "one-time pad", "otp", "many-time pad"],
}

FLAG_PATTERNS = [
    r"flag\{[^}\r\n]{1,200}\}",
    r"FLAG\{[^}\r\n]{1,200}\}",
    r"ctf\{[^}\r\n]{1,200}\}",
    r"picoCTF\{[^}\r\n]{1,200}\}",
    r"DASCTF\{[^}\r\n]{1,200}\}",
    r"NSSCTF\{[^}\r\n]{1,200}\}",
    r"HTB\{[^}\r\n]{1,200}\}",
    r"DUCTF\{[^}\r\n]{1,200}\}",
    r"idek\{[^}\r\n]{1,200}\}",
    r"[A-Za-z0-9_]{2,32}\{[^}\r\n]{1,200}\}",
]


def file_kind(path: str) -> tuple[str, bytes]:
    try:
        with open(path, "rb") as fh:
            head = fh.read(32)
    except OSError:
        return "unreadable", b""
    for magic, name in MAGIC:
        if head.startswith(magic):
            return name, head
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXT:
        return "text", head
    if not head:
        return "empty", head
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(head) > 0.9:
        return "text", head
    return "binary", head


def walk(path: str):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            yield os.path.join(root, name)


def read_text_file(path: str, max_bytes: int) -> str | None:
    kind, _ = file_kind(path)
    if kind != "text" and not path.lower().endswith(tuple(TEXT_EXT)):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes)
    except OSError:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def detect_encodings(text: str) -> list[str]:
    found = []
    stripped = text.strip()
    tokens = re.split(r"\s+", stripped)
    long_tokens = [t for t in tokens if len(t) >= 16]

    def is_hex(t: str) -> bool:
        return (
            bool(re.fullmatch(r"[0-9a-fA-F]+", t))
            and len(t) % 2 == 0
            and bool(re.search(r"[a-fA-F]", t))
        )

    def is_b64(t: str) -> bool:
        if not (re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) and len(t) % 4 == 0):
            return False
        if not re.search(r"[A-Za-z+/=]", t):
            return False  # long decimal numbers are not base64
        try:
            dec = base64.b64decode(t, validate=True)
        except Exception:
            return False
        return bool(dec) and all(32 <= b < 127 or b in (9, 10, 13) for b in dec)

    if long_tokens and all(is_hex(t) for t in long_tokens):
        found.append("hex")
    if long_tokens and all(is_b64(t) for t in long_tokens):
        found.append("base64")
    if long_tokens and all(re.fullmatch(r"[A-Z2-7]+={0,6}", t) and len(t) % 8 == 0 for t in long_tokens):
        found.append("base32")
    if stripped and set(stripped) <= set(".-/ \n\t") and "-" in stripped:
        found.append("morse")
    if stripped and set(stripped.replace(" ", "").replace("\n", "")) <= {"0", "1"}:
        found.append("binary")
    return sorted(set(found))


def service_hint(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r"\b(?:nc|ncat|netcat|socat)\s+(?:tcp:)?([A-Za-z0-9_.-]+)\s+(\d{2,5})", text, re.I):
        out.append({"host": m.group(1), "port": int(m.group(2)), "raw": m.group(0)})
    for m in re.finditer(r"https?://[^\s)\]>\"']+", text, re.I):
        out.append({"url": m.group(0)})
    for m in re.finditer(r"\b([A-Za-z0-9.-]+):(\d{2,5})\b", text):
        host, port = m.group(1), int(m.group(2))
        if host not in ("http", "https") and not any(s.get("host") == host and s.get("port") == port for s in out):
            out.append({"host": host, "port": port, "raw": m.group(0)})
    return out


def bitlen(v: int) -> int:
    return abs(v).bit_length()


def named_params(text: str) -> dict[str, list[int]]:
    # Preserve case: DH uses A/B, ECC uses a/b. Lowercasing would conflate them.
    return parse_named_ints(text)


def add(hyp: dict, name: str, score: int, reason: str, attack: str | None = None, ref: str | None = None):
    h = hyp.setdefault(
        name, {"name": name, "score": 0, "reasons": [], "attacks": [], "refs": []}
    )
    h["score"] += score
    if reason not in h["reasons"]:
        h["reasons"].append(reason)
    if attack and attack not in h["attacks"]:
        h["attacks"].append(attack)
    if ref and ref not in h["refs"]:
        h["refs"].append(ref)


def analyze(path: str, max_bytes: int = 2_000_000) -> dict:
    files = []
    text_parts = []
    for fp in sorted(walk(path)):
        try:
            size = os.path.getsize(fp)
        except OSError:
            continue
        kind, head = file_kind(fp)
        files.append(
            {
                "path": os.path.relpath(fp, path) if os.path.isdir(path) else os.path.basename(fp),
                "size": size,
                "kind": kind,
                "head_hex": head[:16].hex(),
            }
        )
        content = read_text_file(fp, max_bytes)
        if content:
            text_parts.append(f"\n### FILE: {os.path.basename(fp)}\n" + content)

    text = "\n".join(text_parts)
    low = text.lower()
    named = named_params(text)
    hints = {name: [kw for kw in kws if kw in low] for name, kws in HINT_MAP.items()}
    hints = {k: v for k, v in hints.items() if v}
    flag_fmt = detect_flag_regex(text)
    flags = []
    for pat in FLAG_PATTERNS:
        flags.extend(re.findall(pat, text))
    flags = sorted(set(flags))
    services = service_hint(text)
    encodings = detect_encodings(text)
    numeric_lines = len(re.findall(r"(?m)^\s*\d{2,}\s*$", text))

    hyp: dict[str, dict] = {}

    # Case-aware lookup: exact match first, then a unique case-insensitive
    # match. This keeps DH's A/B distinct from ECC's a/b.
    def _ci(name):
        keys = [k for k in named if k.lower() == name.lower()]
        return keys[0] if len(keys) == 1 else None

    def has(*names):
        return all((n in named) or (_ci(n) is not None) for n in names)

    def any_has(*names):
        return any((n in named) or (_ci(n) is not None) for n in names)

    def val(name, default=None):
        key = name if name in named else _ci(name)
        return named[key][0] if key and named[key] else default

    def has_prefix(prefix: str) -> bool:
        return any(k.lower().startswith(prefix.lower()) for k in named)

    hint = lambda *names: any(hints.get(n) for n in names)
    ref = lambda r: f"references/{r}.md"

    # ---------------- RSA ----------------
    if has("n") and any_has("e", "c"):
        add(hyp, "RSA", 6, "n and e/c present", "factor n / standard RSA decrypt", ref("rsa"))
        n = val("n")
        e = val("e")
        if e is not None:
            if e <= 5:
                add(hyp, "RSA", 3, f"small e={e}", "exact e-th root / Hastad broadcast", ref("rsa"))
            if n and bitlen(e) > bitlen(n) * 0.8:
                add(hyp, "RSA", 4, "public exponent is unusually large", "Wiener continued fractions", ref("rsa"))
            if e == 1:
                add(hyp, "RSA", 4, "e = 1", "signature/modulus bypass", ref("rsa"))
        if n and bitlen(n) <= 512:
            add(hyp, "RSA", 3, f"small {bitlen(n)}-bit modulus", "trial division / rho / Fermat", ref("rsa"))
        elif n and bitlen(n) <= 1024:
            add(hyp, "RSA", 1, f"{bitlen(n)}-bit modulus; check for weak primes or leaks", "rho / p-1 / Fermat", ref("rsa"))
        if has("p", "q"):
            add(hyp, "RSA", 6, "p and q are given", "compute phi and decrypt", ref("rsa"))
        if any_has("phi", "d", "dp", "dq", "qinv"):
            add(hyp, "RSA", 6, "private material leaked", "factor from phi/d/dp/dq", ref("rsa"))
        if any_has("p_high", "unknown_low_bits", "p_bits", "high_bits"):
            add(hyp, "RSA", 6, "partial p leak", "Coppersmith partial factor", ref("lattice"))
        ns = named.get("n", [])
        cs = named.get("c", [])
        if len(ns) >= 2 or len(cs) >= 2:
            add(hyp, "RSA", 4, "multiple moduli/ciphertexts", "common modulus / common factor / Hastad", ref("rsa"))
        if hint("coppersmith", "small root"):
            add(hyp, "RSA", 5, "hint mentions Coppersmith/small roots", "small_roots lattice", ref("lattice"))
        if hint("wiener"):
            add(hyp, "RSA", 6, "hint mentions Wiener", "continued fractions", ref("rsa"))
        if hint("hastad"):
            add(hyp, "RSA", 6, "hint mentions Hastad/broadcast", "CRT + e-th root", ref("rsa"))
        if hint("fermat"):
            add(hyp, "RSA", 5, "hint mentions Fermat/close primes", "Fermat factorization", ref("rsa"))
        if hint("fault"):
            add(hyp, "RSA", 5, "hint mentions faults", "CRT fault attack (gcd)", ref("rsa"))
        if hint("lsb", "oracle"):
            add(hyp, "RSA", 5, "oracle/parity hint", "LSB parity oracle / Manger / Bleichenbacher", ref("rsa"))
        if hint("pkcs"):
            add(hyp, "RSA", 5, "PKCS#1 v1.5/OAEP hint", "Bleichenbacher or Manger oracle", ref("rsa"))

    # ---------------- ECC ----------------
    # Require exact lowercase curve coefficients a,b (DH uses uppercase A,B)
    # or explicit curve point parameters.
    ecc_curve = ("a" in named and "b" in named) or any_has("gx", "gy") or hint("ecc")
    if has("p") and ecc_curve and (any_has("gx", "gy", "g") or has("x", "y")):
        add(hyp, "ECC", 6, "curve parameters present", "curve arithmetic / DLP", ref("ecc"))
        px, py = val("x"), val("y")
        if px is not None and py is not None:
            add(hyp, "ECC", 1, "a point is given", "check point is on the curve", ref("ecc"))
    if hint("ecc", "ecdsa", "dsa"):
        add(hyp, "ECC", 5, "hint mentions ECC/ECDSA/DSA", "curve/ECDSA attacks", ref("ecc"))
    sig_present = (
        (any_has("r", "s", "s1", "s2") and any_has("z", "z1", "z2", "h"))
        or (has_prefix("r") and has_prefix("s"))
    )
    if sig_present:
        add(hyp, "ECC", 5, "signature values present", "ECDSA/DSA nonce reuse or biased nonce", ref("ecc"))
    if any(k.lower().startswith(("k_msb", "k_lsb", "leaked", "nonce_msb", "nonce_lsb")) for k in named) or (
        "unknown_low_bits" in named and sig_present
    ):
        add(hyp, "ECC", 6, "nonce bits leaked", "HNP lattice (biased/partial nonce)", ref("ecc"))
    if hint("hnp"):
        add(hyp, "ECC", 6, "hint mentions HNP/biased nonce", "HNP lattice", ref("ecc"))
    if hint("singular", "pohlig"):
        add(hyp, "ECC", 5, "hint mentions singular/smooth order", "singular curve / Pohlig-Hellman", ref("ecc"))

    # ---------------- DH ----------------
    dh_pub = ("A" in named) or ("B" in named) or any_has("ga", "gb", "pa", "pb", "ya", "yb")
    if has("p", "g") and dh_pub:
        add(hyp, "DH", 5, "p, g and public values present", "DLP / small subgroup / PH", ref("dh"))
        p_val = val("p")
        if p_val and p_val.bit_length() <= 512:
            try:
                import sympy as sp

                fac = sp.factorint(p_val - 1, limit=1_000_000)
                largest = max(fac) if fac else 1
                if largest.bit_length() <= 40:
                    add(
                        hyp,
                        "DH",
                        4,
                        f"p-1 is smooth (largest factor {largest})",
                        "Pohlig-Hellman",
                        ref("dh"),
                    )
            except Exception:
                pass
    if hint("dh"):
        add(hyp, "DH", 5, "hint mentions Diffie-Hellman", "trivial g / PH / Lim-Lee", ref("dh"))

    # ---------------- Symmetric ----------------
    if any_has("iv", "nonce", "ct", "ciphertext", "key") or hint("ecb", "cbc", "ctr", "gcm", "padding"):
        add(hyp, "Symmetric", 4, "ciphertext/key/IV material present", "mode-specific attack", ref("symmetric"))
        if hint("ecb"):
            add(hyp, "Symmetric", 5, "ECB hint", "duplicate blocks / byte-at-a-time", ref("symmetric"))
        if hint("cbc"):
            add(hyp, "Symmetric", 4, "CBC hint", "bit flipping / padding oracle", ref("symmetric"))
        if hint("gcm"):
            add(hyp, "Symmetric", 5, "GCM hint", "nonce reuse (forbidden attack)", ref("symmetric"))
        if hint("ctr"):
            add(hyp, "Symmetric", 4, "CTR hint", "keystream reuse / bit flip", ref("symmetric"))
        if hint("padding", "oracle"):
            add(hyp, "Symmetric", 5, "padding oracle hint", "byte-at-a-time CBC decryption", ref("symmetric"))
        for name, values in named.items():
            if name in ("ct", "ciphertext") and values:
                hexstr = "".join(format(v, "x") for v in values)
                if len(hexstr) % 32 == 0 and len(hexstr) >= 64:
                    add(hyp, "Symmetric", 1, "ciphertext is a multiple of 16 bytes", "check AES block mode", ref("symmetric"))

    # ---------------- PRNG ----------------
    if hint("prng", "lcg", "mt"):
        add(hyp, "PRNG", 5, "PRNG/randomness hint", "recover state and predict", ref("prng"))
        if hint("lcg"):
            add(hyp, "PRNG", 4, "LCG hint", "recover a,c,m from outputs", ref("prng"))
        if hint("mt"):
            add(hyp, "PRNG", 5, "MT19937 hint", "untemper 624 outputs", ref("prng"))
        if hint("java"):
            add(hyp, "PRNG", 5, "Java Random hint", "recover 48-bit LCG seed", ref("prng"))
        if hint("v8"):
            add(hyp, "PRNG", 4, "V8 Math.random hint", "XorShift128+ state recovery (Z3)", ref("prng"))
        if hint("crand"):
            add(hyp, "PRNG", 4, "C rand/srand hint", "libc srand/rand synchronization", ref("prng"))
    for name in ("outputs", "randoms", "states", "xs", "nums"):
        if len(named.get(name, [])) >= 6:
            add(hyp, "PRNG", 4, f"{len(named[name])} sequence values named {name}", "LCG/MT/PRNG recovery", ref("prng"))

    # Unnamed sequences: one integer per line (e.g. outputs.txt).
    if numeric_lines >= 624:
        add(hyp, "PRNG", 9, f"{numeric_lines} standalone integer outputs", "MT19937 clone (624 outputs)", ref("prng"))
    elif numeric_lines >= 8:
        add(hyp, "PRNG", 3, f"{numeric_lines} standalone integer outputs", "LCG/MT/PRNG recovery", ref("prng"))

    # ---------------- Hash ----------------
    if hint("length extension"):
        add(hyp, "Hash", 6, "length-extension hint", "Merkle-Damgard extension", ref("hash"))
    if hint("hash") and any_has("digest", "mac", "tag", "h"):
        add(hyp, "Hash", 3, "digest/MAC material present", "length extension / collision / MAC forgery", ref("hash"))
    if hint("classical") and not has("n") and numeric_lines < 8:
        add(hyp, "Classical", 4, "classical cipher hint", "frequency analysis / known plaintext", ref("classical"))

    # ---------------- Lattice / PQ / ZKP / Exotic ----------------
    if hint("lattice", "lwe"):
        add(hyp, "Lattice", 5, "lattice/LWE hint", "LLL/Coppersmith/CVP", ref("lattice"))
    if hint("pq"):
        add(hyp, "Post-quantum", 5, "post-quantum hint", "ML-KEM/ML-DSA/Falcon weaknesses", ref("post-quantum"))
    if hint("zkp", "shamir"):
        add(hyp, "ZKP/SSS", 5, "proof/secret-sharing hint", "Fiat-Shamir / Shamir / constraint solving", ref("zkp"))
    if hint("paillier", "elgamal", "goldwasser", "rabin"):
        add(hyp, "Exotic", 5, "exotic public-key hint", "homomorphic/oracle attacks", ref("exotic"))
    if hint("lfsr", "rc4", "chacha"):
        add(hyp, "Stream", 5, "stream cipher hint", "LFSR/RC4/ChaCha attacks", ref("stream"))

    # Prose-like text suggests a classical/encoding layer, but source code
    # should not trigger it.
    letters = sum(c.isalpha() for c in text)
    digits = sum(c.isdigit() for c in text)
    spaces = text.count(" ")
    code_marks = sum(text.count(ch) for ch in ";=(){}[]")
    if letters > 200 and spaces > 20 and digits < letters * 0.2 and code_marks < 30:
        add(
            hyp,
            "Classical",
            2,
            "large printable prose-like text",
            "classical cipher / encoding layers",
            ref("classical"),
        )

    ordered = sorted(hyp.values(), key=lambda h: (-h["score"], h["name"]))
    for h in ordered:
        h["confidence"] = "high" if h["score"] >= 9 else "medium" if h["score"] >= 5 else "low"

    return {
        "path": os.path.abspath(path),
        "files": files,
        "flag_format": flag_fmt,
        "flags_found_in_files": flags[:20],
        "services": services,
        "named_integers": {
            k: [{"value": v, "bits": bitlen(v)} for v in vals[:8]] for k, vals in named.items()
        },
        "encodings": encodings,
        "hint_keywords": hints,
        "hypotheses": ordered,
        "text_chars": len(text),
    }


def format_report(r: dict) -> str:
    lines = [f"# Challenge intake: {r['path']}", ""]
    lines.append("## Files")
    if not r["files"]:
        lines.append("- (none)")
    for f in r["files"][:40]:
        lines.append(f"- `{f['path']}` - {f['size']} bytes, {f['kind']}")
    if len(r["files"]) > 40:
        lines.append(f"- ... {len(r['files']) - 40} more")

    lines += ["", "## Signals"]
    lines.append(f"- Flag format: `{r['flag_format']}`" if r["flag_format"] else "- Flag format: not stated (try `flag{...}` / any `\\w+{...}`)")
    if r["flags_found_in_files"]:
        lines.append(f"- Flags/flag-like strings in files: {', '.join(r['flags_found_in_files'][:5])}")
        lines.append("- Note: literals inside source files may be placeholders or decoys; submit only a flag you derived.")
    if r["services"]:
        for s in r["services"][:5]:
            if "url" in s:
                lines.append(f"- Service URL: {s['url']}")
            else:
                lines.append(f"- Service: `nc {s.get('host')} {s.get('port')}`")
    if r["named_integers"]:
        parts = []
        for name, vals in list(r["named_integers"].items())[:18]:
            v = vals[0]
            shown = str(v["value"]) if v["bits"] < 128 else f"{v['bits']}-bit"
            parts.append(f"`{name}`={shown}")
        lines.append("- Named integers: " + ", ".join(parts))
    if r["encodings"]:
        lines.append("- Encodings detected: " + ", ".join(r["encodings"]))
    if r["hint_keywords"]:
        kws = ", ".join(f"{k}({', '.join(v[:2])})" for k, v in list(r["hint_keywords"].items())[:12])
        lines.append("- Hint keywords: " + kws)

    lines += ["", "## Ranked hypotheses"]
    if not r["hypotheses"]:
        lines.append("- No strong hypothesis. Read the challenge source line by line; look for a combined weakness.")
    for i, h in enumerate(r["hypotheses"][:5], 1):
        lines.append(f"{i}. **{h['name']}** ({h['confidence']}, score {h['score']})")
        lines.append("   - Why: " + "; ".join(h["reasons"]))
        if h["attacks"]:
            lines.append("   - Try: " + "; ".join(h["attacks"]))
        if h["refs"]:
            lines.append("   - Read: " + ", ".join(h["refs"]))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="CTF crypto challenge intake")
    ap.add_argument("path", help="challenge directory or file")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--max-bytes", type=int, default=2_000_000)
    args = ap.parse_args()
    report = analyze(args.path, args.max_bytes)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
