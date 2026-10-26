"""Hash length extension for MD5, SHA-1 and SHA-256.

Python's hashlib does not expose the chaining state, so the compression
functions are implemented here. Use this when a challenge authenticates
`secret || message` with a plain Merkle-Damgard hash and you know only the
digest and the secret's length.
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


# --------------------------------------------------------------------------
# MD5
# --------------------------------------------------------------------------

_MD5_S = (
    [7, 12, 17, 22] * 4
    + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4
    + [6, 10, 15, 21] * 4
)
_MD5_K = [int(abs(__import__("math").sin(i + 1)) * 2**32) & MASK32 for i in range(64)]
_MD5_INIT = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]


def _md5_compress(state: list[int], block: bytes) -> list[int]:
    a, b, c, d = state
    m = struct.unpack("<16I", block)
    A, B, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            f = (B & C) | (~B & D)
            g = i
        elif i < 32:
            f = (D & B) | (~D & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            f = C ^ (B | (~D & MASK32))
            g = (7 * i) % 16
        f = (f + A + _MD5_K[i] + m[g]) & MASK32
        A, D, C = D, C, B
        B = (B + _rotl(f, _MD5_S[i])) & MASK32
    return [(a + A) & MASK32, (b + B) & MASK32, (c + C) & MASK32, (d + D) & MASK32]


# --------------------------------------------------------------------------
# SHA-1
# --------------------------------------------------------------------------

_SHA1_INIT = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def _sha1_compress(state: list[int], block: bytes) -> list[int]:
    h0, h1, h2, h3, h4 = state
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b & MASK32) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_rotl(a, 5) + f + e + k + w[i]) & MASK32
        e, d, c, b, a = d, c, _rotl(b, 30), a, temp
    return [
        (h0 + a) & MASK32,
        (h1 + b) & MASK32,
        (h2 + c) & MASK32,
        (h3 + d) & MASK32,
        (h4 + e) & MASK32,
    ]


# --------------------------------------------------------------------------
# SHA-256
# --------------------------------------------------------------------------

_SHA256_INIT = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e & MASK32) & g)
        temp1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & MASK32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & MASK32, c, b, a, (temp1 + temp2) & MASK32
    return [
        (state[0] + a) & MASK32,
        (state[1] + b) & MASK32,
        (state[2] + c) & MASK32,
        (state[3] + d) & MASK32,
        (state[4] + e) & MASK32,
        (state[5] + f) & MASK32,
        (state[6] + g) & MASK32,
        (state[7] + h) & MASK32,
    ]


# --------------------------------------------------------------------------
# generic plumbing
# --------------------------------------------------------------------------

_ALGOS = {
    "md5": {
        "init": _MD5_INIT,
        "compress": _md5_compress,
        "digest_size": 16,
        "word_order": "little",
        "len_order": "little",
    },
    "sha1": {
        "init": _SHA1_INIT,
        "compress": _sha1_compress,
        "digest_size": 20,
        "word_order": "big",
        "len_order": "big",
    },
    "sha256": {
        "init": _SHA256_INIT,
        "compress": _sha256_compress,
        "digest_size": 32,
        "word_order": "big",
        "len_order": "big",
    },
}


def _padding(algo: str, length: int) -> bytes:
    info = _ALGOS[algo]
    bit_len = length * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (length + 1) % 64) % 64)
    pad += bit_len.to_bytes(8, info["len_order"])
    return pad


def _digest_from_state(algo: str, state: list[int]) -> bytes:
    info = _ALGOS[algo]
    return b"".join(v.to_bytes(4, info["word_order"]) for v in state)


def _state_from_digest(algo: str, digest: bytes) -> list[int]:
    info = _ALGOS[algo]
    n = info["digest_size"]
    if len(digest) != n:
        raise ValueError(f"{algo} digest must be {n} bytes")
    return [
        int.from_bytes(digest[i : i + 4], info["word_order"])
        for i in range(0, n, 4)
    ]


def hash_bytes(algo: str, data: bytes) -> bytes:
    """Plain hash using the pure-Python implementation (for self-checks)."""
    algo = algo.lower().replace("-", "")
    info = _ALGOS[algo]
    state = list(info["init"])
    padded = data + _padding(algo, len(data))
    for i in range(0, len(padded), 64):
        state = info["compress"](state, padded[i : i + 64])
    return _digest_from_state(algo, state)


def length_extension(
    algo: str, digest: bytes | str, original_length: int, append: bytes
) -> tuple[bytes, bytes]:
    """Forge H(secret || message || glue || append) from H(secret || message).

    Returns (glue_and_append, new_digest_bytes). The forged message the
    server must hash is `original_message + glue_and_append`; the client only
    needs to send that byte string, not know the secret.
    """
    algo = algo.lower().replace("-", "")
    info = _ALGOS[algo]
    if isinstance(digest, str):
        digest = bytes.fromhex(digest)
    state = _state_from_digest(algo, digest)
    glue = _padding(algo, original_length)
    new_total = original_length + len(glue) + len(append)
    data = append + _padding(algo, new_total)
    for i in range(0, len(data), 64):
        state = info["compress"](state, data[i : i + 64])
    return glue + append, _digest_from_state(algo, state)


def length_extension_hex(
    algo: str, digest_hex: str, original_length: int, append: bytes
) -> tuple[bytes, str]:
    glue, new_digest = length_extension(algo, digest_hex, original_length, append)
    return glue, new_digest.hex()
