"""Block cipher mode attacks: ECB/CBC/CTR.

AES primitives use pycryptodome when installed. Every *attack* helper works
against an oracle callable you supply, so it does not matter whether the
challenge is local or remote -- wrap the network in a lambda and pass it in.
"""

from __future__ import annotations

from typing import Callable

# --------------------------------------------------------------------------
# padding
# --------------------------------------------------------------------------


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - len(data) % block_size
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------
# AES primitives (pycryptodome)
# --------------------------------------------------------------------------


def _aes():
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "AES primitives need pycryptodome (`pip install pycryptodome`); "
            "the mode attacks themselves only need an oracle callable"
        ) from exc
    return AES


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    return _aes().new(key, _aes().MODE_ECB).encrypt(pkcs7_pad(data))


def aes_ecb_decrypt(data: bytes, key: bytes, unpad: bool = True) -> bytes:
    out = _aes().new(key, _aes().MODE_ECB).decrypt(data)
    return pkcs7_unpad(out) if unpad else out


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    return _aes().new(key, _aes().MODE_CBC, iv).encrypt(pkcs7_pad(data))


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    out = _aes().new(key, _aes().MODE_CBC, iv).decrypt(data)
    return pkcs7_unpad(out) if unpad else out


def aes_ctr_keystream(length: int, key: bytes, nonce: bytes = b"", counter: int = 0) -> bytes:
    """AES-CTR keystream with a big-endian counter."""
    aes = _aes()
    out = b""
    blk = len(nonce) + 8
    while len(out) < length:
        block = nonce + counter.to_bytes(8, "big")
        out += aes.new(key, aes.MODE_ECB).encrypt(block)
        counter += 1
    return out[:length]


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes = b"", counter: int = 0) -> bytes:
    return xor_bytes(data, aes_ctr_keystream(len(data), key, nonce, counter))


# --------------------------------------------------------------------------
# ECB detection and byte-at-a-time decryption
# --------------------------------------------------------------------------


def count_duplicate_blocks(data: bytes, block_size: int = 16) -> int:
    blocks = [data[i : i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
    return len(blocks) - len(set(blocks))


def detect_ecb(data: bytes, block_size: int = 16) -> bool:
    """ECB shows repeated ciphertext blocks for repeated plaintext blocks."""
    return count_duplicate_blocks(data, block_size) > 0


def detect_block_size(oracle: Callable[[bytes], bytes], max_size: int = 64) -> int:
    """Feed growing input until the ciphertext length jumps."""
    base = len(oracle(b""))
    for n in range(1, max_size + 1):
        length = len(oracle(b"A" * n))
        if length > base:
            return length - base
    raise ValueError("could not detect a block size")


def byte_at_a_time_ecb_decrypt(
    oracle: Callable[[bytes], bytes],
    block_size: int = 16,
    max_length: int = 4096,
    prefix_len: int = 0,
) -> bytes:
    """Decrypt an ECB oracle that appends a secret to attacker input.

    `prefix_len` is the number of attacker-controlled bytes needed to align
    the secret to a block boundary when the oracle prepends a fixed prefix;
    leave it at 0 for the common "secret = prefix + your input" challenge.
    """
    known = b""
    # The padded (secret + PKCS#7) length is constant; use it to stop exactly
    # at the end instead of guessing from repeated bytes.
    expected = max(0, len(oracle(b"")) - prefix_len)
    while len(known) < expected and len(known) < max_length:
        block_index = (prefix_len + len(known)) // block_size
        pad_len = block_size - 1 - ((prefix_len + len(known)) % block_size)
        feed = b"A" * pad_len
        target = oracle(feed)
        start = block_index * block_size
        target_block = target[start : start + block_size]
        found = None
        for guess in range(256):
            probe = oracle(feed + known + bytes([guess]))
            if probe[start : start + block_size] == target_block:
                found = guess
                break
        if found is None:
            break
        known += bytes([found])
    try:
        return pkcs7_unpad(known, block_size)
    except ValueError:
        return known[:expected]


# --------------------------------------------------------------------------
# CBC bit flipping
# --------------------------------------------------------------------------


def cbc_bitflip(
    original_prev: bytes, known_plain: bytes, target_plain: bytes
) -> bytes:
    """Craft a previous ciphertext block so a plaintext block changes.

    Works on the block following `original_prev`. Both plaintext arguments
    must be the same length (one block).
    """
    if len(known_plain) != len(target_plain) or len(original_prev) != len(known_plain):
        raise ValueError("blocks must be the same length")
    return xor_bytes(original_prev, xor_bytes(known_plain, target_plain))


# --------------------------------------------------------------------------
# CBC padding oracle
# --------------------------------------------------------------------------


def padding_oracle_attack(
    oracle: Callable[[bytes], bool],
    ciphertext: bytes,
    block_size: int = 16,
    iv: bytes | None = None,
    max_blocks: int | None = None,
) -> bytes:
    """Decrypt CBC ciphertext using a padding-validity oracle.

    `oracle(data) -> bool` must receive the exact byte string the challenge
    decrypts and return True when the padding is valid. If the challenge
    supplies the IV separately and decrypts `iv + ciphertext`, pass the IV as
    `iv`; the helper prepends it and sends the full modified message. If the
    IV is already the first block of `ciphertext`, leave `iv=None`.

    Returns the plaintext of every block after the IV.
    """
    blocks = [bytearray(ciphertext[i : i + block_size]) for i in range(0, len(ciphertext), block_size)]
    full = ([bytearray(iv)] + blocks) if iv is not None else blocks
    if len(full) < 2:
        return b""
    limit = len(full) - 1 if max_blocks is None else min(len(full) - 1, max_blocks)
    plaintext_blocks = []
    for t in range(1, limit + 1):
        original_prev = bytes(full[t - 1])
        intermediate = bytearray(block_size)
        for pad_val in range(1, block_size + 1):
            pos = block_size - pad_val
            crafted = bytearray(original_prev)
            for j in range(pos + 1, block_size):
                crafted[j] = intermediate[j] ^ pad_val
            found = None
            for guess in range(256):
                crafted[pos] = guess
                # Truncate after the target block so the oracle's padding check
                # applies to the block we are attacking, not the real last block.
                trial = list(full[: t + 1])
                trial[t - 1] = crafted
                message = b"".join(bytes(b) for b in trial)
                if not oracle(message):
                    continue
                if pad_val == 1 and pos > 0:
                    # A guess can produce valid padding longer than one byte
                    # (e.g. 0x02 0x02). Real 0x01 padding survives corrupting
                    # the byte before it, because that byte is not padding.
                    test = bytearray(crafted)
                    test[pos - 1] ^= 1
                    trial_test = list(full[: t + 1])
                    trial_test[t - 1] = test
                    if not oracle(b"".join(bytes(b) for b in trial_test)):
                        continue
                found = guess
                break
            if found is None:
                raise ValueError(f"padding oracle failed on block {t}, byte {pos}")
            intermediate[pos] = found ^ pad_val
        plaintext_blocks.append(bytes(intermediate[j] ^ original_prev[j] for j in range(block_size)))
    return b"".join(plaintext_blocks)


# --------------------------------------------------------------------------
# CTR / stream cipher reuse
# --------------------------------------------------------------------------


def ctr_reuse_recover(c1: bytes, p1: bytes, c2: bytes) -> bytes:
    """Recover p2 when a nonce/keystream is reused: p2 = c2 ^ (c1 ^ p1)."""
    keystream = xor_bytes(c1, p1)
    return xor_bytes(c2, keystream[: len(c2)])


def ctr_bitflip(
    ciphertext: bytes, offset: int, known_plaintext: bytes, target_plaintext: bytes
) -> bytes:
    """Change a CTR plaintext region by XORing the corresponding ciphertext.

    CTR has no chaining, so flipping ciphertext bits flips plaintext bits at
    the same position and nothing else.
    """
    delta = xor_bytes(known_plaintext, target_plaintext)
    out = bytearray(ciphertext)
    for i, b in enumerate(delta):
        out[offset + i] ^= b
    return bytes(out)


def recover_keystream(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    return xor_bytes(ciphertext, known_plaintext)


# --------------------------------------------------------------------------
# AES-GCM nonce reuse (forbidden attack)
# --------------------------------------------------------------------------

_MASK128 = (1 << 128) - 1
_GCM_R = 0xE1000000000000000000000000000000


def gmul(x: int, y: int) -> int:
    """GF(2^128) multiplication, NIST SP 800-38D Algorithm 1."""
    z, v = 0, y & _MASK128
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= _GCM_R
    return z & _MASK128


def gpow(a: int, e: int) -> int:
    r = 1 << 127  # multiplicative identity in the NIST bit-reflected encoding
    while e:
        if e & 1:
            r = gmul(r, a)
        a = gmul(a, a)
        e >>= 1
    return r


def ginv(a: int) -> int:
    return gpow(a, (1 << 128) - 2)


def gsqrt(a: int) -> int:
    return gpow(a, 1 << 127)


def _block_int(data: bytes, block_size: int = 16) -> list[int]:
    return [
        int.from_bytes(data[i : i + block_size].ljust(block_size, b"\x00"), "big")
        for i in range(0, len(data), block_size)
    ]


def ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """GHASH_H(aad, ciphertext) as a 128-bit integer."""
    s = 0
    for block in _block_int(aad):
        s = gmul(s ^ block, h)
    for block in _block_int(ciphertext):
        s = gmul(s ^ block, h)
    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    s = gmul(s ^ len_block, h)
    return s


def gcm_recover_h_1block(
    c1: bytes, c2: bytes, t1: bytes, t2: bytes
) -> int | None:
    """Recover GHASH key H from two equal-length one-block GCM messages.

    Same nonce/key and empty AAD:
        T1 ^ T2 = (C1 ^ C2) * H^2
    This is the easy case; multi-block messages need polynomial factoring.
    """
    if len(c1) != 16 or len(c2) != 16:
        raise ValueError("this helper expects 16-byte ciphertexts")
    num = int.from_bytes(t1, "big") ^ int.from_bytes(t2, "big")
    den = int.from_bytes(c1, "big") ^ int.from_bytes(c2, "big")
    if den == 0:
        return None
    return gsqrt(gmul(num, ginv(den)))


def gcm_j0_mask(h: int, aad: bytes, ciphertext: bytes, tag: bytes) -> int:
    """E_K(J0) = tag XOR GHASH_H(aad, ciphertext)."""
    return int.from_bytes(tag, "big") ^ ghash(h, aad, ciphertext)


def gcm_forge_tag(h: int, j0_mask: int, aad: bytes, ciphertext: bytes) -> bytes:
    """Forge a GCM tag once H and E_K(J0) are known (same nonce/key)."""
    return (j0_mask ^ ghash(h, aad, ciphertext)).to_bytes(16, "big")


def gcm_nonce_reuse_forge(
    c1: bytes, t1: bytes, c2: bytes, t2: bytes, aad: bytes = b""
) -> tuple[int, int]:
    """Convenience: recover (H, E_K(J0)) from a one-block nonce reuse."""
    h = gcm_recover_h_1block(c1, c2, t1, t2)
    if h is None:
        return 0, 0
    return h, gcm_j0_mask(h, aad, c1, t1)


# --------------------------------------------------------------------------
# Multi-block forbidden attack (polynomials over GF(2^128))
# --------------------------------------------------------------------------

def _padd(a, b):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out[i] = x ^ y
    return _ptrim(out)


def _ptrim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def _pmul(a, b):
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj:
                out[i + j] ^= gmul(ai, bj)
    return _ptrim(out)


def _pdivmod(a, b):
    a = list(a)
    db = len(b) - 1
    inv = ginv(b[-1])
    q = [0] * max(1, len(a) - db)
    while len(a) - 1 >= db and any(a):
        d = len(a) - 1 - db
        c = gmul(a[-1], inv)
        q[d] = c
        for i in range(len(b)):
            a[d + i] ^= gmul(c, b[i])
        a = _ptrim(a)
        if len(a) == 1 and a[0] == 0:
            break
    return _ptrim(q), _ptrim(a)


def _pmod(a, b):
    return _pdivmod(a, b)[1]


def _pgcd(a, b):
    a, b = _ptrim(list(a)), _ptrim(list(b))
    while len(b) > 1 or (b and b[0] != 0):
        a, b = b, _pmod(a, b)
    # normalize monic
    if a and a[-1] != 0:
        inv = ginv(a[-1])
        a = [gmul(c, inv) for c in a]
    return _ptrim(a)


def _ppowmod(base, exp, mod):
    r = [_GCM_ONE]
    b = _pmod(base, mod)
    while exp:
        if exp & 1:
            r = _pmod(_pmul(r, b), mod)
        b = _pmod(_pmul(b, b), mod)
        exp >>= 1
    return r


# multiplicative identity in the NIST bit-reflected GF(2^128) encoding
_GCM_ONE = 1 << 127


def ghash_poly(aad: bytes, ciphertext: bytes) -> list[int]:
    """GHASH_H(aad, c) as a polynomial in H (low-degree first, over GF(2^128))."""
    blocks = _block_int(aad) + _block_int(ciphertext)
    blocks.append(((len(aad) * 8) << 64) | (len(ciphertext) * 8))
    N = len(blocks)
    # ghash = sum_k blocks[k] * H^(N-k), k=0..N-1  -> degree N .. 1
    coeffs = [0] * (N + 1)
    for k, blk in enumerate(blocks):
        coeffs[N - k] ^= blk
    return _ptrim(coeffs)


def _poly_roots(p: list[int]) -> list[int]:
    """All roots in GF(2^128) of a polynomial p (over GF(2^128))."""
    p = _ptrim([c & _MASK128 for c in p])
    if len(p) <= 1:
        return []
    # R = gcd(p, x^(2^128) - x) = product of distinct linear factors
    xpoly = [0, _GCM_ONE]
    r = _ppowmod(xpoly, 1 << 128, p)     # x^(2^128) mod p
    R = _pgcd(p, _padd(r, xpoly))
    roots = []
    _split_roots(R, roots, 1)
    return roots


def _split_roots(R, out, seed):
    if len(R) <= 1:
        return
    if len(R) == 2:                       # linear: a1*x + a0 -> root a0/a1
        out.append(gmul(R[0], ginv(R[1])))
        return
    # Cantor-Zassenhaus (equal degree 1, q = 2^128)
    delta = seed
    while True:
        cur = _pmod([0, delta & _MASK128], R)       # delta*x mod R
        T = list(cur)
        for _ in range(127):
            cur = _pmod(_pmul(cur, cur), R)
            T = _padd(T, cur)
        g = _pgcd(T, R)
        if 1 < len(g) < len(R):
            q, _rem = _pdivmod(R, g)
            _split_roots(g, out, delta + 1)
            _split_roots(q, out, delta + 2)
            return
        delta += 1
        if delta > 10000:
            raise RuntimeError("root splitting failed")


def gcm_recover_h_multi(
    c1: bytes, t1: bytes, c2: bytes, t2: bytes,
    aad1: bytes = b"", aad2: bytes = b"",
) -> list[int]:
    """Recover candidate H values from two messages encrypted with the SAME
    nonce/key (multi-block allowed). Returns the roots of the tag-difference
    polynomial; the true H is among them (verify with gcm_j0_mask/forge)."""
    P = _padd(ghash_poly(aad1, c1), ghash_poly(aad2, c2))
    P[0] ^= int.from_bytes(t1, "big") ^ int.from_bytes(t2, "big")
    return _poly_roots(P)


def gcm_nonce_reuse_forge_multi(
    c1: bytes, t1: bytes, c2: bytes, t2: bytes,
    aad1: bytes = b"", aad2: bytes = b"",
) -> list[tuple[int, int]]:
    """Return [(H, E_K(J0))] candidates for any-length single-nonce reuse."""
    return [(h, gcm_j0_mask(h, aad1, c1, t1))
            for h in gcm_recover_h_multi(c1, t1, c2, t2, aad1, aad2)]
