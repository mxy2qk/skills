"""RSA attacks.

Every function takes plain integers/bytes and returns plain integers/bytes.
None means "this attack did not apply" -- check the preconditions before
concluding a challenge is unsolvable.

Optional dependencies: pycryptodome for PEM parsing, sympy for nothing here.
"""

from __future__ import annotations

import math
import random

from .util import (
    b2i,
    crt,
    egcd,
    i2b,
    invmod,
    iroot,
    is_perfect_power,
    is_probable_prime,
    isqrt_exact,
)

# --------------------------------------------------------------------------
# basic decryption
# --------------------------------------------------------------------------


def decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def decrypt_bytes(c: int, d: int, n: int, length: int | None = None) -> bytes:
    m = pow(c, d, n)
    if length is not None:
        return i2b(m, length)
    return i2b(m)


def encrypt_int(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


# --------------------------------------------------------------------------
# factoring from leaked key material
# --------------------------------------------------------------------------


def factor_from_phi(n: int, phi: int) -> tuple[int, int] | None:
    """Recover p, q from n and phi(n)."""
    s = n - phi + 1  # p + q
    disc = s * s - 4 * n
    r = isqrt_exact(disc)
    if r is None or (s + r) % 2:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    if p * q == n and p > 1 and q > 1:
        return p, q
    return None


def factor_from_d(n: int, e: int, d: int) -> tuple[int, int] | None:
    """Recover p, q from a private exponent (standard probabilistic method)."""
    k = e * d - 1
    if k <= 0:
        return None
    t = k
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1
    for _ in range(100):
        a = random.randrange(2, n - 1)
        g = math.gcd(a, n)
        if 1 < g < n:
            return g, n // g
        x = pow(a, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            y = x * x % n
            if y == 1:
                g = math.gcd(x - 1, n)
                if 1 < g < n:
                    return g, n // g
                break
            if y == n - 1:
                break
            x = y
        else:
            g = math.gcd(x - 1, n)
            if 1 < g < n:
                return g, n // g
    return None


def factor_from_dp(n: int, e: int, dp: int) -> tuple[int, int] | None:
    """Recover p from dp = d mod (p-1)."""
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for _ in range(20):
        a = random.choice(bases)
        g = math.gcd(pow(a, e * dp, n) - a, n)
        if 1 < g < n:
            return g, n // g
    return None


def factor_from_dq(n: int, e: int, dq: int) -> tuple[int, int] | None:
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for _ in range(20):
        a = random.choice(bases)
        g = math.gcd(pow(a, e * dq, n) - a, n)
        if 1 < g < n:
            return g, n // g
    return None


# --------------------------------------------------------------------------
# low exponent
# --------------------------------------------------------------------------


def small_e_root(c: int, e: int, n: int) -> int | None:
    """Direct e-th root when m**e < n (no padding)."""
    r = is_perfect_power(c, e)
    return r


def small_e_search(c: int, e: int, n: int, max_k: int = 100_000) -> int | None:
    """Try c + k*n for k < max_k; catches small messages slightly larger than n."""
    for k in range(max_k):
        val = c + k * n
        r = is_perfect_power(val, e)
        if r is not None:
            return r
    return None


def common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> int | None:
    """Same message, same n, coprime exponents."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = invmod(c1, n)
        a = -a
    if b < 0:
        c2 = invmod(c2, n)
        b = -b
    return pow(c1, a, n) * pow(c2, b, n) % n


def hastad_broadcast(ciphertexts: list[int], moduli: list[int], e: int) -> int | None:
    """Same unpadded message under several moduli (Hastad). Needs len >= e."""
    if len(ciphertexts) < e:
        return None
    if len(ciphertexts) != len(moduli):
        return None
    try:
        combined, _ = crt(ciphertexts, moduli)
    except ValueError:
        return None
    return is_perfect_power(combined, e)


# --------------------------------------------------------------------------
# Wiener (small private exponent)
# --------------------------------------------------------------------------


def convergents(num: int, den: int):
    a, b = num, den
    p_prev, p = 1, 0  # numerators of convergents (Euclid on num/den)
    q_prev, q = 0, 1
    # use standard continued fraction of num/den
    p_prev, p = 0, 1
    q_prev, q = 1, 0
    while b:
        quot = a // b
        a, b = b, a - quot * b
        p_prev, p = p, quot * p + p_prev
        q_prev, q = q, quot * q + q_prev
        yield p, q


def wiener_full(n: int, e: int) -> tuple[int, int, int] | None:
    """Return (d, p, q) when d is small enough for Wiener's attack."""
    for k, d in convergents(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        got = factor_from_phi(n, phi)
        if got:
            return d, got[0], got[1]
    return None


def wiener(n: int, e: int) -> int | None:
    res = wiener_full(n, e)
    return res[0] if res else None


# --------------------------------------------------------------------------
# close primes / small factors
# --------------------------------------------------------------------------


def fermat_factor(n: int, max_iter: int = 1_000_000) -> tuple[int, int] | None:
    """Factor n when p and q are close together."""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt_exact(b2)
        if b is not None:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    return None


def pollard_rho(n: int, max_iter: int = 1_000_000) -> tuple[int, int] | None:
    """Brent's variant of Pollard rho. Good for factors up to ~1e12."""
    if n % 2 == 0:
        return 2, n // 2
    if is_probable_prime(n):
        return None
    for seed in range(1, 20):
        y, c, m = seed, seed, 128
        g, r, q = 1, 1, 1
        while g == 1 and r < max_iter:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g, n // g
    return None


def pollard_pm1(n: int, bound: int = 100_000) -> tuple[int, int] | None:
    """Pollard p-1. Works when p-1 is smooth."""
    if n % 2 == 0:
        return 2, n // 2
    a = 2
    for p in range(2, bound):
        if not is_probable_prime(p):
            continue
        # raise a to the largest power of p below bound
        pk = p
        while pk * p < bound:
            pk *= p
        a = pow(a, pk, n)
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            return g, n // g
    return None


def common_factor(moduli: list[int]) -> dict[int, int]:
    """Find moduli sharing a prime factor. Returns {index: factor}."""
    out: dict[int, int] = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i] and 1 < g < moduli[j]:
                out[i] = g
                out[j] = g
    return out


def factor_int(n: int, effort: int = 2) -> tuple[int, int] | None:
    """Convenience: cheap trial division, then Fermat, rho, p-1."""
    if n % 2 == 0:
        return 2, n // 2
    # trial division by tiny primes
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return p, n // p
    got = fermat_factor(n, max_iter=100_000)
    if got:
        return got
    got = pollard_rho(n, max_iter=200_000 * effort)
    if got:
        return got
    got = pollard_pm1(n, bound=50_000 * effort)
    if got:
        return got
    return None


# --------------------------------------------------------------------------
# related-message / Franklin-Reiter
# --------------------------------------------------------------------------


def _poly_mod(a: list[int], n: int) -> list[int]:
    while len(a) > 1 and a[-1] % n == 0:
        a.pop()
    return [c % n for c in a] if a else [0]


def _poly_divmod(a: list[int], b: list[int], n: int):
    a = _poly_mod(list(a), n)
    b = _poly_mod(list(b), n)
    if len(b) == 1 and b[0] == 0:
        raise ZeroDivisionError
    inv_lc = invmod(b[-1], n)  # raises if not invertible
    q = [0] * max(1, len(a) - len(b) + 1)
    r = list(a)
    while len(r) >= len(b) and not (len(r) == 1 and r[0] == 0):
        shift = len(r) - len(b)
        coef = r[-1] * inv_lc % n
        q[shift] = coef
        for i in range(len(b)):
            r[i + shift] = (r[i + shift] - coef * b[i]) % n
        while len(r) > 1 and r[-1] % n == 0:
            r.pop()
    return _poly_mod(q, n), _poly_mod(r, n)


def _poly_gcd_mod(a: list[int], b: list[int], n: int):
    a, b = _poly_mod(list(a), n), _poly_mod(list(b), n)
    while not (len(b) == 1 and b[0] == 0):
        try:
            _, r = _poly_divmod(a, b, n)
        except ValueError:
            # leading coefficient not invertible -> gcd(lc, n) factors n
            g = math.gcd(b[-1], n)
            return "FACTOR", g
        a, b = b, r
    # normalise monic
    if a and a[-1] % n:
        inv = invmod(a[-1], n)
        a = [c * inv % n for c in a]
    return "POLY", a


def franklin_reiter(
    c1: int, c2: int, e: int, n: int, a: int = 1, b: int = 1
) -> int | None:
    """Recover m when c1 = m^e and c2 = (a*m + b)^e mod n.

    Defaults (a=1, b=1) cover the classic "messages differ by 1" challenge.
    """
    # polynomial x^e - c1
    f = [(-c1) % n] + [0] * (e - 1) + [1]
    # polynomial (a*x + b)^e - c2
    g = [0] * (e + 1)
    # binomial expansion
    for i in range(e + 1):
        coeff = math.comb(e, i) * pow(a, i) * pow(b, e - i)
        g[i] = coeff % n
    g[0] = (g[0] - c2) % n
    kind, res = _poly_gcd_mod(f, g, n)
    if kind == "FACTOR":
        return None
    poly = res
    if len(poly) == 2:
        # linear: poly[1]*x + poly[0] = 0
        try:
            return (-poly[0] * invmod(poly[1], n)) % n
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------
# modular square roots (Rabin)
# --------------------------------------------------------------------------


def tonelli_shanks(a: int, p: int) -> int | None:
    """Square root of a modulo prime p."""
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return r


def rabin_roots(c: int, p: int, q: int) -> list[int]:
    """All four square roots of c modulo n = p*q."""
    rp = tonelli_shanks(c, p)
    rq = tonelli_shanks(c, q)
    if rp is None or rq is None:
        return []
    out = []
    for a in (rp, (-rp) % p):
        for b in (rq, (-rq) % q):
            x, _ = crt([a, b], [p, q])
            out.append(x)
    return sorted(set(out))


# --------------------------------------------------------------------------
# PEM loading
# --------------------------------------------------------------------------


def load_pem(path: str) -> tuple[int, int]:
    """Load (n, e) from a PEM public or private key if pycryptodome is present."""
    try:
        from Crypto.PublicKey import RSA
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pycryptodome is needed to parse PEM keys") from exc
    with open(path, "rb") as fh:
        key = RSA.import_key(fh.read())
    return key.n, key.e


def load_pem_private(path: str) -> tuple[int, int, int]:
    try:
        from Crypto.PublicKey import RSA
    except ImportError as exc:  # pragma: no cover
        raise ImportError("pycryptodome is needed to parse PEM keys") from exc
    with open(path, "rb") as fh:
        key = RSA.import_key(fh.read())
    return key.n, key.e, key.d


# --------------------------------------------------------------------------
# Oracle attacks and special RSA variants
# --------------------------------------------------------------------------


def lsb_oracle_candidates(
    oracle,
    c: int,
    e: int,
    n: int,
    extra_bits: int = 8,
    window: int = 8,
) -> list[int]:
    """Recover m from an oracle returning the LSB of Dec(ct).

    Query Enc(m * 2^i) by sending `c * 2^(e*i) mod n`. The parity bits are the
    binary digits of m/n; reconstruct them, then return a small window around
    the estimate (the truncation can leave an off-by-a-few error).
    """
    total = n.bit_length() + extra_bits
    cur = c
    num = 0
    for _ in range(total):
        cur = cur * pow(2, e, n) % n
        num = (num << 1) | (oracle(cur) & 1)
    center = (n * num) >> total
    out = []
    for d in range(-window, window + 1):
        cand = center + d
        if 0 <= cand < n:
            out.append(cand)
    return out


def lsb_oracle_attack(
    oracle,
    c: int,
    e: int,
    n: int,
    verify=None,
    extra_bits: int = 8,
    window: int = 8,
) -> int | None:
    """Recover m from a clean parity oracle.

    If `verify(m_candidate) -> bool` is supplied (e.g. checks for a flag or
    printable bytes), return the matching candidate; otherwise return the
    center estimate. Inspect the neighbouring candidates if the center does
    not decode cleanly.
    """
    cands = lsb_oracle_candidates(oracle, c, e, n, extra_bits, window)
    if verify is not None:
        for cand in cands:
            if verify(cand):
                return cand
        return None
    return cands[len(cands) // 2] if cands else None


def crt_fault_factor(n: int, e: int, known_message: int, faulty_signature: int):
    """Bellcore CRT fault: one faulty signature leaks a factor via gcd."""
    g = math.gcd(pow(faulty_signature, e, n) - known_message, n)
    if 1 < g < n:
        return g, n // g
    return None


def nth_roots_mod(c: int, e: int, p: int, q: int) -> list[int]:
    """All e-th roots of c modulo n = p*q (for gcd(e, phi) > 1)."""
    try:
        import sympy as sp
    except ImportError as exc:  # pragma: no cover
        raise ImportError("sympy is needed to enumerate e-th roots") from exc
    roots_p = sp.nthroot_mod(c % p, e, p, all_roots=True)
    roots_q = sp.nthroot_mod(c % q, e, q, all_roots=True)
    out = []
    for rp in roots_p:
        for rq in roots_q:
            x, _ = crt([int(rp), int(rq)], [p, q])
            out.append(x)
    return sorted(set(out))


def decrypt_non_coprime(c: int, e: int, p: int, q: int) -> list[bytes]:
    """Decrypt when gcd(e, phi) > 1 by enumerating all e-th roots."""
    out = []
    for m in nth_roots_mod(c, e, p, q):
        out.append(i2b(m))
    return out


def crt_signature_fault(
    n: int, e: int, message: int, faulty_signature: int
):
    return crt_fault_factor(n, e, message, faulty_signature)


# --------------------------------------------------------------------------
# Manger and Bleichenbacher padding oracles
# --------------------------------------------------------------------------


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def _floor_div(a: int, b: int) -> int:
    return a // b


def manger_attack(
    oracle,
    n: int,
    e: int,
    c: int,
    oracle_returns_valid: bool = True,
    max_queries: int | None = None,
):
    """Recover an RSA-OAEP plaintext from a threshold oracle.

    `oracle(ct) -> bool` must tell whether the decrypted block has a leading
    zero byte (i.e. `Dec(ct) < B = 2^(8*(k-1))`). If your oracle instead
    returns True for the *invalid* case, set `oracle_returns_valid=False`.

    Returns the plaintext integer. ~`2 * bit_length(n)` queries.
    """
    k = _ceil_div(n.bit_length(), 8)
    B = 1 << (8 * (k - 1))
    if 2 * B >= n:
        raise ValueError("modulus is too small for the OAEP threshold")
    count = 0

    def op(ct: int) -> bool:
        nonlocal count
        count += 1
        if max_queries is not None and count > max_queries:
            raise RuntimeError(f"Manger query limit exceeded ({max_queries})")
        # The interval algorithm expects True == valid (decryption < B).
        return oracle(ct) if oracle_returns_valid else not oracle(ct)

    # Step 1: find f1 with m*f1 mod n < B (op says False).
    f1 = 2
    while op(pow(f1, e, n) * c % n):
        f1 *= 2
    # Step 2: find a crossing f2 with m*f2 mod n >= B.
    f2 = ((n + B) // B) * f1 // 2
    while not op(pow(f2, e, n) * c % n):
        f2 += f1 // 2
    # Step 3: interval narrowing.
    mmin = _ceil_div(n, f2)
    mmax = _floor_div(n + B, f2)
    while mmin < mmax:
        f = _floor_div(2 * B, mmax - mmin)
        i = _floor_div(f * mmin, n)
        f3 = _ceil_div(i * n, mmin)
        if op(pow(f3, e, n) * c % n):
            mmax = _floor_div(i * n + B, f3)
        else:
            mmin = _ceil_div(i * n + B, f3)
    return mmin


def _bleich_insert(M: list[tuple[int, int]], a: int, b: int):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            M[i] = (min(a, a_), max(b, b_))
            return
    M.append((a, b))


def _bleich_step_3(n: int, B: int, s: int, M: list[tuple[int, int]]):
    out: list[tuple[int, int]] = []
    for a, b in M:
        left = _ceil_div(a * s - 3 * B + 1, n)
        right = _floor_div(b * s - 2 * B, n)
        for r in range(left, right + 1):
            a_ = max(a, _ceil_div(2 * B + r * n, s))
            b_ = min(b, _floor_div(3 * B - 1 + r * n, s))
            _bleich_insert(out, a_, b_)
    return out


def bleichenbacher_attack(
    oracle,
    n: int,
    e: int,
    c: int,
    max_queries: int | None = None,
):
    """Recover an RSA PKCS#1 v1.5 plaintext from a padding oracle.

    `oracle(ct) -> bool` returns True when `Dec(ct)` starts with `0x00 0x02`
    and has a valid PKCS#1 v1.5 structure. Returns the plaintext integer.

    This is the classic interval attack; query counts vary widely (typically
    thousands to tens of thousands). Use `max_queries` to bound a remote run.
    Adapted from the standard algorithm (Bleichenbacher 1998; the
    crypto-attacks implementation).
    """
    k = _ceil_div(n.bit_length(), 8)
    B = 1 << (8 * (k - 2))
    count = 0

    def op(ct: int) -> bool:
        nonlocal count
        count += 1
        if max_queries is not None and count > max_queries:
            raise RuntimeError(f"Bleichenbacher query limit exceeded ({max_queries})")
        return oracle(ct)

    # Step 1: random blinding until the oracle accepts.
    s0, c0 = 1, c
    while not op(c0):
        s0 = random.randrange(2, n)
        c0 = c * pow(s0, e, n) % n

    # Step 2.a: search for the first valid s >= ceil(n/(3B)).
    s = _ceil_div(n, 3 * B)
    while not op(c0 * pow(s, e, n) % n):
        s += 1

    M = [(2 * B, 3 * B - 1)]
    M = _bleich_step_3(n, B, s, M)

    while True:
        if len(M) > 1:
            s += 1
            while not op(c0 * pow(s, e, n) % n):
                s += 1
        else:
            a, b = M[0]
            if a == b:
                return a * pow(s0, -1, n) % n
            # Step 2.c: search inside the single interval.
            r = _ceil_div(2 * (b * s - 2 * B), n)
            found = None
            while found is None:
                left = _ceil_div(2 * B + r * n, b)
                right = _floor_div(3 * B + r * n, a)
                for cand in range(left, right + 1):
                    if op(c0 * pow(cand, e, n) % n):
                        found = cand
                        break
                r += 1
            s = found
        M = _bleich_step_3(n, B, s, M)
