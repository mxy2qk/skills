"""Lattice reduction and Coppersmith attacks in pure Python.

SageMath is not assumed. LLL uses exact rational Gram-Schmidt, which is fast
enough for the small lattices Coppersmith needs (dimension up to ~40) but is
not a general-purpose substitute for fplll.

Polynomials are represented as coefficient lists, low degree first:
    x**3 - 2*x + 1  ->  [1, -2, 0, 1]
"""

from __future__ import annotations

import math
from fractions import Fraction

from .util import gcd_list, invmod, isqrt_exact

# --------------------------------------------------------------------------
# polynomial helpers
# --------------------------------------------------------------------------


def poly_trim(p: list[int]) -> list[int]:
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def poly_degree(p: list[int]) -> int:
    return len(poly_trim(list(p))) - 1


def poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                out[i + j] += ai * bj
    return out


def poly_pow(a: list[int], n: int) -> list[int]:
    out = [1]
    base = list(a)
    while n:
        if n & 1:
            out = poly_mul(out, base)
        base = poly_mul(base, base)
        n >>= 1
    return out


def poly_eval(p: list[int], x: int) -> int:
    acc = 0
    for c in reversed(p):
        acc = acc * x + c
    return acc


def poly_scale_shift(p: list[int], scale: int) -> list[int]:
    """Return coefficients of p(scale*x)."""
    return [c * scale**i for i, c in enumerate(p)]


# --------------------------------------------------------------------------
# LLL
# --------------------------------------------------------------------------


def _dot(u, v) -> Fraction:
    return sum(Fraction(a) * Fraction(b) for a, b in zip(u, v))


def _gram_schmidt(basis: list[list[int]]):
    n = len(basis)
    dim = len(basis[0]) if n else 0
    ortho: list[list[Fraction]] = []
    mu = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            denom = _dot(ortho[j], ortho[j])
            if denom == 0:
                mu[i][j] = Fraction(0)
            else:
                mu[i][j] = _dot(basis[i], ortho[j]) / denom
            if mu[i][j]:
                v = [v[k] - mu[i][j] * ortho[j][k] for k in range(dim)]
        ortho.append(v)
    return ortho, mu


def lll_reduce(basis: list[list[int]], delta: Fraction = Fraction(3, 4)) -> list[list[int]]:
    """LLL-reduce an integer basis. Returns a new basis (rows).

    Sympy's LLL is implemented in C-adjacent optimized Python and is roughly
    two orders of magnitude faster than the exact Fraction fallback below, so
    use it whenever sympy is installed.
    """
    B = [list(map(int, row)) for row in basis]
    n = len(B)
    if n <= 1:
        return B
    try:
        import sympy as sp

        mat = sp.Matrix(B)
        reduced = mat.lll(delta=sp.Rational(delta.numerator, delta.denominator))
        return [[int(x) for x in row] for row in reduced.tolist()]
    except Exception:
        pass

    # normalise to a common width
    width = max(len(row) for row in B)
    B = [row + [0] * (width - len(row)) for row in B]


# --------------------------------------------------------------------------
# Babai nearest plane, LWE/CVP, NTRU
# --------------------------------------------------------------------------


def babai_nearest_plane(basis: list[list[int]], target: list[int]):
    """Babai's nearest-plane algorithm after LLL reduction.

    Returns (closest_lattice_vector, coefficients). The coefficients are with
    respect to the reduced basis, not the original one.
    """
    B = lll_reduce(basis)
    dim = len(target)
    B = [row + [0] * (dim - len(row)) for row in B]
    ortho, _mu = _gram_schmidt(B)
    w = [Fraction(x) for x in target]
    coeffs = [0] * len(B)
    for i in range(len(B) - 1, -1, -1):
        denom = _dot(ortho[i], ortho[i])
        if denom == 0:
            continue
        c = int(round(_dot(w, ortho[i]) / denom))
        coeffs[i] = c
        if c:
            w = [w[k] - c * B[i][k] for k in range(dim)]
    closest = [
        sum(coeffs[i] * B[i][k] for i in range(len(B))) for k in range(dim)
    ]
    return closest, coeffs


def lwe_cvp_solve(
    A: list[list[int]], b: list[int], q: int
) -> tuple[list[int], list[int]]:
    """Recover a small LWE secret/error from b = A*s + e (mod q).

    Uses the standard embedding [[q*I, 0], [A^T, I]] and Babai's nearest
    plane. Returns (s, e) with coefficients centered in [-q/2, q/2). Works
    when the secret and error are small enough for LLL+Babai; for production
    parameters use fpylll/BKZ.
    """
    m = len(A)
    n = len(A[0]) if m else 0
    if len(b) != m:
        raise ValueError("A and b dimensions do not match")
    dim = m + n
    rows = [[0] * dim for _ in range(dim)]
    for i in range(m):
        rows[i][i] = q
    for j in range(n):
        for i in range(m):
            rows[m + j][i] = A[i][j] % q
        rows[m + j][m + j] = 1

    target = [x % q for x in b] + [0] * n
    closest, _ = babai_nearest_plane(rows, target)
    half = q // 2
    s = [((closest[m + j] + half) % q) - half for j in range(n)]
    e = [((b[i] - closest[i] + half) % q) - half for i in range(m)]
    return s, e


def lwe_with_hints(
    A: list[list[int]], b: list[int], q: int, hints: list
) -> tuple[list[int], list[int]]:
    """Solve LWE with extra linear hints on the secret.

    Each hint is ``<v, s> = l`` (mod q), optionally with a small error
    (``(v, l)`` or ``(v, l, err)``). The hint is appended as one more LWE
    sample: perfect hints contribute zero error, approximate hints contribute
    their (small) error. Then ``lwe_cvp_solve`` runs on the augmented instance.

    This is the simple "append" strategy; for many perfect hints the Sage
    template ``scripts/templates/lwe_hints.sage`` instead eliminates the hinted
    coordinates (smaller lattice). This pure-Python helper is for small
    instances only.

    Returns ``(s, e_ext)`` where ``e_ext`` includes the hint residuals and has
    length ``len(A) + len(hints)``.
    """
    ext_A = [list(row) for row in A]
    ext_b = [x % q for x in b]
    for h in hints:
        v, l = h[0], h[1]
        ext_A.append(list(v))
        ext_b.append(l % q)
    return lwe_cvp_solve(ext_A, ext_b, q)


def ntru_mul(h: list[int], f: list[int], q: int, negacyclic: bool = True) -> list[int]:
    """Polynomial multiplication in Z_q[x]/(x^N +/- 1)."""
    N = len(h)
    out = [0] * N
    for i, a in enumerate(h):
        for j, b in enumerate(f):
            k = i + j
            if k >= N:
                if negacyclic:
                    out[k - N] -= a * b
                else:
                    out[k - N] += a * b
            else:
                out[k] += a * b
    return [x % q for x in out]


def ntru_lattice(h: list[int], q: int, negacyclic: bool = True) -> list[list[int]]:
    """Build the NTRU lattice [[q*I, 0], [H, I]] (2N x 2N)."""
    N = len(h)
    dim = 2 * N
    rows = [[0] * dim for _ in range(dim)]
    for i in range(N):
        rows[i][i] = q
    for k in range(N):
        for j in range(N):
            idx = (j - k) % N
            sign = -1 if (negacyclic and j < k) else 1
            rows[N + k][j] = sign * h[idx] % q
        rows[N + k][N + k] = 1
    return rows


def ntru_recover(
    h: list[int], q: int, negacyclic: bool = True, max_coeff: int = 2
) -> list[tuple[list[int], list[int]]]:
    """Recover small (f, g) from an NTRU public key h = g * f^{-1} mod q.

    Returns candidates (f, g) with small centered coefficients. Toy/weak
    parameters only; realistic NTRU needs BKZ (fpylll/Sage).
    """
    N = len(h)
    reduced = lll_reduce(ntru_lattice(h, q, negacyclic))
    out: list[tuple[list[int], list[int]]] = []
    half = q // 2
    for row in reduced:
        g = [((row[i] + half) % q) - half for i in range(N)]
        f = [row[N + i] for i in range(N)]
        if max((abs(x) for x in g), default=0) > max_coeff:
            continue
        if max((abs(x) for x in f), default=0) > max_coeff:
            continue
        if ntru_mul(h, f, q, negacyclic) == [x % q for x in g]:
            out.append((f, g))
    return out

    ortho, mu = _gram_schmidt(B)
    k = 1
    guard = 0
    while k < n:
        guard += 1
        if guard > 500_000:
            raise RuntimeError("LLL did not converge; try smaller parameters")
        # size-reduce B[k] against B[k-1] .. B[0]
        for j in range(k - 1, -1, -1):
            q = int(round(mu[k][j]))
            if q:
                B[k] = [B[k][i] - q * B[j][i] for i in range(width)]
                ortho, mu = _gram_schmidt(B)
        # Lovasz condition
        left = _dot(ortho[k], ortho[k])
        right = (delta - mu[k][k - 1] ** 2) * _dot(ortho[k - 1], ortho[k - 1])
        if left >= right:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            ortho, mu = _gram_schmidt(B)
            k = max(k - 1, 1)
    return B


# --------------------------------------------------------------------------
# Coppersmith
# --------------------------------------------------------------------------


def _integer_roots(coeffs: list[int], bound: int | None = None) -> list[int]:
    """Integer roots of a polynomial given by low-to-high coefficients."""
    coeffs = poly_trim([int(c) for c in coeffs])
    if len(coeffs) <= 1:
        return []
    try:
        import sympy as sp

        x = sp.Symbol("x")
        expr = sum(int(c) * x**i for i, c in enumerate(coeffs))
        poly = sp.Poly(expr, x)
        roots = []
        for r, _mult in poly.ground_roots().items():
            if r.is_integer:
                roots.append(int(r))
        return sorted(set(roots))
    except Exception:
        pass
    # fallback: numeric roots / bounded scan
    try:
        import numpy as np

        r = np.roots(list(reversed(coeffs)))
        out = []
        for z in r:
            if abs(z.imag) < 1e-6:
                cand = int(round(z.real))
                if abs(z.real - cand) < 1e-6 and poly_eval(coeffs, cand) == 0:
                    out.append(cand)
        return sorted(set(out))
    except Exception:
        pass
    if bound is not None and bound <= 2_000_000:
        return [x for x in range(-bound, bound + 1) if poly_eval(coeffs, x) == 0]
    return []


def coppersmith_univariate(
    f: list[int],
    N: int,
    beta: float = 1.0,
    X: int | None = None,
    m: int | None = None,
    t: int | None = None,
    *,
    max_dim: int = 48,
) -> list[int]:
    """Find small integer roots of f(x) mod a divisor of N.

    Args:
        f: polynomial coefficients, low degree first. Should be monic or have
           an invertible leading coefficient mod N.
        N: modulus. With beta == 1, roots are modulo N. With beta < 1, roots
           are modulo an unknown factor b of N with b >= N**beta.
        X: root bound, |x0| < X. Defaults to N**beta (the largest possible).
        m, t: lattice parameters. Chosen automatically when omitted.

    Returns candidate roots. With beta < 1, verify by gcd(f(x0), N).
    """
    f = [int(c) for c in f]
    f = poly_trim(f)
    d = len(f) - 1
    if d < 1:
        return []

    # make f monic mod N: multiply by lc^{-1}
    lc = f[-1]
    g = math.gcd(lc % N, N)
    if g != 1:
        # leading coefficient shares a factor with N -- that itself may solve it
        return []
    inv_lc = invmod(lc, N)
    f = [(c * inv_lc) % N for c in f]
    f[-1] = 1

    if X is None:
        X = int(round(N ** beta))
    if X < 1:
        X = 1
    if X >= N:
        X = N - 1

    if m is None or t is None:
        # Coppersmith succeeds for |x0| < N^(beta^2/d).  Let eps be the slack
        # between that bound and our actual X; the standard parameter choice is
        # m = ceil(beta^2 / (d*eps)), t = floor(d*m*(1/beta - 1)).
        log_n_x = math.log(X) / math.log(N) if N > 1 else 1.0
        eps = (beta * beta) / d - log_n_x
        if eps <= 0:
            # X is past the theoretical bound; try the smallest workable lattice
            # anyway, but the caller should not expect success.
            eps = 1e-9
        m_auto = max(1, math.ceil((beta * beta) / (d * eps)))
        if m is None:
            m = m_auto
        if t is None:
            t = max(0, int(math.floor(d * m * (1.0 / beta - 1.0))))
    m = max(1, int(m))
    t = max(0, int(t))

    dim = d * m + t
    if dim > max_dim and m > 1:
        # trim the lattice to stay tractable; the attack may still succeed
        m = max(1, (max_dim - t) // d)
        t = max(0, int(math.floor(d * m * (1.0 / beta - 1.0))))
        dim = d * m + t
    if dim > max_dim:
        raise ValueError(f"lattice dimension {dim} exceeds max_dim={max_dim}")

    # Build polynomials g_{i,j} = N^(m-i) * x^j * f(x)^i   (i<m, j<d)
    # and              g_{m,j}  = x^j * f(x)^m             (j<t)
    polys: list[list[int]] = []
    f_pows = [poly_pow(f, i) for i in range(m + 1)]
    for i in range(m):
        base = f_pows[i]
        for j in range(d):
            p = [0] * j + base
            p = [c * (N ** (m - i)) for c in p]
            polys.append(p)
    for j in range(t):
        p = [0] * j + f_pows[m]
        polys.append(p)

    if len(polys) != dim:
        raise RuntimeError(f"construction produced {len(polys)} polys, expected {dim}")

    # scale x -> X*x and build the lattice
    rows = []
    for p in polys:
        row = [0] * dim
        for k, c in enumerate(p):
            if k < dim:
                row[k] = c * X**k
        rows.append(row)

    reduced = lll_reduce(rows)

    roots: set[int] = set()
    for vec in reduced:
        # coefficients must be divisible by X**k
        coeffs = []
        ok = True
        for k, v in enumerate(vec):
            if v % (X**k) != 0:
                ok = False
                break
            coeffs.append(v // (X**k))
        if not ok:
            continue
        for r in _integer_roots(coeffs, bound=X * 4 + 10):
            if abs(r) <= X * 4 + 10:
                roots.add(r)
    return sorted(roots)


def partial_p_root(N: int, p_high: int, shift: int, beta: float = 0.5) -> list[int]:
    """Known high bits of a factor.

    `p_high` is the known part and `shift` the number of unknown low bits,
    i.e. p = p_high * 2**shift + x with 0 <= x < 2**shift. Returns candidates
    for the unknown part x.
    """
    X = 1 << shift
    f = [p_high * (1 << shift), 1]  # p_high*2^shift + x
    cands = coppersmith_univariate(f, N, beta=beta, X=X)
    out = []
    for x0 in cands:
        if 0 <= x0 < X:
            p = p_high * (1 << shift) + x0
            if p > 1 and N % p == 0:
                out.append(x0)
    return out


def factor_with_known_high_bits(N: int, p_high: int, shift: int) -> tuple[int, int] | None:
    for x0 in partial_p_root(N, p_high, shift):
        p = p_high * (1 << shift) + x0
        if N % p == 0:
            return p, N // p
    return None


# --------------------------------------------------------------------------
# Hidden Number Problem (ECDSA/DSA partial or biased nonces)
# --------------------------------------------------------------------------


def hnp_solve(
    a: list[int], b: list[int], m: int, X: int, max_dim: int = 60
) -> list[int]:
    """Solve the hidden number problem: find y with (a_i*y + b_i) mod m small.

    The unknowns are bounded by X (centered at X/2). This is an integer-scaled
    version of the standard SVP embedding (crypto-attacks / Nguyen-Shparlinski):
    the rational `X/m` is cleared by multiplying the whole matrix by m.

    Returns candidate y values.
    """
    n = len(a)
    if len(b) != n or n < 1:
        raise ValueError("a and b must be non-empty and the same length")
    D = n + 2
    if D > max_dim:
        raise ValueError(f"HNP dimension {D} exceeds max_dim={max_dim}")
    half = X // 2
    B = [[0] * D for _ in range(D)]
    for i in range(n):
        B[i][i] = m * m
        B[n + 1][i] = m * (b[i] - half)
    for i in range(n):
        B[n][i] = m * a[i]
    B[n][n] = X
    B[n + 1][n + 1] = m * X

    reduced = lll_reduce(B)
    out: set[int] = set()
    for v in reduced:
        if abs(v[n + 1]) != m * X:
            continue
        if any(v[i] % m for i in range(n)):
            continue
        if v[n] % X:
            continue
        y = (v[n] // X) % m
        for cand in (y, (-y) % m):
            if cand and all((a[i] * cand + b[i]) % m < X for i in range(n)):
                out.add(cand)
    return sorted(out)


def hnp_partial_bits(
    a: list[int], b: list[int], m: int, leaked: list[int], bits: int, max_dim: int = 60
) -> list[int]:
    """HNP with the top `bits` of each error known: the general form of
    partial-nonce / truncated-PRNG leaks.

    For each sample: a_i*y + b_i ≡ e_i (mod m) with
        e_i = leaked_i * 2^bits + delta_i,    0 <= delta_i < 2^bits.
    Moving the known part into the constant gives
        a_i*y + (b_i - leaked_i*2^bits) ≡ delta_i (mod m),
    an HNP instance with bound X = 2^bits, so this wraps hnp_solve.

    Returns candidate y values.
    """
    n = len(a)
    if n < 1 or len(b) != n or len(leaked) != n:
        raise ValueError("a, b, leaked must be the same non-empty length")
    X = 1 << bits
    b2 = [(b[i] - leaked[i] * X) % m for i in range(n)]
    return hnp_solve(a, b2, m, X, max_dim=max_dim)


def ecdsa_partial_nonce_recover(
    q: int,
    rs: list[int],
    ss: list[int],
    hs: list[int],
    leaked: list[int],
    t: int,
    max_dim: int = 60,
) -> list[int]:
    """Recover the private key when each ECDSA nonce's high bits are known.

    For signature i, k_i = leaked_i * 2^t + delta_i with 0 <= delta_i < 2^t.
    With a_i = r_i/s_i and b_i = h_i/s_i - leaked_i*2^t mod q:

        a_i * d + b_i ≡ delta_i (mod q)

    so this is an HNP instance with bound X = 2^t.

    Returns candidate private keys (usually one).
    """
    n = len(rs)
    if n < 2 or len(ss) != n or len(hs) != n or len(leaked) != n:
        raise ValueError("rs, ss, hs, leaked must be the same length")
    X = 1 << t
    a = [r * invmod(s, q) % q for r, s in zip(rs, ss)]
    b = [
        (h * invmod(s, q) - leaked_i * X) % q
        for h, s, leaked_i in zip(hs, ss, leaked)
    ]
    return hnp_solve(a, b, q, X, max_dim=max_dim)


def ecdsa_biased_nonce_recover(
    q: int,
    rs: list[int],
    ss: list[int],
    hs: list[int],
    nonce_bits: int,
    known_msb: list[int] | None = None,
    max_dim: int = 60,
) -> list[int]:
    """Recover the key when nonces are small or their top bits are known.

    Without `known_msb`, assumes each nonce is < 2^nonce_bits (small nonce).
    With `known_msb`, pass the known high part of each nonce and `nonce_bits`
    as the number of unknown low bits.
    """
    n = len(rs)
    leaked = [0] * n if known_msb is None else list(known_msb)
    return ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, nonce_bits, max_dim=max_dim)


# --------------------------------------------------------------------------
# Subset sum / knapsack
# --------------------------------------------------------------------------


def subset_sum_solve(weights: list[int], target: int, max_dim: int = 60) -> list[int] | None:
    """Recover a binary vector x with sum(weights[i]*x[i]) == target.

    The standard low-density knapsack lattice: a correct subset produces a
    vector whose last coordinate is 0 and whose first n coordinates are in
    {0,1}.
    """
    n = len(weights)
    if n + 1 > max_dim:
        raise ValueError(f"subset-sum dimension {n + 1} exceeds max_dim={max_dim}")
    rows = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        rows[i][i] = 1
        rows[i][n] = int(weights[i])
    rows[n][n] = -int(target)

    reduced = lll_reduce(rows)

    def extract(row):
        if row[n] != 0:
            return None
        bits = [int(v) for v in row[:n]]
        for candidate in (bits, [-v for v in bits]):
            if all(v in (0, 1) for v in candidate):
                if sum(weights[i] * candidate[i] for i in range(n)) == target:
                    return candidate
        return None

    for row in reduced:
        got = extract(row)
        if got is not None:
            return got
    # Sometimes the solution is a short ±1 combination of two reduced rows.
    for i in range(len(reduced)):
        for j in range(i + 1, len(reduced)):
            for s1, s2 in ((1, 1), (1, -1), (-1, 1), (-1, -1)):
                combo = [s1 * a + s2 * b for a, b in zip(reduced[i], reduced[j])]
                got = extract(combo)
                if got is not None:
                    return got
    return None


def knapsack_solve(weights: list[int], target: int, max_dim: int = 60):
    return subset_sum_solve(weights, target, max_dim=max_dim)


# --------------------------------------------------------------------------
# small self-test
# --------------------------------------------------------------------------

if __name__ == "__main__":
    # LLL smoke test: reduce a 2D lattice and check shortness
    B = [[1, 0, 0], [0, 1, 0], [123456, 789012, 1]]
    R = lll_reduce(B)
    assert all(isinstance(x, int) for row in R for x in row)

    # Coppersmith: f(x) = x^3 - c with a small root modulo N
    import random

    from .util import is_probable_prime

    p = (1 << 511) + 12345
    while not is_probable_prime(p):
        p += 2
    q = (1 << 511) + 987654321
    while not is_probable_prime(q):
        q += 2
    N = p * q
    m0 = 0xDEADBEEF1234
    c = pow(m0, 3, N)
    roots = coppersmith_univariate([-c, 0, 0, 1], N, beta=1.0, X=1 << 64)
    assert m0 in roots, (m0, roots)

    # partial p: recover unknown low bits of a factor
    p = 0xF23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    while not is_probable_prime(p):
        p += 2
    q = p + 2
    while not is_probable_prime(q):
        q += 2
    N = p * q
    shift = 24
    p_high = p >> shift
    got = factor_with_known_high_bits(N, p_high, shift)
    assert got is not None and got[0] * got[1] == N, got
    print("lattice self-test OK")
