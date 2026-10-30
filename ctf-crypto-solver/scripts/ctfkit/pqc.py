"""Post-quantum scheme fingerprints and small CTF helpers.

Most PQ CTF challenges reduce to LWE/NTRU once the scheme is recognized:
implementation bugs, tiny noise, leaked randomness, or a small seed. This
module helps identify the scheme and flatten it to the lattice problem, then
`ctfkit.lattice` solves the small/weak instance.
"""

from __future__ import annotations

from . import lattice

# (name, {q, N, ring, rank}) — fingerprints seen in the wild / in CTFs
SCHEMES = [
    ("ML-KEM/Kyber", {"q": 3329, "N": 256, "ring": "negacyclic"}),
    ("ML-DSA/Dilithium", {"q": 8380417, "N": 256, "ring": "negacyclic"}),
    ("Falcon", {"q": 12289, "N": 512, "ring": "negacyclic"}),
    ("Saber", {"q": 8192, "N": 256, "ring": "negacyclic"}),
    ("NTRU (2048)", {"q": 2048, "N": None, "ring": None}),
    ("NTRU Prime (sntrup761)", {"q": 4591, "N": 761, "ring": "cyclic"}),
    ("Kyber (toy q)", {"q": 7681, "N": None, "ring": "negacyclic"}),
]


def detect(q: int | None = None, n: int | None = None,
           ring: str | None = None) -> list[str]:
    """Return scheme names matching the given modulus / ring degree / ring type."""
    out = []
    for name, p in SCHEMES:
        if q is not None and p.get("q") != q:
            continue
        if n is not None and p.get("N") is not None and p.get("N") != n:
            continue
        if ring is not None and p.get("ring") is not None and p.get("ring") != ring:
            continue
        out.append(name)
    return out


def negacyclic_mul(f: list[int], g: list[int], q: int,
                   negacyclic: bool = True) -> list[int]:
    """Polynomial product in Z_q[x]/(x^N +/- 1)."""
    return lattice.ntru_mul(f, g, q, negacyclic)


def negacyclic_matrix(h: list[int], q: int,
                      negacyclic: bool = True) -> list[list[int]]:
    """Multiplication-by-h matrix (column j = h * x^j mod (x^N +/- 1)).

    Useful to turn `h = g/f mod q` and ciphertexts into plain matrix equations.
    """
    N = len(h)
    M = [[0] * N for _ in range(N)]
    for j in range(N):
        e = [0] * N
        e[j] = 1
        col = lattice.ntru_mul(h, e, q, negacyclic)
        for i in range(N):
            M[i][j] = col[i]
    return M


def flatten_lwe(A: list[list[int]], b: list[int], q: int):
    """Treat a PQ instance as plain LWE and solve the small/noisy case.

    Returns (s, e) — use when the secret/error is small, sparse, ternary, or
    partially leaked. For larger dimensions use the Sage templates.
    """
    return lattice.lwe_cvp_solve(A, b, q)
