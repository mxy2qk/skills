"""ctfkit — a small, dependency-light toolkit for CTF cryptography.

Modules:
    util         byte/int helpers, number theory, English scoring, flags, sockets
    classical    Caesar/affine/Vigenere/substitution/transposition/xor solvers
    rsa          RSA attacks (small e, Wiener, Fermat, Hastad, leaks, ...)
    lattice      LLL and Coppersmith
    prng         LCG and Mersenne Twister state recovery
    blockcipher  ECB/CBC/CTR attacks, padding oracles, byte-at-a-time ECB
    ecc          curve arithmetic, Pohlig-Hellman, ECDSA nonce reuse
    hashx        hash length extension
    remote       socket helpers re-exported from util

Optional packages (pycryptodome, sympy, gmpy2) are used when installed and
never required for import.
"""

from . import util  # noqa: F401

__all__ = [
    "util",
    "classical",
    "rsa",
    "lattice",
    "prng",
    "blockcipher",
    "ecc",
    "hashx",
    "dh",
    "stream",
    "exotic",
    "pow",
    "zkp",
]
