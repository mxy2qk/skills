"""PRNG recovery: linear congruential generators and Mersenne Twister."""

from __future__ import annotations

import math
from typing import Iterable

from .util import invmod

# --------------------------------------------------------------------------
# LCG
# --------------------------------------------------------------------------


class LCG:
    """x_{n+1} = (a*x_n + c) mod m."""

    def __init__(self, m: int, a: int, c: int, seed: int):
        self.m, self.a, self.c = m, a, c
        self.state = seed % m

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def __next__(self) -> int:
        return self.next()

    def __iter__(self):
        return self


def recover_lcg_parameters(
    outputs: Iterable[int], modulus: int | None = None
) -> tuple[int, int, int] | None:
    """Recover (m, a, c) from consecutive outputs.

    When the modulus is unknown, the identity
        d_{n+2}*d_n - d_{n+1}^2 = 0 (mod m)
    for differences d_n = x_{n+1}-x_n gives m as a divisor of the gcd of
    those terms. The gcd can be a multiple of the true modulus; the recovered
    recurrence still predicts correctly.
    """
    xs = list(outputs)
    if len(xs) < 4:
        return None
    if modulus is None:
        ds = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
        terms = [ds[i + 2] * ds[i] - ds[i + 1] ** 2 for i in range(len(ds) - 2)]
        m = 0
        for t in terms:
            m = math.gcd(m, abs(t))
            if m == 1:
                break
        if m <= 1:
            return None
        modulus = m
    d0 = (xs[1] - xs[0]) % modulus
    try:
        a = ((xs[2] - xs[1]) % modulus) * invmod(d0, modulus) % modulus
    except ValueError:
        return None
    c = (xs[1] - a * xs[0]) % modulus
    # verify
    if any((a * xs[i] + c - xs[i + 1]) % modulus for i in range(len(xs) - 1)):
        return None
    return modulus, a, c


def predict_lcg(outputs: Iterable[int], count: int = 1, modulus: int | None = None) -> list[int] | None:
    """Recover the recurrence from outputs and predict the next `count` values."""
    xs = list(outputs)
    params = recover_lcg_parameters(xs, modulus)
    if params is None:
        return None
    m, a, c = params
    x = xs[-1]
    out = []
    for _ in range(count):
        x = (a * x + c) % m
        out.append(x)
    return out


def lcg_next(outputs: Iterable[int], count: int = 1, modulus: int | None = None) -> list[int] | None:
    return predict_lcg(outputs, count, modulus)


# --------------------------------------------------------------------------
# Mersenne Twister (MT19937)
# --------------------------------------------------------------------------

MASK32 = 0xFFFFFFFF
MT_N = 624
MT_M = 397
MT_MATRIX_A = 0x9908B0DF
MT_UPPER = 0x80000000
MT_LOWER = 0x7FFFFFFF


def _undo_right_xor(y: int, shift: int) -> int:
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x & MASK32


def _undo_left_xor(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range(32 // shift + 2):
        x = y ^ ((x << shift) & mask)
    return x & MASK32


def untemper(y: int) -> int:
    """Invert the MT19937 output transformation."""
    y = _undo_right_xor(y, 18)
    y = _undo_left_xor(y, 15, 0xEFC60000)
    y = _undo_left_xor(y, 7, 0x9D2C5680)
    y = _undo_right_xor(y, 11)
    return y & MASK32


def temper(y: int) -> int:
    y &= MASK32
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & MASK32


class MT19937:
    """A from-scratch MT19937 with state injection and cloning."""

    def __init__(self, seed: int | None = None):
        self.mt = [0] * MT_N
        self.index = MT_N
        if seed is not None:
            self.seed(seed)

    def seed(self, seed: int):
        self.mt[0] = seed & MASK32
        for i in range(1, MT_N):
            prev = self.mt[i - 1]
            self.mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & MASK32
        self.index = MT_N

    def _twist(self):
        mt = self.mt
        for i in range(MT_N):
            y = (mt[i] & MT_UPPER) | (mt[(i + 1) % MT_N] & MT_LOWER)
            mt[i] = mt[(i + MT_M) % MT_N] ^ (y >> 1)
            if y & 1:
                mt[i] ^= MT_MATRIX_A

    def next(self) -> int:
        if self.index >= MT_N:
            self._twist()
            self.index = 0
        y = self.mt[self.index]
        self.index += 1
        return temper(y)

    def next_float(self) -> float:
        """Python's random.random(): 53 bits from two draws."""
        a = self.next() >> 5
        b = self.next() >> 6
        return (a * 67108864.0 + b) / 9007199254740992.0

    @classmethod
    def from_state(cls, state: list[int], index: int = MT_N) -> "MT19937":
        obj = cls()
        obj.mt = [s & MASK32 for s in state] + [0] * (MT_N - len(state))
        obj.index = index
        return obj

    @classmethod
    def from_outputs(cls, outputs: Iterable[int], index: int = 0) -> "MT19937":
        """Clone from 624 consecutive tempered outputs.

        `index` is the position of the first output within the state block
        (0 means the outputs begin exactly after a twist, which is the usual
        case when a challenge consumes 624 draws from a fresh seed).
        """
        ys = [y & MASK32 for y in outputs]
        if len(ys) < MT_N:
            raise ValueError(f"need {MT_N} outputs, got {len(ys)}")
        state = [untemper(y) for y in ys[:MT_N]]
        return cls.from_state(state, index=MT_N)

    def clone_next(self, count: int = 1) -> list[int]:
        return [self.next() for _ in range(count)]


def mt19937_predict(outputs: Iterable[int], count: int = 1) -> list[int]:
    """Predict the next `count` 32-bit outputs from 624 observed outputs."""
    mt = MT19937.from_outputs(outputs)
    return mt.clone_next(count)


def mt19937_from_python_random(random_module) -> MT19937:
    """Clone a `random.Random` instance by consuming its state.

    Python's Random stores the MT state as a tuple; this reconstructs the
    equivalent MT19937 so you can advance it offline.
    """
    version, internal, gauss = random_module.getstate()
    return MT19937.from_state(list(internal), index=MT_N)


# --------------------------------------------------------------------------
# Java java.util.Random (48-bit LCG)
# --------------------------------------------------------------------------

JAVA_MULT = 0x5DEECE66D
JAVA_ADD = 0xB
JAVA_MASK = (1 << 48) - 1


class JavaRandom:
    """java.util.Random: seed = (seed * 0x5DEECE66D + 0xB) mod 2^48."""

    def __init__(self, seed: int, scramble: bool = True):
        self.seed = ((seed ^ JAVA_MULT) if scramble else seed) & JAVA_MASK

    @classmethod
    def from_state(cls, state: int) -> "JavaRandom":
        obj = cls(0, scramble=False)
        obj.seed = state & JAVA_MASK
        return obj

    def _next(self, bits: int) -> int:
        self.seed = (self.seed * JAVA_MULT + JAVA_ADD) & JAVA_MASK
        return self.seed >> (48 - bits)

    def next_int(self, signed: bool = False) -> int:
        value = self._next(32)
        if signed and value >= 1 << 31:
            value -= 1 << 32
        return value

    def next_long(self, signed: bool = False) -> int:
        hi = self._next(32)
        lo = self._next(32)
        value = (hi << 32) + lo
        if signed and value >= 1 << 63:
            value -= 1 << 64
        return value

    def next_double(self) -> float:
        hi = self._next(26)
        lo = self._next(27)
        return ((hi << 27) + lo) / float(1 << 53)

    def next_int_bound(self, bound: int) -> int:
        """Java nextInt(bound): rejection sampling, variable draws."""
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound & (bound - 1) == 0:
            return (bound * self._next(31)) >> 31
        while True:
            bits = self._next(31)
            value = bits % bound
            if bits - value + (bound - 1) >= 0:
                return value

    def next_bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            rnd = self._next(32)
            chunk = n - len(out)
            take = min(chunk, 4)
            # Java emits the low `take` bytes of the 32-bit value, little-endian.
            out.extend(rnd.to_bytes(4, "little")[:take])
        return bytes(out)


def recover_java_seed(out1: int, out2: int) -> list[int]:
    """Recover Java Random internal states from two consecutive nextInt()s.

    Returns candidate 48-bit states *after* the first output. Feed each to
    `JavaRandom.from_state` and predict the next values; verify against
    held-out outputs.
    """
    out1 &= 0xFFFFFFFF
    out2 &= 0xFFFFFFFF
    states = []
    for low in range(1 << 16):
        seed1 = ((out1 << 16) | low) & JAVA_MASK
        seed2 = (seed1 * JAVA_MULT + JAVA_ADD) & JAVA_MASK
        if (seed2 >> 16) & 0xFFFFFFFF == out2:
            states.append(seed1)
    return states


def java_random_predict(outputs: list[int], count: int = 1) -> list[list[int]] | list[int]:
    """Predict Java nextInt() values after the first two observed outputs.

    The state recovered from (out1, out2) is the state after out1, so one
    `next_int()` reproduces out2; subsequent calls are the predictions.
    """
    if len(outputs) < 2:
        raise ValueError("need at least two outputs")
    predictions = []
    for state in recover_java_seed(outputs[0], outputs[1]):
        rng = JavaRandom.from_state(state)
        if rng.next_int() != (outputs[1] & 0xFFFFFFFF):
            continue
        predictions.append([rng.next_int() for _ in range(count)])
    if len(predictions) == 1:
        return predictions[0]
    return predictions


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def recover_lcg_from_modular_outputs(outputs: list[int], modulus: int) -> tuple[int, int]:
    """Recover (a, c) when the modulus is known."""
    params = recover_lcg_parameters(outputs, modulus)
    if params is None:
        raise ValueError("could not recover LCG parameters")
    return params[1], params[2]


def crack_truncated_lcg(
    outputs: list[int],
    modulus: int,
    a: int,
    c: int,
    bits_kept: int,
    search_bits: int = 20,
) -> int | None:
    """Recover the state of an LCG leaking the top `bits_kept` bits.

    Brute-forces the unknown low `search_bits` bits of the first output and
    keeps the state consistent with every later observation. Suitable for
    small truncations only.
    """
    shift = max(0, (modulus - 1).bit_length() - bits_kept)
    limit = 1 << search_bits
    for guess in range(limit):
        x = (outputs[0] << shift) | guess
        ok = True
        cur = x
        for obs in outputs[1:]:
            cur = (a * cur + c) % modulus
            if (cur >> shift) != obs:
                ok = False
                break
        if ok:
            return x
    return None
