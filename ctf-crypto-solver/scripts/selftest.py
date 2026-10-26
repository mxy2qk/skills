"""Run me to verify the toolkit works in this environment.

    python selftest.py

Every check is deterministic and should finish in well under a minute.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import sys
import time

from ctfkit import blockcipher as bc
from ctfkit import classical as cl
from ctfkit import dh, ecc, exotic, hashx, lattice, prng, rsa, stream, zkp
from ctfkit import pow as powkit
from ctfkit import util

PASS = 0
FAIL = []


def check(name: str, condition: bool, detail: str = ""):
    global PASS
    if condition:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL {name} {detail}")


def prime(bits: int, offset: int = 0, cond=None) -> int:
    x = (1 << (bits - 1)) + offset
    if x % 2 == 0:
        x += 1
    while not util.is_probable_prime(x) or (cond is not None and not cond(x)):
        x += 2
    return x


def solve_mod(matrix, target, q):
    """Solve matrix * x = target (mod q) by Gauss-Jordan; None if singular."""
    n = len(matrix)
    A = [list(matrix[i]) + [target[i] % q] for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if A[r][col] % q), None)
        if piv is None:
            return None
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, q)
        A[col] = [x * inv % q for x in A[col]]
        for r in range(n):
            if r != col and A[r][col] % q:
                f = A[r][col]
                A[r] = [(A[r][k] - f * A[col][k]) % q for k in range(n + 1)]
    return [A[i][n] % q for i in range(n)]


def section(name: str):
    print(f"\n[{name}]")


def test_util():
    section("util")
    check("int/bytes roundtrip", util.i2b(util.b2i(b"\x01\x02\xff")) == b"\x01\x02\xff")
    check("invmod", util.invmod(3, 11) == 4)
    check("crt", util.crt([2, 3, 2], [3, 5, 7])[0] % 105 == 23)
    check("iroot", util.iroot(10**30, 3) == 10**10)
    check("flag regex", util.find_flags("x flag{abc_def} y") == ["flag{abc_def}"])
    check("english > random", util.english_score("the quick brown fox jumps") > util.english_score("qzx vbn mkl"))


def test_pow():
    section("pow")
    text = "Give me a string such that sha256('abc' + answer) starts with 4 zeros"
    info = powkit.parse_pow(text)
    check("parse", info["prefix"] == "abc" and info["zeros"] == 4)
    res = powkit.solve_pow(prefix="abc", zeros=4)
    ok = res is not None and hashlib.sha256(("abc" + res[0]).encode()).hexdigest().startswith("0000")
    check("solve", ok)
    check("timeout", powkit.solve_pow(literal="deadbeef", time_limit=0.1) is None)


def test_dh():
    section("dh")
    p, g = 101, 2
    check("trivial g", all(dh.is_trivial_generator(v, p) for v in (0, 1, p - 1)))
    e = dh.subgroup_element(g, p, 4)
    check("subgroup element", pow(e, 4, p) == 1 and e != 1)
    h = pow(g, 37, p)
    got = dh.pohlig_hellman_fp(g, h, p)
    check("pohlig-hellman", got is not None and pow(g, got, p) == h)


def test_stream():
    section("stream")
    check("rc4 vector", stream.rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3")
    bits = [1, 0, 1, 1]
    while len(bits) < 120:
        bits.append(bits[-1] ^ bits[-4])
    check("lfsr predict", stream.lfsr_predict(bits[:80], 40) == bits[80:])
    p1, p2 = b"hello world", b"secret text"
    ks = os.urandom(len(p1))
    c1, c2 = bc.xor_bytes(p1, ks), bc.xor_bytes(p2, ks)
    hits = stream.crib_drag([c1, c2], b"hello")
    check("crib drag", any(cand == p2[:5] for _, _, _, cand in hits))


def test_exotic():
    section("exotic")
    n, g, lam, mu = exotic.paillier_keygen(61, 53)
    c1 = exotic.paillier_encrypt(1234, n, g, r=17)
    check("paillier", exotic.paillier_decrypt(c1, n, lam, mu) == 1234)
    csum = exotic.paillier_add(
        exotic.paillier_encrypt(10, n, r=3), exotic.paillier_encrypt(20, n, r=5), n
    )
    check("paillier add", exotic.paillier_decrypt(csum, n, lam, mu) == 30)
    p, gg, x = 467, 2, 123
    h = pow(gg, x, p)
    a, b = exotic.elgamal_encrypt(42, p, gg, h, 7)
    check("elgamal", exotic.elgamal_decrypt(a, b, x, p) == 42)
    bits = [0, 1, 0, 1]
    cts = [pow(5, 2, 77) * pow(6, bit, 77) % 77 for bit in bits]
    check("goldwasser-micali", exotic.gm_decrypt(cts, 7, 11) == bits)


def test_zkp():
    section("zkp")
    p = 101
    shares = [(x, (5 + 3 * x + 7 * x * x) % p) for x in (1, 2, 3)]
    check("shamir", zkp.shamir_recover(shares, p) == 5)
    q = 101
    x, r, c1, c2 = 42, 7, 3, 9
    s1 = (r + c1 * x) % q
    s2 = (r + c2 * x) % q
    check("fiat-shamir nonce reuse", zkp.fiat_shamir_nonce_reuse(s1, s2, c1, c2, q) == x)


def test_classical():
    section("classical")
    pt = (
        "The quick brown fox jumps over the lazy dog. This is a test message for classical "
        "cipher detection. The flag is flag{classical_ciphers_are_fun}."
    )
    check("caesar", "flag{" in cl.caesar_bruteforce(cl.caesar_encrypt(pt, 7))[0][2])
    check("affine", "flag{" in cl.affine_bruteforce(
        "".join(
            chr((5 * (ord(c.lower()) - 97) + 8) % 26 + 97) if c.isalpha() else c
            for c in pt
        )
    )[0][3])
    check("vigenere", cl.vigenere_bruteforce(cl.vigenere_encrypt(pt, "lemon"), 12)[0][1] == "lemon")
    check("rail fence", cl.rail_fence_bruteforce(cl.rail_fence_encrypt(pt, 4))[0][1] == 4)
    check("columnar roundtrip", cl.columnar_decrypt(cl.columnar_encrypt(pt, "zebra"), "zebra").rstrip() == pt)
    check("columnar brute", "classical" in cl.columnar_bruteforce(cl.columnar_encrypt(pt, "zebra"), 6)[0][2])
    fwd = {c: "qwertyuiopasdfghjklzxcvbnm"[i] for i, c in enumerate(cl.ALPHABET)}
    ct = "".join(fwd[c.lower()] if c.isalpha() else c for c in pt)
    check("substitution", "flag{" in cl.substitution_hillclimb(ct, restarts=3, iterations=1500)[0][2])
    data = pt.encode()
    check("repeating xor", cl.repeating_xor_bruteforce(cl.repeating_key_xor(data, b"secret"), 12)[0][1] == b"secret")


def test_rsa():
    section("rsa")
    p, q = prime(256, 0), prime(256, 1 << 200)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    m = 0x123456789ABC
    check("decrypt", rsa.decrypt_bytes(pow(m, e, n), pow(e, -1, phi), n) == m.to_bytes(6, "big"))
    check("small e", rsa.small_e_root(pow(m, 3, n), 3, n) == m)
    check("common modulus", rsa.common_modulus(n, 17, 65537, pow(m, 17, n), pow(m, 65537, n)) == m)
    mods = [
        prime(256, i << 200) * prime(256, (i + 3) << 200) for i in range(3)
    ]
    check("hastad", rsa.hastad_broadcast([pow(m, 3, N) for N in mods], mods, 3) == m)
    pw, qw = prime(256, 0), prime(256, 1 << 200)
    phiw = (pw - 1) * (qw - 1)
    d = prime(64, 300)
    while math.gcd(d, phiw) != 1:
        d += 2
    check("wiener", rsa.wiener(pw * qw, pow(d, -1, phiw)) == d)
    pf = prime(256, 400)
    qf = pf + 2
    while not util.is_probable_prime(qf):
        qf += 2
    check("fermat", rsa.fermat_factor(pf * qf) == (pf, qf))
    check("from phi", set(rsa.factor_from_phi(n, phi)) == {p, q})
    check("from d", set(rsa.factor_from_d(n, e, pow(e, -1, phi))) == {p, q})
    check("dp leak", rsa.factor_from_dp(n, e, pow(e, -1, p - 1)) is not None)
    check("franklin reiter", rsa.franklin_reiter(pow(m, 3, n), pow(m + 1, 3, n), 3, n) == m)
    pr, qr = prime(128, 0), prime(128, 1 << 100)
    nr = pr * qr
    mr = random.randrange(2, nr)
    check("rabin", mr in rsa.rabin_roots(pow(mr, 2, nr), pr, qr))

    # LSB parity oracle
    p2 = prime(256, 0)
    q2 = prime(256, 1 << 200)
    n2 = p2 * q2
    phi2 = (p2 - 1) * (q2 - 1)
    e2 = 65537
    m2 = int.from_bytes(b"flag{lsb_oracle_works}", "big")
    c2 = pow(m2, e2, n2)
    d2 = pow(e2, -1, phi2)

    def verify_lsb(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return b.startswith(b"flag{") and b.endswith(b"}")

    check(
        "lsb oracle",
        rsa.lsb_oracle_attack(lambda ct: pow(ct, d2, n2) & 1, c2, e2, n2, verify=verify_lsb)
        == m2,
    )

    # CRT fault
    sig = pow(m2, d2, n2)
    faulty = (sig + p2 * 12345) % n2
    check("crt fault", rsa.crt_fault_factor(n2, e2, m2, faulty) is not None)

    # gcd(e, phi) > 1: enumerate roots
    p3 = prime(128, 0, cond=lambda x: x % 3 == 1)
    q3 = prime(128, 1 << 100, cond=lambda x: x % 3 == 1)
    n3 = p3 * q3
    m3 = int.from_bytes(b"flag{non_coprime_root}", "big")
    c3 = pow(m3, 3, n3)
    check("nth roots", m3 in rsa.nth_roots_mod(c3, 3, p3, q3))

    # Manger threshold oracle
    p4 = prime(128, 0)
    q4 = prime(128, 1 << 90)
    n4 = p4 * q4
    phi4 = (p4 - 1) * (q4 - 1)
    d4 = pow(65537, -1, phi4)
    k4 = (n4.bit_length() + 7) // 8
    B4 = 1 << (8 * (k4 - 1))
    m4 = B4 // 2 + 1234567
    c4 = pow(m4, 65537, n4)
    check(
        "manger",
        rsa.manger_attack(
            lambda ct: pow(ct, d4, n4) < B4, n4, 65537, c4, max_queries=100000
        )
        == m4,
    )


def test_lattice():
    section("lattice")
    p = (1 << 255) + 12345
    while not util.is_probable_prime(p):
        p += 2
    q = (1 << 255) + 987654321
    while not util.is_probable_prime(q):
        q += 2
    N = p * q
    m = 0xDEADBEEF
    check("coppersmith", m in lattice.coppersmith_univariate([-pow(m, 3, N), 0, 0, 1], N, beta=1.0, X=1 << 40))
    shift = 20
    check("partial p", lattice.factor_with_known_high_bits(N, p >> shift, shift) is not None)

    # ECDSA partial-nonce HNP
    q = 2**64 - 59
    rng = random.Random(5)
    d_hnp = rng.randrange(1, q)
    W = 1 << 8
    rs, ss, hs, leaked = [], [], [], []
    for _ in range(12):
        delta = rng.randrange(W)
        li = rng.randrange(1, (q - delta) // W)
        k = li * W + delta
        r = rng.randrange(1, q)
        h = rng.randrange(1, q)
        s = pow(k, -1, q) * (h + r * d_hnp) % q
        rs.append(r)
        ss.append(s)
        hs.append(h)
        leaked.append(li)
    check("ecdsa hnp", d_hnp in lattice.ecdsa_partial_nonce_recover(q, rs, ss, hs, leaked, 8))

    # Low-density subset sum
    rng = random.Random(6)
    weights = [rng.randrange(1, 1 << 60) for _ in range(16)]
    bits = [rng.randrange(2) for _ in range(16)]
    target = sum(w * b for w, b in zip(weights, bits))
    got = lattice.subset_sum_solve(weights, target)
    check(
        "subset sum",
        got is not None and all(b in (0, 1) for b in got)
        and sum(w * b for w, b in zip(weights, got)) == target,
    )

    # LWE/CVP
    rng = random.Random(11)
    n_lwe, m_lwe, q_lwe = 8, 16, 97
    s_lwe = [rng.choice([-1, 0, 1]) for _ in range(n_lwe)]
    e_lwe = [rng.randrange(-2, 3) for _ in range(m_lwe)]
    A_lwe = [[rng.randrange(q_lwe) for _ in range(n_lwe)] for _ in range(m_lwe)]
    b_lwe = [
        (sum(A_lwe[i][j] * s_lwe[j] for j in range(n_lwe)) + e_lwe[i]) % q_lwe
        for i in range(m_lwe)
    ]
    got_s, _got_e = lattice.lwe_cvp_solve(A_lwe, b_lwe, q_lwe)
    check("lwe cvp", got_s == s_lwe)

    # NTRU (toy parameters)
    N_ntru, q_ntru = 12, 97
    rng = random.Random(12)
    h_ntru = None
    for _ in range(50):
        f_ntru = [rng.choice([-1, 0, 1]) for _ in range(N_ntru)]
        g_ntru = [rng.choice([-1, 0, 1]) for _ in range(N_ntru)]
        if not any(f_ntru):
            continue
        F = [[0] * N_ntru for _ in range(N_ntru)]
        for c in range(N_ntru):
            for i in range(N_ntru):
                d = c - i
                F[c][i] = f_ntru[d % N_ntru] * (-1 if d < 0 else 1) % q_ntru
        h_ntru = solve_mod(F, g_ntru, q_ntru)
        if h_ntru is not None:
            break
    cands = lattice.ntru_recover(h_ntru, q_ntru, True, max_coeff=2) if h_ntru else []
    check(
        "ntru",
        any(
            lattice.ntru_mul(h_ntru, f2, q_ntru, True) == [x % q_ntru for x in g2]
            for f2, g2 in cands
        ),
    )


def test_prng():
    section("prng")
    m, a, c, seed = 2**31 - 1, 1103515245, 12345, 42
    g = prng.LCG(m, a, c, seed)
    out = [next(g) for _ in range(10)]
    check("lcg params", prng.recover_lcg_parameters(out) == (m, a, c))
    rnd = random.Random(7)
    obs = [rnd.getrandbits(32) for _ in range(624)]
    nxt = [rnd.getrandbits(32) for _ in range(5)]
    check("mt clone", prng.mt19937_predict(obs, 5) == nxt)
    check("temper", prng.untemper(prng.temper(0xDEADBEEF)) == 0xDEADBEEF)
    jr = prng.JavaRandom(12345)
    jouts = [jr.next_int() for _ in range(14)]
    check("java random", prng.java_random_predict(jouts[:2], 12) == jouts[2:])


def test_blockcipher():
    section("blockcipher")
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("  skip (pycryptodome not installed)")
        return
    key, iv = os.urandom(16), os.urandom(16)
    pt = b"The flag is flag{block_modes_work}. Padding oracle demo text."
    ct = bc.aes_cbc_encrypt(pt, key, iv)
    check("cbc roundtrip", bc.aes_cbc_decrypt(ct, key, iv) == pt)
    check("ecb detect", bc.detect_ecb(AES.new(key, AES.MODE_ECB).encrypt(b"A" * 64)))
    secret = b"secret flag{byte_at_a_time_ecb}"

    def ecb_oracle(data):
        return AES.new(key, AES.MODE_ECB).encrypt(bc.pkcs7_pad(data + secret))

    check("byte-at-a-time", bc.byte_at_a_time_ecb_decrypt(ecb_oracle, 16) == secret)

    def pad_oracle(msg):
        if len(msg) < 16 or len(msg) % 16:
            return False
        try:
            bc.pkcs7_unpad(AES.new(key, AES.MODE_CBC, msg[:16]).decrypt(msg[16:]))
            return True
        except Exception:
            return False

    check("padding oracle", bc.padding_oracle_attack(pad_oracle, iv + ct, 16) == bc.pkcs7_pad(pt))
    ks = os.urandom(20)
    p1, p2 = b"known message here!!", b"unknown secret two!!"
    check("ctr reuse", bc.ctr_reuse_recover(bc.xor_bytes(p1, ks), p1, bc.xor_bytes(p2, ks)) == p2)

    # CTR bit-flipping
    ctr_key, ctr_nonce = os.urandom(16), os.urandom(8)
    ctr_pt = b"role=user&admin=0"
    ctr_ct = AES.new(ctr_key, AES.MODE_CTR, nonce=ctr_nonce).encrypt(ctr_pt)
    off = ctr_pt.index(b"admin=0")
    forged_ct = bc.ctr_bitflip(ctr_ct, off, b"admin=0", b"admin=1")
    check(
        "ctr bitflip",
        AES.new(ctr_key, AES.MODE_CTR, nonce=ctr_nonce).decrypt(forged_ct)
        == b"role=user&admin=1",
    )

    # AES-GCM nonce reuse: recover H and forge a tag
    gkey, gnonce = os.urandom(16), os.urandom(12)
    gp1, gp2 = os.urandom(16), os.urandom(16)
    gp3 = b"flag{gcm_forged!}"
    c1, t1 = AES.new(gkey, AES.MODE_GCM, nonce=gnonce).encrypt_and_digest(gp1)
    c2, t2 = AES.new(gkey, AES.MODE_GCM, nonce=gnonce).encrypt_and_digest(gp2)
    h, j0 = bc.gcm_nonce_reuse_forge(c1, t1, c2, t2)
    c3 = bc.xor_bytes(gp3.ljust(16, b"\x00")[:16], bc.xor_bytes(c1, gp1))
    tag3 = bc.gcm_forge_tag(h, j0, b"", c3)
    try:
        AES.new(gkey, AES.MODE_GCM, nonce=gnonce).decrypt_and_verify(c3, tag3)
        gcm_ok = True
    except Exception:
        gcm_ok = False
    check("gcm forge", gcm_ok)


def test_ecc():
    section("ecc")
    p = 2**256 - 2**32 - 977
    G = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    curve = ecc.Curve(p, 0, 7)
    check("secp256k1 order", curve.mul(n, G) is None)
    d, k, z1, z2 = 12345, 67890, 111, 222
    r = curve.mul(k, G)[0] % n
    s1 = pow(k, -1, n) * (z1 + r * d) % n
    s2 = pow(k, -1, n) * (z2 + r * d) % n
    check("ecdsa nonce reuse", ecc.ecdsa_recover_private_key(r, s1, s2, z1, z2, n) == (k, d))
    small = ecc.Curve(1009, 1, 1)
    g = (0, 1)
    order = 0
    cur = None
    while True:
        cur = small.add(cur, g)
        order += 1
        if cur is None:
            break
    check("pohlig-hellman", ecc.pohlig_hellman(small, g, small.mul(137, g), order) == 137)
    node = ecc.Curve(101, (-3 * 4) % 101, (2 * 8) % 101)
    check("singular node", ecc.singular_curve_dlog(node, (0, 97), node.mul(37, (0, 97))) == 37)
    cusp = ecc.Curve(101, 0, 0)
    check("cusp", ecc.singular_curve_dlog(cusp, (1, 1), cusp.mul(23, (1, 1))) == 23)


def test_hash():
    section("hashx")
    secret, message, append = b"secret123", b"user=guest", b"&role=admin"
    for algo, h in [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)]:
        check(f"{algo} plain", hashx.hash_bytes(algo, b"abc" * 100) == h(b"abc" * 100).digest())
        tail, digest = hashx.length_extension(
            algo, h(secret + message).digest(), len(secret) + len(message), append
        )
        check(f"{algo} extension", h(secret + message + tail).digest() == digest)


def test_scripts():
    section("scripts")
    import pathlib
    import tempfile

    import flagcheck
    import intake

    check("flagcheck", flagcheck.extract_flags("x flag{abc_def} y")[0]["value"] == "flag{abc_def}")
    check("flag crib", flagcheck.flag_crib("the flag is flag{abc}") == b"flag{")
    with tempfile.TemporaryDirectory() as td:
        pathlib.Path(td, "output.txt").write_text(
            "n = 12345678901234567890123456789012345678901234567890\n"
            "e = 3\nc = 12345\n",
            encoding="utf-8",
        )
        report = intake.analyze(td)
        check("intake RSA", any(h["name"] == "RSA" for h in report["hypotheses"]))


def main():
    start = time.time()
    test_util()
    test_pow()
    test_classical()
    test_rsa()
    test_lattice()
    test_prng()
    test_dh()
    test_stream()
    test_exotic()
    test_zkp()
    test_blockcipher()
    test_ecc()
    test_hash()
    test_scripts()
    print(f"\n{PASS} checks passed, {len(FAIL)} failed, {time.time() - start:.1f}s")
    if FAIL:
        print("failed:", ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
