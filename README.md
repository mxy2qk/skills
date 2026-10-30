# skills

funny skills

## ctf-crypto-solver

End-to-end CTF cryptography solving skill: intake/triage, attack selection, nc
oracle interaction, solve scripts and flag verification.

- `ctf-crypto-solver/SKILL.md` — entry point
- `references/` — 25 topic cards (RSA, ECC/ECDSA, EC-HNP, DH, symmetric, PRNG, lattices, LWE, PQC, ...)
- `scripts/` — `intake.py`, `flagcheck.py`, `selftest.py`, `ctfkit/`, 22 solve templates
- `assets/papers/` — curated ePrint attack-paper library with Chinese summaries and a search helper
- `evals/` — synthetic challenges + grading scripts used during development
- `ctf-crypto-solver.skill` — installable package (zip)

Install: copy `ctf-crypto-solver/` into your Claude Code skills directory, or
unpack `ctf-crypto-solver.skill` there. Self-test: `python scripts/selftest.py`.
