#!/usr/bin/env bash
# Locate a usable Python interpreter and report optional crypto packages.
# Usage: bash env.sh
# The skill reads the PYTHON= line and uses that interpreter for solves.

set -u

candidates=()

add() {
  [ -n "${1:-}" ] && [ -x "$1" ] && candidates+=("$1")
}

# PATH first
for name in python3 python py; do
  p=$(command -v "$name" 2>/dev/null || true)
  [ -n "$p" ] && add "$p"
done

# active conda env
if [ -n "${CONDA_PREFIX:-}" ]; then
  add "$CONDA_PREFIX/bin/python"
  add "$CONDA_PREFIX/python.exe"
fi

# conda base from the conda tool
if command -v conda >/dev/null 2>&1; then
  base=$(conda info --base 2>/dev/null || true)
  [ -n "$base" ] && add "$base/bin/python" && add "$base/python.exe"
fi

# common install locations (Linux/macOS and Windows/Git-Bash)
for p in \
  "$HOME/miniconda3/bin/python" "$HOME/miniconda3/python.exe" \
  "$HOME/anaconda3/bin/python" "$HOME/anaconda3/python.exe" \
  "$HOME/miniforge3/bin/python" "$HOME/miniforge3/python.exe" \
  /opt/conda/bin/python /usr/local/bin/python3 /usr/bin/python3 \
  /c/code/miniconda/python.exe \
  /c/ProgramData/Anaconda3/python.exe \
  /c/ProgramData/miniconda3/python.exe; do
  add "$p"
done

# glob a few Windows roots without assuming a username
for p in /c/code/*conda*/python.exe /c/Users/*/miniconda3/python.exe \
         /c/Users/*/anaconda3/python.exe /c/Users/*/AppData/Local/*conda*/python.exe; do
  [ -x "$p" ] && add "$p"
done

if [ ${#candidates[@]} -eq 0 ]; then
  echo "PYTHON="
  echo "ERROR: no Python interpreter found. Install Python 3 or add it to PATH."
  exit 1
fi

PY=""
for p in "${candidates[@]}"; do
  # Skip Microsoft Store aliases and anything that is not a working Python 3.
  case "$p" in *WindowsApps*) continue ;; esac
  if "$p" -c "import sys; raise SystemExit(0 if sys.version_info[0] == 3 else 1)" >/dev/null 2>&1; then
    PY="$p"
    break
  fi
done

if [ -z "$PY" ]; then
  echo "PYTHON="
  echo "ERROR: found candidates but none is a working Python 3: ${candidates[*]}"
  exit 1
fi

echo "PYTHON=$PY"
"$PY" - <<'PYEOF'
import importlib.util, sys
mods = ["Crypto", "sympy", "gmpy2", "numpy", "z3", "pwn", "ecdsa",
        "fpylll", "galois", "hashpumpy", "py_ecc", "sageall"]
print("VERSION=" + sys.version.split()[0])
print("EXECUTABLE=" + sys.executable)
print("PACKAGES=" + " ".join(f"{m}:{'yes' if importlib.util.find_spec(m) else 'no'}" for m in mods))
missing = [m for m in ("Crypto",) if not importlib.util.find_spec(m)]
if missing:
    print("RECOMMENDED=pip install pycryptodome")
else:
    print("RECOMMENDED=ready")
PYEOF
