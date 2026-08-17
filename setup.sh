#!/usr/bin/env bash
# One-command setup for the API Attack-Path & Authorization Tester.
#
#   ./setup.sh            installs into a local .venv
#   ./setup.sh --lab      also starts the vulnerable lab afterwards
#
# Safe to re-run - it's idempotent.
set -euo pipefail
cd "$(dirname "$0")"

BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
info()  { echo -e "${BOLD}==>${RESET} $1"; }
ok()    { echo -e "${GREEN}✓${RESET} $1"; }
warn()  { echo -e "${YELLOW}!${RESET} $1"; }
fail()  { echo -e "${RED}✗ $1${RESET}"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Check for Python 3.10+
# ---------------------------------------------------------------------------
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    fail "python3 not found. On Kali/Debian: sudo apt install -y python3 python3-venv python3-pip"
fi

PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
PY_OK=$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')
if [ "$PY_OK" != "1" ]; then
    fail "Python 3.10+ required, found $PY_VERSION."
fi
ok "Found Python $PY_VERSION"

# ---------------------------------------------------------------------------
# 2. Ensure venv module is available (Debian/Kali split it into a separate package)
# ---------------------------------------------------------------------------
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    warn "python3-venv missing. Attempting to install it (requires sudo)..."
    if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y python3-venv python3-pip
    else
        fail "Could not auto-install python3-venv. Install it manually for your distro and re-run."
    fi
fi

# ---------------------------------------------------------------------------
# 3. Create / reuse the virtual environment
# ---------------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    info "Creating virtual environment in .venv/"
    "$PYTHON_BIN" -m venv .venv
else
    ok "Reusing existing .venv/"
fi

VENV_PY=".venv/bin/python"
VENV_PIP=".venv/bin/pip"

# ---------------------------------------------------------------------------
# 4. Install dependencies (pinned versions, including the click compat pin)
# ---------------------------------------------------------------------------
info "Installing dependencies (this can take a minute)..."
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet -r requirements-dev.txt
"$VENV_PIP" install --quiet -e .
ok "Dependencies installed"

# ---------------------------------------------------------------------------
# 5. Sanity check the CLI actually runs
# ---------------------------------------------------------------------------
if "$VENV_PY" -m apiattack.cli list-checks >/dev/null 2>&1; then
    ok "apiattack CLI verified working"
else
    fail "apiattack CLI failed to run. Try: source .venv/bin/activate && apiattack list-checks  (to see the full error)"
fi

echo
echo -e "${GREEN}${BOLD}Setup complete.${RESET}"
echo "Activate the environment in new terminals with:"
echo "    source .venv/bin/activate"
echo
echo "Quick start:"
echo "    make lab-scan     # start the vulnerable lab and run a full demo scan"
echo "  or manually:"
echo "    source .venv/bin/activate"
echo "    cd lab && python app.py &"
echo "    cd .. && python3 scripts/generate_lab_config.py http://localhost:8000"
echo "    apiattack scan --spec examples/openapi_lab.yaml --config examples/roles_lab.yaml \\"
echo "        --out ./report --yes-i-am-authorized"

# ---------------------------------------------------------------------------
# 6. Optional: --lab flag runs the whole demo immediately
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--lab" ]; then
    echo
    info "Running the demo lab scan now (--lab was passed)..."
    exec make lab-scan
fi
