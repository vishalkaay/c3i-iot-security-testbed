#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# C3i Hub IoT Security Testbed - installer (office PC / workstation / Pi).
# Idempotent. Run from the repository root:  bash deploy/install.sh
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
VENV="$ROOT/.venv"

echo "==> Checking Python"
"$PY" -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"' \
  || { echo "Python 3.11+ is required"; exit 1; }

echo "==> Creating virtual environment"
[ -d "$VENV" ] || "$PY" -m venv --system-site-packages "$VENV"
"$VENV/bin/pip" install -q -U pip wheel

echo "==> Installing backend dependencies"
EXTRAS="dev"
if grep -qi raspberry /proc/cpuinfo 2>/dev/null; then
  echo "    Raspberry Pi detected - adding hardware extras"
  EXTRAS="dev,hardware"
fi
"$VENV/bin/pip" install -q -e ".[${EXTRAS}]"

echo "==> Preparing environment file"
if [ ! -f .env ]; then
  cp .env.example .env
  SECRET="$("$VENV/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))')"
  "$VENV/bin/python" - "$SECRET" <<'PY'
import sys, pathlib
p = pathlib.Path(".env"); s = p.read_text()
p.write_text(s.replace("change-me-in-production-please-32-bytes-min", sys.argv[1]))
PY
  echo "    Wrote .env with a fresh SECRET_KEY - review it before production use."
else
  echo "    .env already exists - leaving it untouched."
fi

echo "==> Building the web console (if Node is available)"
if command -v npm >/dev/null 2>&1; then
  (cd web && npm install --no-audit --no-fund && npm run build)
else
  echo "    npm not found - skipping. The API still runs; install Node 18+ to build the console."
fi

echo "==> Seeding database"
(cd backend && "$VENV/bin/python" -m app.cli seed)

cat <<EOF

==================================================================
 Installation complete.

   Start the API + console:
       source .venv/bin/activate
       cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8080

   Or run the diagnostics:
       cd backend && ../.venv/bin/python -m app.cli doctor

   Open:  http://<this-host>:8080
   Docs:  http://<this-host>:8080/docs

   IMPORTANT: the bootstrap admin password is in .env (C3I_ADMIN_PASSWORD).
   Change it on first login. Invasive modules stay disabled until you set
   C3I_ENABLE_INVASIVE=true AND sign a Rules of Engagement per engagement.
==================================================================
EOF
