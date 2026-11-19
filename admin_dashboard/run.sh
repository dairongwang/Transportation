#!/usr/bin/env bash
# Admin dashboard launcher (Linux / macOS). Independent of the ServiceUber app's launcher.
#   ./run.sh          -> http://127.0.0.1:5001
#   ./run.sh --test   -> run the dashboard's tests
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
# (re)create the venv when it is missing or was made on another OS
if [ ! -f .venv/bin/activate ]; then
  echo ">> creating virtual environment"; rm -rf .venv; "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
[ -f .env ] || { cp .env.example .env; echo ">> created .env from .env.example (DUMMY secrets - dev/test only)"; }
if [ "${1:-}" = "--test" ]; then exec python -m pytest; fi
echo ">> admin dashboard on http://127.0.0.1:${ADMIN_PORT:-5001} (Ctrl+C to stop)"
exec python app.py
