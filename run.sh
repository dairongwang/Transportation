#!/usr/bin/env bash
# Linux / macOS launcher: creates a venv, installs deps, prepares .env, starts the app.
#   ./run.sh            -> http://127.0.0.1:5000
#   ./run.sh --lan      -> also reachable from phones/tablets on the same Wi-Fi
#   ./run.sh --check    -> only run the environment doctor
#   ./run.sh --test     -> only run the test suite
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
if [ ! -d .venv ]; then
  echo ">> creating virtual environment"; "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
[ -f .env ] || { cp .env.example .env; echo ">> created .env from .env.example (DUMMY secrets - dev/test only)"; }

case "${1:-}" in
  --check) exec python scripts/check_env.py ;;
  --test)  exec python -m pytest ;;
  --lan)   export HOST=0.0.0.0 ;;
esac
python scripts/check_env.py || { echo "Environment check failed"; exit 1; }
echo ">> starting app (Ctrl+C to stop)"
exec python app.py
