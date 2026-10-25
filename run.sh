#!/usr/bin/env bash
# Sherlock - macOS / Linux launcher. Creates .venv, installs requirements, starts the server.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  echo "Creating virtual environment in .venv..."
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

echo "Installing requirements..."
python -m pip install -q -r requirements.txt

URL="http://127.0.0.1:8000"
echo "Starting Sherlock at $URL (Ctrl+C to stop)"
(
  sleep 3
  if command -v open >/dev/null 2>&1; then open "$URL"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  fi
) >/dev/null 2>&1 &

exec python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
