#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi
if [[ -f .env.local ]]; then
  set -a
  source .env.local
  set +a
fi
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
if [[ ! -x .venv/bin/gunicorn ]]; then
  .venv/bin/pip install -r requirements.txt
fi
exec .venv/bin/gunicorn --config gunicorn.conf.py --bind "${HOST:-127.0.0.1}:${PORT:-5000}" --workers 1 --threads 12 --timeout 90 app:app
