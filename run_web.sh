#!/usr/bin/env bash
# Sent Eye web application startup script.
#   PORT / HOST environment variables (default 127.0.0.1:8000)
#   For local Codespaces port-forwarding: HOST=0.0.0.0 bash run_web.sh
set -euo pipefail

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"

echo "Sent Eye web — http://${HOST}:${PORT}"
echo "  Health  : http://${HOST}:${PORT}/health"
echo "  Modules : http://${HOST}:${PORT}/api/modules"
echo

exec python -m uvicorn backend.main:app --host "$HOST" --port "$PORT"
