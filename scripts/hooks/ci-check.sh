#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  RUFF="$ROOT/.venv/bin/ruff"
  PYTEST="$ROOT/.venv/bin/pytest"
elif [[ -x "$ROOT/backend/.venv/bin/python" ]]; then
  RUFF="$ROOT/backend/.venv/bin/ruff"
  PYTEST="$ROOT/backend/.venv/bin/pytest"
else
  RUFF="ruff"
  PYTEST="pytest"
fi

echo "ci-check: ruff check app/"
(cd backend && "$RUFF" check app/)

echo "ci-check: pytest (cov>=60)"
(cd backend && "$PYTEST" tests/ -q --tb=short --cov=app --cov-fail-under=60)

echo "ci-check: frontend build"
(cd frontend && npm run build)

echo "ci-check: OK"
