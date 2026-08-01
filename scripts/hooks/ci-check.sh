#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "ci-check: ruff check app/"
(cd backend && ruff check app/)

echo "ci-check: pytest (cov>=60)"
(cd backend && pytest tests/ -q --tb=short --cov=app --cov-fail-under=60)

echo "ci-check: frontend build"
(cd frontend && npm run build)

echo "ci-check: OK"
