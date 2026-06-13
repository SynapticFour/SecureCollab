#!/usr/bin/env bash
# SecureCollab — local full stack (backend + frontend via Docker Compose).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -f infra/docker-compose.yml)

usage() {
  cat <<'EOF'
Usage: scripts/stack.sh <up|down|destroy>

  up        Build and start backend + frontend
  down      Stop stack; keep volumes
  destroy   Stop stack; remove volumes
EOF
}

cmd="${1:-}"
case "$cmd" in
  up)
    "${COMPOSE[@]}" up -d --build
    echo ""
    echo "SecureCollab is up:"
    echo "  Frontend: http://localhost:3000"
    echo "  Backend:  http://localhost:8000"
    ;;
  down)
    "${COMPOSE[@]}" down --remove-orphans
    echo "SecureCollab stopped (volumes kept)."
    ;;
  destroy)
    "${COMPOSE[@]}" down -v --remove-orphans
    echo "SecureCollab stack destroyed (volumes removed)."
    ;;
  -h|--help|"")
    usage
    exit 0
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage >&2
    exit 2
    ;;
esac
