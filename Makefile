# SecureCollab — Synaptic Four unified local lifecycle

.PHONY: help up down destroy

help:
	@echo "SecureCollab — local lifecycle"
	@echo ""
	@echo "  make up        Start backend + frontend (Docker Compose)"
	@echo "  make down      Stop stack; keep volumes"
	@echo "  make destroy   Stop stack; remove volumes"
	@echo ""
	@echo "Also: ./scripts/stack.sh up|down|destroy"
	@echo "Dev without Docker: see README (split backend + frontend terminals)"

up:
	@chmod +x scripts/stack.sh 2>/dev/null || true
	./scripts/stack.sh up

down:
	@chmod +x scripts/stack.sh 2>/dev/null || true
	./scripts/stack.sh down

destroy:
	@chmod +x scripts/stack.sh 2>/dev/null || true
	./scripts/stack.sh destroy
