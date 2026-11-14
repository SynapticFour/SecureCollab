# SecureCollab — deployment matrix

| Scenario | Method | Doc |
|----------|--------|-----|
| **Local (one command)** | `make up` | [README](../../README.md) |
| Local (manual dev) | Backend + frontend terminals | [DOCUMENTATION.md](../../DOCUMENTATION.md) |
| **Production** | workflow in this repository | [README § Deployment](../../README.md#deployment) |

## Prerequisites

- Docker (for `make up`)
- Python 3.11 + Node 18+ (for manual dev)

## Local lifecycle

```bash
make up        # http://localhost:3000
make down      # stop; keep volumes
make destroy   # remove volumes
```

Secondary: `./scripts/stack.sh up|down|destroy`, `docker compose -f infra/docker-compose.yml …`

## Production (synapticfour-infra)

- App catalog entry: `securecollab`
- Domain: `securecollab.synapticfour.tech`
- Dispatch: `.github/workflows/ghcr-infra.yml` posts a deploy event when `INFRA_DISPATCH_TOKEN` is set. The operator tree names `terraform/apps/securecollab/`. This page does not link that other repository.

## Tear down (production)

Tear-down uses that operator tree's `infrastructure.yml` with `action: destroy` for the `securecollab` app. It is manual only, not automated on push. This page does not link that repository.

## Status

Proof of concept — not for real patient data. See [LEGAL_NOTES.md](../../LEGAL_NOTES.md).
