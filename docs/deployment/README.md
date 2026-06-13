# SecureCollab — deployment matrix

| Scenario | Method | Doc |
|----------|--------|-----|
| **Local (one command)** | `make up` | [README](../README.md) |
| Local (manual dev) | Backend + frontend terminals | [DOCUMENTATION.md](../DOCUMENTATION.md) |
| **Production** | synapticfour-infra `compose_stack` | [README § Deployment](../README.md#deployment-synapticfour-infra) |

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
- Dispatch: GitHub Actions `workflow_dispatch` on [synapticfour-infra](https://github.com/SynapticFour/synapticfour-infra)

See synapticfour-infra `terraform/apps/securecollab/` and product README.

## Tear down (production)

Use synapticfour-infra `infrastructure.yml` with `action: destroy` for the `securecollab` app — **manual only**, not automated on push.

## Status

Proof of concept — not production-ready for real patient data. See [LEGAL_NOTES.md](../LEGAL_NOTES.md).
