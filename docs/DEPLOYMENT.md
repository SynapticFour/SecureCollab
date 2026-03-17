# SPDX-License-Identifier: Apache-2.0

## Deployment Notes (non-production, no guarantees)

This file outlines a **technical** sequence for deploying SecureCollab (environment, Docker, reverse proxy, basic backups). It does **not** constitute legal advice, a security benchmark, or a guarantee that any given deployment is compliant or sufficient for a particular purpose (e.g. clinical production use).

For legal and compliance considerations, see:

- `LEGAL_NOTES.md` – internal wording guidelines and high-level legal caveats.
- `docs/DECISION_MAKER.md` – overview for institutions and decision makers.
- `SECURITY.md` and `docs/OWASP_ANALYSIS.md` – technical security design and open points.

---

## 1. Environments

- **Demo / local development**
  - Single VM or laptop, SQLite, self-signed TLS or HTTP only.
  - Intended **only** for development and demonstrations with synthetic or non-personal data.

- **Pre-production / test**
  - Dedicated VM, PostgreSQL, proper TLS certificates (e.g. Let’s Encrypt), separated from production data.
  - Use for integration tests, performance tests, and security reviews.

- **Production (if ever used)**
  - Requires:
    - managed database (e.g. PostgreSQL),
    - hardened OS and container runtime,
    - proper TLS termination and key management,
    - monitoring, logging, alerting,
    - backup and disaster-recovery procedures.
  - The concrete setup must be designed and reviewed by the operating institution’s security and operations teams.

---

## 2. Backups and Disaster Recovery

- This repository does **not** ship a complete backup/restore solution.
- Each institution operating an instance is responsible for:
  - creating, encrypting and testing backups of:
    - the database,
    - uploaded encrypted datasets,
    - configuration and secrets (where appropriate),
  - defining retention, restore procedures and RPO/RTO targets.
- No guarantee is given that the example configuration ensures data availability or regulatory-compliant retention.

---

## 3. Example High-Level Steps (to be adapted)

The following is a **starting point** for technical teams, not a hard requirement or audited standard:

1. Prepare environment
   - Harden base OS (patches, minimal packages, firewall).
   - Install Docker / container runtime.

2. Configure environment variables
   - Use `.env` / secret management for:
     - `DATABASE_URL`,
     - `SECRET_KEY`,
     - upload directories,
     - CORS origins,
     - rate limits (if exposed as env vars).
   - Do **not** commit secrets to git.

3. Deploy backend
   - Build backend image from `backend/Dockerfile`.
   - Run container with:
     - read-only filesystem where possible,
     - volume for uploads and logs,
     - restricted network access.

4. Deploy frontend
   - Build Next.js app and serve via a hardened web server or managed service.

5. Reverse proxy (nginx, Traefik, …)
   - Terminate TLS,
   - forward to backend/frontend,
   - enforce security headers (CSP, HSTS where appropriate),
   - optionally add basic rate limiting and IP allowlists.

6. Monitoring and logging
   - Collect logs (backend, reverse proxy, OS) centrally.
   - Define alerting thresholds for errors, resource exhaustion, suspicious traffic.

---

## 4. Monitoring and Logging (out of the box)

The application does **not** ship with a built-in log aggregation or monitoring stack. Operators are responsible for:

- **Logs:** Backend uses Python `logging`; configure level and handlers via environment or standard logging config. Forward stdout/stderr (e.g. Docker logs, journald, or a log shipper) to your central logging solution. No guarantee is given that log content is sufficient for compliance or forensics.
- **Metrics:** No Prometheus/StatsD exporters are included. For availability and performance monitoring, use health checks (`GET /system/health`), reverse-proxy metrics, or add your own instrumentation.
- **Alerting:** Define your own thresholds (e.g. health check failures, disk usage, error rates). The project does not provide runbooks or SLA targets.

See also `SECURITY.md` for security-relevant logging recommendations.

---

## 5. Security and Compliance Checklist (non-exhaustive)

Before handling sensitive or personal data, operating institutions should at minimum:

- Verify:
  - TLS configuration and certificate management,
  - access control around the instance (VPN, IP allowlists, firewall),
  - that secrets (DB password, keys) are stored securely.
- Conduct:
  - a vulnerability scan of images and host,
  - at least one penetration test or external security review of the concrete deployment.
- Clarify:
  - who is responsible for incident response,
  - how security incidents are detected, documented, and reported,
  - how data export and deletion requests would be implemented.

All of the above is for orientation only and does **not** replace an institution’s own security and compliance processes.

---

## 6. How to run a pilot

For a **controlled pilot** with one or a few partner institutions (e.g. synthetic or anonymised data):

1. **Deploy** a dedicated instance (see above). Use a separate database and upload storage from any production system.
2. **Legal and governance:** Agree with participants on data use, roles (controller/processor), and exit (export/deletion). Use the templates in `docs/IMPRINT_TEMPLATE.md` and `docs/PRIVACY_TEMPLATE.md` only as a starting point; have them reviewed by legal counsel.
3. **Access:** Restrict network access (VPN or IP allowlist) and use strong secrets. Document who has access to the instance and to key shares.
4. **Demo seed (optional):** For a quick showcase, use the demo stack: `docker compose -f infra/docker-compose.demo.yml up -d`, then run the seed once: `docker compose -f infra/docker-compose.demo.yml run --rm seed`. This creates a pre-filled demo study; see `backend/scripts/seed_demo.py`.
5. **Verification:** Share the codebase hash from `GET /system/integrity` with participants so they can verify the deployed version against the reviewed code.
6. **Feedback:** Collect operational and UX feedback; plan iterations (e.g. auth, monitoring, backup procedures) before scaling.

This section is for orientation only and does not constitute legal or project-management advice.

