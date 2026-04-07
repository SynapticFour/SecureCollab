# Security Policy

## Cryptographic design (no legal guarantees)

SecureCollab relies on the following cryptographic building blocks:

- **Homomorphic Encryption (CKKS):** Computations run on ciphertext; the platform is designed so that it does not need plaintext patient data. In the intended protocol, only the combination of threshold key shares can decrypt results.
- **Threshold Key Generation:** The full secret key is intended never to exist in one place. Decryption is designed to require at least `t` of `n` participants' key shares.
- **Cryptographic Commitments:** Every dataset upload is bound to a commitment hash `SHA3-256(ciphertext || public_key_fingerprint || timestamp || institution_id)`. This provides cryptographic evidence about which key was used and reduces the risk of unnoticed data swaps after upload.
- **Audit Trail:** All operations are logged in an append-only, hash-chained audit trail. Each entry includes `entry_hash = SHA3-256(action_type || actor || details || timestamp || previous_hash)`. Under the stated assumptions, tampering should be technically detectable.
- **Codebase Integrity:** A deterministic hash of the deployed codebase is computed at startup and included in every audit log entry. Institutions can compare this with a locally computed hash to assess whether the running instance matches a reviewed code version via `GET /system/integrity`.

- **Deserialization (pickle):** Uploaded `.bin` files are deserialized with `pickle`. Only trusted institutions upload; consider validating bundle structure before use (see `docs/OWASP_ANALYSIS.md`).

## Known Limitations (non-exhaustive)

- **Side-channel attacks:** TenSEAL/SEAL are not formally hardened against all side-channel attacks. For highest assurance, consider future migration to TFHE-rs or formally verified runtimes (upstream and roadmap).
- **CKKS approximation errors:** Results are approximate (floating point). Documented per algorithm; not a security issue but relevant for interpretation.
- **No formal verification:** The application code has not undergone formal verification. Security relies on design, review, and standard library use.
- **Secret key storage (SDK):** Secret keys are protected by password-derived encryption (PBKDF2 + Fernet when `cryptography` is installed). The password never leaves the machine. Fallback uses a simpler scheme; prefer installing `cryptography` for production.

## Reporting Vulnerabilities (security only)

**Responsible disclosure:** Please do **not** report security vulnerabilities as public GitHub issues. Send details to:

**contact@synapticfour.com**

- We aim to acknowledge within **48 hours** and to provide a fix or mitigation plan within **30 days** where feasible.
- We will coordinate with you before any public disclosure.

## Dependency Policy (security only)

- Dependencies are pinned in `backend/requirements.txt` (exact or minimal compatible versions).
- We run **pip-audit** (or equivalent) regularly (e.g. via CI) to check for known CVEs.
- Updates are applied after review; security-relevant patches are prioritised.

## External audits (planned, not completed)

- Cryptographic design and key lifecycle.
- File upload and input validation (path traversal, size limits, allowed extensions).
- Algorithm registry and absence of code injection (no `eval`/user-supplied code execution).
- Rate limiting and denial-of-service resilience.
- Security headers and transport (TLS, HSTS in production).
- Error handling (no sensitive data or stack traces to clients).
- Dependency supply chain and CVE process.

**Honest statement:** This project has not yet undergone an independent external security audit or legal review. The above measures describe technical mechanisms and do not replace a formal security or compliance assessment for high-assurance deployments. Institutions should obtain their own expert advice for their specific use case.

## Lightweight auth & roles for pilots (no production guarantee)

For demos and small pilots, SecureCollab supports a **header-based, lightweight auth/role model**:

- Clients can send an `X-User-Email` header.
- The backend maps this email to a simple role based on configuration lists (`admin_emails`, `provider_emails`, `researcher_emails`) in `app.config.settings`.
- Example (environment variables, to be adapted per deployment):
  - `ADMIN_EMAILS=admin1@example.com,admin2@example.com`
  - `PROVIDER_EMAILS=provider@example.com`
  - `RESEARCHER_EMAILS=researcher@example.com`

Important:

- This is designed for **controlled pilots** and internal demos, not as a full auth system.
- It does **not** implement passwords, SSO, MFA, token expiry or session management.
- It is not a substitute for institutional identity management (IdP, SSO, etc.).
- For a production deployment, institutions should integrate with their own auth/SSO and enforce roles according to their policies.

Currently, `/system/config-summary` is restricted to users with the `admin` role (as derived from the header and configuration). Additional endpoints can be wired to these role checks in future iterations as required by the operating institution.

## Monitoring and logging (operator responsibility)

The application does not ship with built-in log aggregation or monitoring. For deployments that handle sensitive or regulated data, operators should:

- **Logging:** Configure backend logging (level, handlers) and ship logs to a central store. Ensure that audit-relevant events (see audit trail) are retained according to your policy. Application logs are not designed as the single source of truth for compliance; supplement with reverse-proxy and infrastructure logs as needed.
- **Monitoring:** Use health checks (`GET /system/health`) and, where appropriate, add your own metrics (e.g. error rates, latency). No Prometheus or similar stack is included by default.
- **Alerting:** Define and test alerting on failures, anomalies, and security-relevant events. The project does not provide runbooks or SLA definitions.
