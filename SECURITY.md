# Security Policy

## Cryptographic design (no legal guarantees)

SecureCollab relies on the following cryptographic building blocks:

- **Homomorphic Encryption (CKKS):** Computations run on ciphertext. The server never decrypts; it returns encrypted sufficient statistics. Institutions finalize locally with a secret context that is never uploaded.
- **Study public key:** In this prototype the encryption key is the **creator's public CKKS context** (`key_source: creator_public_key`). This is not threshold DKG.
- **Result release:** After `t` institutions authorize, the server returns the **still-encrypted** result blob. Shares are authorizations, not partial decrypts.
- **Cryptographic Commitments:** Every dataset upload is bound to a commitment hash `SHA3-256(ciphertext || public_key_fingerprint || timestamp || institution_id)`.
- **Audit Trail:** All operations are logged in an append-only, hash-chained audit trail. Each entry includes `entry_hash = SHA3-256(action_type || actor || details || timestamp || previous_hash)`.
- **Codebase Integrity:** A deterministic hash of the deployed codebase is computed at startup and cached; `GET /system/integrity` returns that cached value.
- **Bundle format:** Uploaded `.bin` files are JSON + base64 TenSEAL bytes. Pickle and `secret_context` are rejected.

## Known Limitations (non-exhaustive)

- **Side-channel attacks:** TenSEAL/SEAL are not formally hardened against all side-channel attacks. For highest assurance, consider future migration to TFHE-rs or formally verified runtimes (upstream and roadmap).
- **CKKS approximation errors:** Results are approximate (floating point). Documented per algorithm; not a security issue but relevant for interpretation.
- **No formal verification:** The application code has not undergone formal verification. Security relies on design, review, and standard library use.
- **Secret key storage (SDK):** Secret keys are Fernet-wrapped with PBKDF2 (600k iterations). Empty passwords and XOR fallbacks are refused. The password never leaves the machine.

## Reporting Vulnerabilities (security only)

**Responsible disclosure:** Please do **not** report security vulnerabilities as public GitHub issues. Send details to:

**contact@synapticfour.com**

- We aim to acknowledge within **48 hours** and to provide a fix or mitigation plan within **30 days** where feasible.
- We will coordinate with you before any public disclosure.

## Dependency Policy (security only)

- Dependencies are pinned in `backend/requirements.txt` (exact versions for the main stack).
- We run **pip-audit** on pull requests and weekly (security.yml).
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

## Prototype auth (not SSO)

Accounts are email + password (PBKDF2). After login the API issues an HMAC-SHA256 access token signed with `SECRET_KEY`. Mutating routes require `Authorization: Bearer <token>`. `X-User-Email` is not identity.

- Email addresses are **not verified**. Do not register real institutional mailboxes on a public instance.
- Roles (`admin_emails`, …) still apply to the token subject. `/system/config-summary` is admin-only.
- Production (`SECURECOLLAB_PRODUCTION=1`) refuses to start with the documented development `SECRET_KEY`.
- This is not a substitute for institutional IdP/SSO. HSTS is enabled when production is set **or** `SECRET_KEY` is not the development default.

Result release shares are `SHA3-256(job_id|email|key_commitment)` and must match the commitment stored at join. Arbitrary strings (`dummy_share`) are rejected. Shares are still authorizations, not CKKS partial decrypts.

## Monitoring and logging (operator responsibility)

The application does not ship with built-in log aggregation or monitoring. For deployments that handle sensitive or regulated data, operators should:

- **Logging:** Configure backend logging (level, handlers) and ship logs to a central store. Ensure that audit-relevant events (see audit trail) are retained according to your policy. Application logs are not designed as the single source of truth for compliance; supplement with reverse-proxy and infrastructure logs as needed.
- **Monitoring:** Use health checks (`GET /system/health`) and, where appropriate, add your own metrics (e.g. error rates, latency). No Prometheus or similar stack is included by default.
- **Alerting:** Define and test alerting on failures, anomalies, and security-relevant events. The project does not provide runbooks or SLA definitions.
