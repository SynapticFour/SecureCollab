# Changelog

All notable changes to this project will be documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed

- Password + HMAC Bearer tokens (`POST /auth/register`, `/auth/login`). `X-User-Email` is not identity.
- Release shares verified as `SHA3-256(job_id|email|key_commitment)`; `dummy_share` rejected.
- Study join requires `invite_code`. Dataset column IDOR closed. Job requests require `allow_external_requests` unless owner.
- Alembic baseline (`0001_baseline`). Docker images run as non-root.
- Dependabot restored; security scans on PR; coverage includes `algorithms.py`.
- Uploads are JSON+base64 bundles. Pickle and `secret_context` are rejected.
- Study encryption key is the creator's public key (`key_source: creator_public_key`), not DKG.
- Result "shares" authorize release of the encrypted blob; they are not partial decrypts.
- SDK lives in `sdk/securecollab`; Fernet-only secret storage (no XOR, no empty password); HTTP timeout 30s.
- Config accepts both `DATABASE_URL`/`SECURECOLLAB_DATABASE_URL` and `UPLOAD_DIR`/`SECURECOLLAB_UPLOADS_DIR`.
- Run the API with `uvicorn app.main:app` (`backend/main.py` is a deprecation shim).

### Removed

- Server-side CKKS decrypt, pickle uploads, XOR key wrapping, silent zero results, fake `run_distribution` histograms.

## [0.1.0] — 2025-02-26

### Added

- HE core with TenSEAL CKKS scheme
- FastAPI backend with Study management
- Multi-party workflow (creator key + authorization shares; not DKG)
- Cryptographic commitments on every upload
- Hash-chained audit trail with codebase hash
- Client SDK with CLI interface
- Schema validation and synthetic dry-run
- Algorithms: descriptive statistics, correlation, group comparison, linear regression, survival analysis approximation
- OWASP security hardening
- Next.js frontend with Provider and Researcher dashboards
