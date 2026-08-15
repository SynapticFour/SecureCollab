# SPDX-License-Identifier: Apache-2.0

# Architecture

Key design decisions for SecureCollab.

## Why FastAPI over Django/Flask

- **Async support** for I/O-bound operations (file uploads, external calls later).
- **OpenAPI out of the box** for SDK and frontend code generation.
- **Lightweight** and easy to wrap in a thin app factory for testing and deployment.
- **Type hints** and Pydantic integrate well with our config and request/response models.

## Why SQLite for Phase 0, PostgreSQL for Phase 1

- **Phase 0:** SQLite keeps setup minimal; no separate DB server. Single file, easy backup. Sufficient for demos and small multi-party trials.
- **Phase 1:** Switch by changing `DATABASE_URL` or `SECURECOLLAB_DATABASE_URL` to a PostgreSQL connection string. SQLModel/SQLAlchemy work with both; no application code change. PostgreSQL gives concurrency, replication, and compliance-friendly tooling.

## Why TenSEAL/CKKS over TFHE

- **Floating point:** Clinical and GWAS data are continuous (lab values, dosages). CKKS supports approximate arithmetic on reals.
- **TFHE** is for exact integer/binary circuits; better for discrete logic, worse for statistics and regression.
- **Performance:** CKKS is orders of magnitude faster for large vectors; we need to run many scalar ops per column.

## Why the SDK is a separate installable package

- **Institutions** run the SDK on their own machines; it must install with `pip install ./sdk` without pulling the full backend.
- **Clear boundary:** Crypto and API client live in one package; the server never sees plaintext. Versioning the SDK independently allows safe upgrades.

## Router/service split

Routers still own HTTP orchestration for studies (create, join, activate, HE job). Shared crypto/auth lives in `app/core/` (`tokens`, `release`, `passwords`) and services (`he_service`, `bundle`, `user_service`). The studies router is large; treat it as the workflow facade, not as "thin HTTP".

## Why config comes from environment variables

- **12-factor app:** Config varies per environment. Demo defaults exist in `app/config.py` (SQLite, `./uploads`, a documented dev `SECRET_KEY`).
- **Secrets:** Production must set `SECRET_KEY` (HMAC for access tokens). The API refuses to start if `SECURECOLLAB_PRODUCTION` is set and the default secret is still in use.
- **Pydantic Settings** validates types at startup.

## Auth (implemented)

Identity is a password-bound account plus an HMAC access token (`Authorization: Bearer`). Client-supplied `X-User-Email` is not identity. Email is not verified; do not use real institutional addresses on this prototype.

## Data flow: what is encrypted at each step

1. **Institution (SDK):** Raw CSV → encrypted per-column CKKS vectors → `.bin` bundle. Commitment = hash(ciphertext || public_key_fingerprint || timestamp || institution_id). Only ciphertext and commitment leave the machine.
2. **Upload:** Server stores `.bin` and commitment; never sees plaintext.
3. **Computation:** Server runs HE algorithms on ciphertext and stores **encrypted** sufficient statistics. It never holds a secret key.
4. **Result release:** After `t` institutions authorize, the encrypted blob is returned. Plaintext is produced only locally with `finalize_encrypted_result`.

```
[Institution] --(JSON bundle + commitment)--> [Server] --(HE compute, no decrypt)--> [Encrypted result]
                                                                              |
[Institution] <--(authorization share to release blob)------------------------+
     local finalize with secret context => plaintext statistics
```
