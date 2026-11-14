# For evaluators

**Status: No public status recorded yet.** The claims registry has no SecureCollab entry.

## What this repository is

A proof piece about encryption. The running interface computes on ciphertexts with CKKS (TenSEAL). The design notes are in [ARCHITECTURE.md](ARCHITECTURE.md). The mechanisms are in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

The banner in `frontend/app/layout.tsx` says the deployment is for synthetic or test data only, that there has been no formal security or legal review, and that real patient data must not be uploaded. The page metadata says the same limit.

## What this repository is not

- It is not for patient data.
- It is not a medical device and not a certification. The short brief in [DECISION_MAKER.md](DECISION_MAKER.md) says the same.
- Result shares are authorizations to release an encrypted blob. They are not a threshold decryption. A full t-of-n distributed key generation is not implemented.
- CKKS is approximate. [ALGORITHMS.md](ALGORITHMS.md) lists the statistics.
- A green test run is not a formal security audit.
- [LEGAL_NOTES.md](../LEGAL_NOTES.md) is a writing guardrail. It is not legal advice.

## What a local run shows

`make up` shows the web interface on port 3000 and the API on port 8000. The checks that run without Docker are the backend tests, the frontend build, and the SDK tests named in `.github/workflows/ci.yml`.
