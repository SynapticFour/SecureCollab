# SecureCollab

A proof piece about encryption, not for patient data.

For someone reading a homomorphic-encryption demonstration on synthetic or test data.

**Status: No public status recorded yet.** The claims registry has no entry for this repository.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

The banner in `frontend/app/layout.tsx` says the same limit: synthetic or test data only, no formal security or legal review, and do not upload real patient data.

> This repository documents technical capabilities and operating guidance. It is not legal advice and does not by itself provide regulatory certification or compliance guarantees.

## What it does

Homomorphic encryption computes on ciphertext. This prototype uses the CKKS scheme, via TenSEAL and Microsoft SEAL, because CKKS supports approximate arithmetic on real numbers: means, regression, and correlation. The server does not decrypt. It runs the same operations on encrypted vectors and returns encrypted sufficient statistics. An institution finalizes plaintext locally with its secret key.

Encryption uses the study creator's public key. That is not threshold distributed key generation. A "share" is an authorization to release the encrypted blob, checked as `SHA3-256(job_id|email|key_commitment)` against the value stored at join. It is not a cryptographic partial decrypt. A full t-of-n distributed key generation is not implemented.

A commitment at upload is `SHA3-256(ciphertext || public_key_fingerprint || timestamp || institution)`. It records which key was used and that the stored file matches the upload. A reader can check that locally.

The audit trail is append-only and hash-chained. Each entry includes the hash of the previous one. A later change breaks the chain. Publishing the trail root on a chain is listed as planned in [ROADMAP.md](ROADMAP.md). It is not implemented here.

```
  Institution A          Institution B
  [CSV data]             [CSV data]
      |                      |
  [encrypt locally]      [encrypt locally]
      |                      |
  [upload ciphertext]    [upload ciphertext]
      |                      |
      +------+  Server  +----+
             |          |
        [HE computation on ciphertexts]
             |
        [encrypted result]
             |
    [A approves] + [B approves]
             |
        [decrypted result]
             |
       both institutions
       (neither saw the other's data)
```

### Designed to ensure

These are design goals. They are not a legal guarantee.

- Raw data is not decrypted on the server.
- The secret key stays on the institution's machine. The SDK runs locally.
- Every operation is recorded in a hash-chained audit log.
- Commitment hashes record which key was used for each upload.
- A codebase hash is computed at startup and included in every audit entry. `GET /system/integrity` returns `codebase_hash`, `git_commit`, and versions. The steps to reproduce the hash are in [VERIFY.md](VERIFY.md).

### What the operator can see

| Can see | Cannot see |
|---------|------------|
| Encrypted datasets (ciphertexts) | Raw data |
| Metadata (file sizes, timestamps, institution names) | Secret keys (they stay on each institution's machine) |
| Audit trail entries (actions, not contents) | Decrypted results before every participant has authorized release |
| Commitment hashes | Which values are in a dataset |
| Combined public key fingerprint | |
| Encrypted intermediate results | |

The right column is the intended cryptographic design. Under that model, and assuming a correct implementation and deployment, those values stay hidden from the operator. That is not a legal or absolute guarantee. The wording guardrail is [LEGAL_NOTES.md](LEGAL_NOTES.md).

The statistics, the inputs, and the approximate times are in [docs/ALGORITHMS.md](docs/ALGORITHMS.md).

## Limits

- The interface is for synthetic or test data. It is not for patient data. `frontend/app/layout.tsx` says so. `backend/encrypt.py` reads `sample_clinical_data.csv` as the local example file.
- There is no formal security audit. [ROADMAP.md](ROADMAP.md) still lists one as later work.
- CKKS is approximate. Results have small floating-point errors. The notes are per algorithm in [docs/ALGORITHMS.md](docs/ALGORITHMS.md).
- Side-channel attacks are not mitigated in hardware. A trusted execution environment is planned, not present.
- There is no formal security proof of the full system.
- This repository is a research prototype. It is not an enterprise homomorphic-encryption platform.
- GitHub may report this repository's licence as not asserted. The file in the tree is Apache-2.0.
- A green test run is not a certificate and not a clinical pilot.

## Quick start

Prerequisites: Docker. Or Python 3.11 and Node.js 18 or newer for the split path.

```bash
git clone https://github.com/SynapticFour/SecureCollab
cd SecureCollab
make up
```

You should see the frontend at `http://localhost:3000` and the backend at `http://localhost:8000`. Stop and keep data with `make down`. Remove volumes with `make destroy`.

The split path, and the encrypt example, are in [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

## Deployment

Image build and an optional deploy dispatch are in [`.github/workflows/ghcr-infra.yml`](.github/workflows/ghcr-infra.yml). The workflow pushes:

- `ghcr.io/synapticfour/securecollab-backend:<tag>`
- `ghcr.io/synapticfour/securecollab-frontend:<tag>`

When `INFRA_DISPATCH_TOKEN` is set, the workflow posts a deploy event for app name `securecollab`. The operator repository is not linked from this page. The local matrix is [docs/deployment/README.md](docs/deployment/README.md). The domain named there is `securecollab.synapticfour.tech`.

## Documentation

### Tutorial

- [Getting started](docs/GETTING-STARTED.md)

### How-to guides

- [Deployment notes](docs/DEPLOYMENT.md)
- [Deployment matrix](docs/deployment/README.md)
- [Local development](DOCUMENTATION.md)
- [Verify a running instance](VERIFY.md)

### Reference

- [Algorithms](docs/ALGORITHMS.md)
- [For evaluators](docs/FOR-EVALUATORS.md)
- [Legal notes](LEGAL_NOTES.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

### Explanation

- [Architecture](docs/ARCHITECTURE.md)
- [Cryptography](docs/CRYPTOGRAPHY.md)
- [Roadmap](ROADMAP.md)

The full index is [docs/README.md](docs/README.md).

## Licence

This repository is Apache License 2.0. The file is [LICENSE](LICENSE).

## Cite

Use [CITATION.cff](CITATION.cff). Prefer that file over a hand-copied line.

## Website

- Open source: [https://synapticfour.com/en/opensource/](https://synapticfour.com/en/opensource/)
- Technical profile: [https://synapticfour.com/en/technical/code/](https://synapticfour.com/en/technical/code/)

The same pages exist in German (`/de/opensource/`, `/de/technik/code/`) and in French (`/fr/opensource/`, `/fr/technique/code/`).

The map of repositories: [profile/README.md](https://github.com/SynapticFour/.github/blob/main/profile/README.md).

Contact: [contact@synapticfour.com](mailto:contact@synapticfour.com)
