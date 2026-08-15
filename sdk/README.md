# SPDX-License-Identifier: Apache-2.0
"""SecureCollab SDK

Local encryption, schema negotiation, and API client. The secret key never
leaves the institution machine. Uploads are JSON+base64 TenSEAL bundles — never
pickle, never `secret_context`.

## Install

From repo root:

```bash
pip install -e ./sdk
```

## Usage

```python
from securecollab import SecureCollabClient, generate_key_share
client = SecureCollabClient("http://localhost:8000", email="you@org.example")
algorithms = client.get_algorithms()
```

## CLI

```bash
securecollab generate-key --email you@org.example
securecollab verify-study --study-id 1 --url http://localhost:8000
securecollab upload --csv data.csv --study-id 1 --email you@org.example --url http://localhost:8000
securecollab decrypt-share --study-id 1 --job-id 1 --email you@org.example --url http://localhost:8000
securecollab verify-audit --study-id 1 --url http://localhost:8000 --email you@org.example
```

`python backend/sdk.py …` still works; it is a shim to this package.

HTTP calls send `Authorization: Bearer` after `POST /auth/login` and use a 30s timeout. Secret-key files are
Fernet-wrapped (PBKDF2); empty passwords and XOR fallbacks are refused.
"""
