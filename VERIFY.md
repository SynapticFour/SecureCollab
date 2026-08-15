# How To Verify SecureCollab

This guide is for operators who want to check that an instance runs the code they reviewed.

## Step 1: Review the Source Code

- **Repository:** https://github.com/SynapticFour/SecureCollab
- **Critical paths (current tree):**
  - `backend/app/main.py` – app factory, routers
  - `backend/app/core/security.py` / `tokens.py` – Bearer HMAC auth
  - `backend/app/core/release.py` – release-share verification
  - `backend/app/services/bundle.py` – JSON bundle codec (rejects pickle / secret_context)
  - `backend/app/services/he_service.py` and `backend/algorithms.py` – HE compute, local finalize
  - `backend/integrity.py` – codebase hash

`backend/main.py` and `backend/sdk.py` are deprecation shims. Do not review those as the live API.

## Step 2: Reproduce the Build

Images are built from `backend/Dockerfile` and `frontend/Dockerfile`:

```bash
docker build --no-cache -t securecollab-backend:verify -f backend/Dockerfile backend
docker build --no-cache -t securecollab-frontend:verify -f frontend/Dockerfile frontend
```

Compare image digests to whatever the operator published for that release. This repository does not ship a fixed "expected hash" for every commit.

## Step 3: Verify the Running Instance

```bash
curl https://your-instance.com/system/integrity
curl "https://your-instance.com/system/integrity/verify?expected_hash=<hash-from-step-3>"
```

`/system/integrity` returns the **startup-cached** hash. `/system/integrity/verify` re-walks the tree.
