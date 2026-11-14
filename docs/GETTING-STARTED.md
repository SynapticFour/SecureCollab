# Getting started

This page starts the demonstration. It does not make the deployment suitable for patient data. The banner in `frontend/app/layout.tsx` says synthetic or test data only.

Prerequisites for the Docker path: Docker. For the split path: Python 3.11 and Node.js 18 or newer.

## Docker

```bash
git clone https://github.com/SynapticFour/SecureCollab
cd SecureCollab
make up
```

You should see the frontend at `http://localhost:3000` and the backend at `http://localhost:8000`. Stop and keep data with `make down`. Remove volumes with `make destroy`.

## Two terminals, no Docker

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

In another terminal:

```bash
cd frontend
npm install && npm run dev
```

Open `http://localhost:3000`. Create a study at `http://localhost:3000/studies/new`.

`backend/encrypt.py` reads `sample_clinical_data.csv` when run as the README's encrypt example. Upload the generated `.bin` from the study page. The page says synthetic or test data only.

The longer local notes are in [DOCUMENTATION.md](../DOCUMENTATION.md).
