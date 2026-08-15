# SPDX-License-Identifier: Apache-2.0

# Migrations

Local demo still uses `app.database.create_db_and_tables()` at API startup (SQLite).

For production schema:

```bash
cd backend
pip install alembic
alembic upgrade head
```

New changes: `alembic revision --autogenerate -m "description"` then `alembic upgrade head`.
Do not rely on the ALTER TABLE fallbacks in `database.py` for production.
