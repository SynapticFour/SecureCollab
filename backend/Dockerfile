# SPDX-License-Identifier: Apache-2.0
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data /app/uploads \
    && chown -R appuser:appuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .
ENV SECURECOLLAB_DATABASE_URL=sqlite:///./data/secure_collab.db
ENV SECURECOLLAB_UPLOADS_DIR=/app/uploads

USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
