FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV IDS_HOST=0.0.0.0
ENV IDS_PORT=8080
ENV MODEL_DIR=/app/NewApprochmodels

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY deepshield_backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY deepshield_backend ./deepshield_backend
COPY NewApprochmodels ./NewApprochmodels

WORKDIR /app/deepshield_backend

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} run:app --workers 1 --threads 8 --timeout 0"]
