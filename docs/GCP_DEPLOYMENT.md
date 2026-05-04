# DeepShield GCP Deployment

This is a small, practical deployment path for the DeepShield mini-project. It deploys:

- `deepshield_backend` to Cloud Run
- `uii-main` to Cloud Run
- model artifacts bundled with the backend container
- optional n8n webhook integration through environment variables

## 1. GCP services used

- Cloud Run
- Cloud Build
- Artifact Registry
- Secret Manager
- Cloud Logging

## 2. One-time setup

Set your project:

```bash
gcloud config set project YOUR_PROJECT_ID
```

Enable APIs:

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
```

Create the Docker repository:

```bash
gcloud artifacts repositories create deepshield --repository-format=docker --location=us-central1
```

## 3. Backend environment variables

At minimum, configure these for Cloud Run:

```text
FLASK_SECRET_KEY=strong-secret
FLASK_DEBUG=0
IDS_HOST=0.0.0.0
IDS_PORT=8080
DATABASE_URL=sqlite:////tmp/deepshield.db
MODEL_DIR=/app/NewApprochmodels
IDS_CORS_ORIGINS=https://YOUR_FRONTEND_URL
IDS_N8N_WEBHOOK_URL=https://your-n8n-instance/webhook/deepshield-report
IDS_N8N_WEBHOOK_SECRET=shared-secret
OPENROUTER_API_KEY=your-key
OPENROUTER_MODEL=openai/gpt-4o-mini
```

Notes:

- `DATABASE_URL=sqlite:////tmp/deepshield.db` is acceptable for a mini-project demo, but it is ephemeral.
- For a stronger deployment later, move to Cloud SQL Postgres.
- `MODEL_DIR=/app/NewApprochmodels` matches the backend container image.

## 4. Frontend build variables

The Vite frontend needs these at build time:

```text
VITE_API_BASE=https://YOUR_BACKEND_URL
VITE_ANALYST_API_KEY=optional-demo-key
```

## 5. Manual first deployment

Deploy backend:

```bash
gcloud run deploy deepshield-backend \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

For this repo, the recommended method is Cloud Build with the included `cloudbuild.yaml`, but a manual first deployment helps verify the environment.

## 6. Cloud Build pipeline

The repository includes `cloudbuild.yaml` that:

1. builds backend and frontend Docker images,
2. pushes them to Artifact Registry,
3. deploys both services to Cloud Run.

Example trigger command:

```bash
gcloud builds submit \
  --config cloudbuild.yaml \
  --substitutions=_REGION=us-central1,_API_BASE_URL=https://BACKEND_URL,_BACKEND_ENV_VARS='FLASK_SECRET_KEY=strong-secret,FLASK_DEBUG=0,IDS_HOST=0.0.0.0,IDS_PORT=8080,DATABASE_URL=sqlite:////tmp/deepshield.db,MODEL_DIR=/app/NewApprochmodels',_FRONTEND_ENV_VARS='VITE_API_BASE=https://BACKEND_URL'
```

## 7. Validation for this IDS project

This system is validated as an operational prototype, not as a normal end-user app. After deployment, verify:

- backend health endpoint returns success,
- prediction endpoint accepts a valid feature payload,
- frontend loads and fetches alerts/realtime data,
- report dispatch endpoint can reach the configured n8n webhook,
- logs are visible in Cloud Logging.

Suggested mini-project evidence:

- screenshot of Cloud Run services,
- screenshot of frontend running from cloud URL,
- successful `GET /health`,
- one successful `POST /predict`,
- one successful report dispatch or logged webhook attempt.

## 8. Report justification

Use this wording in your report:

> DeepShield is deployed as a cloud-hosted IDS prototype to demonstrate reproducibility, remote accessibility, and basic operational readiness. Because the platform is a complete detection and response workflow rather than a single-user prediction app, validation focuses on service health, inference execution, dashboard connectivity, and report automation.
