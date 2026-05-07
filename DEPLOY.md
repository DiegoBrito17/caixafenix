# Deploy & Security Checklist

This document describes how to prepare the project for production hosting (GitHub, Render, Heroku, etc.) and recommended security measures.

## Quick deploy (example: Render / Heroku)

1. Create repository on GitHub and push the project.
2. Add environment variables in the host dashboard (do NOT commit `.env`):
   - `SECRET_KEY` — long secret string
   - `DATABASE_URL` — production DB (Postgres recommended)
   - `ENV=production`
   - `ADMIN_PASSWORD` (optional)
   - `PORT` (Render/Heroku sets this automatically)
3. Choose Python environment (requirements.txt present). The `Procfile` runs migrations then `gunicorn app:app`.

## Security checklist

- Secrets:
  - Never commit `SECRET_KEY`, database credentials or `.env` to Git.
  - Use the platform secrets manager or `.env` locally (use `.env.example` as template).
- HTTPS:
  - Ensure HTTPS is enabled (SSL/TLS) by your host. `ENV=production` enables HSTS headers in the app.
- Cookies and sessions:
  - `SESSION_COOKIE_HTTPONLY` is enabled by default.
  - In production, `SESSION_COOKIE_SECURE` is set when `ENV=production`.
- HTTP headers:
  - `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` are set by the app.
- Database:
  - Prefer Postgres for production. Update `DATABASE_URL` accordingly.
  - Do not use SQLite for public-facing deployments.
- Backups:
  - Implement scheduled backups for your production DB.
- Access control:
  - Review users and remove default admin after initial setup.
  - Change the admin password immediately if created automatically.

## CI/CD & Testing

- Add GitHub Actions to run `pip install -r requirements.txt` and basic tests (optional).

## Recommended host settings

- Gunicorn workers: `web: gunicorn -w 4 -k gthread app:app --bind 0.0.0.0:$PORT`
- Use managed Postgres for reliability.

## Local development

- Copy `.env.example` to `.env` and customize values.
- Create virtualenv and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

## Post-deploy

- Verify pages `/`, `/vendas`, `/delivery` load over HTTPS.
- Remove any test data and change the admin password.

