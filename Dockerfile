# Production-ready Dockerfile for the Flask app
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# copy app
COPY . /app

# create runtime user
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

ENV FLASK_APP=app.py

# production entrypoint (optional one-time migration + gunicorn)
CMD ["sh", "/app/start.sh"]
