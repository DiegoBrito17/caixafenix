#!/bin/sh
set -eu

if [ "${RUN_MIGRATION:-0}" = "1" ]; then
  echo "RUN_MIGRATION=1 -> migrando SQLite para Postgres..."
  python migrate_sqlite_to_postgres.py
  echo "Migração concluída."
else
  echo "RUN_MIGRATION!=1 -> pulando migração."
fi

workers="${WEB_CONCURRENCY:-4}"

exec gunicorn -w "$workers" -k gthread --bind 0.0.0.0:8000 app:app
