#!/usr/bin/env bash
# Lightweight runner for development
# Usage: ./run_server.sh

export FLASK_APP=app
export FLASK_ENV=development
export FLASK_DEBUG=1
python -m flask run --host=127.0.0.1 --port=${PORT:-5001} --reload
