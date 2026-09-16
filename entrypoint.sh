#!/bin/sh
set -eu
echo "[startup] WireGuard panel container started"
echo "[startup] PORT=${PORT:-8080}"
echo "[startup] DATA_DIR=${DATA_DIR:-/data}"
mkdir -p "${DATA_DIR:-/data}"
echo "[startup] Starting Gunicorn..."
exec gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 1 --threads 4 --timeout 120 --access-logfile - --error-logfile - --capture-output wsgi:app
