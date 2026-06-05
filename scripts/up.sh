#!/usr/bin/env bash
set -euo pipefail

echo "[pctl] running tests..."
docker compose run --rm pctl-tests

echo "[pctl] starting proxy..."
docker compose up --build -d pctl-proxy

echo "[pctl] done"