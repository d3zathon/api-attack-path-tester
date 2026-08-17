#!/usr/bin/env bash
# Spins up the vulnerable lab, waits for it to be healthy, generates a roles config with
# live tokens, runs a full scan against it, and prints where the reports landed.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Starting lab (docker compose)..."
docker compose up -d lab

echo "==> Waiting for lab to become healthy..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/health > /dev/null; then
    echo "lab is up."
    break
  fi
  sleep 1
done

echo "==> Generating roles_lab.yaml with fresh tokens..."
python3 scripts/generate_lab_config.py http://localhost:8000

echo "==> Running scan..."
python3 -m apiattack.cli scan \
  --spec examples/openapi_lab.yaml \
  --config examples/roles_lab.yaml \
  --out ./demo-report \
  --yes-i-am-authorized

echo "==> Done. See ./demo-report/report.md and ./demo-report/report.html"
