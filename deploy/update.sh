#!/usr/bin/env bash
# Pull the latest HiveWatch and restart it. Captured data (Docker volume) is kept.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
docker compose up -d --build
docker image prune -f >/dev/null
echo "HiveWatch updated to $(git rev-parse --short HEAD)"
