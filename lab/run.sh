#!/usr/bin/env bash
# Run the evaluation end to end: certs → zones → lab up → harness → lab down.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run python lab/ca/generate.py
uv run python lab/dns/render.py
mkdir -p lab/logs && : > lab/logs/outside-access.log

compose=(docker compose -f lab/docker-compose.lab.yml --profile eval)
trap '"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true' EXIT
"${compose[@]}" build eval
"${compose[@]}" run --rm eval
