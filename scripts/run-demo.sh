#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
bash scripts/start-local.sh
exec bash scripts/local-python.sh -m production_approval.cli demo
