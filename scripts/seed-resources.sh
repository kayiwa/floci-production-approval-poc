#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
exec bash scripts/local-python.sh -m production_approval.cli seed
