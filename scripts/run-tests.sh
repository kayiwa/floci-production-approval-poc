#!/usr/bin/env bash
set -euo pipefail
PROJECT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$PROJECT"
exec bash scripts/local-python.sh -m pytest "$@"
